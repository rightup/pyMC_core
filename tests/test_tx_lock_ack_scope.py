"""OH-002: the ACK wait must not hold the dispatcher's global transmit lock.

Firmware reference (MeshCore ``8a69f34``): ``Dispatcher::loop`` owns the radio
only from ``startSendRaw`` until ``isSendComplete()`` / ``outbound_expiry``
(1.5x estimated airtime), then immediately services the outbound queue again
(``Dispatcher.cpp:86-131``, ``checkSend:275-354``). ACK correlation lives a
layer up in ``BaseChatMesh``: ``sendMessage`` queues the packet and arms a
non-blocking ``txt_send_timeout`` deadline polled from ``loop()``
(``BaseChatMesh.cpp:442-483``, ``:958-961``); ``onAckRecv`` just clears it
(``:347-351``). The send funnel is never held across an ACK wait.

Core previously held ``_tx_lock`` through ``sleep(tx_delay)`` +
``wait_for_ack(ACK_TIMEOUT=5.0)``, blocking every other funnel user (including
client-repeat relay forwards) for up to five seconds while the radio sat idle.
These tests pin the corrected shape: transmit + budget debit + ACK-waiter
registration under the lock, the wait itself outside it.

Companion invariant note: ``test_tx_budget.py`` already guards "lock held during
``radio.send``, released after" for ``wait_for_ack=False``; this module extends
that to the ACK-waiting path and adds the release-before-wait guarantee.
"""

import asyncio
import time

import pytest

from openhop_core.node import dispatcher as disp_mod
from openhop_core.node.dispatcher import Dispatcher, DispatcherState
from openhop_core.protocol import Packet
from openhop_core.protocol.constants import (
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_TXT_MSG,
    ROUTE_TYPE_FLOOD,
)

SELF_KEY = b"0123456789abcdef0123456789abcdef"


class Radio:
    """Records every transmit; ``gate`` lets a test hold one open mid-send."""

    def __init__(self):
        self.rx_callback = None
        self.send_count = 0
        self.send_starts = []
        self.tx_data = None
        self.gate = None  # asyncio.Event: when set (or None), send returns at once
        self.lock_held_during_send = []
        self.dispatcher = None
        self.fail_with = None  # Exception instance to raise instead of sending
        self.metadata = {"ok": 1}

    def set_rx_callback(self, cb):
        self.rx_callback = cb

    async def send(self, data):
        self.send_count += 1
        self.send_starts.append(time.monotonic())
        self.tx_data = data
        if self.dispatcher is not None:
            self.lock_held_during_send.append(self.dispatcher._tx_lock.locked())
        if self.fail_with is not None:
            raise self.fail_with
        if self.gate is not None:
            await self.gate.wait()
        return self.metadata

    def get_last_rssi(self):
        return -70

    def get_last_snr(self):
        return 8.0


class Identity:
    def get_public_key(self):
        return SELF_KEY


def _make(*, tx_delay=0.0, client_repeat=False):
    radio = Radio()
    d = Dispatcher(radio, tx_delay=tx_delay, dedupe_enabled=True)
    d.local_identity = Identity()
    radio.dispatcher = d
    if client_repeat:
        d.set_client_repeat_enabled(True)
    return d, radio


def _txt(seq: int = 0) -> Packet:
    """A flood TXT_MSG packet; ``seq`` varies the payload so CRCs differ."""
    p = Packet()
    p.header = (PAYLOAD_TYPE_TXT_MSG << 2) | ROUTE_TYPE_FLOOD
    p.payload = bytearray([0x77, 0x99, seq & 0xFF]) + bytearray(b"\xAA" * 12)
    p.payload_len = len(p.payload)
    return p


def _typed(payload_type: int) -> Packet:
    p = Packet()
    p.header = (payload_type << 2) | ROUTE_TYPE_FLOOD
    p.payload = bytearray(b"\xAA" * 8)
    p.payload_len = len(p.payload)
    return p


async def _spin_until(pred, turns: int = 500) -> bool:
    """Yield to the event loop until ``pred()`` holds, without wall-clock sleeps."""
    for _ in range(turns):
        if pred():
            return True
        await asyncio.sleep(0)
    return pred()


# --------------------------------------------------------------------------- #
# Lock scope: held for the transmit, released for the wait
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_lock_is_held_during_transmit_on_the_ack_path():
    # Firmware holds the radio for the physical send; so must we. This is the
    # invariant the OH-002 fix must NOT relax (test_tx_budget covers the same
    # thing for wait_for_ack=False sends).
    d, radio = _make()
    pkt = _txt()
    crc = pkt.get_crc()

    task = asyncio.create_task(d.send_packet(pkt, wait_for_ack=True))
    assert await _spin_until(lambda: radio.send_count == 1)

    assert radio.lock_held_during_send == [True]

    await d._register_ack_received(crc)
    assert await task is True


@pytest.mark.asyncio
async def test_tx_lock_is_free_while_parked_in_the_ack_wait():
    # The core of OH-002: once the physical transmit completes the funnel is
    # free, exactly as Dispatcher::loop releases `outbound` on isSendComplete().
    d, radio = _make()
    pkt = _txt()
    crc = pkt.get_crc()

    task = asyncio.create_task(d.send_packet(pkt, wait_for_ack=True))
    assert await _spin_until(lambda: crc in d._waiting_acks)

    assert radio.send_count == 1  # transmit already happened
    assert not d._tx_lock.locked()  # ...and the lock is already released
    assert d.state == DispatcherState.WAIT
    assert not task.done()

    await d._register_ack_received(crc)
    assert await task is True


@pytest.mark.asyncio
async def test_second_send_transmits_while_first_awaits_its_ack():
    # Pre-fix, B queued on _tx_lock behind A's up-to-5s ACK wait and the radio
    # sat idle. Post-fix B transmits immediately.
    d, radio = _make()
    pkt_a = _txt(1)
    crc_a = pkt_a.get_crc()

    task_a = asyncio.create_task(d.send_packet(pkt_a, wait_for_ack=True))
    assert await _spin_until(lambda: crc_a in d._waiting_acks)
    assert not task_a.done()

    # B goes out during A's wait window, well inside ACK_TIMEOUT.
    assert await d.send_packet(_txt(2), wait_for_ack=False) is True
    assert radio.send_count == 2
    assert not task_a.done()  # A is still waiting; B did not resolve it

    await d._register_ack_received(crc_a)
    assert await task_a is True


@pytest.mark.asyncio
async def test_second_ack_waiting_send_overlaps_the_first():
    # Two independent ACK waits may now be in flight at once; each resolves on
    # its own CRC.
    d, radio = _make()
    pkt_a, pkt_b = _txt(1), _txt(2)
    crc_a, crc_b = pkt_a.get_crc(), pkt_b.get_crc()
    assert crc_a != crc_b

    task_a = asyncio.create_task(d.send_packet(pkt_a, wait_for_ack=True))
    assert await _spin_until(lambda: crc_a in d._waiting_acks)
    task_b = asyncio.create_task(d.send_packet(pkt_b, wait_for_ack=True))
    assert await _spin_until(lambda: crc_b in d._waiting_acks)

    assert radio.send_count == 2
    assert not task_a.done() and not task_b.done()

    await d._register_ack_received(crc_b)
    assert await task_b is True
    assert not task_a.done()  # B's ACK must not resolve A

    await d._register_ack_received(crc_a)
    assert await task_a is True
    assert d._waiting_acks == {}


@pytest.mark.asyncio
async def test_client_repeat_forward_is_not_blocked_by_an_ack_wait():
    # The client-repeat branch of send_packet is separate code (budget gate +
    # under-lock admission recheck); it must release the lock before the wait
    # too, or relay forwards stall behind every DM awaiting an ACK.
    d, radio = _make(client_repeat=True)
    pkt_a = _txt(1)
    crc_a = pkt_a.get_crc()

    task_a = asyncio.create_task(d.send_packet(pkt_a, wait_for_ack=True))
    assert await _spin_until(lambda: crc_a in d._waiting_acks)
    assert not d._tx_lock.locked()

    # A relay forward is a plain wait_for_ack=False send through the funnel.
    assert await d.send_packet(_txt(2), wait_for_ack=False) is True
    assert radio.send_count == 2

    await d._register_ack_received(crc_a)
    assert await task_a is True


# --------------------------------------------------------------------------- #
# Waiter registration happens under the lock (no missed ACKs)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_waiter_is_registered_before_the_lock_is_released():
    # Registering under _tx_lock is what makes the off-lock wait safe: the CRC
    # is already in _waiting_acks the instant the funnel reopens, so an ACK that
    # lands in the gap is matched rather than dropped.
    d, radio = _make()
    pkt = _txt()
    crc = pkt.get_crc()
    radio.gate = asyncio.Event()  # hold the transmit open

    task = asyncio.create_task(d.send_packet(pkt, wait_for_ack=True))
    assert await _spin_until(lambda: radio.send_count == 1)
    assert d._tx_lock.locked()
    assert crc not in d._waiting_acks  # not yet -- transmit hasn't completed

    radio.gate.set()
    assert await _spin_until(lambda: not d._tx_lock.locked())
    assert crc in d._waiting_acks  # registered by the time the lock frees

    await d._register_ack_received(crc)
    assert await task is True


@pytest.mark.asyncio
async def test_ack_arriving_during_tx_delay_is_still_matched():
    # tx_delay now elapses off-lock, and the waiter is registered before it, so
    # an ACK during that window resolves the send instead of being missed.
    d, radio = _make(tx_delay=0.05)
    pkt = _txt()
    crc = pkt.get_crc()

    started = time.monotonic()
    task = asyncio.create_task(d.send_packet(pkt, wait_for_ack=True))
    assert await _spin_until(lambda: crc in d._waiting_acks)
    assert not d._tx_lock.locked()  # funnel free during tx_delay as well
    assert not task.done()

    await d._register_ack_received(crc)
    assert await task is True
    # The tx_delay pause still happened -- it was moved, not removed.
    assert time.monotonic() - started >= 0.05


@pytest.mark.asyncio
async def test_ack_already_cached_resolves_without_waiting():
    # _recent_acks is the belt-and-braces guard for an ACK that beat the
    # registration; expect_ack() fires the event immediately in that case.
    d, _radio = _make()
    pkt = _txt()
    crc = pkt.get_crc()
    d._recent_acks[crc] = asyncio.get_running_loop().time()

    assert await d.send_packet(pkt, wait_for_ack=True) is True
    assert crc not in d._waiting_acks


@pytest.mark.asyncio
async def test_expected_crc_override_is_used_for_correlation():
    # Text sends pass the SHA-derived expected_ack from PacketBuilder rather
    # than the packet CRC; the override must survive the lock restructure.
    d, _radio = _make()
    pkt = _txt()
    override = 0x1234ABCD
    assert override != pkt.get_crc()

    task = asyncio.create_task(d.send_packet(pkt, wait_for_ack=True, expected_crc=override))
    assert await _spin_until(lambda: override in d._waiting_acks)
    assert pkt.get_crc() not in d._waiting_acks

    await d._register_ack_received(override)
    assert await task is True


@pytest.mark.asyncio
async def test_waiting_ack_registration_marks_relayed_ack_do_not_retransmit():
    # AckHandler.__call__ keys `markDoNotRetransmit` off membership in
    # _waiting_acks (firmware BaseChatMesh::onAckRecv, which marks when
    # processAck matches). Registering under the lock only widens that window.
    d, _radio = _make()
    pkt = _txt()
    crc = pkt.get_crc()

    task = asyncio.create_task(d.send_packet(pkt, wait_for_ack=True))
    assert await _spin_until(lambda: crc in d._waiting_acks)

    ack_pkt = Packet()
    ack_pkt.header = (PAYLOAD_TYPE_ACK << 2) | ROUTE_TYPE_FLOOD
    ack_pkt.payload = bytearray(crc.to_bytes(4, "little")) + bytearray(b"\x01\x5A")
    ack_pkt.payload_len = len(ack_pkt.payload)

    handler = disp_mod.AckHandler(d._log, dispatcher=d)
    handler.set_ack_received_callback(d._register_ack_received)
    await handler(ack_pkt)

    assert ack_pkt.is_marked_do_not_retransmit() is True
    assert await task is True


# --------------------------------------------------------------------------- #
# Failure, timeout and cancellation paths
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_ack_timeout_returns_false_and_cleans_up(monkeypatch):
    monkeypatch.setattr(disp_mod, "ACK_TIMEOUT", 0.05)
    d, _radio = _make()
    pkt = _txt()
    crc = pkt.get_crc()

    assert await d.send_packet(pkt, wait_for_ack=True) is False
    assert crc not in d._waiting_acks
    assert not d._tx_lock.locked()
    assert d.state == DispatcherState.IDLE
    assert d._current_expected_crc is None


@pytest.mark.asyncio
async def test_transmit_exception_registers_no_waiter():
    d, radio = _make()
    radio.fail_with = RuntimeError("radio down")
    pkt = _txt()

    assert await d.send_packet(pkt, wait_for_ack=True) is False
    assert d._waiting_acks == {}
    assert not d._tx_lock.locked()
    assert d.state == DispatcherState.IDLE


@pytest.mark.asyncio
async def test_missing_tx_metadata_registers_no_waiter():
    d, radio = _make()
    radio.metadata = None
    pkt = _txt()

    assert await d.send_packet(pkt, wait_for_ack=True) is False
    assert d._waiting_acks == {}
    assert not d._tx_lock.locked()
    assert d.state == DispatcherState.IDLE


@pytest.mark.asyncio
async def test_cancel_during_ack_wait_frees_lock_and_registration():
    d, radio = _make()
    pkt = _txt()
    crc = pkt.get_crc()

    task = asyncio.create_task(d.send_packet(pkt, wait_for_ack=True))
    assert await _spin_until(lambda: crc in d._waiting_acks)
    assert not d._tx_lock.locked()

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert crc not in d._waiting_acks
    assert not d._tx_lock.locked()
    # The funnel is still usable after a cancelled ACK wait.
    assert await d.send_packet(_txt(2), wait_for_ack=False) is True
    assert radio.send_count == 2


@pytest.mark.asyncio
async def test_cancel_during_tx_delay_does_not_strand_the_waiter():
    # The waiter is now registered under _tx_lock, one await *earlier* than
    # _await_ack_event's own try/finally. A cancel landing in that gap -- the
    # tx_delay pause, which is non-zero by default -- must still unregister the
    # CRC. Nothing prunes _waiting_acks (unlike _recent_acks, cleaned in
    # run_forever), so a stranded entry would make AckHandler mark every relayed
    # ACK for that CRC do-not-retransmit for the life of the process.
    d, _radio = _make(tx_delay=0.5)
    pkt = _txt()
    crc = pkt.get_crc()

    task = asyncio.create_task(d.send_packet(pkt, wait_for_ack=True))
    assert await _spin_until(lambda: crc in d._waiting_acks)
    assert d.state == DispatcherState.WAIT  # parked in tx_delay, not yet awaiting

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert crc not in d._waiting_acks
    assert d._waiting_acks == {}
    assert not d._tx_lock.locked()


# --------------------------------------------------------------------------- #
# Paths that never wait
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("payload_type", [PAYLOAD_TYPE_ADVERT, PAYLOAD_TYPE_ACK])
@pytest.mark.asyncio
async def test_advert_and_ack_never_register_a_waiter(payload_type):
    # Firmware never awaits an ACK for an ADVERT or an ACK; wait_for_ack=True
    # from a caller must stay a no-op for these types.
    d, radio = _make()

    assert await d.send_packet(_typed(payload_type), wait_for_ack=True) is True
    assert radio.send_count == 1
    assert d._waiting_acks == {}
    assert d.state == DispatcherState.IDLE
    assert not d._tx_lock.locked()


@pytest.mark.asyncio
async def test_wait_for_ack_false_returns_after_transmit():
    d, radio = _make()

    assert await d.send_packet(_txt(), wait_for_ack=False) is True
    assert radio.send_count == 1
    assert d._waiting_acks == {}
    assert d.state == DispatcherState.IDLE
    assert not d._tx_lock.locked()


@pytest.mark.asyncio
async def test_state_returns_to_idle_after_a_successful_ack_wait():
    d, _radio = _make()
    pkt = _txt()
    crc = pkt.get_crc()

    task = asyncio.create_task(d.send_packet(pkt, wait_for_ack=True))
    assert await _spin_until(lambda: d.state == DispatcherState.WAIT)

    await d._register_ack_received(crc)
    assert await task is True
    assert d.state == DispatcherState.IDLE
    assert d._current_expected_crc is None


# --------------------------------------------------------------------------- #
# Waiter ownership when two sends collide on one CRC (issue #136)
# --------------------------------------------------------------------------- #
#
# Releasing _tx_lock before the ACK wait (the fix these tests pin) is what lets
# two sends wait on the same CRC at once. That is legitimate -- the CRC hashes
# timestamp, flags and text with a key (PacketBuilder.create_text_message), so a
# caller supplying its own timestamp reproduces it exactly, and a plain retry of
# one packet does too. Each waiter must therefore own its registration: one
# leaving, for any reason, must not detach the other.


@pytest.mark.asyncio
async def test_same_crc_sends_each_get_their_own_waiter():
    d, radio = _make()
    crc = 0x12345678

    first = asyncio.create_task(d.send_packet(_txt(0), wait_for_ack=True, expected_crc=crc))
    second = asyncio.create_task(d.send_packet(_txt(1), wait_for_ack=True, expected_crc=crc))
    assert await _spin_until(lambda: radio.send_count == 2)

    waiters = d._waiting_acks[crc]
    assert len(waiters) == 2
    assert waiters[0] is not waiters[1]  # not coalesced onto one shared Event

    await d._register_ack_received(crc)
    assert await first is True
    assert await second is True


@pytest.mark.asyncio
async def test_cancelling_one_same_crc_send_leaves_the_other_waiting():
    # Issue #136: cancelling one sender deleted the shared registration, so the
    # ACK that arrived next was cached but woke nobody, and the surviving send
    # reported a delivery failure it never had.
    d, radio = _make()
    crc = 0x12345678

    first = asyncio.create_task(d.send_packet(_txt(0), wait_for_ack=True, expected_crc=crc))
    second = asyncio.create_task(d.send_packet(_txt(1), wait_for_ack=True, expected_crc=crc))
    assert await _spin_until(lambda: radio.send_count == 2)

    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first

    # Only the cancelled sender's own registration is gone.
    assert len(d._waiting_acks[crc]) == 1

    await d._register_ack_received(crc)
    assert await second is True
    assert d._waiting_acks == {}


@pytest.mark.asyncio
async def test_cancel_during_tx_delay_spares_a_co_waiter():
    # The send_packet finally-block owns cleanup for a cancel landing in the
    # tx_delay gap, before _await_ack_event's own try/finally is entered
    # (test_cancel_during_tx_delay_does_not_strand_the_waiter). That earlier
    # cleanup path must be waiter-scoped too, not just the later one.
    d, radio = _make(tx_delay=0.5)
    crc = 0x0BADF00D

    first = asyncio.create_task(d.send_packet(_txt(0), wait_for_ack=True, expected_crc=crc))
    assert await _spin_until(lambda: crc in d._waiting_acks)
    second = asyncio.create_task(d.send_packet(_txt(1), wait_for_ack=True, expected_crc=crc))
    assert await _spin_until(lambda: len(d._waiting_acks.get(crc, [])) == 2)

    first.cancel()  # still parked in tx_delay, not yet inside _await_ack_event
    with pytest.raises(asyncio.CancelledError):
        await first

    assert len(d._waiting_acks[crc]) == 1

    await d._register_ack_received(crc)
    assert await second is True
    assert d._waiting_acks == {}


@pytest.mark.asyncio
async def test_crc_stays_registered_until_the_last_waiter_leaves():
    # AckHandler decides do-not-retransmit with `crc in _waiting_acks`
    # (firmware BaseChatMesh::onAckRecv). One waiter leaving must not clear that
    # while another send is still in flight, and the last one leaving must clear
    # it -- an empty list left behind would read as a waiter that is still there
    # and mark every relayed ACK for that CRC for the life of the process.
    d, radio = _make()
    crc = 0x0BADF00D

    first = asyncio.create_task(d.send_packet(_txt(0), wait_for_ack=True, expected_crc=crc))
    second = asyncio.create_task(d.send_packet(_txt(1), wait_for_ack=True, expected_crc=crc))
    assert await _spin_until(lambda: radio.send_count == 2)

    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    assert crc in d._waiting_acks  # second is still waiting on it

    second.cancel()
    with pytest.raises(asyncio.CancelledError):
        await second
    assert crc not in d._waiting_acks
    assert d._waiting_acks == {}
