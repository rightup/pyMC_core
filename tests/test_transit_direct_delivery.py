"""Local delivery of routed-direct packets still carrying hops.

MeshCore ``Mesh::onRecvPacket`` never runs payload processing for a direct
packet whose path is not yet exhausted::

    if (pkt->isRouteDirect() && pkt->getPathHashCount() > 0) {
      if (pkt->getPayloadType() == PAYLOAD_TYPE_ACK) { ... onAckRecv(...); }   // early-ACK peek
      if (self_id.isHashMatch(pkt->path, ...) && allowPacketForward(pkt)) {
        ... markSeen(pkt); removeSelfFromPath(pkt); ACTION_RETRANSMIT_DELAYED ...
      }
      return ACTION_RELEASE;   // NOT the next hop (or already forwarded)
    }

So a direct packet is delivered to payload processing only once its hop count
reaches 0, and the un-stripped copy is never delivered — not even by the node
that is its next hop, which forwards instead.

openHop diverged: ``_dispatch`` had no such gate, and the dedup table was the
only thing hiding it. Once dedup stopped tracking routed-direct packets this
node is not the next hop for (correct firmware parity — otherwise an overheard
route variant suppresses a copy this node *does* own), a node in direct range of
a sender that routes through a relay delivered the same DM twice: once from the
overheard pre-relay copy and again from the relayed copy, which share a
path-independent packet hash.

The gate applies only to handlers registered ``local_delivery=True``, because
``_dispatch`` is also how applications route: openhop_repeater installs its
router as the fallback handler (and its own RAW_CUSTOM handler) and must keep
seeing exactly these transit packets.
"""

import asyncio

import pytest

from openhop_core.node.dispatcher import Dispatcher
from openhop_core.protocol import Packet
from openhop_core.protocol.constants import (
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_PATH,
    PAYLOAD_TYPE_RESPONSE,
    PAYLOAD_TYPE_TRACE,
    PAYLOAD_TYPE_TXT_MSG,
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
)
from openhop_core.protocol.packet_utils import PathUtils

SELF_KEY = b"0123456789abcdef0123456789abcdef"
SELF_HASH = SELF_KEY[0]  # 0x30
OTHER_HASH = 0xEE


class CountingRadio:
    def __init__(self):
        self.rx_callback = None
        self.send_count = 0

    def set_rx_callback(self, callback):
        self.rx_callback = callback

    async def send(self, data: bytes):
        self.send_count += 1
        return {"ok": True}

    def get_last_rssi(self):
        return -70

    def get_last_snr(self):
        return 8.0


class MockIdentity:
    def get_public_key(self):
        return SELF_KEY


def _make_dispatcher():
    radio = CountingRadio()
    d = Dispatcher(radio, dedupe_enabled=True)
    d.local_identity = MockIdentity()
    return d, radio


def _direct_pkt(payload_type, path, hops, payload=None):
    """A routed-direct packet with a path-independent payload.

    Every route variant of the same payload hashes alike, which is what makes
    the overheard copy and the relayed copy collide in the dedup table.
    """
    p = Packet()
    p.header = (payload_type << 2) | ROUTE_TYPE_DIRECT
    body = (
        payload if payload is not None else bytearray([SELF_HASH, 0x99]) + bytearray(b"\xaa" * 12)
    )
    p.payload = bytearray(body)
    p.payload_len = len(p.payload)
    p.path = bytearray(path)
    p.path_len = PathUtils.encode_path_len(1, hops)
    return p


def _flood_pkt(payload_type):
    p = Packet()
    p.header = (payload_type << 2) | ROUTE_TYPE_FLOOD
    # Distinct payload: the packet hash is path-independent, so reusing the
    # direct payload here would collide with it in the dedup table.
    p.payload = bytearray([SELF_HASH, 0x99]) + bytearray(b"\xbb" * 12)
    p.payload_len = len(p.payload)
    p.path = bytearray()
    p.path_len = 0
    return p


def _recording_handler(seen):
    async def _handler(pkt):
        seen.append(bytes(pkt.path))
        return None

    return _handler


async def _feed(dispatcher, pkt):
    await dispatcher._process_received_packet(pkt.write_to(), -70, 8.0)
    await asyncio.sleep(0)


# --------------------------------------------------------------------------- #
# The regression: one DM, two received copies, one local delivery
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_overheard_transit_copy_is_not_delivered_locally():
    """The pre-relay copy is released; only the exhausted-path copy is delivered.

    Before the fix both copies reached the handler, because dedup (correctly) no
    longer tracks a routed-direct packet this node is not the next hop for.
    """
    d, _radio = _make_dispatcher()
    seen = []
    d.register_handler(PAYLOAD_TYPE_TXT_MSG, _recording_handler(seen), local_delivery=True)

    # Overheard while still addressed via a relay: first hash is not ours.
    await _feed(d, _direct_pkt(PAYLOAD_TYPE_TXT_MSG, bytes([OTHER_HASH, 0xBB]), hops=2))
    assert seen == [], "a direct packet with hops left must not be delivered locally"

    # The relay strips itself; the path is now exhausted and this copy is ours.
    await _feed(d, _direct_pkt(PAYLOAD_TYPE_TXT_MSG, b"", hops=0))
    assert seen == [b""], "the exhausted-path copy must be delivered exactly once"


@pytest.mark.asyncio
async def test_transit_copy_addressed_via_us_is_not_delivered_either():
    """Being the next hop means forward, not deliver (firmware strips then relays)."""
    d, _radio = _make_dispatcher()
    seen = []
    d.register_handler(PAYLOAD_TYPE_TXT_MSG, _recording_handler(seen), local_delivery=True)

    await _feed(d, _direct_pkt(PAYLOAD_TYPE_TXT_MSG, bytes([SELF_HASH, 0xBB]), hops=2))
    assert seen == []


@pytest.mark.asyncio
async def test_every_core_local_delivery_type_is_gated():
    """RESPONSE / PATH / TXT all carry replies; none may be delivered in transit."""
    for payload_type in (PAYLOAD_TYPE_TXT_MSG, PAYLOAD_TYPE_RESPONSE, PAYLOAD_TYPE_PATH):
        d, _radio = _make_dispatcher()
        seen = []
        d.register_handler(payload_type, _recording_handler(seen), local_delivery=True)
        await _feed(d, _direct_pkt(payload_type, bytes([OTHER_HASH]), hops=1))
        assert seen == [], f"payload type {payload_type} delivered while in transit"


# --------------------------------------------------------------------------- #
# The gate must not over-reach
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_routing_handler_still_sees_transit_packets():
    """An application router (registered without ``local_delivery``) is un-gated.

    openhop_repeater routes through the dispatcher's handler chain; gating it
    would silently stop the repeater relaying routed-direct traffic.
    """
    d, _radio = _make_dispatcher()
    seen = []
    d.register_handler(PAYLOAD_TYPE_TXT_MSG, _recording_handler(seen))

    await _feed(d, _direct_pkt(PAYLOAD_TYPE_TXT_MSG, bytes([OTHER_HASH, 0xBB]), hops=2))
    assert seen == [bytes([OTHER_HASH, 0xBB])]


@pytest.mark.asyncio
async def test_fallback_handler_still_sees_transit_packets():
    """The repeater installs its router via register_fallback_handler."""
    d, _radio = _make_dispatcher()
    seen = []
    d.register_fallback_handler(_recording_handler(seen))

    await _feed(d, _direct_pkt(PAYLOAD_TYPE_TXT_MSG, bytes([OTHER_HASH]), hops=1))
    assert seen == [bytes([OTHER_HASH])]


def test_default_handler_wiring_marks_exactly_the_local_delivery_types():
    """Pin which core payload types are gated, so a new handler cannot slip through.

    Everything ``register_default_handlers`` installs consumes the payload for
    this node except: ACK / MULTIPART (firmware peeks a transit direct ACK, and
    CRC correlation is idempotent) and TRACE (its own firmware branch; its path
    bytes are per-hop SNR, not routing hashes). Adding a handler here means
    deciding which side of that line it falls on.
    """
    d, _radio = _make_dispatcher()
    d.register_default_handlers(contacts=None, local_identity=d.local_identity)

    from openhop_core.protocol.constants import (
        PAYLOAD_TYPE_ADVERT,
        PAYLOAD_TYPE_ANON_REQ,
        PAYLOAD_TYPE_CONTROL,
        PAYLOAD_TYPE_GRP_TXT,
        PAYLOAD_TYPE_MULTIPART,
        PAYLOAD_TYPE_RAW_CUSTOM,
    )

    assert d._local_delivery_types == {
        PAYLOAD_TYPE_ADVERT,
        PAYLOAD_TYPE_TXT_MSG,
        PAYLOAD_TYPE_GRP_TXT,
        PAYLOAD_TYPE_PATH,
        PAYLOAD_TYPE_RESPONSE,
        PAYLOAD_TYPE_ANON_REQ,
        PAYLOAD_TYPE_CONTROL,
        PAYLOAD_TYPE_RAW_CUSTOM,
    }
    # The deliberate exemptions, spelled out.
    assert d._local_delivery_types.isdisjoint(
        {PAYLOAD_TYPE_ACK, PAYLOAD_TYPE_MULTIPART, PAYLOAD_TYPE_TRACE}
    )
    # Every gated type must actually have a handler installed.
    assert d._local_delivery_types <= set(d._handlers)


@pytest.mark.asyncio
async def test_application_override_of_a_core_type_clears_the_gate():
    """Re-registering a core payload type hands the decision to the application."""
    d, _radio = _make_dispatcher()
    d.register_default_handlers(contacts=None, local_identity=d.local_identity)
    assert PAYLOAD_TYPE_TXT_MSG in d._local_delivery_types

    seen = []
    d.register_handler(PAYLOAD_TYPE_TXT_MSG, _recording_handler(seen))
    assert PAYLOAD_TYPE_TXT_MSG not in d._local_delivery_types

    await _feed(d, _direct_pkt(PAYLOAD_TYPE_TXT_MSG, bytes([OTHER_HASH]), hops=1))
    assert seen == [bytes([OTHER_HASH])]


@pytest.mark.asyncio
async def test_direct_ack_is_still_peeked_in_transit():
    """Firmware's "early received ACK": onAckRecv runs before the next-hop check."""
    d, _radio = _make_dispatcher()
    d.register_default_handlers(contacts=None, local_identity=d.local_identity)
    assert PAYLOAD_TYPE_ACK not in d._local_delivery_types

    crc = 0x12345678
    evt = d.expect_ack(crc)

    ack = _direct_pkt(
        PAYLOAD_TYPE_ACK, bytes([OTHER_HASH, 0xBB]), hops=2, payload=crc.to_bytes(4, "little")
    )
    await _feed(d, ack)

    assert evt.is_set(), "a transit direct ACK must still be correlated"


@pytest.mark.asyncio
async def test_direct_trace_is_not_gated():
    """Direct TRACE has its own firmware branch, and its path bytes are SNR data."""
    d, _radio = _make_dispatcher()
    seen = []
    d.register_handler(PAYLOAD_TYPE_TRACE, _recording_handler(seen))
    assert PAYLOAD_TYPE_TRACE not in d._local_delivery_types

    await _feed(d, _direct_pkt(PAYLOAD_TYPE_TRACE, bytes([OTHER_HASH]), hops=1))
    assert seen == [bytes([OTHER_HASH])]


@pytest.mark.asyncio
async def test_zero_hop_direct_and_flood_are_delivered():
    """The gate is scoped to routed-direct packets: nothing else changes."""
    d, _radio = _make_dispatcher()
    seen = []
    d.register_handler(PAYLOAD_TYPE_TXT_MSG, _recording_handler(seen), local_delivery=True)

    await _feed(d, _direct_pkt(PAYLOAD_TYPE_TXT_MSG, b"", hops=0))
    await _feed(d, _flood_pkt(PAYLOAD_TYPE_TXT_MSG))
    assert len(seen) == 2


@pytest.mark.asyncio
async def test_packet_received_callback_still_fires_for_a_transit_packet():
    """Only payload delivery is suppressed; observers (RX stats) are untouched."""
    d, _radio = _make_dispatcher()
    seen = []
    d.register_handler(PAYLOAD_TYPE_TXT_MSG, _recording_handler(seen), local_delivery=True)

    observed = []

    async def _on_received(pkt):
        observed.append(pkt.get_payload_type())

    d.set_packet_received_callback(_on_received)

    await _feed(d, _direct_pkt(PAYLOAD_TYPE_TXT_MSG, bytes([OTHER_HASH]), hops=1))
    assert seen == []
    assert observed == [PAYLOAD_TYPE_TXT_MSG]


# --------------------------------------------------------------------------- #
# Interaction with the dedup rule the gate exists to complement
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_dedup_skip_and_delivery_gate_hold_together():
    """The two halves of firmware parity must both hold at once.

    Dedup must not track a routed-direct packet this node is not the next hop
    for (or an overheard variant suppresses the copy it later owns), *and* that
    untracked copy must not be delivered locally. Asserting them together is
    what pins the regression: satisfying either one alone reintroduces a bug.
    """
    d, radio = _make_dispatcher()
    d.set_client_repeat_enabled(True)
    d._client_repeat_delay_ms = lambda pkt: 0.0
    seen = []
    d.register_handler(PAYLOAD_TYPE_TXT_MSG, _recording_handler(seen), local_delivery=True)

    # Overheard longer variant: not ours to relay, not delivered, not tracked.
    await _feed(d, _direct_pkt(PAYLOAD_TYPE_TXT_MSG, bytes([OTHER_HASH, SELF_HASH, 0xBB]), hops=3))
    await asyncio.sleep(0.01)
    assert radio.send_count == 0
    assert seen == []

    # Upstream strips itself: we are the next hop now. Relay it (not delivered).
    await _feed(d, _direct_pkt(PAYLOAD_TYPE_TXT_MSG, bytes([SELF_HASH, 0xBB]), hops=2))
    await asyncio.sleep(0.01)
    assert radio.send_count == 1, "an overheard variant must not suppress a relay we own"
    assert seen == []
