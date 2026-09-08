"""Flood reception-quality delay vs. the MeshCore firmware reference.

MeshCore's Dispatcher::checkRecv holds flood packets for a delay derived
from the reception score (RadioLibWrapper::packetScoreInt) and the packet's
airtime, so a better-received copy processes first and dedupe — which runs
at process time, after the hold — drops the worse copy when it wakes.
Direct routes are never delayed, delays under 50 ms process immediately,
delays cap at 32 s, and the shipped default rx_delay_base of 0 disables the
mechanism entirely.
"""

import asyncio

import pytest

from openhop_core.node.dispatcher import MAX_RX_DELAY_MS, Dispatcher
from openhop_core.protocol import Packet
from openhop_core.protocol.constants import (
    PAYLOAD_TYPE_TXT_MSG,
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_FLOOD,
)
from openhop_core.protocol.packet_filter import PacketFilter
from openhop_core.protocol.packet_utils import flood_rx_metrics, packet_score


class StubRadio:
    """Radio double exposing the LoRa settings the delay estimator reads."""

    def __init__(self, sf=10, bandwidth=250000, coding_rate=5, preamble_length=8):
        self.spreading_factor = sf
        self.bandwidth = bandwidth
        self.coding_rate = coding_rate
        self.preamble_length = preamble_length
        self.rx_callback = None

    def set_rx_callback(self, callback):
        self.rx_callback = callback

    def get_last_rssi(self):
        return -70

    def get_last_snr(self):
        return 0.0

    async def send(self, data: bytes):
        return True


class RecordingHandler:
    def __init__(self):
        self.packets = []

    async def __call__(self, packet: Packet):
        self.packets.append(packet)


def make_frame(route_type: int, payload: bytes, path: bytes = b"") -> bytes:
    pkt = Packet()
    pkt.header = route_type | (PAYLOAD_TYPE_TXT_MSG << 2)
    pkt.path = bytearray(path)
    pkt.path_len = len(path)
    pkt.payload = bytearray(payload)
    pkt.payload_len = len(payload)
    return pkt.write_to()


def make_dispatcher(radio=None) -> Dispatcher:
    return Dispatcher(radio=radio or StubRadio(), packet_filter=PacketFilter())


# ---------------------------------------------------------------------------
# packet_score — MeshCore RadioLibWrapper::packetScoreInt
# ---------------------------------------------------------------------------
class TestPacketScore:
    def test_firmware_formula_values(self):
        # (snr - threshold) / 10 * (1 - len / 256), clamped to [0, 1]
        assert packet_score(-5.0, 7, 24) == pytest.approx(0.2265625)
        assert packet_score(-10.0, 12, 128) == pytest.approx(0.5)

    def test_below_threshold_is_zero(self):
        assert packet_score(-8.0, 7, 24) == 0.0

    def test_sf_below_7_is_zero(self):
        assert packet_score(10.0, 6, 24) == 0.0
        assert packet_score(10.0, 5, 24) == 0.0

    def test_clamped_to_one(self):
        assert packet_score(20.0, 10, 0) == 1.0

    def test_max_length_packet_scores_zero(self):
        assert packet_score(0.0, 8, 256) == 0.0

    @pytest.mark.parametrize(
        "sf,threshold",
        [(7, -7.5), (8, -10.0), (9, -12.5), (10, -15.0), (11, -17.5), (12, -20.0)],
    )
    def test_per_sf_thresholds_match_firmware_table(self, sf, threshold):
        assert packet_score(threshold, sf, 0) == 0.0
        assert packet_score(threshold + 10.0, sf, 0) == 1.0


# ---------------------------------------------------------------------------
# Dispatcher.calc_rx_delay — the node firmwares' calcRxDelay override
# ---------------------------------------------------------------------------
class TestCalcRxDelay:
    def test_disabled_by_default(self):
        dispatcher = make_dispatcher()
        assert dispatcher.rx_delay_base == 0.0
        assert dispatcher.calc_rx_delay(0.0, 1000.0) == 0.0

    def test_firmware_formula(self):
        dispatcher = make_dispatcher()
        dispatcher.rx_delay_base = 10.0
        # (rx_delay_base ** (0.85 - score) - 1) * air_time
        assert dispatcher.calc_rx_delay(0.0, 100.0) == pytest.approx(
            607.945784, rel=1e-6
        )
        assert dispatcher.calc_rx_delay(0.85, 100.0) == 0.0

    def test_worse_reception_waits_longer(self):
        dispatcher = make_dispatcher()
        dispatcher.rx_delay_base = 10.0
        assert dispatcher.calc_rx_delay(0.2, 100.0) > dispatcher.calc_rx_delay(
            0.6, 100.0
        )


# ---------------------------------------------------------------------------
# Dispatcher._flood_rx_delay_ms — thresholds and cap
# ---------------------------------------------------------------------------
class TestFloodRxDelayMs:
    def test_zero_when_disabled(self):
        dispatcher = make_dispatcher()
        assert dispatcher._flood_rx_delay_ms(24, -15.0) == 0.0

    def test_weak_reception_delay_value(self):
        # SF10 / 250 kHz / CR5 / preamble 8, 24-byte frame = 185.344 ms on air
        # (RadioLib vector); SNR at the SF10 threshold scores 0.
        dispatcher = make_dispatcher()
        dispatcher.rx_delay_base = 10.0
        assert dispatcher._flood_rx_delay_ms(24, -15.0) == pytest.approx(
            1126.791035, rel=1e-6
        )

    def test_strong_reception_is_immediate(self):
        # Score clamps to 1.0, making the exponent negative -> delay below 0.
        dispatcher = make_dispatcher()
        dispatcher.rx_delay_base = 10.0
        assert dispatcher._flood_rx_delay_ms(24, 5.0) == 0.0

    def test_sub_50ms_delay_is_immediate(self):
        # SF5 (score 0) at 500 kHz: 32-byte frame = 5.904 ms on air, so the
        # computed delay (~35.9 ms) sits below the firmware's 50 ms threshold.
        dispatcher = make_dispatcher(StubRadio(sf=5, bandwidth=500000))
        dispatcher.rx_delay_base = 10.0
        assert dispatcher._flood_rx_delay_ms(32, -10.0) == 0.0

    def test_capped_at_32_seconds(self):
        # SF12 / 125 kHz / CR8, 255-byte frame = 14032.896 ms on air; a
        # score-0 reception would wait ~85 s uncapped.
        dispatcher = make_dispatcher(StubRadio(sf=12, bandwidth=125000, coding_rate=8))
        dispatcher.rx_delay_base = 10.0
        assert dispatcher._flood_rx_delay_ms(255, -25.0) == MAX_RX_DELAY_MS


class TestFloodRxMetricsShared:
    def test_matches_dispatcher_delay_logic(self):
        dispatcher = make_dispatcher()
        dispatcher.rx_delay_base = 10.0
        frame_len = 24
        snr = -15.0

        metrics = flood_rx_metrics(
            frame_len,
            snr,
            dispatcher.radio.spreading_factor,
            dispatcher.radio.bandwidth,
            dispatcher.radio.coding_rate,
            dispatcher.radio.preamble_length,
            rx_delay_base=dispatcher.rx_delay_base,
            min_delay_ms=50.0,
            max_delay_ms=32000.0,
        )
        assert metrics.delay_ms == pytest.approx(
            dispatcher._flood_rx_delay_ms(frame_len, snr)
        )

    def test_disabled_delay_still_reports_score_and_airtime(self):
        metrics = flood_rx_metrics(24, -5.0, 10, 250000, 5, 8, rx_delay_base=0.0)
        assert metrics.delay_ms == 0.0
        assert 0.0 <= metrics.score <= 1.0
        assert metrics.air_time_ms > 0.0


# ---------------------------------------------------------------------------
# Receive-path behavior
# ---------------------------------------------------------------------------
class HoldRecorder:
    """Replaces Dispatcher._hold_flood_packet with an externally released wait."""

    def __init__(self):
        self.delays = []
        self.release = asyncio.Event()

    async def __call__(self, delay_ms: float) -> None:
        self.delays.append(delay_ms)
        await self.release.wait()


@pytest.fixture
def dispatcher():
    return make_dispatcher()


@pytest.fixture
def handler(dispatcher):
    handler = RecordingHandler()
    dispatcher.register_handler(PAYLOAD_TYPE_TXT_MSG, handler)
    return handler


PAYLOAD = b"flood-delay-regression"


class TestReceivePath:
    @pytest.mark.asyncio
    async def test_default_processes_flood_immediately(self, dispatcher, handler):
        hold = HoldRecorder()
        dispatcher._hold_flood_packet = hold
        await dispatcher._process_received_packet(
            make_frame(ROUTE_TYPE_FLOOD, PAYLOAD), rssi=-80, snr=-15.0
        )
        assert hold.delays == []
        assert len(handler.packets) == 1

    @pytest.mark.asyncio
    async def test_direct_route_never_delayed(self, dispatcher, handler):
        dispatcher.rx_delay_base = 10.0
        hold = HoldRecorder()
        dispatcher._hold_flood_packet = hold
        await dispatcher._process_received_packet(
            make_frame(ROUTE_TYPE_DIRECT, PAYLOAD, path=b"\xaa"), rssi=-80, snr=-15.0
        )
        assert hold.delays == []
        assert len(handler.packets) == 1

    @pytest.mark.asyncio
    async def test_weak_flood_is_held_then_processed(self, dispatcher, handler):
        dispatcher.rx_delay_base = 10.0
        hold = HoldRecorder()
        hold.release.set()  # do not block, just record
        dispatcher._hold_flood_packet = hold
        await dispatcher._process_received_packet(
            make_frame(ROUTE_TYPE_FLOOD, PAYLOAD), rssi=-80, snr=-15.0
        )
        assert len(hold.delays) == 1
        assert hold.delays[0] == pytest.approx(
            dispatcher._flood_rx_delay_ms(
                len(make_frame(ROUTE_TYPE_FLOOD, PAYLOAD)), -15.0
            )
        )
        assert len(handler.packets) == 1

    @pytest.mark.asyncio
    async def test_transport_flood_is_held_too(self, dispatcher, handler):
        dispatcher.rx_delay_base = 10.0
        hold = HoldRecorder()
        hold.release.set()
        dispatcher._hold_flood_packet = hold
        await dispatcher._process_received_packet(
            make_frame(ROUTE_TYPE_TRANSPORT_FLOOD, PAYLOAD), rssi=-80, snr=-15.0
        )
        assert len(hold.delays) == 1
        assert len(handler.packets) == 1

    @pytest.mark.asyncio
    async def test_better_copy_wins_and_suppresses_held_copy(self, dispatcher, handler):
        """The whole point of the mechanism: a rebroadcast copy heard at good
        SNR during the hold window processes first; the held weak copy then
        dies at the process-time dedupe check."""
        dispatcher.rx_delay_base = 10.0
        hold = HoldRecorder()
        dispatcher._hold_flood_packet = hold

        weak_task = asyncio.create_task(
            dispatcher._process_received_packet(
                make_frame(ROUTE_TYPE_FLOOD, PAYLOAD), rssi=-110, snr=-15.0
            )
        )
        while not hold.delays:
            await asyncio.sleep(0)

        # Rebroadcast: one hop appended, so the raw bytes differ but the
        # packet hash (payload-based, like firmware's hasSeen) is the same.
        await dispatcher._process_received_packet(
            make_frame(ROUTE_TYPE_FLOOD, PAYLOAD, path=b"\xaa"), rssi=-40, snr=5.0
        )
        assert len(handler.packets) == 1
        assert handler.packets[0]._snr == 5.0

        hold.release.set()
        await weak_task
        assert len(handler.packets) == 1  # held copy was dropped as duplicate

    @pytest.mark.asyncio
    async def test_without_delay_first_copy_wins(self, dispatcher, handler):
        """Baseline contrast: with the delay disabled (firmware default) the
        weak first arrival wins and the better copy is the duplicate."""
        await dispatcher._process_received_packet(
            make_frame(ROUTE_TYPE_FLOOD, PAYLOAD), rssi=-110, snr=-15.0
        )
        await dispatcher._process_received_packet(
            make_frame(ROUTE_TYPE_FLOOD, PAYLOAD, path=b"\xaa"), rssi=-40, snr=5.0
        )
        assert len(handler.packets) == 1
        assert handler.packets[0]._snr == -15.0

    @pytest.mark.asyncio
    async def test_hold_sleeps_in_milliseconds(self, dispatcher):
        """The production hold takes milliseconds; the behavior tests above
        override it, so pin the ms -> s conversion with a real (short) sleep."""
        loop = asyncio.get_running_loop()
        start = loop.time()
        await dispatcher._hold_flood_packet(30.0)
        elapsed = loop.time() - start
        assert 0.02 <= elapsed < 1.0


# ---------------------------------------------------------------------------
# Companion wiring: prefs.rx_delay_base -> dispatcher
# ---------------------------------------------------------------------------
class TestCompanionRadioWiring:
    def _make_companion(self):
        from openhop_core.companion import CompanionRadio
        from openhop_core.protocol import LocalIdentity

        return CompanionRadio(StubRadio(), LocalIdentity(), node_name="TestNode")

    def test_set_tuning_params_syncs_dispatcher(self):
        comp = self._make_companion()
        assert comp.node.dispatcher.rx_delay_base == 0.0
        comp.set_tuning_params(10.0, 2.0)
        assert comp.prefs.rx_delay_base == 10.0
        assert comp.node.dispatcher.rx_delay_base == 10.0

    @pytest.mark.asyncio
    async def test_start_syncs_persisted_pref_to_dispatcher(self):
        comp = self._make_companion()
        comp.prefs.rx_delay_base = 10.0  # as if loaded from persistence
        await comp.start()
        try:
            assert comp.node.dispatcher.rx_delay_base == 10.0
        finally:
            await comp.stop()
