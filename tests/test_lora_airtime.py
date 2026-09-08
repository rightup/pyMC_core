"""Shared LoRa airtime estimator vs. the firmware reference.

MeshCore firmware airtime is RadioLib ``getTimeOnAir``. The expected values
below were generated with RadioLib 7.6.0's exact integer arithmetic
(``SX126x::calculateTimeOnAir``, SX126x.cpp) plus its ``ldroAuto`` rule from
``setModulationParams`` (LDRO on when the symbol time is >= 16 ms), which
firmware nodes rely on. Values are microseconds / 1000.
"""

import math
from unittest.mock import MagicMock, patch

import pytest

from openhop_core.companion.timing import estimate_airtime_ms as timing_estimate
from openhop_core.protocol.packet_utils import PacketTimingUtils, calculate_lora_airtime_ms

# (payload_len, sf, bw_hz, cr_denom, preamble_symbols) -> RadioLib 7.6.0 ms
RADIOLIB_VECTORS = [
    ((24, 10, 250000, 5, 8), 185.344),
    ((16, 7, 125000, 5, 8), 51.456),
    ((16, 7, 500000, 5, 8), 12.864),
    ((80, 10, 250000, 5, 8), 431.104),
    ((24, 10, 250000, 8, 8), 246.784),
    ((200, 7, 500000, 8, 8), 123.968),
    ((10, 7, 125000, 5, 12), 45.312),
    # LDRO on under both the symbol-time rule and the SF/BW shorthand
    ((255, 12, 125000, 8, 8), 14032.896),
    ((64, 11, 125000, 7, 8), 2052.096),
    # LDRO divergent: 16.384 ms symbols, so real hardware enables LDRO even
    # though the "SF >= 11 and BW <= 125 kHz" shorthand says off
    ((50, 12, 250000, 5, 8), 1150.976),
    ((32, 10, 62500, 6, 8), 1216.512),
    # SF5/SF6 special case (6.25 sync symbols, numerator constant 0)
    ((32, 5, 500000, 5, 8), 5.904),
    ((48, 6, 125000, 8, 8), 81.024),
    # Zero payload: negative numerator clamps to the 8-symbol minimum
    ((0, 12, 125000, 5, 8), 663.552),
]


@pytest.mark.parametrize("params,expected_ms", RADIOLIB_VECTORS)
def test_matches_radiolib_time_on_air(params, expected_ms):
    payload_len, sf, bw_hz, cr, preamble = params
    got = calculate_lora_airtime_ms(payload_len, sf, bw_hz, cr, preamble)
    assert got == pytest.approx(expected_ms, rel=1e-9)


def test_accepts_denominator_and_index_cr_forms():
    for index, denom in zip((1, 2, 3, 4), (5, 6, 7, 8)):
        assert calculate_lora_airtime_ms(32, 9, 125000, index) == pytest.approx(
            calculate_lora_airtime_ms(32, 9, 125000, denom)
        )


def test_explicit_ldro_override_beats_auto_rule():
    auto = calculate_lora_airtime_ms(50, 12, 250000, 5, 8)
    forced_off = calculate_lora_airtime_ms(50, 12, 250000, 5, 8, low_dr_opt=False)
    assert auto > forced_off  # LDRO shrinks the divisor, adding symbols


def test_timing_module_delegates_to_shared_estimator():
    for (payload_len, sf, bw_hz, cr, preamble), expected_ms in RADIOLIB_VECTORS:
        if sf < 6:
            continue  # timing wrapper is only used with protocol-valid SF
        assert timing_estimate(payload_len, sf, bw_hz, cr, preamble) == pytest.approx(
            expected_ms, rel=1e-9
        )


class TestPacketTimingUtilsEstimate:
    def test_matches_shared_estimator(self):
        for (payload_len, sf, bw_hz, cr, preamble), expected_ms in RADIOLIB_VECTORS:
            config = {
                "spreading_factor": sf,
                "bandwidth": bw_hz,
                "coding_rate": cr,
                "preamble_length": preamble,
            }
            got = PacketTimingUtils.estimate_airtime_ms(payload_len, config)
            # The legacy 50 ms floor is still applied here (TODO in source).
            assert got == pytest.approx(max(expected_ms, 50.0), rel=1e-9)

    def test_khz_bandwidth_is_coerced_to_hz(self):
        hz = PacketTimingUtils.estimate_airtime_ms(32, {"bandwidth": 250000})
        khz = PacketTimingUtils.estimate_airtime_ms(32, {"bandwidth": 250})
        assert khz == pytest.approx(hz)

    def test_measured_airtime_short_circuits(self):
        config = {"measured_airtime_ms": 42.5, "spreading_factor": 12}
        assert PacketTimingUtils.estimate_airtime_ms(200, config) == 42.5

    def test_legacy_floor_still_applies_on_fast_settings(self):
        # SF7 @ 500 kHz, 16 bytes is 12.864 ms on air; the retained legacy
        # floor reports 50 ms (see the TODO in estimate_airtime_ms).
        config = {"spreading_factor": 7, "bandwidth": 500000, "coding_rate": 5}
        assert PacketTimingUtils.estimate_airtime_ms(16, config) == 50.0

    def test_default_config_matches_meshcore_defaults(self):
        assert PacketTimingUtils.estimate_airtime_ms(24) == pytest.approx(185.344, rel=1e-9)


class TestSX1262TimeoutUsesSharedEstimator:
    def _make_radio(self, **kwargs):
        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        SX1262Radio._active_instance = None
        try:
            with (
                patch(
                    "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
                    return_value=MagicMock(),
                ),
                patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
            ):
                return SX1262Radio(radio_timing_delay=0.0, **kwargs)
        finally:
            SX1262Radio._active_instance = None

    def test_default_config_timeout(self):
        radio = self._make_radio()
        timeout_ms, driver_timeout = radio._calculate_tx_timeout(10)
        # SF7 / 125 kHz / CR5 / preamble 12, 10 bytes -> 45.312 ms airtime
        assert timeout_ms == math.ceil(45.312) + 1000
        assert driver_timeout == timeout_ms * 64

    def test_ldro_uses_symbol_time_rule(self):
        radio = self._make_radio(
            spreading_factor=12, bandwidth=250000, coding_rate=5, preamble_length=8
        )
        timeout_ms, driver_timeout = radio._calculate_tx_timeout(50)
        # 16.384 ms symbols -> LDRO on (RadioLib auto rule): 1150.976 ms airtime.
        # The former "SF >= 11 and BW <= 125 kHz" shorthand would give 2070 ms.
        assert timeout_ms == math.ceil(1150.976) + 1000
        assert driver_timeout == timeout_ms * 64
