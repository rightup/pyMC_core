"""Tests for SX126x TX power mapping behavior."""

from unittest.mock import MagicMock

import pytest
from openhop_core.hardware.lora.LoRaRF.SX126x import SX126x


def _make_radio() -> SX126x:
    radio = SX126x()
    radio.setCurrentProtection = MagicMock()
    radio.setPaConfig = MagicMock()
    radio.setTxParams = MagicMock()
    return radio


@pytest.mark.parametrize(
    ("requested_dbm", "expected"),
    [
        (-9, (2, 2, -5)),
        (0, (2, 1, 11)),
        (10, (1, 2, 22)),
        (15, (3, 3, 20)),
        (20, (3, 6, 22)),
        (21, (4, 6, 22)),
        (22, (4, 7, 22)),
    ],
)
def test_sx1262_tx_power_uses_radiolib_optimized_pa_table(requested_dbm, expected):
    radio = _make_radio()

    radio.setTxPower(requested_dbm, radio.TX_POWER_SX1262)

    duty, hp_max, pa_val = expected
    radio.setPaConfig.assert_called_once_with(duty, hp_max, 0x00, 0x01)
    radio.setTxParams.assert_called_once_with(pa_val, radio.PA_RAMP_200U)
    radio.setCurrentProtection.assert_called_once_with(0x38)


def test_sx1262_tx_power_clamps_below_minimum_to_minus_9_dbm():
    radio = _make_radio()

    radio.setTxPower(-20, radio.TX_POWER_SX1262)

    # -20 dBm clamps to -9 dBm table entry.
    radio.setPaConfig.assert_called_once_with(2, 2, 0x00, 0x01)
    radio.setTxParams.assert_called_once_with(-5, radio.PA_RAMP_200U)


def test_sx1262_tx_power_clamps_above_maximum_to_22_dbm():
    radio = _make_radio()

    radio.setTxPower(30, radio.TX_POWER_SX1262)

    # 30 dBm clamps to 22 dBm table entry.
    radio.setPaConfig.assert_called_once_with(4, 7, 0x00, 0x01)
    radio.setTxParams.assert_called_once_with(22, radio.PA_RAMP_200U)


def test_sx1262_15_dbm_regression_not_legacy_fixed_max_pa():
    radio = _make_radio()

    radio.setTxPower(15, radio.TX_POWER_SX1262)

    pa_args = radio.setPaConfig.call_args.args
    tx_args = radio.setTxParams.call_args.args

    # Legacy behavior was fixed max PA plus direct power register write.
    assert pa_args != (0x04, 0x07, 0x00, 0x01)
    assert tx_args != (15, radio.PA_RAMP_200U)


@pytest.mark.parametrize(
    ("requested_dbm", "expected_pa", "expected_power_reg"),
    [
        (15, (0x04, 0x00, 0x01, 0x01), 14),
        (10, (0x01, 0x00, 0x01, 0x01), 10),
        (5, (0x00, 0x00, 0x01, 0x01), 5),
    ],
)
def test_sx1261_path_unchanged(requested_dbm, expected_pa, expected_power_reg):
    radio = _make_radio()

    radio.setTxPower(requested_dbm, radio.TX_POWER_SX1261)

    radio.setPaConfig.assert_called_once_with(*expected_pa)
    radio.setTxParams.assert_called_once_with(expected_power_reg, radio.PA_RAMP_200U)
    radio.setCurrentProtection.assert_not_called()


@pytest.mark.parametrize(
    ("requested_dbm", "expected_pa", "expected_power_reg"),
    [
        (14, (0x04, 0x06, 0x01, 0x01), 14),
        (10, (0x00, 0x03, 0x00, 0x01), 10),
        (5, (0x00, 0x00, 0x00, 0x01), 5),
    ],
)
def test_sx1268_path_unchanged(requested_dbm, expected_pa, expected_power_reg):
    radio = _make_radio()

    radio.setTxPower(requested_dbm, radio.TX_POWER_SX1268)

    radio.setPaConfig.assert_called_once_with(*expected_pa)
    radio.setTxParams.assert_called_once_with(expected_power_reg, radio.PA_RAMP_200U)
    radio.setCurrentProtection.assert_not_called()
