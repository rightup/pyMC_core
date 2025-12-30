import pytest

from pymc_core.hardware.signal_utils import snr_register_to_db


def test_positive_snr_conversion():
    assert snr_register_to_db(0x10) == pytest.approx(4.0)


def test_negative_snr_conversion():
    assert snr_register_to_db(0xF0) == pytest.approx(-4.0)


def test_fractional_negative_snr_conversion():
    assert snr_register_to_db(0xEE) == pytest.approx(-4.5)


def test_snr_register_bounds():
    assert snr_register_to_db(0x7F) == pytest.approx(31.75)
    assert snr_register_to_db(0x80) == pytest.approx(-32.0)


def test_none_defaults_to_zero():
    assert snr_register_to_db(None) == 0.0


def test_16bit_positive_conversion():
    assert snr_register_to_db(0x0014, bits=16) == pytest.approx(5.0)


def test_16bit_negative_conversion():
    assert snr_register_to_db(0xFFF0, bits=16) == pytest.approx(-4.0)


def test_invalid_bit_width_raises():
    with pytest.raises(ValueError):
        snr_register_to_db(0x00, bits=0)
