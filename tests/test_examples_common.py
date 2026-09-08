import importlib
from typing import Any
from unittest.mock import patch

from openhop_core.hardware import tcp_radio, usb_radio
from openhop_core.hardware.tcp_radio import TCPLoRaRadio
from openhop_core.hardware.usb_radio import USBLoRaRadio

with patch("logging.basicConfig"):
    common = importlib.import_module("examples.common")


def _capture_constructor(monkeypatch, module, class_name):
    calls = []

    def constructor(**kwargs):
        calls.append(kwargs)
        return kwargs

    monkeypatch.setattr(module, class_name, constructor)
    return calls


def test_radio_types_expose_canonical_modem_names_and_compatibility_aliases():
    assert "modem_tcp" in common.RADIO_TYPES
    assert "modem_usb" in common.RADIO_TYPES
    assert "pymc_tcp" in common.RADIO_TYPES
    assert "pymc_usb" in common.RADIO_TYPES


def test_modem_tcp_prefers_canonical_environment_variables(monkeypatch):
    calls = _capture_constructor(monkeypatch, tcp_radio, "TCPLoRaRadio")
    monkeypatch.setenv("MODEM_TCP_HOST", "canonical.example")
    monkeypatch.setenv("MODEM_TCP_PORT", "6001")
    monkeypatch.setenv("MODEM_TCP_TOKEN", "canonical-token")
    monkeypatch.setenv("MODEM_TCP_CONNECT_TIMEOUT", "7.5")
    monkeypatch.setenv("PYMC_TCP_HOST", "legacy.example")
    monkeypatch.setenv("PYMC_TCP_PORT", "6002")
    monkeypatch.setenv("PYMC_TCP_TOKEN", "legacy-token")
    monkeypatch.setenv("PYMC_TCP_CONNECT_TIMEOUT", "8.5")

    common.create_radio("modem_tcp")

    assert calls == [
        {
            "host": "canonical.example",
            "port": 6001,
            "token": "canonical-token",
            "connect_timeout": 7.5,
            "frequency": 869618000,
            "bandwidth": 62500,
            "spreading_factor": 8,
            "coding_rate": 8,
            "tx_power": 22,
            "sync_word": 0x12,
            "preamble_length": 16,
            "lbt_enabled": True,
            "lbt_max_attempts": 5,
        }
    ]


def test_modem_tcp_uses_legacy_environment_variables_as_fallback(monkeypatch):
    calls = _capture_constructor(monkeypatch, tcp_radio, "TCPLoRaRadio")
    monkeypatch.delenv("MODEM_TCP_HOST", raising=False)
    monkeypatch.delenv("MODEM_TCP_PORT", raising=False)
    monkeypatch.delenv("MODEM_TCP_TOKEN", raising=False)
    monkeypatch.delenv("MODEM_TCP_CONNECT_TIMEOUT", raising=False)
    monkeypatch.setenv("PYMC_TCP_HOST", "legacy.example")
    monkeypatch.setenv("PYMC_TCP_PORT", "6002")
    monkeypatch.setenv("PYMC_TCP_TOKEN", "legacy-token")
    monkeypatch.setenv("PYMC_TCP_CONNECT_TIMEOUT", "8.5")

    common.create_radio("modem_tcp")

    assert calls[0]["host"] == "legacy.example"
    assert calls[0]["port"] == 6002
    assert calls[0]["token"] == "legacy-token"
    assert calls[0]["connect_timeout"] == 8.5


def test_legacy_tcp_radio_type_remains_a_compatibility_alias(monkeypatch):
    calls = _capture_constructor(monkeypatch, tcp_radio, "TCPLoRaRadio")
    monkeypatch.setenv("MODEM_TCP_HOST", "modem.example")

    common.create_radio("pymc_tcp")

    assert calls[0]["host"] == "modem.example"


def test_canonical_and_legacy_usb_radio_types_use_usb_transport(monkeypatch):
    calls = _capture_constructor(monkeypatch, usb_radio, "USBLoRaRadio")

    common.create_radio("modem_usb", "/dev/canonical-modem")
    common.create_radio("pymc_usb", "/dev/legacy-modem")

    assert calls[0]["port"] == "/dev/canonical-modem"
    assert calls[1]["port"] == "/dev/legacy-modem"


def _status_radio(radio_class: type[Any], **transport_fields):
    radio = object.__new__(radio_class)
    fields = {
        "_initialized": True,
        "frequency": 869_618_000,
        "tx_power": 22,
        "spreading_factor": 8,
        "bandwidth": 62_500,
        "coding_rate": 8,
        "last_rssi": -90,
        "last_snr": 7.5,
        "last_signal_rssi": -88,
        "_tx_count": 3,
        "_rx_count": 4,
        "_crc_errors": 1,
        "crc_error_count": 1,
        **transport_fields,
    }
    for name, value in fields.items():
        setattr(radio, name, value)
    return radio


def test_tcp_status_reports_canonical_modem_driver():
    status = _status_radio(TCPLoRaRadio, host="modem.local", port=5055).get_status()

    assert status["driver"] == "modem_tcp"


def test_usb_status_reports_canonical_modem_driver():
    status = _status_radio(USBLoRaRadio, port="/dev/ttyACM0").get_status()

    assert status["driver"] == "modem_usb"
