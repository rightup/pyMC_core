"""CH341 multi-adapter USB selection tests."""

from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# Provide a minimal fake pyusb so this module imports without hardware deps.
if "usb" not in sys.modules:
    usb_mod = ModuleType("usb")
    usb_core = ModuleType("usb.core")
    usb_util = ModuleType("usb.util")

    class _USBError(Exception):
        def __init__(self, *args, errno=None, **kwargs):
            super().__init__(*args)
            self.errno = errno

    usb_core.USBError = _USBError
    usb_core.find = MagicMock(return_value=[])
    usb_util.get_string = MagicMock(return_value=None)
    usb_util.claim_interface = MagicMock()
    usb_util.release_interface = MagicMock()
    usb_util.dispose_resources = MagicMock()
    usb_util.find_descriptor = MagicMock(return_value=None)
    usb_mod.core = usb_core
    usb_mod.util = usb_util
    sys.modules["usb"] = usb_mod
    sys.modules["usb.core"] = usb_core
    sys.modules["usb.util"] = usb_util

from openhop_core.hardware.ch341.ch341_async import CH341Async, CH341Error


def _fake_dev(bus, address, serial=None, vid=0x1A86, pid=0x5512):
    return SimpleNamespace(
        idVendor=vid,
        idProduct=pid,
        bus=bus,
        address=address,
        iSerialNumber=1 if serial else 0,
    )


@pytest.fixture(autouse=True)
def _reset_ch341():
    CH341Async._instances = {}
    CH341Async._instance = None
    yield
    CH341Async._instances = {}
    CH341Async._instance = None


def test_find_device_by_bus_address():
    d1 = _fake_dev(1, 5, "AAA")
    d2 = _fake_dev(1, 8, "BBB")
    with patch("openhop_core.hardware.ch341.ch341_async.usb.core.find", return_value=[d1, d2]):
        with patch.object(
            CH341Async, "_device_serial", side_effect=lambda d: {d1: "AAA", d2: "BBB"}[d]
        ):
            got = CH341Async._find_device(0x1A86, 0x5512, bus=1, address=8)
    assert got is d2


def test_find_device_by_serial():
    d1 = _fake_dev(1, 5)
    d2 = _fake_dev(2, 3)
    with patch("openhop_core.hardware.ch341.ch341_async.usb.core.find", return_value=[d1, d2]):
        with patch.object(
            CH341Async,
            "_device_serial",
            side_effect=lambda d: "SER-B" if d is d2 else "SER-A",
        ):
            got = CH341Async._find_device(0x1A86, 0x5512, serial_number="SER-B")
    assert got is d2


def test_find_device_ambiguous_without_filter_raises():
    d1 = _fake_dev(1, 5)
    d2 = _fake_dev(1, 8)
    with patch("openhop_core.hardware.ch341.ch341_async.usb.core.find", return_value=[d1, d2]):
        with patch.object(CH341Async, "_device_serial", return_value=None):
            with pytest.raises(CH341Error, match="Multiple CH341 devices"):
                CH341Async._find_device(0x1A86, 0x5512)


def test_find_device_single_unfiltered_ok():
    d1 = _fake_dev(1, 5)
    with patch("openhop_core.hardware.ch341.ch341_async.usb.core.find", return_value=[d1]):
        with patch.object(CH341Async, "_device_serial", return_value=None):
            got = CH341Async._find_device(0x1A86, 0x5512)
    assert got is d1


def test_get_instance_reuses_same_bus_address():
    d1 = _fake_dev(1, 5, "AAA")

    def fake_open(self):
        self.dev = d1
        self.bus = 1
        self.address = 5
        self.serial_number = "AAA"

    with patch.object(CH341Async, "_open_device", fake_open):
        a = CH341Async.get_instance(bus=1, address=5)
        b = CH341Async.get_instance(bus=1, address=5)
    assert a is b


def test_get_instance_two_locations_are_distinct():
    d1 = _fake_dev(1, 5)
    d2 = _fake_dev(1, 8)

    def fake_open(self):
        self.dev = d1 if self.address == 5 else d2
        self.bus = 1
        self.serial_number = None

    with patch.object(CH341Async, "_open_device", fake_open):
        a = CH341Async.get_instance(bus=1, address=5)
        b = CH341Async.get_instance(bus=1, address=8)
    assert a is not b
    assert a.address == 5
    assert b.address == 8


def test_list_devices_returns_locations():
    d1 = _fake_dev(1, 5)
    d2 = _fake_dev(2, 9)
    with patch("openhop_core.hardware.ch341.ch341_async.usb.core.find", return_value=[d1, d2]):
        with patch.object(
            CH341Async, "_device_serial", side_effect=lambda d: "A" if d is d1 else "B"
        ):
            listed = CH341Async.list_devices()
    assert listed == [
        {"vid": 0x1A86, "pid": 0x5512, "bus": 1, "address": 5, "serial_number": "A"},
        {"vid": 0x1A86, "pid": 0x5512, "bus": 2, "address": 9, "serial_number": "B"},
    ]
