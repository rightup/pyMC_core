"""Ingress identity must survive scheduling and asynchronous RX subscribers."""

import asyncio
from types import SimpleNamespace

import pytest

from openhop_core.node.dispatcher import Dispatcher
from openhop_core.rf_fabric import FabricRadio
from tests.test_rf_fabric_phase2 import _MockRadio, _advert_bytes


@pytest.mark.asyncio
@pytest.mark.parametrize("pause_raw", [False, True])
async def test_fabric_burst_preserves_ingress(pause_raw):
    local, link = _MockRadio(), _MockRadio()
    radio = FabricRadio(radios=[(local, "local"), (link, "link")])
    dispatcher = Dispatcher(radio)
    entered, release, complete = asyncio.Event(), asyncio.Event(), asyncio.Event()
    seen, raw = [], []
    link_data, local_data = _advert_bytes(b"link"), _advert_bytes(b"local")

    async def on_raw(data, rssi, snr):
        raw.append((data, rssi, snr))
        if pause_raw and data == link_data:
            entered.set()
            await release.wait()

    def on_packet(pkt, data):
        seen.append((data, pkt._rx_radio_id, pkt._rssi, pkt._snr))
        if len(seen) == 2:
            complete.set()

    dispatcher.add_raw_rx_subscriber(on_raw)
    dispatcher.packet_analysis_callback = on_packet
    try:
        link.inject(link_data, -80, 2.0)
        if pause_raw:
            await asyncio.wait_for(entered.wait(), 1)
        local.inject(local_data, -60, 7.0)
        release.set()
        await asyncio.wait_for(complete.wait(), 1)
        assert sorted(seen) == sorted([
            (link_data, "link", -80, 2.0),
            (local_data, "local", -60, 7.0),
        ])
        assert raw == [(link_data, -80, 2.0), (local_data, -60, 7.0)]
    finally:
        release.set()
        await dispatcher.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("nested_fabric", [False, True])
async def test_direct_processing_snapshots_ingress_before_raw_subscriber(nested_fabric):
    radio = _MockRadio()
    source = SimpleNamespace(last_rx_radio_id="link") if nested_fabric else radio
    source.last_rx_radio_id = "link"
    if nested_fabric:
        radio.fabric = source
    dispatcher = Dispatcher(radio)
    seen = []

    async def on_raw(data, rssi, snr):
        source.last_rx_radio_id = "local"
        await asyncio.sleep(0)

    dispatcher.add_raw_rx_subscriber(on_raw)
    dispatcher.packet_analysis_callback = lambda pkt, data: seen.append(pkt._rx_radio_id)
    try:
        await dispatcher._process_received_packet(_advert_bytes(), -80, 2.0)
        assert seen == ["link"]
    finally:
        await dispatcher.stop()


@pytest.mark.asyncio
async def test_unknown_ingress_is_not_replaced_after_scheduling():
    radio = _MockRadio()
    radio.last_rx_radio_id = None
    dispatcher = Dispatcher(radio)
    seen, complete = [], asyncio.Event()

    def on_packet(pkt, data):
        seen.append(getattr(pkt, "_rx_radio_id", None))
        complete.set()

    dispatcher.packet_analysis_callback = on_packet
    try:
        radio.inject(_advert_bytes())
        radio.last_rx_radio_id = "later"
        await asyncio.wait_for(complete.wait(), 1)
        assert seen == [None]
    finally:
        await dispatcher.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("wrapped", [False, True])
@pytest.mark.parametrize("with_metrics", [False, True])
async def test_single_radio_callback_compatibility(wrapped, with_metrics):
    physical = _MockRadio()
    radio = FabricRadio(radio=physical, radio_id="solo") if wrapped else physical
    dispatcher = Dispatcher(radio)
    seen, complete = [], asyncio.Event()

    def on_packet(pkt, data):
        seen.append((getattr(pkt, "_rx_radio_id", None), pkt._rssi, pkt._snr))
        complete.set()

    dispatcher.packet_analysis_callback = on_packet
    try:
        args = (-70, 3.0) if with_metrics else ()
        physical.inject(_advert_bytes(), *args)
        await asyncio.wait_for(complete.wait(), 1)
        assert seen == [("solo" if wrapped else None,
                         -70 if with_metrics else -80,
                         3.0 if with_metrics else 7.5)]
    finally:
        await dispatcher.stop()
