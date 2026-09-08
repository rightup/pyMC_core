"""Regression tests for invoke_maybe_awaitable and await-inline callback dispatch."""

from __future__ import annotations

import warnings
from unittest.mock import AsyncMock, Mock

import pytest

from openhop_core.companion.companion_bridge import CompanionBridge
from openhop_core.node.dispatcher import Dispatcher
from openhop_core.node.handlers.ack import AckHandler
from openhop_core.node.handlers.login_response import LoginResponseHandler
from openhop_core.protocol import LocalIdentity, Packet
from openhop_core.protocol.packet_filter import PacketFilter
from openhop_core.util.callbacks import invoke_maybe_awaitable


@pytest.fixture
def dispatcher():
    radio = Mock()
    radio.set_rx_callback = Mock()
    radio.get_last_rssi = Mock(return_value=-70)
    radio.get_last_snr = Mock(return_value=30.0)
    radio.get_state = Mock(return_value="idle")
    d = Dispatcher(radio=radio, packet_filter=PacketFilter(), log_fn=Mock())
    d.local_identity = Mock()
    d.contact_book = Mock()
    return d


@pytest.mark.asyncio
async def test_invoke_maybe_awaitable_awaits_returned_coroutine():
    ran = []

    async def body():
        ran.append("body")

    def sync_wrapper():
        return body()

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        await invoke_maybe_awaitable(sync_wrapper)

    assert ran == ["body"]
    assert not any(issubclass(w.category, RuntimeWarning) for w in caught)


@pytest.mark.asyncio
async def test_invoke_maybe_awaitable_awaits_async_call_object():
    ran = []

    class Handler:
        async def __call__(self):
            ran.append("call")

    await invoke_maybe_awaitable(Handler())
    assert ran == ["call"]


@pytest.mark.asyncio
async def test_invoke_maybe_awaitable_plain_sync_and_async_def():
    sync_ran = []
    async_ran = []

    def sync_cb():
        sync_ran.append(1)

    async def async_cb():
        async_ran.append(1)

    await invoke_maybe_awaitable(sync_cb)
    await invoke_maybe_awaitable(async_cb)
    assert sync_ran == [1]
    assert async_ran == [1]


@pytest.mark.asyncio
async def test_dispatcher_awaits_sync_wrapper_raw_callback(dispatcher):
    ran = []

    async def body(packet, data, analysis):
        ran.append((packet, data, analysis))

    def sync_wrapper(packet, data, analysis):
        return body(packet, data, analysis)

    pkt = Packet()
    data = b"\x00raw"
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        await dispatcher._invoke_enhanced_raw_callback(sync_wrapper, pkt, data, {})

    assert len(ran) == 1
    assert ran[0][0] is pkt and ran[0][1] == data
    assert not any(issubclass(w.category, RuntimeWarning) for w in caught)


@pytest.mark.asyncio
async def test_dispatcher_awaits_async_call_raw_callback(dispatcher):
    ran = []

    class Handler:
        async def __call__(self, packet, data, analysis):
            ran.append(True)

    await dispatcher._invoke_enhanced_raw_callback(Handler(), Packet(), b"x", {})
    assert ran == [True]


@pytest.mark.asyncio
async def test_dispatcher_awaits_sync_wrapper_packet_received(dispatcher):
    ran = []

    async def body(pkt: Packet):
        ran.append(pkt)

    def sync_wrapper(pkt: Packet):
        return body(pkt)

    pkt = Packet()
    await dispatcher._invoke_callback(sync_wrapper, pkt)
    assert ran == [pkt]


@pytest.mark.asyncio
async def test_fire_callbacks_awaits_sync_wrapper_returning_coro():
    bridge = CompanionBridge(LocalIdentity(), AsyncMock())
    ran = []

    async def body(event):
        ran.append(event)

    def sync_wrapper(event):
        return body(event)

    bridge.on_message_event(sync_wrapper)
    sentinel = object()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        await bridge._fire_callbacks("message_event", sentinel)

    assert ran == [sentinel]
    assert not any(issubclass(w.category, RuntimeWarning) for w in caught)


@pytest.mark.asyncio
async def test_ack_handler_awaits_sync_wrapper_returning_coro():
    ran = []

    async def body(crc: int):
        ran.append(crc)

    def sync_wrapper(crc: int):
        return body(crc)

    handler = AckHandler(lambda _m: None)
    handler.set_ack_received_callback(sync_wrapper)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        await handler._notify_ack_received(0xABCD)

    assert ran == [0xABCD]
    assert not any(issubclass(w.category, RuntimeWarning) for w in caught)


@pytest.mark.asyncio
async def test_login_handler_awaits_sync_wrapper_returning_coro():
    ran = []

    async def body(success: bool, data: dict):
        ran.append((success, data))

    def sync_wrapper(success: bool, data: dict):
        return body(success, data)

    handler = LoginResponseHandler(LocalIdentity(), object(), lambda _m: None)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        await handler._safe_callback(sync_wrapper, True, {"ok": 1})

    assert ran == [(True, {"ok": 1})]
    assert not any(issubclass(w.category, RuntimeWarning) for w in caught)
