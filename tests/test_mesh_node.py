"""Lifecycle tests for MeshNode start/stop (cooperative dispatcher shutdown)."""

from __future__ import annotations

import asyncio

import pytest

from openhop_core.node.node import MeshNode
from openhop_core.protocol import LocalIdentity


class MockRadio:
    """Minimal radio: set_rx_callback, send, RSSI/SNR stubs."""

    def __init__(self):
        self.rx_callback = None
        self.sent: list[bytes] = []

    def set_rx_callback(self, callback):
        self.rx_callback = callback

    async def send(self, data: bytes):
        self.sent.append(data)
        return {}

    def get_last_rssi(self):
        return -70

    def get_last_snr(self):
        return 5.0


def _make_node(radio: MockRadio | None = None) -> tuple[MeshNode, MockRadio]:
    radio = radio or MockRadio()
    node = MeshNode(radio, LocalIdentity())
    return node, radio


@pytest.mark.asyncio
async def test_stop_exits_start_task():
    node, _radio = _make_node()
    task = asyncio.create_task(node.start())
    await asyncio.sleep(0)  # let run_forever arm
    assert not task.done()

    await node.stop()
    await asyncio.wait_for(task, timeout=2.0)
    assert task.done()
    assert task.exception() is None


@pytest.mark.asyncio
async def test_stop_is_idempotent():
    node, _radio = _make_node()
    task = asyncio.create_task(node.start())
    await asyncio.sleep(0)

    await node.stop()
    await node.stop()
    await asyncio.wait_for(task, timeout=2.0)


@pytest.mark.asyncio
async def test_stop_without_start_does_not_hang():
    node, radio = _make_node()
    # Construction arms RX; stop should disarm and return immediately.
    assert radio.rx_callback is not None
    await asyncio.wait_for(node.stop(), timeout=1.0)
    assert radio.rx_callback is None
    assert node.dispatcher._rx_enabled is False


@pytest.mark.asyncio
async def test_stop_disarms_rx_no_new_packet_tasks():
    node, radio = _make_node()
    task = asyncio.create_task(node.start())
    await asyncio.sleep(0)
    assert radio.rx_callback is not None
    assert radio.rx_callback.__func__ is node.dispatcher._on_packet_received.__func__

    await node.stop()
    await asyncio.wait_for(task, timeout=2.0)

    assert radio.rx_callback is None
    assert node.dispatcher._rx_enabled is False

    # Gate drops deliveries even if a stale callback handle were kept.
    spawned: list[asyncio.Task] = []
    real_create = asyncio.get_running_loop().create_task

    def tracking_create(coro, *args, **kwargs):
        t = real_create(coro, *args, **kwargs)
        spawned.append(t)
        return t

    loop = asyncio.get_running_loop()
    loop.create_task = tracking_create  # type: ignore[method-assign]
    try:
        node.dispatcher._on_packet_received(b"\x00" * 16)
        await asyncio.sleep(0)
    finally:
        loop.create_task = real_create  # type: ignore[method-assign]

    assert spawned == []


@pytest.mark.asyncio
async def test_restart_rearms_rx():
    node, radio = _make_node()

    task1 = asyncio.create_task(node.start())
    await asyncio.sleep(0)
    await node.stop()
    await asyncio.wait_for(task1, timeout=2.0)
    assert radio.rx_callback is None

    task2 = asyncio.create_task(node.start())
    await asyncio.sleep(0)
    assert node.dispatcher._rx_enabled is True
    assert radio.rx_callback is not None
    assert radio.rx_callback.__func__ is node.dispatcher._on_packet_received.__func__

    await node.stop()
    await asyncio.wait_for(task2, timeout=2.0)


@pytest.mark.asyncio
async def test_cleanup_signals_stop_without_await():
    node, radio = _make_node()
    task = asyncio.create_task(node.start())
    await asyncio.sleep(0)

    node.dispatcher.cleanup()
    await asyncio.wait_for(task, timeout=2.0)
    assert radio.rx_callback is None
    assert node.dispatcher._rx_enabled is False
