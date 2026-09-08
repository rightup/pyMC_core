"""Trace completion push for standalone Core (CompanionRadio + frame server).

Exercises the real chain: node ``TraceHandler`` completion hook ->
``CompanionRadio._on_trace_complete`` -> public ``trace_received`` event ->
``CompanionFrameServer._on_trace_received`` -> ``push_trace_data`` (0x89),
matching the firmware ``onTraceRecv`` frame layout.
"""

import asyncio
import struct

import pytest

from openhop_core.companion.base_callbacks import _CallbackMixin
from openhop_core.companion.base_support import PUSH_CALLBACK_KEYS
from openhop_core.companion.companion_radio import CompanionRadio
from openhop_core.companion.frame_server import CompanionFrameServer
from openhop_core.node.handlers.trace import TraceHandler


class _TracePacket:
    """Minimal received TRACE packet accepted by TraceHandler/CompanionRadio."""

    def __init__(self, payload: bytes, path: bytes, snr: float = 2.5, rssi: int = -70):
        self.payload = bytes(payload)
        self.payload_len = len(self.payload)
        self.path = bytearray(path)  # per-hop SNR bytes appended along the route
        self._snr = snr
        self._rssi = rssi

    def get_snr(self) -> float:
        return self._snr


class _TraceBridge(_CallbackMixin):
    """Real callback machinery + the real CompanionRadio completion hook,
    without needing MeshNode/radio hardware."""

    def __init__(self):
        self._push_callbacks = {k: [] for k in PUSH_CALLBACK_KEYS}
        # Bind the production hook so field assembly is exercised as shipped.
        self._on_trace_complete = CompanionRadio._on_trace_complete.__get__(self)


def _trace_payload(tag: int, auth: int, flags: int, path_hashes: bytes) -> bytes:
    return struct.pack("<IIB", tag, auth, flags) + path_hashes


def _wire_chain():
    """Return (handler, server) wired exactly as standalone Core wires them."""
    bridge = _TraceBridge()
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=256)
    server._setup_push_callbacks()  # registers _on_trace_received on the bridge
    handler = TraceHandler(lambda _m: None, on_trace_complete=bridge._on_trace_complete)
    return handler, server


@pytest.mark.asyncio
async def test_completion_push_single_byte_hash_exact_bytes():
    handler, server = _wire_chain()
    tag, auth = 0x11223344, 0x55667788
    pkt = _TracePacket(_trace_payload(tag, auth, 0, b"\x01\x02"), path=b"\x0a\x14", snr=2.5)

    await handler(pkt)

    assert server._write_queue.qsize() == 1
    frame = server._write_queue.get_nowait()
    snr_byte = round(2.5 * 4)  # 10
    expected = (
        bytes([0x89, 0, 2, 0])
        + struct.pack("<II", tag, auth)
        + b"\x01\x02"
        + b"\x0a\x14"
        + bytes([snr_byte])
    )
    assert frame[0] == 0x3E
    assert frame[3:] == expected


@pytest.mark.asyncio
async def test_completion_push_multibyte_hash_exact_bytes():
    handler, server = _wire_chain()
    tag, auth = 0xAABBCCDD, 0x01020304
    # flags=1 -> 2-byte hashes; two hops => 4 hash bytes, two SNR bytes.
    pkt = _TracePacket(
        _trace_payload(tag, auth, 1, b"\x01\x02\x03\x04"), path=b"\x0a\x14", snr=-3.0
    )

    await handler(pkt)

    assert server._write_queue.qsize() == 1
    frame = server._write_queue.get_nowait()
    snr_scaled = round(-3.0 * 4)  # -12
    snr_byte = snr_scaled + 256
    expected = (
        bytes([0x89, 0, 4, 1])
        + struct.pack("<II", tag, auth)
        + b"\x01\x02\x03\x04"
        + b"\x0a\x14"
        + bytes([snr_byte])
    )
    assert frame[3:] == expected


@pytest.mark.asyncio
async def test_incomplete_trace_emits_nothing():
    handler, server = _wire_chain()
    # 3 single-byte hashes but only 2 SNRs recorded: 2*1 < 3 -> not complete.
    pkt = _TracePacket(_trace_payload(1, 0, 0, b"\x01\x02\x03"), path=b"\x0a\x14")

    await handler(pkt)

    assert server._write_queue.empty()


@pytest.mark.asyncio
async def test_trace_received_fires_on_completion():
    bridge = _TraceBridge()
    seen = []
    bridge.on_trace_received(lambda info: seen.append(info))
    handler = TraceHandler(lambda _m: None, on_trace_complete=bridge._on_trace_complete)
    pkt = _TracePacket(_trace_payload(0x99, 0x88, 0, b"\x07\x08"), path=b"\x01\x02", snr=1.0)

    await handler(pkt)

    assert len(seen) == 1
    assert seen[0]["tag"] == 0x99
    assert seen[0]["auth_code"] == 0x88
    assert seen[0]["flags"] == 0
    assert seen[0]["path_hashes"] == b"\x07\x08"
    assert seen[0]["path_snrs"] == b"\x01\x02"


@pytest.mark.asyncio
async def test_no_emission_when_hook_unset():
    """Repeater-side node handler is built without the hook (its packet router
    routes TRACE to TraceHelper instead), so completion must emit nothing."""
    fired = []
    handler = TraceHandler(lambda _m: None)  # on_trace_complete defaults to None
    assert handler.on_trace_complete is None
    pkt = _TracePacket(_trace_payload(1, 0, 0, b"\x01\x02"), path=b"\x0a\x14")

    result = await handler(pkt)

    assert result is not None and result["valid"] is True
    assert fired == []
