import struct

import pytest

from openhop_core.node.handlers.control import ControlHandler
from openhop_core.protocol import Packet
from openhop_core.protocol.constants import (
    PAYLOAD_TYPE_CONTROL,
    PH_TYPE_SHIFT,
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_DIRECT,
    ROUTE_TYPE_TRANSPORT_FLOOD,
)
from openhop_core.protocol.packet_utils import PathUtils


def _make_control_header(route_type: int) -> int:
    """Build a packet header byte for a CONTROL payload with the given route type."""
    return (PAYLOAD_TYPE_CONTROL << PH_TYPE_SHIFT) | route_type


@pytest.mark.asyncio
async def test_control_handler_accepts_encoded_zero_hop_discovery_request():
    logs = []
    handler = ControlHandler(log_fn=lambda msg: logs.append(msg))

    pkt = Packet()
    pkt.header = _make_control_header(ROUTE_TYPE_DIRECT)
    pkt.path_len = PathUtils.encode_path_len(2, 0)  # encoded zero-hop (0x40)
    pkt.payload = bytearray(bytes([0x80, 0x04]) + struct.pack("<I", 0x12345678))
    pkt.payload_len = len(pkt.payload)

    result = await handler(pkt)

    assert result is not None
    assert result["tag"] == 0x12345678
    assert result["filter"] == 0x04
    assert all("Non-zero path length" not in msg for msg in logs)


@pytest.mark.asyncio
async def test_control_handler_rejects_nonzero_hop_discovery_request():
    logs = []
    handler = ControlHandler(log_fn=lambda msg: logs.append(msg))

    pkt = Packet()
    pkt.header = _make_control_header(ROUTE_TYPE_DIRECT)
    pkt.path_len = PathUtils.encode_path_len(2, 1)  # one hop encoded
    pkt.payload = bytearray(bytes([0x80, 0x04]) + struct.pack("<I", 0x12345678))
    pkt.payload_len = len(pkt.payload)

    result = await handler(pkt)

    assert result is None
    assert any("Non-zero path length" in msg for msg in logs)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "route_type,expect_accept",
    [
        (ROUTE_TYPE_TRANSPORT_FLOOD, False),  # 0x00
        (ROUTE_TYPE_FLOOD, False),  # 0x01
        (ROUTE_TYPE_DIRECT, True),  # 0x02
        (ROUTE_TYPE_TRANSPORT_DIRECT, True),  # 0x03
    ],
)
async def test_control_handler_only_accepts_direct_routes(route_type, expect_accept):
    """MeshCore gates the CONTROL discovery subset on isRouteDirect(): only the two
    direct route forms (0x02, 0x03) are processed; flood forms (0x00, 0x01) are ignored."""
    logs = []
    handler = ControlHandler(log_fn=lambda msg: logs.append(msg))

    pkt = Packet()
    pkt.header = _make_control_header(route_type)
    pkt.path_len = PathUtils.encode_path_len(2, 0)  # encoded zero-hop
    pkt.payload = bytearray(bytes([0x80, 0x04]) + struct.pack("<I", 0x12345678))
    pkt.payload_len = len(pkt.payload)

    result = await handler(pkt)

    if expect_accept:
        assert result is not None
        assert result["tag"] == 0x12345678
    else:
        assert result is None
        assert any("Non-direct route" in msg for msg in logs)


@pytest.mark.asyncio
async def test_control_handler_rejects_missing_high_bit():
    """A CONTROL payload without the high bit (payload[0] & 0x80) is not part of the
    discovery subset and is ignored, even on a direct route."""
    logs = []
    handler = ControlHandler(log_fn=lambda msg: logs.append(msg))

    pkt = Packet()
    pkt.header = _make_control_header(ROUTE_TYPE_DIRECT)
    pkt.path_len = PathUtils.encode_path_len(2, 0)  # encoded zero-hop
    pkt.payload = bytearray(bytes([0x00, 0x04]) + struct.pack("<I", 0x12345678))
    pkt.payload_len = len(pkt.payload)

    result = await handler(pkt)

    assert result is None
    assert any("high bit not set" in msg for msg in logs)
