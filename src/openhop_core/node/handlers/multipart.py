from __future__ import annotations

from typing import Awaitable, Callable, Optional

from ...protocol import Packet
from ...protocol.constants import PAYLOAD_TYPE_ACK, PAYLOAD_TYPE_MULTIPART
from ...util.callbacks import invoke_maybe_awaitable
from .base import BaseHandler


class MultipartAckHandler(BaseHandler):
    """Handle PAYLOAD_TYPE_MULTIPART packets that carry an embedded ACK ("multi-ack").

    Mirrors the endpoint-receive branch of MeshCore ``Mesh::onRecvPacket``
    (PAYLOAD_TYPE_MULTIPART case): the payload is a one-byte wrapper
    ``(remaining << 4) | inner_type`` followed by the embedded ACK bytes. When the
    inner type is PAYLOAD_TYPE_ACK, the first 4 bytes after the wrapper are the ACK
    CRC, which is routed into the same ack-received path as discrete ACKs so a pending
    send is cancelled identically.

    Forwarding/retransmission of multi-acks (the repeater role) is intentionally not
    implemented here.
    """

    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_MULTIPART

    def __init__(self, log_fn):
        self.log = log_fn
        self._ack_received_callback: Optional[Callable[[int], Awaitable[None] | None]] = None

    def set_ack_received_callback(
        self, callback: Optional[Callable[[int], Awaitable[None] | None]]
    ):
        """Set callback to notify the dispatcher when an embedded ACK is received."""
        self._ack_received_callback = callback

    async def __call__(self, packet: Packet) -> None:
        crc = self.extract_ack_crc(packet)
        if crc is not None:
            await self._notify_ack_received(crc)

    def extract_ack_crc(self, packet: Packet) -> Optional[int]:
        """Return the embedded ACK CRC, or None if this is not a multi-ack."""
        payload = packet.payload
        # wrapper byte (1) + at least a 4-byte CRC
        if len(payload) < 5:
            self.log(f"MULTIPART too short for embedded ACK: {len(payload)} bytes")
            return None

        inner_type = payload[0] & 0x0F
        if inner_type != PAYLOAD_TYPE_ACK:
            # FUTURE: other multipart inner types
            self.log(f"MULTIPART inner type {inner_type} is not an ACK, ignoring")
            return None

        crc = int.from_bytes(payload[1:5], "little")
        self.log(f"Multi-ack received: CRC={crc:08X}")
        return crc

    async def _notify_ack_received(self, crc: int):
        """Notify the dispatcher that an ACK was received."""
        if self._ack_received_callback:
            await invoke_maybe_awaitable(self._ack_received_callback, crc)
