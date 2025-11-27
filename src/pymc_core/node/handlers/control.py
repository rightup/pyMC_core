"""Control packet handler for mesh network discovery.

Handles control packets for node discovery requests and responses.
These are zero-hop packets used for network topology discovery.
"""

import struct
import time
from typing import Any, Callable, Dict

from ...protocol import Packet
from ...protocol.constants import PAYLOAD_TYPE_CONTROL

# Control packet type constants (upper 4 bits of first byte)
CTL_TYPE_NODE_DISCOVER_REQ = 0x80  # Discovery request
CTL_TYPE_NODE_DISCOVER_RESP = 0x90  # Discovery response


class ControlHandler:
    """Handler for control packets (payload type 0x0B).

    Control packets are used for node discovery and network topology mapping.
    This handler processes incoming discovery requests and responses.
    """

    def __init__(self, log_fn: Callable[[str], None]):
        """Initialize control handler.
        
        Args:
            log_fn: Logging function
        """
        self._log = log_fn

        # Callbacks for discovery responses
        self._response_callbacks: Dict[int, Callable[[Dict[str, Any]], None]] = {}
        self._request_callbacks: Dict[int, Callable[[Dict[str, Any]], None]] = {}

    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_CONTROL

    def set_response_callback(
        self, tag: int, callback: Callable[[Dict[str, Any]], None]
    ) -> None:
        """Set callback for discovery responses with a specific tag."""
        self._response_callbacks[tag] = callback

    def clear_response_callback(self, tag: int) -> None:
        """Clear callback for discovery responses with a specific tag."""
        self._response_callbacks.pop(tag, None)

    def set_request_callback(
        self, callback: Callable[[Dict[str, Any]], None]
    ) -> None:
        """Set callback for discovery requests (for logging/monitoring)."""
        self._request_callbacks[0] = callback

    def clear_request_callback(self) -> None:
        """Clear callback for discovery requests."""
        self._request_callbacks.pop(0, None)

    async def __call__(self, pkt: Packet) -> None:
        """Handle incoming control packet."""
        try:
            if not pkt.payload or len(pkt.payload) == 0:
                self._log("[ControlHandler] Empty payload, ignoring")
                return

            # Check if this is a zero-hop packet (path_len must be 0)
            if pkt.path_len != 0:
                self._log(
                    f"[ControlHandler] Non-zero path length ({pkt.path_len}), ignoring"
                )
                return

            # Extract control type (upper 4 bits of first byte)
            control_type = pkt.payload[0] & 0xF0

            if control_type == CTL_TYPE_NODE_DISCOVER_REQ:
                await self._handle_discovery_request(pkt)
            elif control_type == CTL_TYPE_NODE_DISCOVER_RESP:
                await self._handle_discovery_response(pkt)
            else:
                self._log(
                    f"[ControlHandler] Unknown control type: 0x{control_type:02X}"
                )

        except Exception as e:
            self._log(f"[ControlHandler] Error processing control packet: {e}")

    async def _handle_discovery_request(self, pkt: Packet) -> None:
        """Handle node discovery request packet.
        
        Expected format:
        - byte 0: type (0x80) + flags (bit 0: prefix_only)
        - byte 1: filter (bitfield of node types to respond)
        - bytes 2-5: tag (uint32_t, little-endian)
        - bytes 6-9: since timestamp (uint32_t, optional)
        """
        try:
            if len(pkt.payload) < 6:
                self._log("[ControlHandler] Discovery request too short")
                return

            # Parse request
            flags_byte = pkt.payload[0]
            prefix_only = (flags_byte & 0x01) != 0
            filter_byte = pkt.payload[1]
            tag = struct.unpack("<I", pkt.payload[2:6])[0]

            # Optional since timestamp
            since = 0
            if len(pkt.payload) >= 10:
                since = struct.unpack("<I", pkt.payload[6:10])[0]

            self._log(
                f"[ControlHandler] Discovery request: tag=0x{tag:08X}, "
                f"filter=0x{filter_byte:02X}, since={since}, prefix_only={prefix_only}"
            )

            # Build request data for callback
            request_data = {
                "tag": tag,
                "filter": filter_byte,
                "since": since,
                "prefix_only": prefix_only,
                "snr": pkt._snr,
                "rssi": pkt._rssi,
                "timestamp": time.time(),
            }

            # Call request callback if registered (for logging/monitoring)
            if 0 in self._request_callbacks:
                callback = self._request_callbacks[0]
                if callback:
                    callback(request_data)

        except Exception as e:
            self._log(f"[ControlHandler] Error handling discovery request: {e}")

    async def _handle_discovery_response(self, pkt: Packet) -> None:
        """Handle node discovery response packet.
        
        Response format:
        - byte 0: type (0x90) + node_type (lower 4 bits)
        - byte 1: SNR of our request (int8_t, multiplied by 4)
        - bytes 2-5: tag (matches our request)
        - bytes 6-onwards: public key (8 or 32 bytes)
        """
        try:
            if len(pkt.payload) < 6:
                self._log("[ControlHandler] Discovery response too short")
                return

            # Parse response
            type_byte = pkt.payload[0]
            node_type = type_byte & 0x0F
            snr_byte = pkt.payload[1]
            # Convert signed byte to float SNR (C++ stores as int8_t multiplied by 4)
            inbound_snr = (snr_byte if snr_byte < 128 else snr_byte - 256) / 4.0
            tag = struct.unpack("<I", pkt.payload[2:6])[0]
            pub_key = pkt.payload[6:]

            self._log(
                f"[ControlHandler] Discovery response: tag=0x{tag:08X}, "
                f"node_type={node_type}, inbound_snr={inbound_snr:.1f}dB (their RX), "
                f"response_snr={pkt._snr:.1f}dB (our RX), "
                f"key_len={len(pub_key)}, rssi={pkt._rssi}dBm"
            )

            # Build response data
            response_data = {
                "tag": tag,
                "node_type": node_type,
                "inbound_snr": inbound_snr,  # SNR of our request at their end
                "response_snr": pkt._snr,    # SNR of their response at our end
                "rssi": pkt._rssi,           # RSSI of their response at our end
                "pub_key": pub_key.hex(),
                "pub_key_bytes": bytes(pub_key),
                "timestamp": time.time(),
            }

            # Call callback if registered for this tag
            if tag in self._response_callbacks:
                callback = self._response_callbacks[tag]
                if callback:
                    callback(response_data)
                    self._log(
                        f"[ControlHandler] Called response callback for tag 0x{tag:08X}"
                    )
            else:
                self._log(
                    f"[ControlHandler] No callback waiting for tag 0x{tag:08X}"
                )

        except Exception as e:
            self._log(f"[ControlHandler] Error handling discovery response: {e}")
