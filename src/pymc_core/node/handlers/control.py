"""Control packet handler for mesh network discovery.

Handles control packets for node discovery requests and responses.
These are zero-hop packets used for network topology discovery.
"""

import struct
import time
from typing import Any, Callable, Dict, List, Optional

from ...protocol import Packet
from ...protocol.constants import (
    ADV_TYPE_CHAT,
    ADV_TYPE_LABELS,
    ADV_TYPE_REPEATER,
    ADV_TYPE_ROOM,
    ADV_TYPE_SENSOR,
    PAYLOAD_TYPE_CONTROL,
)

# Control packet type constants (upper 4 bits of first byte)
CTL_TYPE_NODE_DISCOVER_REQ = 0x80  # Discovery request
CTL_TYPE_NODE_DISCOVER_RESP = 0x90  # Discovery response
CTL_TYPE_MASK = 0xF0
DISCOVER_REQ_PREFIX_FLAG = 0x01

KNOWN_ADV_TYPES = [ADV_TYPE_CHAT, ADV_TYPE_REPEATER, ADV_TYPE_ROOM, ADV_TYPE_SENSOR]
KNOWN_ADV_TYPE_MASK = sum(1 << adv_type for adv_type in KNOWN_ADV_TYPES)


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

        # Callbacks for discovery responses/requests
        self._response_callbacks: Dict[int, Callable[[Dict[str, Any]], None]] = {}
        self._request_callback: Optional[Callable[[Dict[str, Any]], None]] = None

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
        self._request_callback = callback

    def clear_request_callback(self) -> None:
        """Clear callback for discovery requests."""
        self._request_callback = None

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
            control_type = pkt.payload[0] & CTL_TYPE_MASK

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
            prefix_only = (flags_byte & DISCOVER_REQ_PREFIX_FLAG) != 0
            filter_mask = pkt.payload[1]
            tag = struct.unpack("<I", pkt.payload[2:6])[0]

            # Optional since timestamp
            since = 0
            if len(pkt.payload) >= 10:
                since = struct.unpack("<I", pkt.payload[6:10])[0]

            requested_types = self._decode_filter_types(filter_mask)
            type_names = [ADV_TYPE_LABELS.get(t, f"type_{t}") for t in requested_types]

            self._log(
                f"[ControlHandler] Discovery request: tag=0x{tag:08X}, "
                f"filter=0x{filter_mask:02X} ({'/'.join(type_names) or 'none'}), "
                f"since={since}, prefix_only={prefix_only}"
            )

            # Build request data for callback
            request_data = {
                "tag": tag,
                "filter": filter_mask,  # Backwards compat alias
                "filter_mask": filter_mask,
                "requested_types": requested_types,
                "requested_type_names": type_names,
                "since": since,
                "since_active": since > 0,
                "prefix_only": prefix_only,
                "snr": pkt.get_snr(),
                "raw_snr": pkt._snr,
                "rssi": pkt.rssi,
                "timestamp": time.time(),
                "payload_len": pkt.payload_len,
            }

            unknown_filter_bits = filter_mask & ~KNOWN_ADV_TYPE_MASK
            if unknown_filter_bits:
                request_data["unknown_filter_bits"] = unknown_filter_bits

            # Call request callback if registered (for logging/monitoring)
            if self._request_callback:
                self._request_callback(request_data)

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
            if len(pkt.payload) < 14:
                self._log("[ControlHandler] Discovery response too short")
                return

            # Parse response
            type_byte = pkt.payload[0]
            node_type = type_byte & 0x0F
            snr_byte = pkt.payload[1]
            # Convert signed byte to float SNR (C++ stores as int8_t multiplied by 4)
            inbound_snr = self._decode_response_snr(snr_byte)
            tag = struct.unpack("<I", pkt.payload[2:6])[0]
            pub_key = bytes(pkt.payload[6:])
            pubkey_len = len(pub_key)

            if pubkey_len not in (8, 32):
                self._log(
                    f"[ControlHandler] Discovery response invalid key length {pubkey_len}"
                )
                return

            prefix_only = pubkey_len == 8

            self._log(
                f"[ControlHandler] Discovery response: tag=0x{tag:08X}, "
                f"node_type={node_type}, inbound_snr={inbound_snr:.1f}dB (their RX), "
                f"response_snr={pkt.get_snr():.1f}dB (our RX), "
                f"key_len={pubkey_len}, rssi={pkt.rssi}dBm"
            )

            # Build response data
            node_type_name = ADV_TYPE_LABELS.get(node_type, f"type_{node_type}")
            pub_key_hex = pub_key.hex()
            prefix_hex = pub_key_hex if prefix_only else pub_key_hex[:16]
            prefix_bytes = pub_key if prefix_only else pub_key[:8]
            response_data = {
                "tag": tag,
                "node_type": node_type,
                "node_type_name": node_type_name,
                "inbound_snr": inbound_snr,  # SNR of our request at their end
                "response_snr": pkt.get_snr(),
                "raw_response_snr": pkt._snr,
                "rssi": pkt.rssi,
                "pub_key": pub_key_hex,
                "pub_key_bytes": pub_key,
                "prefix_only": prefix_only,
                "pub_key_prefix": prefix_hex,
                "pub_key_prefix_bytes": prefix_bytes,
                "key_length": pubkey_len,
                "timestamp": time.time(),
            }

            # Call callback if registered for this tag
            callback = self._response_callbacks.pop(tag, None)
            if callback:
                callback(response_data)
                self._log(f"[ControlHandler] Called response callback for tag 0x{tag:08X}")
            else:
                self._log(
                    f"[ControlHandler] No callback waiting for tag 0x{tag:08X}"
                )

        except Exception as e:
            self._log(f"[ControlHandler] Error handling discovery response: {e}")

    @staticmethod
    def _decode_filter_types(filter_mask: int) -> List[int]:
        if filter_mask is None:
            return []
        matched = []
        for adv_type in KNOWN_ADV_TYPES:
            if filter_mask & (1 << adv_type):
                matched.append(adv_type)
        return matched

    @staticmethod
    def _decode_response_snr(raw_snr: int) -> float:
        if raw_snr is None:
            return 0.0
        signed = raw_snr if raw_snr < 128 else raw_snr - 256
        return signed / 4.0
