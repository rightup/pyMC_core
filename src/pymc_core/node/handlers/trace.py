"""Trace packet handler for mesh network diagnostics.

Handles trace packets that contain SNR and routing information
for network diagnostics and analysis.
"""

import struct
from typing import Any, Callable, Dict

from ...protocol import Packet
from ...protocol.constants import PAYLOAD_TYPE_TRACE


class TraceHandler:
    """Handler for trace packets (payload type 0x09).

    Trace packets are used for network diagnostics and routing analysis.
    They contain tag, auth_code, flags, and trace path information with SNR data.
    """

    def __init__(self, log_fn: Callable[[str], None], protocol_response_handler=None):
        self._log = log_fn
        self._protocol_response_handler = protocol_response_handler

        # Callbacks for trace responses
        self._response_callbacks: Dict[int, Callable[[bool, str, Dict[str, Any]], None]] = {}

    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_TRACE

    def set_response_callback(
        self, contact_hash: int, callback: Callable[[bool, str, Dict[str, Any]], None]
    ) -> None:
        """Set callback for trace responses from a specific contact."""
        self._response_callbacks[contact_hash] = callback

    def clear_response_callback(self, contact_hash: int) -> None:
        """Clear callback for trace responses from a specific contact."""
        self._response_callbacks.pop(contact_hash, None)

    async def __call__(self, pkt: Packet) -> None:
        """Handle incoming trace packet."""
        try:
            self._log(f"[TraceHandler] Processing trace packet: {len(pkt.payload)} bytes")

            # Parse trace packet payload
            parsed_data = self._parse_trace_payload(pkt.payload)

            # Add signal strength information from the received packet
            parsed_data["snr"] = pkt._snr
            parsed_data["rssi"] = pkt._rssi

            # Log the parsed trace data
            self._log(
                f"[TraceHandler] Parsed trace: tag=0x{parsed_data.get('tag', 0):08X}, "
                f"auth=0x{parsed_data.get('auth_code', 0):08X}, "
                f"flags=0x{parsed_data.get('flags', 0):02X}, "
                f"path_length={parsed_data.get('path_length', 0)}"
            )

            # Extract source hash from trace data if available
            src_hash = None
            trace_path = parsed_data.get("trace_path", [])
            if trace_path:
                # Usually the source is the last node in the trace path
                src_hash = trace_path[-1] if trace_path else None

            # If we have a callback waiting for this source, call it
            if src_hash and src_hash in self._response_callbacks:
                callback = self._response_callbacks[src_hash]
                if callback:
                    # Create response text with trace information
                    response_text = self._format_trace_response(parsed_data)
                    callback(True, response_text, parsed_data)
                    self._log(f"[TraceHandler] Called response callback for 0x{src_hash:02X}")
            else:
                src_hash_str = f"0x{src_hash:02X}" if src_hash is not None else "0x00"
                self._log(
                    f"[TraceHandler] No callback waiting for trace response "
                    f"(src_hash={src_hash_str})"
                )

            # Always forward to protocol response handler if available for broader integration
            if self._protocol_response_handler and hasattr(
                self._protocol_response_handler, "_response_callbacks"
            ):
                for (
                    contact_hash,
                    callback,
                ) in self._protocol_response_handler._response_callbacks.items():
                    if callback:
                        response_text = self._format_trace_response(parsed_data)
                        callback(True, response_text, parsed_data)
                        self._log(
                            f"[TraceHandler] Forwarded to protocol response handler "
                            f"for 0x{contact_hash:02X}"
                        )

        except Exception as e:
            self._log(f"[TraceHandler] Error processing trace packet: {e}")

    def _parse_trace_payload(self, payload: bytes) -> Dict[str, Any]:
        """Parse trace packet payload.

        Expected format: tag(4) + auth_code(4) + flags(1) + trace_path_bytes...
        """
        try:
            if len(payload) < 9:
                return {"error": "Payload too short", "raw_payload": payload.hex()}

            # Unpack the fixed fields (little-endian)
            tag, auth_code, flags = struct.unpack("<IIB", payload[:9])

            # Extract trace path bytes (remaining payload)
            trace_path_bytes = payload[9:]
            trace_path = list(trace_path_bytes) if trace_path_bytes else []

            return {
                "tag": tag,
                "auth_code": auth_code,
                "flags": flags,
                "trace_path": trace_path,
                "path_length": len(trace_path),
                "raw_payload": payload.hex(),
                "valid": True,
            }

        except Exception as e:
            return {
                "error": f"Parse error: {e}",
                "raw_payload": payload.hex(),
                "valid": False,
            }

    def _format_trace_response(self, parsed_data: Dict[str, Any]) -> str:
        """Format trace data into a human-readable response string."""
        if not parsed_data.get("valid", False):
            return f"Invalid trace data: {parsed_data.get('error', 'Unknown error')}"

        tag = parsed_data.get("tag", 0)
        auth_code = parsed_data.get("auth_code", 0)
        flags = parsed_data.get("flags", 0)
        trace_path = parsed_data.get("trace_path", [])

        response_parts = [
            f"TRACE_RESPONSE tag=0x{tag:08X}",
            f"auth=0x{auth_code:08X}",
            f"flags=0x{flags:02X}",
        ]

        if trace_path:
            path_str = " -> ".join(f"0x{hop:02X}" for hop in trace_path)
            response_parts.append(f"path=[{path_str}]")

        # Add signal strength information
        snr = parsed_data.get("snr", 0.0)
        rssi = parsed_data.get("rssi", 0)
        response_parts.append(f"snr={snr:.1f}dB")
        response_parts.append(f"rssi={rssi}dBm")

        return " ".join(response_parts)
