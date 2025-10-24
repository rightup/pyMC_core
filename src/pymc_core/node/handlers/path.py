"""Path packet handler for mesh network routing."""

from typing import Callable

from ...protocol import Packet
from ...protocol.constants import PAYLOAD_TYPE_PATH


class PathHandler:
    """Handler for PATH packets (payload type 0x08) - "Returned path" packets.

    According to the official documentation, PATH packets are used for returning
    responses through the mesh network along discovered routing paths.

    Official Packet Structure:
    - Header [1B]: Route type (0-1) + Payload type (2-5) + Version (6-7)
    - Path Length [1B]: Length of the path field
    - Path [up to 64B]: Routing path data (if applicable)
    - Payload [up to 184B]: The actual data being transmitted

    For PATH packets, the payload typically contains:
    - [1B] dest_hash: Destination node hash
    - [1B] src_hash: Source node hash
    - [2B] MAC: Message Authentication Code (for payload version 0x00)
    - [NB] encrypted_data: Contains ACK or other response data
    """

    def __init__(
        self,
        log_fn: Callable[[str], None],
        ack_handler=None,
        protocol_response_handler=None,
    ):
        self._log = log_fn
        self._ack_handler = ack_handler
        self._protocol_response_handler = protocol_response_handler

    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_PATH

    def set_ack_handler(self, ack_handler):
        """Set the ACK handler for processing bundled/encrypted ACKs in PATH packets."""
        self._ack_handler = ack_handler

    async def __call__(self, pkt: Packet) -> None:
        """Handle incoming PATH packet according to official specification."""
        try:
            # First, check if this PATH packet contains protocol responses
            if self._protocol_response_handler:
                await self._protocol_response_handler(pkt)

            # Then, check if this PATH packet contains ACKs and delegate to ACK handler
            if self._ack_handler:
                ack_crc = await self._ack_handler.process_path_ack_variants(pkt)
                if ack_crc is not None:
                    # ACK was found, notify dispatcher
                    await self._ack_handler._notify_ack_received(ack_crc)

            # Optional PATH packet analysis if analyzer is available
            try:
                # Try to use any available packet analyzer through callback
                if hasattr(self, "_dispatcher") and hasattr(
                    self._dispatcher, "packet_analysis_callback"
                ):
                    if self._dispatcher.packet_analysis_callback:
                        self._dispatcher.packet_analysis_callback(pkt)
                        self._log("PATH packet analysis delegated to app")
                else:
                    self._log("PATH packet received - hop analysis requires app-level analyzer")

            except Exception as e:
                self._log(f"PATH packet analysis failed: {e}")

            # Extract and log key PATH information directly from packet
            try:
                payload = pkt.get_payload()
                if len(payload) >= 2:
                    hop_count = payload[1]
                    self._log(f"PATH packet: hop_count={hop_count}, payload_len={len(payload)}")
                    self._log(f"Path contains {hop_count} hops")
                else:
                    self._log("PATH packet received with minimal payload")

                # Log basic routing behavior based on header
                try:
                    # These constants are already imported at the top
                    # from ...protocol.constants import (
                    #     ROUTE_TYPE_DIRECT,
                    #     ROUTE_TYPE_FLOOD,
                    # )

                    # Extract route type from packet header if possible
                    # This is a simplified version without full analysis
                    self._log("PATH packet routing analysis requires app-level analyzer")
                except ImportError:
                    pass

            except Exception as e:
                self._log(f"Error extracting PATH information: {e}")

        except Exception as e:
            self._log(f"Error in PATH handler: {e}")
            import traceback

            self._log(traceback.format_exc())
