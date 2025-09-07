from __future__ import annotations

import asyncio
import enum
import logging
from typing import Any, Awaitable, Callable, Optional

from ..protocol import Packet
from ..protocol.constants import (  # Payload types
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_ADVERT,
    PH_TYPE_SHIFT,
)
from ..protocol.utils import PAYLOAD_TYPES, ROUTE_TYPES, format_packet_info

# Import handler classes
from .handlers import (
    AckHandler,
    AdvertHandler,
    AnonReqResponseHandler,
    GroupTextHandler,
    LoginResponseHandler,
    PathHandler,
    ProtocolResponseHandler,
    TextMessageHandler,
    TraceHandler,
)

ACK_TIMEOUT = 5.0  # seconds to wait for an ACK


class DispatcherState(str, enum.Enum):
    """Simple state machine for managing radio transmission."""

    IDLE = "IDLE"
    TRANSMIT = "TRANSMIT"
    WAIT = "WAIT"


class Dispatcher:
    """Handles all the packet routing and radio communication.

    This class doesn't do much packet processing itself - it just routes
    incoming packets to the right handler that knows what to do with them.
    """

    # ------------------------------------------------------------------
    # Setup and configuration
    # ------------------------------------------------------------------

    def __init__(
        self,
        radio,
        *,
        tx_delay: float = 0.05,
        log_fn: Optional[Callable[[str], None]] = None,
        packet_filter: Optional[Any] = None,
    ) -> None:
        self.radio = radio
        self.tx_delay = tx_delay
        self.state: DispatcherState = DispatcherState.IDLE

        self.packet_received_callback: Optional[
            Callable[[Packet], Awaitable[None] | None]
        ] = None
        self.packet_sent_callback: Optional[
            Callable[[Packet], Awaitable[None] | None]
        ] = None

        # Add raw packet callback for detailed logging
        self.raw_packet_callback: Optional[
            Callable[[Packet, bytes], Awaitable[None] | None]
        ] = None

        self._handlers: dict[int, Any] = {}  # Keep track of packet handlers
        self._handler_instances: dict[
            int, Any
        ] = {}  # Store actual handler objects for method access

        # Keep our identity handy for detecting our own packets
        self.local_identity: Optional[Any] = None

        # Contact book for decrypting messages (set by the node later)
        self.contact_book = None

        self._logger = logging.getLogger("Dispatcher")
        self._current_expected_crc: Optional[int] = None
        self._recent_acks: dict[int, float] = {}  # {crc: timestamp}
        self._waiting_acks = {}

        # Use provided packet filter or create default
        if packet_filter is not None:
            self.packet_filter = packet_filter
        else:
            # Create simple packet filter for routing decisions
            from ..protocol.packet_filter import PacketFilter

            self.packet_filter = PacketFilter()

        # Let the node register for packet analysis if it wants
        self.packet_analysis_callback: Optional[Callable[[Any, bytes], None]] = None

        # Initialize fallback handler
        self._fallback_handler = None

        # Hook up the radio's receive callback - all radios should support this
        self.radio.set_rx_callback(self._on_packet_received)
        self._logger.info("Registered RX callback with radio")

    def set_contact_book(self, contact_book):
        """Set the contact book for decryption operations."""
        self.contact_book = contact_book

    # ------------------------------------------------------------------
    # Public interface - registering handlers and callbacks
    # ------------------------------------------------------------------

    def register_handler(self, payload_type: int, handler_instance) -> None:
        """Register a handler for a specific type of packet."""
        # Keep the handler instance around so we can call methods on it
        self._handler_instances[payload_type] = handler_instance

        # Figure out what function to call when we get this packet type
        if hasattr(handler_instance, "handle_packet"):
            self._handlers[payload_type] = handler_instance.handle_packet
        elif callable(handler_instance):
            # Assume it's already a proper handler function
            handler_func = handler_instance
            self._handlers[payload_type] = handler_func
        else:
            raise ValueError(
                f"Handler for payload type {payload_type} must be callable "
                f"or have handle_packet method"
            )

        self._logger.info(f"Registered handler for payload type {payload_type}")

    def register_fallback_handler(self, handler: Callable[[Packet], Awaitable[None]]):
        """Register a fallback handler for unhandled payload types."""
        self._fallback_handler = handler
        self._logger.info("Registered fallback handler for unknown payload types.")

    def register_default_handlers(
        self,
        *,
        contacts=None,
        local_identity=None,
        channel_db=None,
        event_service=None,
        node_name=None,
    ) -> None:
        """Quick setup for all the standard packet handlers."""
        # Keep our identity handy for detecting our own packets
        self.local_identity = local_identity

        # Set up ACK handler with callback to us
        ack_handler = AckHandler(self._log, self)
        ack_handler.set_ack_received_callback(self._register_ack_received)

        # Register all the standard handlers
        self.register_handler(
            AdvertHandler.payload_type(),
            AdvertHandler(contacts, self._log, local_identity, event_service),
        )
        self.register_handler(AckHandler.payload_type(), ack_handler)

        # Text message handler - needs to send ACKs back through us
        text_message_handler = TextMessageHandler(
            local_identity,
            contacts,
            self._log,
            self.send_packet,
            event_service,
        )
        # Keep a reference so the node can use it
        self.text_message_handler = text_message_handler
        self.register_handler(
            TextMessageHandler.payload_type(),
            text_message_handler,
        )
        # Group text handler with channel database
        self.register_handler(
            GroupTextHandler.payload_type(),
            GroupTextHandler(
                local_identity,
                contacts,
                self._log,
                self.send_packet,
                channel_db,
                event_service,
                node_name,
            ),
        )
        # Protocol response handler for encrypted responses (including telemetry)
        protocol_response_handler = ProtocolResponseHandler(
            self._log, local_identity, contacts
        )
        # Keep a reference for the node
        self.protocol_response_handler = protocol_response_handler

        # Login response handler for PAYLOAD_TYPE_RESPONSE packets
        login_response_handler = LoginResponseHandler(
            local_identity, contacts, self._log
        )
        # Connect protocol response handler for forwarding telemetry
        login_response_handler.set_protocol_response_handler(protocol_response_handler)
        # Keep references for backward compatibility
        # Note: telemetry now uses protocol_response_handler, login uses PAYLOAD_TYPE_RESPONSE
        self.login_response_handler = login_response_handler
        # For backward compatibility, point telemetry handler to protocol response handler
        self.telemetry_response_handler = protocol_response_handler

        # PATH handler - for route discovery packets, with ACK and protocol response processing
        path_handler = PathHandler(self._log, ack_handler, protocol_response_handler)
        self.register_handler(PathHandler.payload_type(), path_handler)

        # Login response handler for PAYLOAD_TYPE_RESPONSE packets
        self.register_handler(
            LoginResponseHandler.payload_type(),
            login_response_handler,
        )

        # Anonymous request response handler for login responses that come as ANON_REQ
        self.register_handler(
            AnonReqResponseHandler.payload_type(),
            AnonReqResponseHandler(local_identity, contacts, self._log),
        )

        # TRACE handler for diagnostics and routing analysis
        trace_handler = TraceHandler(self._log, protocol_response_handler)
        self.register_handler(
            TraceHandler.payload_type(),
            trace_handler,
        )
        # Keep a reference for the node
        self.trace_handler = trace_handler

        self._logger.info("Default handlers registered.")

        # Set up a fallback handler for unknown packet types
        async def fallback_handler(pkt):
            # Get payload type for logging
            try:
                ptype = pkt.header >> PH_TYPE_SHIFT
                type_name = PAYLOAD_TYPES.get(ptype, f"unknown_{ptype}")
            except Exception:
                type_name = "unknown"
            self._logger.info(f"Fallback handler: Unhandled payload type {type_name}")
            # Optionally, call the packet_received_callback to pass downstream
            if self.packet_received_callback:
                await self._invoke_callback(self.packet_received_callback, pkt)

        self.register_fallback_handler(fallback_handler)

    def _get_handler(self, ptype: int):
        """Get handler for payload type, or fallback if not found."""
        return self._handlers.get(ptype, self._fallback_handler)

    def _is_own_packet(self, pkt: Packet) -> bool:
        """Check if this packet came from us by comparing the source hash."""
        if not self.local_identity or len(pkt.payload) < 2:
            return False

        # Get our public key hash (first byte)
        our_pubkey = self.local_identity.get_public_key()
        our_hash = our_pubkey[0] if len(our_pubkey) > 0 else 0

        # Compare with src_hash in payload[1]
        src_hash = pkt.payload[1]
        is_own = src_hash == our_hash

        if is_own:
            self._log(
                f"Own packet detected: src_hash={src_hash:02X}, our_hash={our_hash:02X}"
            )

        return is_own

    def set_packet_received_callback(
        self, callback: Callable[[Packet], Awaitable[None] | None]
    ) -> None:
        self.packet_received_callback = callback

    def set_packet_sent_callback(
        self, callback: Callable[[Packet], Awaitable[None] | None]
    ) -> None:
        self.packet_sent_callback = callback

    def set_raw_packet_callback(
        self, callback: Callable[[Packet, bytes], Awaitable[None] | None]
    ) -> None:
        """Set callback for raw packet data (includes both parsed packet and raw bytes)."""
        self.raw_packet_callback = callback

    def _on_packet_received(self, data: bytes) -> None:
        """Called by the radio when a packet comes in."""
        self._log(f"[RX DEBUG] Packet received: {len(data)} bytes")

        # Schedule the packet processing in the event loop
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._process_received_packet(data))
        except RuntimeError:
            # No event loop running, can't process packet
            self._log("No event loop running, cannot process received packet")

    async def _process_received_packet(self, data: bytes) -> None:
        """Process a received packet from the radio callback."""
        self._log(
            f"[RX DEBUG] Processing packet: {len(data)} bytes, data: {data.hex()[:32]}..."
        )

        # Generate packet hash for deduplication and blacklist checking
        packet_hash = self.packet_filter.generate_hash(data)

        # Skip blacklisted packets (known malformed)
        if self.packet_filter.is_blacklisted(packet_hash):
            self._log("[RX DEBUG] Packet blacklisted, skipping")
            return

        # Skip duplicate packets
        if self.packet_filter.is_duplicate(packet_hash):
            self._log(f"Duplicate packet ignored (hash: {packet_hash})")
            return

        # Update packet hash tracking
        self.packet_filter.track_packet(packet_hash)

        pkt = Packet()
        try:
            pkt.read_from(data)
            self._log("[RX DEBUG] Packet parsed successfully")
        except Exception as err:
            self._log(f"Malformed packet: {err}")
            # Blacklist this packet to avoid repeated parsing attempts
            self.packet_filter.blacklist(packet_hash)
            self._log(f"Blacklisted malformed packet (hash: {packet_hash})")
            return

        ptype = pkt.header >> PH_TYPE_SHIFT

        self._log(f"[RX DEBUG] Packet type: {ptype:02X}")

        # Add signal strength information to packet from radio
        pkt._rssi = self.radio.get_last_rssi()
        pkt._snr = self.radio.get_last_snr()

        # Let the node know about this packet for analysis (statistics, caching, etc.)
        if self.packet_analysis_callback:
            try:
                import asyncio

                if asyncio.iscoroutinefunction(self.packet_analysis_callback):
                    await self.packet_analysis_callback(pkt, data)
                else:
                    self.packet_analysis_callback(pkt, data)
                self._log("[RX DEBUG] Packet analysis callback completed")
            except Exception as e:
                self._log(f"Error in packet analysis callback: {e}")

        # Always call raw packet callback first for logging (regardless of source)
        if self.raw_packet_callback:
            await self._invoke_enhanced_raw_callback(
                self.raw_packet_callback, pkt, data, {}
            )
            self._log("[RX DEBUG] Raw packet callback completed")

        # Check if this is our own packet before processing handlers
        if self._is_own_packet(pkt):
            packet_info = format_packet_info(pkt.header, len(pkt.payload))

            self._log(f"OWN PACKET RECEIVED! {packet_info}")
            self._log(
                "   This suggests your packet was repeated by another node and came back to you!"
            )
            self._log(
                f"Ignoring own packet (type={pkt.header >> 4:02X}) to prevent loops"
            )
            return

        # Handle ACK matching for waiting senders
        self._log("[RX DEBUG] Dispatching packet to handlers")
        await self._dispatch(pkt)

    # ------------------------------------------------------------------
    # Public interface - sending and receiving packets
    # ------------------------------------------------------------------

    async def send_packet(
        self,
        packet: Packet,
        wait_for_ack: bool = True,
        expected_crc: Optional[int] = None,
    ) -> bool:
        """
        Send a packet and optionally wait for an ACK.

        Args:
            packet: The packet to send
            wait_for_ack: Whether to wait for an ACK
            expected_crc: The expected CRC for ACK matching.
                If None, will be calculated from packet.
        """
        payload_type = packet.header >> PH_TYPE_SHIFT

        # ------------------------------------------------------------------ #
        #  Make sure we're not already busy
        # ------------------------------------------------------------------ #
        if self.state != DispatcherState.IDLE:
            self._log("Busy, skipping TX.")
            return False

        # ------------------------------------------------------------------ #
        #  Send the packet
        # ------------------------------------------------------------------ #
        self.state = DispatcherState.TRANSMIT
        raw = packet.write_to()
        try:
            await self.radio.send(raw)
        except Exception as e:
            self._log(f"Radio transmit error: {e}")
            self.state = DispatcherState.IDLE
            return False
        # Log what we sent
        type_name = PAYLOAD_TYPES.get(payload_type, f"UNKNOWN_{payload_type}")
        route_name = ROUTE_TYPES.get(
            packet.get_route_type(), f"UNKNOWN_{packet.get_route_type()}"
        )
        self._log(
            f"TX {packet.get_raw_length()} bytes (type={type_name}, route={route_name})"
        )

        if self.packet_sent_callback:
            await self._invoke_callback(self.packet_sent_callback, packet)

        # Skip waiting for ACK if not needed
        if payload_type in {PAYLOAD_TYPE_ADVERT, PAYLOAD_TYPE_ACK} or not wait_for_ack:
            self.state = DispatcherState.IDLE
            return True

        # ------------------------------------------------------------------ #
        #  Wait for ACK using the callback system
        # ------------------------------------------------------------------ #
        await asyncio.sleep(self.tx_delay)
        self.state = DispatcherState.WAIT

        # Set the expected CRC for ACK matching
        if expected_crc is not None:
            self._current_expected_crc = expected_crc
        else:
            self._current_expected_crc = packet.get_crc()

        self._log(
            f"Waiting for ACK with CRC {self._current_expected_crc:08X} (timeout: {ACK_TIMEOUT}s)"
        )

        try:
            # Wait for the ACK using the event-based system
            ack_received = await self.wait_for_ack(
                self._current_expected_crc, ACK_TIMEOUT
            )
            if ack_received:
                self._log(f"[>>acK] received for CRC {self._current_expected_crc:08X}")
                return True
            else:
                self._log(f"ACK timeout for CRC {self._current_expected_crc:08X}")
                return False
        finally:
            self.state = DispatcherState.IDLE
            self._current_expected_crc = None

    async def wait_for_ack(self, crc: int, timeout: float = ACK_TIMEOUT) -> bool:
        """Wait for a specific ACK CRC for up to `timeout` seconds."""
        event = self.expect_ack(crc)
        try:
            await asyncio.wait_for(event.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            self._log(f"wait_for_ack() timeout for CRC {crc:08X}")
            return False

    # ------------------------------------------------------------------#
    # ACK tracking and management
    # ------------------------------------------------------------------#
    def expect_ack(self, crc: int) -> asyncio.Event:
        """
        Register an ACK CRC we're waiting for and return an asyncio.Event
        that will be set as soon as the ACK arrives (or is already cached).
        """
        evt = self._waiting_acks.get(crc)
        if evt is None:
            evt = asyncio.Event()
            self._waiting_acks[crc] = evt

            # ACK might already be in the recent-ACK cache -> fire instantly
        if crc in self._recent_acks:
            evt.set()
        return evt

    # RX path for every incoming packet
    async def _dispatch(self, pkt: Packet) -> None:
        payload_type = pkt.get_payload_type()
        type_name = PAYLOAD_TYPES.get(payload_type, f"UNKNOWN_{payload_type}")
        self._log(f"RX {type_name} ({payload_type})")

        self._logger.debug(
            f"Received packet type {type_name}, payload length: {pkt.payload_len}"
        )
        if pkt.payload_len > 0:
            self._logger.debug(
                f"Payload preview: {pkt.payload[:min(10, pkt.payload_len)].hex()}"
            )

        handler = self._get_handler(payload_type)
        if not handler:
            self._log(f"No handler for payload {type_name}")
            return

        try:
            await handler(pkt)
            if self.packet_received_callback:
                await self._invoke_callback(self.packet_received_callback, pkt)
        except Exception as err:
            self._log(f"Handler error for {type_name}: {err}")

    # ------------------------------------------------------------------
    # ACK registration system
    #
    # Simple interface for handlers to notify dispatcher when ACKs are received.
    # All ACK processing logic is delegated to the AckHandler.
    # ------------------------------------------------------------------

    def _register_ack_received(self, crc: int) -> None:
        """Record that an ACK with the given CRC was received."""
        ts = asyncio.get_event_loop().time()
        self._recent_acks[crc] = ts

        # Notify waiting sender if this CRC matches
        if evt := self._waiting_acks.pop(crc, None):
            self._log(f"ACK matched! CRC {crc:08X}")
            evt.set()

    async def run_forever(self) -> None:
        """Run the dispatcher maintenance loop indefinitely (call this in an asyncio task)."""
        while True:
            # Clean out old ACK CRCs (older than 5 seconds)
            now = asyncio.get_event_loop().time()
            self._recent_acks = {
                crc: ts for crc, ts in self._recent_acks.items() if now - ts < 5
            }

            # Clean old packet hashes for deduplication
            self.packet_filter.cleanup_old_hashes()

            # With callback-based RX, just do maintenance tasks
            await asyncio.sleep(1.0)  # Check every second for cleanup

    # ------------------------------------------------------------------
    # Internal helper methods
    # ------------------------------------------------------------------

    async def _rx_once(self) -> None:
        """Fallback RX method for radios that don't support callbacks."""
        try:
            data = await self.radio.wait_for_rx()
        except Exception as err:
            self._log(f"Radio RX error: {err}")
            return

        # Process the received packet using the same method as callbacks
        await self._process_received_packet(data)

    async def _invoke_callback(self, cb, pkt: Packet) -> None:
        if asyncio.iscoroutinefunction(cb):
            await cb(pkt)
        else:
            cb(pkt)

    async def _invoke_enhanced_raw_callback(
        self, callback, pkt: Packet, data: bytes, analysis: dict
    ) -> None:
        """Call raw packet callback with extra analysis data."""
        try:
            if asyncio.iscoroutinefunction(callback):
                await callback(pkt, data, analysis)
            else:
                callback(pkt, data, analysis)
        except Exception as e:
            self._log(f"Raw callback error: {e}")
            # Fallback to original callback format
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(pkt, data)
                else:
                    callback(pkt, data)
            except Exception as e2:
                self._log(f"Fallback raw callback error: {e2}")

    # ------------------------------------------------------------------
    # Logging helper
    # ------------------------------------------------------------------
    def _log(self, msg: str) -> None:
        self._logger.info(msg)

    def get_filter_stats(self) -> dict:
        """Get current packet filter statistics."""
        return self.packet_filter.get_stats()

    def clear_packet_filter(self) -> None:
        """Clear packet filter data."""
        self.packet_filter.clear()
        self._log("Packet filter cleared")

    async def _find_contact_by_hash(self, src_hash: int):
        """Find contact by source hash. Returns None if not found or no contacts available."""
        if not self.contact_book:
            self._log("Contact book not available for PATH decryption")
            return None

        for contact in self.contact_book.contacts:
            try:
                if contact.public_key:
                    if bytes.fromhex(contact.public_key)[0] == src_hash:
                        return contact
            except Exception:
                continue
        return None
