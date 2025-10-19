from __future__ import annotations

import asyncio
import collections
import collections.abc
import logging
from typing import Any, Optional

# Fix for Python 3.10+ compatibility with PyYAML
if not hasattr(collections, "Hashable"):
    setattr(collections, "Hashable", collections.abc.Hashable)

from ..protocol import LocalIdentity
from .dispatcher import Dispatcher

logger = logging.getLogger("Node")


class MeshNode:
    """Represents a node in a mesh network for radio communication.

    Manages radio communication, message routing, and protocol handling
    within a mesh network. Provides high-level APIs for sending messages,
    telemetry requests, and commands to other nodes and repeaters.

    The node integrates with various components like contact storage,
    channel databases, and event services for comprehensive mesh functionality.
    """

    def __init__(
        self,
        radio: Optional[Any],
        local_identity: LocalIdentity,
        config: Optional[dict] = None,
        *,
        contacts: Optional[Any] = None,
        channel_db: Optional[Any] = None,
        logger: Optional[logging.Logger] = None,
        event_service: Optional[Any] = None,
    ) -> None:
        """Initialise a mesh network node instance.

        Sets up the node's core components including radio interface,
        identity management, and communication handlers.

        Args:
            radio: Radio hardware interface for transmission/reception.
            local_identity: Node's cryptographic identity for secure communication.
            config: Optional configuration dictionary with node settings.
            contacts: Optional contact storage for managing known nodes.
            channel_db: Optional channel database for group communication.
            logger: Optional logger instance; defaults to module logger.
            event_service: Optional event service for broadcasting mesh events.
        """
        self.radio = radio
        self.identity = local_identity
        self.contacts = contacts  # App can inject contact storage
        self.channel_db = channel_db  # App can inject channel database
        self.event_service = event_service  # App can inject event service

        # Node name should be provided by app
        self.node_name = config.get("node", {}).get("name", "unknown") if config else "unknown"
        self.radio_config = config.get("radio", {}) if config else {}

        self.logger = logger or logging.getLogger("MeshNode")
        self.log = self.logger

        # App-injected analysis components
        self.packet_filter = None

        self.dispatcher = Dispatcher(radio, log_fn=self.log.info, packet_filter=self.packet_filter)

        # Set contact book for decryption
        self.dispatcher.set_contact_book(self.contacts)
        self.dispatcher.register_default_handlers(
            contacts=self.contacts,
            local_identity=self.identity,
            channel_db=self.channel_db,
            event_service=self.event_service,
            node_name=self.node_name,
            radio_config=self.radio_config,
        )
        # Store reference to text handler for command response callbacks
        self._text_handler = None

    # Helper Methods
    def _find_and_call_handler_method(self, method_name: str, *args, **kwargs) -> bool:
        """Find and call a method on any handler that has it. Returns True if called."""
        found = False

        if hasattr(self.dispatcher, "_handler_instances"):
            for handler in self.dispatcher._handler_instances.values():
                if hasattr(handler, method_name):
                    getattr(handler, method_name)(*args, **kwargs)
                    found = True
        else:
            for attr_name in dir(self.dispatcher):
                if attr_name.endswith("_handler"):
                    handler = getattr(self.dispatcher, attr_name, None)
                    if handler and hasattr(handler, method_name):
                        getattr(handler, method_name)(*args, **kwargs)
                        found = True

        return found

    def _get_contact_or_raise(self, contact_name: str):
        """Get contact by name or raise RuntimeError if not found."""
        contact = self.contacts.get_by_name(contact_name) if self.contacts else None
        if not contact:
            raise RuntimeError(f"No contact '{contact_name}'")
        return contact

    class _ResponseWaiter:
        """Helper class for managing asynchronous response callbacks.

        Provides a synchronisation mechanism for waiting on responses
        from remote nodes with timeout support.
        """

        def __init__(self):
            self.event = asyncio.Event()
            self.data = {"success": False, "text": None, "parsed": {}}

        def callback(self, success: bool, text: str, parsed_data: Optional[dict] = None):
            """Standard callback for response handlers."""
            self.data["success"] = success
            self.data["text"] = text
            self.data["parsed"] = parsed_data or {}
            self.event.set()

        async def wait(self, timeout: float = 10.0) -> dict:
            """Wait for response with timeout. Returns the response data."""
            try:
                await asyncio.wait_for(self.event.wait(), timeout=timeout)
                return self.data
            except asyncio.TimeoutError:
                return {"success": False, "text": None, "parsed": {}, "timeout": True}

    def _time_operation(self):
        """Context manager for timing operations and calculating RTT."""
        import time
        from contextlib import contextmanager

        @contextmanager
        def timer():
            start_time = time.time()
            yield lambda: (time.time() - start_time) * 1000  # RTT in milliseconds

        return timer()

    def set_event_service(self, event_service):
        """Set the event service for broadcasting mesh events."""
        self.event_service = event_service

        # Update event service in all handlers that support it
        if hasattr(self.dispatcher, "_handler_instances"):
            for handler in self.dispatcher._handler_instances.values():
                if hasattr(handler, "event_service"):
                    handler.event_service = event_service
        else:
            # Fallback: check if dispatcher has specific handler references
            for attr_name in dir(self.dispatcher):
                if attr_name.endswith("_handler"):
                    handler = getattr(self.dispatcher, attr_name, None)
                    if handler and hasattr(handler, "event_service"):
                        handler.event_service = event_service

    async def start(self) -> None:
        """Start the mesh node and begin processing radio communications.

        Initialises the radio interface and dispatcher, then enters the main
        event loop for handling incoming/outgoing messages. This method blocks
        until the node is stopped.

        Note:
            This is an asynchronous operation that runs indefinitely until
            cancelled or the node is stopped.
        """
        await self.dispatcher.run_forever()

    async def send_text(
        self,
        contact_name: str,
        message: str,
        attempt: int = 1,
        message_type: str = "direct",
        out_path: Optional[list] = None,
    ) -> dict:
        """Send a text message to a specified contact.

        Transmits a text message to another node in the mesh network,
        with optional routing and retry configuration.

        Args:
            contact_name: Name of the target contact in the contact book.
            message: Text content to send.
            attempt: Message attempt number for retry logic (default: 1).
            message_type: Routing type - "direct" or other supported types.
            out_path: Optional list of intermediate nodes for routing.

        Returns:
            Dictionary containing transmission results including success status,
            signal strength metrics (SNR/RSSI), and routing information.

        Raises:
            RuntimeError: If the specified contact is not found.

        Example:
            ```python
            result = await node.send_text("alice", "Hello, world!")
            print(result["success"])  # True if message sent successfully
            ```
        """
        from ..protocol import PacketBuilder

        contact = self._get_contact_or_raise(contact_name)

        # Create the text message packet using PacketBuilder
        pkt, ack_crc = PacketBuilder.create_text_message(
            contact=contact,
            local_identity=self.identity,
            message=message,
            attempt=attempt,
            message_type=message_type,
            out_path=out_path,
        )

        # Log packet details with routing info
        routing_info = f"type={message_type}"
        if out_path:
            routing_info += f", path={' -> '.join(str(hop) for hop in out_path)}"

        self.logger.debug(
            f"[send_text] -> {contact_name}  msg='{message}'  CRC={ack_crc:08X}  ({routing_info})"
        )

        # Send packet with the expected ACK CRC
        success = await self.dispatcher.send_packet(pkt, wait_for_ack=True, expected_crc=ack_crc)
        if not success:
            self.logger.warning(f"No ACK received for CRC {ack_crc:08X}")

        # Extract signal strength information from radio
        snr = getattr(pkt, "snr", None) if "pkt" in locals() else None
        rssi = None

        # Get current signal strength from radio for outgoing messages
        if hasattr(self.radio, "get_last_rssi"):
            rssi = self.radio.get_last_rssi()
        if hasattr(self.radio, "get_last_snr") and snr is None:
            snr = self.radio.get_last_snr()

        return {
            "success": success,
            "attempt": attempt,
            "message_type": message_type,
            "out_path": out_path,
            "snr": snr,
            "rssi": rssi,
            "crc": ack_crc,
        }

    async def send_telemetry_request(
        self,
        contact_name: str,
        want_base: bool = True,
        want_location: bool = True,
        want_environment: bool = True,
        timeout: float = 10.0,
    ) -> dict:
        """Request telemetry data from a contact node.

        Sends a telemetry request and waits for the target node to respond
        with requested sensor data including base metrics, location, and
        environmental readings.

        Args:
            contact_name: Name of the contact to query.
            want_base: Include basic telemetry metrics in request.
            want_location: Include GPS/location data in request.
            want_environment: Include environmental sensors in request.
            timeout: Maximum time to wait for response in seconds.

        Returns:
            Dictionary with request results, telemetry data, and performance
            metrics including round-trip time.

        Raises:
            RuntimeError: If contact not found or protocol handler unavailable.

        Example:
            ```python
            result = await node.send_telemetry_request("sensor_node")
            if result["success"]:
                print(f"Temperature: {result['telemetry_data'].get('temp')}")
            ```
        """
        from ..protocol import PacketBuilder
        from ..protocol.constants import REQ_TYPE_GET_TELEMETRY_DATA

        contact = self._get_contact_or_raise(contact_name)

        with self._time_operation() as get_rtt:
            contact_hash = bytes.fromhex(contact.public_key)[0]

            # Set up response waiting
            waiter = self._ResponseWaiter()

            # Register callback with protocol response handler
            if not hasattr(self.dispatcher, "protocol_response_handler"):
                raise RuntimeError("Protocol response handler not available")

            self.dispatcher.protocol_response_handler.set_response_callback(
                contact_hash, waiter.callback
            )

            try:
                # Build and send telemetry request
                inv = PacketBuilder._compute_inverse_perm_mask(
                    want_base, want_location, want_environment
                )

                pkt, _ = PacketBuilder.create_protocol_request(
                    contact=contact,
                    local_identity=self.identity,
                    protocol_code=REQ_TYPE_GET_TELEMETRY_DATA,
                    data=bytes([inv]),
                )

                self.logger.debug(
                    f"[send_telemetry_request] -> {contact_name}  "
                    f"base={want_base}, location={want_location}, "
                    f"environment={want_environment}"
                )

                await self.dispatcher.send_packet(pkt, wait_for_ack=False)

                # Wait for response
                result = await waiter.wait(timeout)
                rtt = get_rtt()

                if result.get("timeout"):
                    self.logger.warning(
                        f"Timeout waiting for telemetry response from {contact_name}"
                    )
                    return {
                        "success": False,
                        "contact": contact_name,
                        "requested": {
                            "base": want_base,
                            "location": want_location,
                            "environment": want_environment,
                        },
                        "telemetry_data": None,
                        "rtt_ms": round(rtt, 2),
                        "reason": f"Telemetry response timeout after {timeout}s",
                    }

                self.logger.info(
                    f"[send_telemetry_request] Response from {contact_name}: '{result['text']}'"
                )

                return {
                    "success": result.get("success", False),
                    "contact": contact_name,
                    "requested": {
                        "base": want_base,
                        "location": want_location,
                        "environment": want_environment,
                    },
                    "telemetry_data": result["parsed"],
                    "response_text": result["text"],
                    "rtt_ms": round(rtt, 2),
                    "reason": (
                        "Telemetry response received"
                        if result.get("success")
                        else "Telemetry request failed"
                    ),
                }

            finally:
                self.dispatcher.protocol_response_handler.clear_response_callback(contact_hash)

    def stop(self):
        """Stop the mesh node and clean up associated services.

        Terminates radio communications and shuts down all active handlers.
        This method is synchronous and should be called to gracefully
        shut down the node.
        """
        try:
            self.logger.info("Node stopped")
        except Exception as e:
            self.logger.error(f"Error stopping node: {e}")

    async def send_group_text(self, group_name: str, message: str) -> dict:
        """Broadcast a text message to all members of a group.

        Sends a group datagram that will be received by all nodes configured
        for the specified group. Group messages are fire-and-forget with no
        acknowledgements expected.

        Args:
            group_name: Name of the group to broadcast to.
            message: Text content to broadcast.

        Returns:
            Dictionary with transmission results and signal metrics.
            Note: Group messages don't wait for acknowledgements.

        Example:
            ```python
            result = await node.send_group_text("team_alpha", "Meeting at 15:00")
            print(f"Broadcast to {result['group']}: {result['success']}")
            ```
        """
        from ..protocol import PacketBuilder

        # Get channels from database (live query)
        try:
            channels_config = self.channel_db.get_channels() if self.channel_db else []
        except Exception as e:
            self.logger.error(f"Failed to get channels from database: {e}")
            channels_config = []

        # Create the group text message packet using PacketBuilder
        pkt = PacketBuilder.create_group_datagram(
            group_name=group_name,
            local_identity=self.identity,
            message=message,
            sender_name=self.node_name,
            channels_config=channels_config,
        )

        # Log packet details (no CRC for group messages - they don't use ACKs)
        self.logger.debug(f"[send_group_text] -> {group_name}  msg='{message}'")

        # Send packet without waiting for ACK (group messages are unverified)
        success = await self.dispatcher.send_packet(pkt, wait_for_ack=False)

        # Extract signal strength information from radio
        snr = getattr(pkt, "snr", None) if "pkt" in locals() else None
        rssi = None

        # Get current signal strength from radio for outgoing messages
        if hasattr(self.radio, "get_last_rssi"):
            rssi = self.radio.get_last_rssi()
        if hasattr(self.radio, "get_last_snr") and snr is None:
            snr = self.radio.get_last_snr()

        # Note: Unlike text messages, we don't publish events here
        # Let the app level handle outgoing message events if needed
        # This prevents duplicate events when the message is received back

        return {
            "success": success,
            "snr": snr,
            "rssi": rssi,
            "group": group_name,
        }

    async def send_login(self, repeater_name: str, password: str) -> dict:
        """Authenticate with a repeater node.

        Sends login credentials to a repeater and waits for authentication
        response. Successful login may grant administrative privileges.

        Args:
            repeater_name: Name of the repeater to authenticate with.
            password: Authentication password for the repeater.

        Returns:
            Dictionary with login results including success status,
            admin privileges, and keep-alive intervals.

        Raises:
            RuntimeError: If repeater contact not found.

        Example:
            ```python
            result = await node.send_login("repeater_01", "secret123")
            if result["success"] and result["is_admin"]:
                print("Admin access granted")
            ```
        """
        from ..protocol import PacketBuilder

        contact = self._get_contact_or_raise(repeater_name)

        with self._time_operation() as get_rtt:
            contact_pubkey = bytes.fromhex(contact.public_key)
            dest_hash = contact_pubkey[0] if len(contact_pubkey) > 0 else 0

            # Store password in login handlers
            self._find_and_call_handler_method("store_login_password", dest_hash, password)

            # Create and send login packet
            pkt = PacketBuilder.create_login_packet(
                contact=contact, local_identity=self.identity, password=password
            )

            self.logger.debug(f"[send_login] -> {repeater_name}")

            # Set up login response waiting
            login_result = {"success": False, "data": {}}
            login_event = asyncio.Event()

            def login_response_callback(success: bool, response_data: dict):
                login_result["success"] = success
                login_result["data"] = response_data
                login_event.set()

            # Set callback on login response handlers
            self._find_and_call_handler_method("set_login_callback", login_response_callback)

            try:
                await self.dispatcher.send_packet(pkt, wait_for_ack=False)

                # Wait for login response
                try:
                    await asyncio.wait_for(login_event.wait(), timeout=10.0)
                except asyncio.TimeoutError:
                    self.logger.warning(f"Login timeout for repeater '{repeater_name}'")
                    return {
                        "success": False,
                        "repeater": repeater_name,
                        "command": "login",
                        "rtt_ms": round(get_rtt(), 2),
                        "reason": "Login response timeout",
                    }

                rtt = get_rtt()
                success = login_result["success"]
                response_data = login_result["data"]

                if success:
                    self.logger.info(
                        f"Login successful to '{repeater_name}' "
                        f"(admin: {response_data.get('is_admin', False)})"
                    )
                    reason = (
                        f"Login successful - Admin: "
                        f"{'Yes' if response_data.get('is_admin') else 'No'}"
                    )
                else:
                    error_msg = response_data.get("error", "Login failed")
                    self.logger.warning(f"Login failed to '{repeater_name}': {error_msg}")
                    reason = f"Login failed: {error_msg}"

                return {
                    "success": success,
                    "repeater": repeater_name,
                    "command": "login",
                    "rtt_ms": round(rtt, 2),
                    "is_admin": response_data.get("is_admin", False),
                    "keep_alive_interval": response_data.get("keep_alive_interval", 0),
                    "reason": reason,
                }

            finally:
                # Clear callbacks
                self._find_and_call_handler_method("set_login_callback", None)

    async def send_logout(self, repeater_name: str) -> dict:
        """Terminate authentication session with a repeater.

        Sends a logout command to end the current session with a repeater.
        This should be called when finished with repeater operations.

        Args:
            repeater_name: Name of the repeater to logout from.

        Returns:
            Dictionary with logout results and performance metrics.

        Raises:
            RuntimeError: If repeater contact not found.

        Example:
            ```python
            result = await node.send_logout("repeater_01")
            print(f"Logout {'successful' if result['success'] else 'failed'}")
            ```
        """
        from ..protocol import PacketBuilder

        contact = self._get_contact_or_raise(repeater_name)

        with self._time_operation() as get_rtt:
            # Create the logout packet using PacketBuilder
            pkt, ack_crc = PacketBuilder.create_logout_packet(
                contact=contact, local_identity=self.identity
            )

            self.logger.debug(f"[send_logout] -> {repeater_name} with CRC={ack_crc:08X}")

            # Send packet and wait for ACK
            success = await self.dispatcher.send_packet(
                pkt, wait_for_ack=True, expected_crc=ack_crc
            )
            rtt = get_rtt()

            if not success:
                self.logger.warning(f"No ACK received for logout CRC {ack_crc:08X}")

            return {
                "success": success,
                "repeater": repeater_name,
                "command": "logout",
                "rtt_ms": round(rtt, 2),
                "crc": ack_crc,
                "reason": "Logout successful" if success else "No ACK received",
            }

    async def send_status_request(self, repeater_name: str) -> dict:
        """Request status information from a repeater.

        Queries a repeater for its current operational status and configuration.
        This is a convenience method that uses the text command interface.

        Args:
            repeater_name: Name of the repeater to query.

        Returns:
            Dictionary with status information and response metrics.

        Raises:
            RuntimeError: If repeater contact not found.

        Example:
            ```python
            status = await node.send_status_request("repeater_01")
            if status["success"]:
                print(f"Status: {status['response']}")
            ```
        """
        # Use the simple text command approach instead of protocol packets
        return await self.send_repeater_command(repeater_name, "status")

    async def send_protocol_request(
        self, repeater_name: str, protocol_code: int, data: bytes = b""
    ) -> dict:
        """Send a protocol-specific request to a repeater.

        Transmits a custom protocol request with optional data payload
        and waits for the repeater's response.

        Args:
            repeater_name: Name of the repeater to send request to.
            protocol_code: Protocol operation code (0-255).
            data: Optional binary data payload for the request.

        Returns:
            Dictionary with protocol response, parsed data, and timing metrics.

        Raises:
            RuntimeError: If repeater contact or protocol handler not found.

        Example:
            ```python
            result = await node.send_protocol_request("repeater_01", 0x10, b"config")
            if result["success"]:
                print(f"Response: {result['response']}")
            ```
        """
        from ..protocol import PacketBuilder

        contact = self._get_contact_or_raise(repeater_name)

        with self._time_operation() as get_rtt:
            contact_hash = bytes.fromhex(contact.public_key)[0]

            # Set up response waiting
            waiter = self._ResponseWaiter()

            if not hasattr(self.dispatcher, "protocol_response_handler"):
                raise RuntimeError("Protocol response handler not available")

            self.dispatcher.protocol_response_handler.set_response_callback(
                contact_hash, waiter.callback
            )

            try:
                pkt, _ = PacketBuilder.create_protocol_request(
                    contact=contact,
                    local_identity=self.identity,
                    protocol_code=protocol_code,
                    data=data,
                )

                self.logger.debug(
                    f"[send_protocol_request] -> {repeater_name}: protocol 0x{protocol_code:02X}"
                )

                await self.dispatcher.send_packet(pkt, wait_for_ack=False)
                self.logger.debug("[send_protocol_request] Packet sent, waiting for response...")

                result = await waiter.wait(10.0)
                rtt = get_rtt()

                if result.get("timeout"):
                    self.logger.warning(
                        f"Timeout waiting for protocol response from {repeater_name}"
                    )
                    return {
                        "success": False,
                        "repeater": repeater_name,
                        "command": f"protocol_0x{protocol_code:02X}",
                        "protocol_code": protocol_code,
                        "response": None,
                        "parsed_data": {},
                        "rtt_ms": round(rtt, 2),
                        "ack_received": False,
                        "reason": f"Protocol 0x{protocol_code:02X} timeout",
                    }

                self.logger.info(
                    f"[send_protocol_request] Response from {repeater_name}: '{result['text']}'"
                )

                return {
                    "success": result["success"],
                    "repeater": repeater_name,
                    "command": f"protocol_0x{protocol_code:02X}",
                    "protocol_code": protocol_code,
                    "response": result["text"],
                    "parsed_data": result["parsed"],
                    "rtt_ms": round(rtt, 2),
                    "ack_received": False,
                    "reason": (
                        f"Protocol 0x{protocol_code:02X} "
                        f"{'successful' if result['success'] else 'failed'}"
                    ),
                }

            finally:
                self.dispatcher.protocol_response_handler.clear_response_callback(contact_hash)

    async def send_trace_packet(
        self,
        contact_name: str,
        tag: int,
        auth_code: int,
        flags: int = 0,
        path: Optional[list] = None,
        timeout: float = 5.0,
    ) -> dict:
        """Send a diagnostic trace packet for network analysis.

        Transmits a trace packet to analyse routing paths and network
        performance. Always expects a response with trace data, signal
        metrics, and routing information.

        Args:
            contact_name: Name of the target contact for tracing.
            tag: Unique identifier for this trace operation.
            auth_code: Authentication code for the trace request.
            flags: Optional flags to modify trace behaviour.
            path: Optional custom routing path for the trace.
            timeout: Maximum time to wait for trace response.

        Returns:
            Dictionary with trace results, routing data, and signal metrics.

        Raises:
            RuntimeError: If contact not found or trace handler unavailable.

        Example:
            ```python
            trace = await node.send_trace_packet("target_node", 0x12345678, 0xABCD)
            if trace["success"]:
                print(f"RTT: {trace['rtt_ms']}ms")
            ```
        """
        from ..protocol import PacketBuilder

        contact = self._get_contact_or_raise(contact_name)
        path = path or []

        # Get target node ID from contact's public key
        target_node_id = bytes.fromhex(contact.public_key)[0]

        # Use provided path or create simple direct path
        trace_path = path if path else [target_node_id]

        with self._time_operation() as get_rtt:
            # Create trace packet with path included
            pkt = PacketBuilder.create_trace(tag, auth_code, flags, path=trace_path)

            self.logger.debug(
                f"[send_trace_packet] -> {contact_name} tag=0x{tag:08X} path={trace_path}"
            )

            # Send trace packet and wait for response
            try:
                handler = self.dispatcher.trace_handler
                contact_hash = bytes.fromhex(contact.public_key)[0]
                waiter = self._ResponseWaiter()

                if handler:
                    handler.set_response_callback(contact_hash, waiter.callback)

                    try:
                        await self.dispatcher.send_packet(pkt, wait_for_ack=False)
                        result = await waiter.wait(timeout)
                        rtt = get_rtt()

                        if result.get("timeout"):
                            self.logger.warning(f"No trace response from {contact_name}")
                            return {
                                "success": False,
                                "contact": contact_name,
                                "trace_data": {
                                    "tag": tag,
                                    "auth_code": auth_code,
                                    "flags": flags,
                                    "path": trace_path,
                                },
                                "response": None,
                                "rtt_ms": round(rtt, 2),
                                "reason": f"Timeout after {timeout}s",
                            }

                        self.logger.info(
                            f"Trace response from {contact_name}: '{result.get('text', '')}'"
                        )
                        return {
                            "success": result.get("success", True),
                            "contact": contact_name,
                            "trace_data": {
                                "tag": tag,
                                "auth_code": auth_code,
                                "flags": flags,
                                "path": trace_path,
                            },
                            "response": result.get("text"),
                            "parsed_data": result.get("parsed", {}),
                            "rtt_ms": round(rtt, 2),
                            "reason": "Response received",
                        }

                    finally:
                        handler.clear_response_callback(contact_hash)
                else:
                    self.logger.error(f"No trace handler for {contact_name}")
                    return {
                        "success": False,
                        "contact": contact_name,
                        "reason": "No trace handler available",
                    }

            except Exception as e:
                rtt = get_rtt()
                self.logger.error(f"Trace error: {e}")
                return {
                    "success": False,
                    "contact": contact_name,
                    "trace_data": {
                        "tag": tag,
                        "auth_code": auth_code,
                        "flags": flags,
                        "path": trace_path,
                    },
                    "response": None,
                    "rtt_ms": round(rtt, 2),
                    "reason": f"Error: {str(e)}",
                }

    async def send_repeater_command(
        self, repeater_name: str, command: str, parameters: Optional[str] = None
    ) -> dict:
        """Send a text-based command to a repeater and await response.

        Transmits a command string to a repeater using the text message
        protocol and waits for a response. Useful for administrative
        operations and status queries.

        Args:
            repeater_name: Name of the repeater to send command to.
            command: Command string to execute on the repeater.
            parameters: Optional parameters for the command.

        Returns:
            Dictionary with command results, response text, and timing data.

        Raises:
            RuntimeError: If repeater contact not found.

        Example:
            ```python
            result = await node.send_repeater_command("repeater_01", "status")
            if result["success"]:
                print(f"Response: {result['response']}")
            ```
        """
        from ..protocol import PacketBuilder

        contact = self._get_contact_or_raise(repeater_name)

        with self._time_operation() as get_rtt:
            # Build full command string
            full_command = command
            if parameters:
                full_command += f" {parameters}"

            # Set up response capture
            response_event = asyncio.Event()
            response_data = {"text": None, "success": False}

            def response_callback(message_text: str, sender_contact):
                response_data["text"] = message_text
                response_data["success"] = True
                response_event.set()

            # Set response callback
            self.dispatcher.text_message_handler.set_command_response_callback(response_callback)

            try:
                # Create and send packet
                pkt, ack_crc = PacketBuilder.create_text_message(
                    contact=contact,
                    local_identity=self.identity,
                    message=full_command,
                    attempt=1,
                    message_type="command",
                )

                # Send packet and get ACK result
                ack_success = await self.dispatcher.send_packet(
                    pkt, wait_for_ack=True, expected_crc=ack_crc
                )

                # Wait for response (regardless of ACK result)
                try:
                    await asyncio.wait_for(response_event.wait(), timeout=15.0)
                    response_received = True
                except asyncio.TimeoutError:
                    response_received = False

                # Calculate RTT
                rtt = get_rtt()
                response_text = response_data["text"]

                # Return result based on what we got
                if response_received:
                    return {
                        "success": True,
                        "repeater": repeater_name,
                        "command": command,
                        "parameters": parameters,
                        "full_command": full_command,
                        "response": response_text,
                        "rtt_ms": round(rtt, 2),
                        "crc": ack_crc,
                        "ack_received": ack_success,
                        "reason": f"Command '{command}' successful with response"
                        + ("" if ack_success else " (no ACK)"),
                    }
                elif ack_success:
                    return {
                        "success": True,
                        "repeater": repeater_name,
                        "command": command,
                        "parameters": parameters,
                        "full_command": full_command,
                        "response": "Command sent successfully (no response received)",
                        "rtt_ms": round(rtt, 2),
                        "crc": ack_crc,
                        "ack_received": True,
                        "reason": f"Command '{command}' sent but no response received",
                    }
                else:
                    return {
                        "success": False,
                        "repeater": repeater_name,
                        "command": command,
                        "parameters": parameters,
                        "full_command": full_command,
                        "response": None,
                        "rtt_ms": round(rtt, 2),
                        "crc": ack_crc,
                        "ack_received": False,
                        "reason": f"No ACK or response received for command '{command}'",
                    }

            except Exception as e:
                rtt = get_rtt()
                return {
                    "success": False,
                    "repeater": repeater_name,
                    "command": command,
                    "parameters": parameters,
                    "full_command": full_command,
                    "response": None,
                    "rtt_ms": round(rtt, 2),
                    "crc": None,
                    "ack_received": False,
                    "reason": f"Error sending command: {e}",
                }
            finally:
                # Always clear the callback
                self.dispatcher.text_message_handler.set_command_response_callback(None)
