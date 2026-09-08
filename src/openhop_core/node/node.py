from __future__ import annotations

import collections
import collections.abc
import logging
from typing import Any, Optional

# Fix for Python 3.10+ compatibility with PyYAML
if "Hashable" not in collections.__dict__:
    setattr(collections, "Hashable", collections.abc.Hashable)

from ..protocol import LocalIdentity
from .dispatcher import Dispatcher

logger = logging.getLogger("Node")


class MeshNode:
    """Thin transport layer for mesh radio communication.

    Owns a radio interface and a :class:`Dispatcher` that handles raw packet
    I/O (TX lock, ACK management, handler dispatch).  Application-layer
    concerns — contact lookup, message building, response waiting — belong in
    the companion layer (:class:`CompanionBase` and its subclasses).

    Typical usage::

        node = MeshNode(radio, identity, config={...})
        task = asyncio.create_task(node.start())  # blocks in dispatcher.run_forever()
        ...
        await node.stop()
        await task
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

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    async def start(self) -> None:
        """Start the mesh node and begin processing radio communications.

        Enters the dispatcher's main event loop for handling incoming/outgoing
        messages.  This method blocks until the node is stopped via
        :meth:`stop` (typically called from another task).
        """
        await self.dispatcher.run_forever()

    async def stop(self) -> None:
        """Stop the mesh node: disarm RX and exit the dispatcher loop.

        Does not close the radio; the caller owns hardware lifecycle.
        Idempotent. In-flight packet tasks are not cancelled.
        """
        try:
            await self.dispatcher.stop()
            self.logger.info("Node stopped")
        except Exception as e:
            self.logger.error(f"Error stopping node: {e}")
            raise

    # -------------------------------------------------------------------------
    # Transport
    # -------------------------------------------------------------------------

    async def send_packet(self, pkt: Any, *, wait_for_ack: bool = False, **kwargs) -> bool:
        """Send a raw packet via the dispatcher.

        This is the single transport entry point.  All message-building and
        response-waiting logic lives in the companion layer.
        """
        return await self.dispatcher.send_packet(pkt, wait_for_ack=wait_for_ack, **kwargs)

    # -------------------------------------------------------------------------
    # Event service propagation
    # -------------------------------------------------------------------------

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
