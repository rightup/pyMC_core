"""
Generic event broadcasting service for mesh library.
Provides a clean abstraction layer for notifying multiple subscribers about mesh events.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class EventSubscriber(ABC):
    """Abstract base class for event subscribers."""

    @abstractmethod
    async def handle_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Handle an event with the given type and data."""
        pass


class EventService:
    """
    Generic event broadcasting service for the mesh library.
    Allows multiple subscribers to listen for different types of events.
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger("MeshEventService")
        self._subscribers: Dict[str, List[EventSubscriber]] = {}
        self._global_subscribers: List[EventSubscriber] = []

    def subscribe(self, event_type: str, subscriber: EventSubscriber) -> None:
        """Subscribe to a specific event type."""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(subscriber)
        self.logger.debug(f"Subscribed {subscriber.__class__.__name__} to {event_type}")

    def subscribe_all(self, subscriber: EventSubscriber) -> None:
        """Subscribe to all events (global subscriber)."""
        self._global_subscribers.append(subscriber)
        self.logger.debug(f"Added global subscriber {subscriber.__class__.__name__}")

    def unsubscribe(self, event_type: str, subscriber: EventSubscriber) -> None:
        """Unsubscribe from a specific event type."""
        if event_type in self._subscribers:
            try:
                self._subscribers[event_type].remove(subscriber)
                self.logger.debug(f"Unsubscribed {subscriber.__class__.__name__} from {event_type}")
            except ValueError:
                pass

    def unsubscribe_all(self, subscriber: EventSubscriber) -> None:
        """Unsubscribe from all events."""
        try:
            self._global_subscribers.remove(subscriber)
            self.logger.debug(f"Removed global subscriber {subscriber.__class__.__name__}")
        except ValueError:
            pass

    async def publish(self, event_type: str, data: Dict[str, Any]) -> None:
        """Publish an event to all subscribers."""
        self.logger.debug(f"Publishing event: {event_type}")

        # Notify specific subscribers
        if event_type in self._subscribers:
            for subscriber in self._subscribers[event_type]:
                try:
                    await subscriber.handle_event(event_type, data)
                except Exception as e:
                    self.logger.error(f"Error in subscriber {subscriber.__class__.__name__}: {e}")

        # Notify global subscribers
        for subscriber in self._global_subscribers:
            try:
                await subscriber.handle_event(event_type, data)
            except Exception as e:
                self.logger.error(
                    f"Error in global subscriber {subscriber.__class__.__name__}: {e}"
                )

    def publish_sync(self, event_type: str, data: Dict[str, Any]) -> None:
        """Publish an event synchronously (creates async task)."""
        asyncio.create_task(self.publish(event_type, data))


# Example logging subscriber for debugging
class LoggingEventSubscriber(EventSubscriber):
    """Logs all mesh events for debugging/audit purposes."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger("MeshEventLogger")

    async def handle_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Log the event details."""
        self.logger.info(f"Mesh Event: {event_type} - {data}")
