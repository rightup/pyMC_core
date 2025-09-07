import asyncio
import logging

import pytest

from pymc_core.node.events import EventService, EventSubscriber, MeshEvents


class MockEventSubscriber(EventSubscriber):
    """Mock subscriber for testing."""

    def __init__(self):
        self.handled_events = []
        self.call_count = 0

    async def handle_event(self, event_type: str, data: dict) -> None:
        self.handled_events.append((event_type, data))
        self.call_count += 1


class FailingEventSubscriber(EventSubscriber):
    """Mock subscriber that raises exceptions."""

    async def handle_event(self, event_type: str, data: dict) -> None:
        raise Exception("Test exception")


# EventService tests
def test_event_service_initialization():
    """Test EventService initialization."""
    service = EventService()
    assert service._subscribers == {}
    assert service._global_subscribers == []
    assert service.logger is not None


def test_event_service_with_custom_logger():
    """Test EventService with custom logger."""
    custom_logger = logging.getLogger("test_logger")
    service = EventService(custom_logger)
    assert service.logger == custom_logger


def test_subscribe_to_event():
    """Test subscribing to a specific event type."""
    service = EventService()
    subscriber = MockEventSubscriber()

    service.subscribe("test.event", subscriber)

    assert "test.event" in service._subscribers
    assert subscriber in service._subscribers["test.event"]


def test_subscribe_all_events():
    """Test subscribing to all events (global subscriber)."""
    service = EventService()
    subscriber = MockEventSubscriber()

    service.subscribe_all(subscriber)

    assert subscriber in service._global_subscribers


def test_unsubscribe_from_event():
    """Test unsubscribing from a specific event type."""
    service = EventService()
    subscriber = MockEventSubscriber()

    service.subscribe("test.event", subscriber)
    assert subscriber in service._subscribers["test.event"]

    service.unsubscribe("test.event", subscriber)
    assert subscriber not in service._subscribers["test.event"]


def test_unsubscribe_nonexistent():
    """Test unsubscribing a subscriber that doesn't exist."""
    service = EventService()
    subscriber = MockEventSubscriber()

    # Should not raise an exception
    service.unsubscribe("test.event", subscriber)


def test_unsubscribe_all():
    """Test unsubscribing from all events."""
    service = EventService()
    subscriber = MockEventSubscriber()

    service.subscribe_all(subscriber)
    assert subscriber in service._global_subscribers

    service.unsubscribe_all(subscriber)
    assert subscriber not in service._global_subscribers


def test_unsubscribe_all_nonexistent():
    """Test unsubscribing a global subscriber that doesn't exist."""
    service = EventService()
    subscriber = MockEventSubscriber()

    # Should not raise an exception
    service.unsubscribe_all(subscriber)


@pytest.mark.asyncio
async def test_publish_event_to_specific_subscribers():
    """Test publishing an event to specific subscribers."""
    service = EventService()
    subscriber1 = MockEventSubscriber()
    subscriber2 = MockEventSubscriber()

    service.subscribe("test.event", subscriber1)
    service.subscribe("test.event", subscriber2)
    service.subscribe("other.event", subscriber1)  # Different event

    test_data = {"key": "value"}
    await service.publish("test.event", test_data)

    # Both subscribers should have received the event
    assert subscriber1.call_count == 1
    assert subscriber2.call_count == 1
    assert subscriber1.handled_events[0] == ("test.event", test_data)
    assert subscriber2.handled_events[0] == ("test.event", test_data)


@pytest.mark.asyncio
async def test_publish_event_to_global_subscribers():
    """Test publishing an event to global subscribers."""
    service = EventService()
    subscriber = MockEventSubscriber()

    service.subscribe_all(subscriber)

    test_data = {"key": "value"}
    await service.publish("test.event", test_data)

    assert subscriber.call_count == 1
    assert subscriber.handled_events[0] == ("test.event", test_data)


@pytest.mark.asyncio
async def test_publish_event_no_subscribers():
    """Test publishing an event when no subscribers are registered."""
    service = EventService()

    # Should not raise an exception
    await service.publish("test.event", {"key": "value"})


@pytest.mark.asyncio
async def test_publish_event_with_failing_subscriber():
    """Test publishing an event when a subscriber raises an exception."""
    service = EventService()
    good_subscriber = MockEventSubscriber()
    failing_subscriber = FailingEventSubscriber()

    service.subscribe("test.event", good_subscriber)
    service.subscribe("test.event", failing_subscriber)

    test_data = {"key": "value"}
    await service.publish("test.event", test_data)

    # Good subscriber should still receive the event
    assert good_subscriber.call_count == 1
    assert good_subscriber.handled_events[0] == ("test.event", test_data)


@pytest.mark.asyncio
async def test_publish_event_with_failing_global_subscriber():
    """Test publishing an event when a global subscriber raises an exception."""
    service = EventService()
    good_subscriber = MockEventSubscriber()
    failing_subscriber = FailingEventSubscriber()

    service.subscribe("test.event", good_subscriber)
    service.subscribe_all(failing_subscriber)

    test_data = {"key": "value"}
    await service.publish("test.event", test_data)

    # Good subscriber should still receive the event
    assert good_subscriber.call_count == 1
    assert good_subscriber.handled_events[0] == ("test.event", test_data)


@pytest.mark.asyncio
async def test_publish_sync():
    """Test synchronous event publishing."""
    service = EventService()
    subscriber = MockEventSubscriber()
    service.subscribe("test.event", subscriber)

    test_data = {"key": "value"}
    service.publish_sync("test.event", test_data)

    # Give the async task a moment to complete
    await asyncio.sleep(0.01)

    assert subscriber.call_count == 1
    assert subscriber.handled_events[0] == ("test.event", test_data)


# MeshEvents tests
def test_mesh_events_constants():
    """Test that MeshEvents constants are properly defined."""
    assert MeshEvents.NEW_CONTACT == "mesh.contact.new"
    assert MeshEvents.CONTACT_UPDATED == "mesh.contact.updated"
    assert MeshEvents.NEW_MESSAGE == "mesh.message.new"
    assert MeshEvents.MESSAGE_READ == "mesh.message.read"
    assert MeshEvents.UNREAD_COUNT_CHANGED == "mesh.message.unread_count_changed"
    assert MeshEvents.NEW_CHANNEL_MESSAGE == "mesh.channel.message.new"
    assert MeshEvents.CHANNEL_UPDATED == "mesh.channel.updated"
    assert MeshEvents.NODE_DISCOVERED == "mesh.network.node_discovered"
    assert MeshEvents.SIGNAL_STRENGTH_UPDATED == "mesh.network.signal_updated"
    assert MeshEvents.NODE_STARTED == "mesh.system.node_started"
    assert MeshEvents.NODE_STOPPED == "mesh.system.node_stopped"
    assert MeshEvents.TELEMETRY_UPDATED == "mesh.system.telemetry_updated"


# Integration tests
@pytest.mark.asyncio
async def test_event_service_integration():
    """Test a complete event service workflow."""
    service = EventService()

    # Create multiple subscribers
    contact_subscriber = MockEventSubscriber()
    message_subscriber = MockEventSubscriber()
    global_subscriber = MockEventSubscriber()

    # Subscribe to specific events
    service.subscribe(MeshEvents.NEW_CONTACT, contact_subscriber)
    service.subscribe(MeshEvents.NEW_MESSAGE, message_subscriber)

    # Subscribe to all events
    service.subscribe_all(global_subscriber)

    # Publish different events
    contact_data = {"contact_id": "123", "name": "Alice"}
    message_data = {"message_id": "456", "content": "Hello"}

    await service.publish(MeshEvents.NEW_CONTACT, contact_data)
    await service.publish(MeshEvents.NEW_MESSAGE, message_data)
    await service.publish(MeshEvents.NODE_STARTED, {"status": "online"})

    # Verify subscribers received correct events
    assert contact_subscriber.call_count == 1
    assert message_subscriber.call_count == 1
    assert global_subscriber.call_count == 3

    # Verify event data
    assert contact_subscriber.handled_events[0] == (
        MeshEvents.NEW_CONTACT,
        contact_data,
    )
    assert message_subscriber.handled_events[0] == (
        MeshEvents.NEW_MESSAGE,
        message_data,
    )

    # Global subscriber should have received all events
    expected_events = [
        (MeshEvents.NEW_CONTACT, contact_data),
        (MeshEvents.NEW_MESSAGE, message_data),
        (MeshEvents.NODE_STARTED, {"status": "online"}),
    ]
    assert global_subscriber.handled_events == expected_events
