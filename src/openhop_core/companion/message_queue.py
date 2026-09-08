"""Fixed-size offline message queue for companion radio."""

from __future__ import annotations

from collections import deque
from typing import Optional

from .constants import DEFAULT_OFFLINE_QUEUE_SIZE
from .models import QueuedMessage


class MessageQueue:
    """Fixed-size offline message queue (FIFO).

    Stores incoming messages that arrive when no consumer is actively
    reading. Matches the firmware's offline_queue behaviour with a
    configurable maximum size. When full, the oldest channel message is
    evicted; direct messages are never displaced by another queue entry.
    """

    def __init__(self, max_size: int = DEFAULT_OFFLINE_QUEUE_SIZE):
        # Eviction is explicit in ``push`` because deque(maxlen=...) would
        # silently discard the oldest message even when it is a direct one.
        self._queue: deque[QueuedMessage] = deque()
        self._max_size = max_size

    @property
    def max_size(self) -> int:
        """Maximum number of messages retained (zero disables storage)."""
        return self._max_size

    def push(self, msg: QueuedMessage) -> bool:
        """Add a message to the queue using MeshCore's protected eviction rule.

        At capacity, remove the oldest channel message and append ``msg``. If
        every retained message is direct, retain them all and reject ``msg``.
        Returns whether ``msg`` was queued.
        """
        if self._max_size <= 0:
            return False
        if len(self._queue) >= self._max_size:
            for index, queued in enumerate(self._queue):
                if queued.is_channel:
                    del self._queue[index]
                    break
            else:
                return False
        self._queue.append(msg)
        return True

    def pop(self) -> Optional[QueuedMessage]:
        """Remove and return the oldest message, or None if empty."""
        if self._queue:
            return self._queue.popleft()
        return None

    def pop_last(self) -> Optional[QueuedMessage]:
        """Remove and return the most recently pushed message, or None if empty."""
        if self._queue:
            return self._queue.pop()
        return None

    def remove(self, msg: QueuedMessage) -> bool:
        """Remove a specific entry from the queue by identity (``is``).

        Used by persistence layers to remove exactly the entry they persisted,
        immune to interleaved pushes that reorder the queue. Returns True if the
        entry was found and removed, False otherwise.
        """
        for index, queued in enumerate(self._queue):
            if queued is msg:
                del self._queue[index]
                return True
        return False

    def peek(self) -> Optional[QueuedMessage]:
        """Return the oldest message without removing it, or None if empty."""
        if self._queue:
            return self._queue[0]
        return None

    def is_empty(self) -> bool:
        """Check if the queue has no messages."""
        return len(self._queue) == 0

    def is_full(self) -> bool:
        """Check if the queue is at capacity."""
        return len(self._queue) >= self._max_size

    @property
    def count(self) -> int:
        """Return the number of messages in the queue."""
        return len(self._queue)

    def clear(self) -> None:
        """Remove all messages from the queue."""
        self._queue.clear()
