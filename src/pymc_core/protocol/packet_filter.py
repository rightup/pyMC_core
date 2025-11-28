"""MeshCore-aligned packet filter used by the dispatcher.

Matches firmware heuristics by:
- Keeping a bounded pool of recent packet hashes for duplicate detection.
- Tracking a timed blacklist so malformed packets eventually expire.
- Providing a delayed-queue helper so callers can avoid reprocessing floods
    that are already waiting for their score-based holdoff window.
"""

import hashlib
import time
from collections import OrderedDict
from typing import MutableMapping


class PacketFilter:
    """Stateful packet filter mirroring MeshCore's inbound manager heuristics."""

    def __init__(
        self,
        window_seconds: int = 45,
        *,
        blacklist_duration: int = 180,
        max_tracked_packets: int = 4096,
        max_blacklist_size: int = 512,
        max_delayed_packets: int = 512,
    ):
        self.window_seconds = max(0, window_seconds)
        self.blacklist_duration = max(1, blacklist_duration)
        self.max_tracked_packets = max(1, max_tracked_packets)
        self.max_blacklist_size = max(1, max_blacklist_size)
        self.max_delayed_packets = max(1, max_delayed_packets)

        self._packet_hashes: MutableMapping[str, float] = OrderedDict()
        self._blacklist: MutableMapping[str, float] = OrderedDict()
        self._delayed_packets: MutableMapping[str, float] = OrderedDict()

    def generate_hash(self, data: bytes) -> str:
        """Generate a hash for packet data."""
        return hashlib.sha256(data).hexdigest()[:16]

    def is_duplicate(self, packet_hash: str) -> bool:
        """Check if we've seen this packet recently."""
        if self.window_seconds == 0:
            # Deduplication disabled - always treat as new packet.
            self._packet_hashes.pop(packet_hash, None)
            return False

        now = time.time()
        timestamp = self._packet_hashes.get(packet_hash)
        if timestamp is None:
            return False

        if (now - timestamp) >= self.window_seconds:
            # Entry aged out – drop from pool and treat as new.
            self._packet_hashes.pop(packet_hash, None)
            return False

        return True

    def track_packet(self, packet_hash: str) -> None:
        """Track a packet hash with current timestamp."""
        now = time.time()
        self._packet_hashes[packet_hash] = now
        # Maintain insertion order so we can evict the oldest hashes first.
        if isinstance(self._packet_hashes, OrderedDict):
            self._packet_hashes.move_to_end(packet_hash)
        self._evict_old_packets(now)

    def blacklist(self, packet_hash: str) -> None:
        """Add a packet hash to the blacklist."""
        expiry = time.time() + self.blacklist_duration
        self._blacklist[packet_hash] = expiry
        if isinstance(self._blacklist, OrderedDict):
            self._blacklist.move_to_end(packet_hash)
        self._evict_old_blacklist_entries(time.time())

    def is_blacklisted(self, packet_hash: str) -> bool:
        """Check if a packet hash is blacklisted."""
        expiry = self._blacklist.get(packet_hash)
        if expiry is None:
            return False
        if time.time() >= expiry:
            self._blacklist.pop(packet_hash, None)
            return False
        return True

    def schedule_delay(self, packet_hash: str, delay_seconds: float) -> None:
        """Register that a packet is being delayed before processing."""

        expiry = time.time() + max(0.0, delay_seconds)
        self._delayed_packets[packet_hash] = expiry
        if isinstance(self._delayed_packets, OrderedDict):
            self._delayed_packets.move_to_end(packet_hash)
        self._evict_old_delays(time.time())

    def is_delay_active(self, packet_hash: str) -> bool:
        """Return True if a packet is currently waiting in the delayed queue."""

        expiry = self._delayed_packets.get(packet_hash)
        if expiry is None:
            return False
        if time.time() >= expiry:
            self._delayed_packets.pop(packet_hash, None)
            return False
        return True

    def cleanup_old_hashes(self) -> None:
        """Clean up old packet hashes beyond the deduplication window."""
        current_time = time.time()
        self._evict_old_packets(current_time)
        self._evict_old_blacklist_entries(current_time)
        self._evict_old_delays(current_time)

    def get_stats(self) -> dict:
        """Get basic filter statistics."""
        return {
            "tracked_packets": len(self._packet_hashes),
            "blacklisted_packets": len(self._blacklist),
            "delayed_packets": len(self._delayed_packets),
            "window_seconds": self.window_seconds,
            "blacklist_duration": self.blacklist_duration,
        }

    def clear(self) -> None:
        """Clear all tracked data."""
        self._packet_hashes.clear()
        self._blacklist.clear()
        self._delayed_packets.clear()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evict_old_packets(self, now: float) -> None:
        if not self._packet_hashes:
            return
        cutoff = now - self.window_seconds if self.window_seconds else None
        keys_to_remove = []
        for packet_hash, ts in self._packet_hashes.items():
            if cutoff is not None and ts < cutoff:
                keys_to_remove.append(packet_hash)
            elif len(self._packet_hashes) - len(keys_to_remove) > self.max_tracked_packets:
                keys_to_remove.append(packet_hash)
            else:
                # OrderedDict is chronological; break when remaining entries are recent.
                if cutoff is not None and ts >= cutoff:
                    break
        for key in keys_to_remove:
            self._packet_hashes.pop(key, None)

        # Trim if still above cap (window might be 0 -> no cutoff)
        while len(self._packet_hashes) > self.max_tracked_packets:
            self._packet_hashes.popitem(last=False)

    def _evict_old_blacklist_entries(self, now: float) -> None:
        if not self._blacklist:
            return
        keys_to_remove = []
        for packet_hash, expiry in self._blacklist.items():
            if expiry <= now or len(self._blacklist) - len(keys_to_remove) > self.max_blacklist_size:
                keys_to_remove.append(packet_hash)
            else:
                break
        for key in keys_to_remove:
            self._blacklist.pop(key, None)

        while len(self._blacklist) > self.max_blacklist_size:
            self._blacklist.popitem(last=False)

    def _evict_old_delays(self, now: float) -> None:
        if not self._delayed_packets:
            return
        keys_to_remove = []
        for packet_hash, expiry in self._delayed_packets.items():
            if expiry <= now or len(self._delayed_packets) - len(keys_to_remove) > self.max_delayed_packets:
                keys_to_remove.append(packet_hash)
            else:
                break
        for key in keys_to_remove:
            self._delayed_packets.pop(key, None)

        while len(self._delayed_packets) > self.max_delayed_packets:
            self._delayed_packets.popitem(last=False)
