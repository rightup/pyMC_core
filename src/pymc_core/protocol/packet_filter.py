"""
Simple packet filter for dispatcher-level routing decisions.

This handles only the essential routing concerns:
- Duplicate detection
- Packet blacklisting for malformed packets
- Basic packet hash tracking
"""

import hashlib
import time
from typing import Dict, Set


class PacketFilter:
    """Lightweight packet filter for dispatcher routing decisions."""

    def __init__(self, window_seconds: int = 30):
        self.window_seconds = window_seconds
        self._packet_hashes: Dict[str, float] = {}  # packet_hash -> timestamp
        self._blacklist: Set[str] = set()  # blacklisted packet hashes

    def generate_hash(self, data: bytes) -> str:
        """Generate a hash for packet data."""
        return hashlib.sha256(data).hexdigest()[:16]

    def is_duplicate(self, packet_hash: str) -> bool:
        """Check if we've seen this packet recently."""
        now = time.time()
        if packet_hash in self._packet_hashes:
            age = now - self._packet_hashes[packet_hash]
            if age < self.window_seconds:
                return True
        return False

    def track_packet(self, packet_hash: str) -> None:
        """Track a packet hash with current timestamp."""
        self._packet_hashes[packet_hash] = time.time()

    def blacklist(self, packet_hash: str) -> None:
        """Add a packet hash to the blacklist."""
        self._blacklist.add(packet_hash)

    def is_blacklisted(self, packet_hash: str) -> bool:
        """Check if a packet hash is blacklisted."""
        return packet_hash in self._blacklist

    def cleanup_old_hashes(self) -> None:
        """Clean up old packet hashes beyond the deduplication window."""
        current_time = time.time()
        old_hashes = [
            h for h, ts in self._packet_hashes.items() if current_time - ts > self.window_seconds
        ]
        for h in old_hashes:
            del self._packet_hashes[h]

    def get_stats(self) -> dict:
        """Get basic filter statistics."""
        return {
            "tracked_packets": len(self._packet_hashes),
            "blacklisted_packets": len(self._blacklist),
            "window_seconds": self.window_seconds,
        }

    def clear(self) -> None:
        """Clear all tracked data."""
        self._packet_hashes.clear()
        self._blacklist.clear()
