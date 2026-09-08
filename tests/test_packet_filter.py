import time

from openhop_core.protocol.packet_filter import PacketFilter, PacketHashCache


class TestPacketFilter:
    def test_packet_filter_initialization(self):
        """Test packet filter initialization with default and custom window."""
        # Default window
        pf = PacketFilter()
        assert pf.window_seconds == 30
        assert len(pf._packet_hashes) == 0
        assert len(pf._blacklist) == 0

        # Custom window
        pf_custom = PacketFilter(window_seconds=60)
        assert pf_custom.window_seconds == 60

    def test_generate_hash(self):
        """Test hash generation for packet data."""
        pf = PacketFilter()
        data = b"test_packet_data"
        hash1 = pf.generate_hash(data)
        hash2 = pf.generate_hash(data)

        # Same data should produce same hash
        assert hash1 == hash2
        assert len(hash1) == 16  # SHA256 truncated to 16 chars
        assert isinstance(hash1, str)

        # Different data should produce different hash
        different_data = b"different_packet"
        hash3 = pf.generate_hash(different_data)
        assert hash1 != hash3

    def test_duplicate_detection(self):
        """Test duplicate packet detection."""
        pf = PacketFilter(window_seconds=10)
        packet_hash = "test_hash_123"

        # Initially not a duplicate
        assert not pf.is_duplicate(packet_hash)

        # Track the packet
        pf.track_packet(packet_hash)

        # Now it should be detected as duplicate within window
        assert pf.is_duplicate(packet_hash)

        # Different hash should not be duplicate
        assert not pf.is_duplicate("different_hash")

    def test_duplicate_expiration(self):
        """Test that duplicates expire after window time."""
        pf = PacketFilter(window_seconds=1)  # 1 second window
        packet_hash = "test_hash_123"

        # Track packet
        pf.track_packet(packet_hash)
        assert pf.is_duplicate(packet_hash)

        # Wait for expiration
        time.sleep(1.1)

        # Should no longer be duplicate
        assert not pf.is_duplicate(packet_hash)

    def test_blacklist_functionality(self):
        """Test packet blacklisting."""
        pf = PacketFilter()
        packet_hash = "bad_packet_hash"

        # Initially not blacklisted
        assert not pf.is_blacklisted(packet_hash)

        # Add to blacklist
        pf.blacklist(packet_hash)

        # Now should be blacklisted
        assert pf.is_blacklisted(packet_hash)

        # Different hash should not be blacklisted
        assert not pf.is_blacklisted("good_packet_hash")

    def test_cleanup_old_hashes(self):
        """Test cleanup of old packet hashes."""
        pf = PacketFilter(window_seconds=1)

        # Track some packets
        pf.track_packet("hash1")
        pf.track_packet("hash2")

        assert len(pf._packet_hashes) == 2

        # Wait for expiration
        time.sleep(1.1)

        # Cleanup should remove old hashes
        pf.cleanup_old_hashes()
        assert len(pf._packet_hashes) == 0

    def test_get_stats(self):
        """Test statistics reporting."""
        pf = PacketFilter(window_seconds=45)

        # Add some data
        pf.track_packet("hash1")
        pf.track_packet("hash2")
        pf.blacklist("bad_hash1")
        pf.blacklist("bad_hash2")

        stats = pf.get_stats()

        assert stats["tracked_packets"] == 2
        assert stats["blacklisted_packets"] == 2
        assert stats["window_seconds"] == 45

    def test_clear_functionality(self):
        """Test clearing all tracked data."""
        pf = PacketFilter()

        # Add some data
        pf.track_packet("hash1")
        pf.blacklist("bad_hash")

        assert len(pf._packet_hashes) == 1
        assert len(pf._blacklist) == 1

        # Clear everything
        pf.clear()

        assert len(pf._packet_hashes) == 0
        assert len(pf._blacklist) == 0

    def test_edge_cases(self):
        """Test edge cases and error conditions."""
        pf = PacketFilter()

        # Empty data hash
        empty_hash = pf.generate_hash(b"")
        assert isinstance(empty_hash, str)
        assert len(empty_hash) == 16

        # Very large data hash
        large_data = b"x" * 10000
        large_hash = pf.generate_hash(large_data)
        assert isinstance(large_hash, str)
        assert len(large_hash) == 16

        # Test with zero window (should still work)
        pf_zero = PacketFilter(window_seconds=0)
        pf_zero.track_packet("hash1")
        # With zero window, should not be considered duplicate immediately
        assert not pf_zero.is_duplicate("hash1")

    def test_blacklist_cap_evicts_oldest(self):
        """Inserting past BLACKLIST_MAX_ENTRIES evicts the oldest entry (FIFO)."""
        pf = PacketFilter()
        cap = PacketFilter.BLACKLIST_MAX_ENTRIES

        for i in range(cap):
            pf.blacklist(f"hash_{i}")
        assert len(pf._blacklist) == cap
        assert pf.is_blacklisted("hash_0")

        # One more distinct entry pushes past the cap: oldest is evicted.
        pf.blacklist("hash_overflow")
        assert len(pf._blacklist) == cap
        assert not pf.is_blacklisted("hash_0")
        assert pf.is_blacklisted("hash_overflow")
        assert pf.is_blacklisted("hash_1")  # second-oldest survives

    def test_blacklist_cap_never_exceeded(self):
        """Size never exceeds the cap even with many more insertions than capacity."""
        pf = PacketFilter()
        cap = PacketFilter.BLACKLIST_MAX_ENTRIES

        for i in range(cap + 500):
            pf.blacklist(f"hash_{i}")
            assert len(pf._blacklist) <= cap
        assert len(pf._blacklist) == cap

    def test_blacklist_ttl_expiry(self, monkeypatch):
        """An entry older than the TTL reads as not-blacklisted before cleanup runs,
        and is actually removed once cleanup_old_hashes runs."""
        pf = PacketFilter()
        current = [1_000_000.0]
        monkeypatch.setattr(time, "time", lambda: current[0])

        pf.blacklist("stale_hash")
        assert pf.is_blacklisted("stale_hash")

        # Advance time past the TTL without running cleanup yet.
        current[0] += PacketFilter.BLACKLIST_TTL_SECONDS + 1
        assert not pf.is_blacklisted("stale_hash")
        # Still physically present until cleanup runs.
        assert "stale_hash" in pf._blacklist

        pf.cleanup_old_hashes()
        assert "stale_hash" not in pf._blacklist
        assert not pf.is_blacklisted("stale_hash")

    def test_is_blacklisted_does_not_mutate(self):
        """is_blacklisted is a pure read: no timestamp refresh, no size/order change."""
        pf = PacketFilter()
        pf.blacklist("hash_a")
        pf.blacklist("hash_b")

        before_items = list(pf._blacklist.items())
        for _ in range(5):
            pf.is_blacklisted("hash_a")
            pf.is_blacklisted("hash_b")
            pf.is_blacklisted("nonexistent")
        after_items = list(pf._blacklist.items())

        assert before_items == after_items
        assert len(pf._blacklist) == 2

    def test_reblacklisting_refreshes_timestamp_and_order(self, monkeypatch):
        """Re-blacklisting an existing entry updates its timestamp and moves it
        to the most-recently-inserted end."""
        pf = PacketFilter()
        current = [2_000_000.0]
        monkeypatch.setattr(time, "time", lambda: current[0])

        pf.blacklist("first")
        current[0] += 10
        pf.blacklist("second")
        assert list(pf._blacklist.keys()) == ["first", "second"]
        assert pf._blacklist["first"] == 2_000_000.0

        # Re-blacklist "first": timestamp refreshes and it becomes newest.
        current[0] += 10
        pf.blacklist("first")
        assert pf._blacklist["first"] == 2_000_020.0
        assert list(pf._blacklist.keys()) == ["second", "first"]

    def test_blacklist_basic_membership(self):
        """Basic membership still works after the TTL/cap rework."""
        pf = PacketFilter()
        assert not pf.is_blacklisted("some_hash")
        pf.blacklist("some_hash")
        assert pf.is_blacklisted("some_hash")
        assert not pf.is_blacklisted("other_hash")


class TestPacketHashCache:
    def test_uses_full_hash_keys(self):
        cache = PacketHashCache(ttl_seconds=60, max_entries=4)
        full_hash = "ab" * 32
        same_prefix_different_hash = "ab" * 8 + "cd" * 24

        assert cache.check_and_add(full_hash) is False
        assert cache.check_and_add(same_prefix_different_hash) is False
        assert cache.check_and_add(full_hash) is True

    def test_evicts_oldest_entry_at_capacity(self):
        cache = PacketHashCache(ttl_seconds=60, max_entries=2)

        assert cache.check_and_add("first") is False
        assert cache.check_and_add("second") is False
        assert cache.check_and_add("third") is False
        assert cache.check_and_add("first") is False

    def test_evicts_expired_entries_on_insert(self):
        cache = PacketHashCache(ttl_seconds=60, max_entries=4)
        cache._entries["expired"] = time.monotonic() - 61

        assert cache.check_and_add("fresh") is False
        assert list(cache._entries) == ["fresh"]

    def test_hit_refreshes_entry_lifetime(self):
        """Suppression extends while duplicates keep arriving: an entry near
        expiry that gets a hit survives past its original TTL."""
        cache = PacketHashCache(ttl_seconds=60, max_entries=4)
        cache._entries["echoing"] = time.monotonic() - 50  # 10 s of TTL left

        assert cache.check_and_add("echoing") is True
        # The hit reset the clock: backdating by the original remainder no
        # longer expires it.
        cache._entries["echoing"] -= 50
        assert cache.check_and_add("echoing") is True

    def test_entry_expires_after_quiet_ttl(self):
        cache = PacketHashCache(ttl_seconds=60, max_entries=4)
        assert cache.check_and_add("once") is False
        cache._entries["once"] = time.monotonic() - 61

        assert cache.check_and_add("once") is False  # expired -> fresh again

    def test_hit_refreshes_lru_position(self):
        """A refreshed entry moves to the back of the eviction order."""
        cache = PacketHashCache(ttl_seconds=60, max_entries=2)
        assert cache.check_and_add("first") is False
        assert cache.check_and_add("second") is False
        assert cache.check_and_add("first") is True  # refresh: now newest

        assert cache.check_and_add("third") is False  # evicts "second"
        assert cache.check_and_add("first") is True
        assert cache.check_and_add("second") is False
