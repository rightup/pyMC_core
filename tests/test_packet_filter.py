import time

from pymc_core.protocol.packet_filter import PacketFilter


class TestPacketFilter:
    def test_packet_filter_initialization(self):
        """Test packet filter initialization with default and custom window."""
        # Default window
        pf = PacketFilter()
        assert pf.window_seconds == 45
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

    def test_blacklist_expiration(self):
        pf = PacketFilter(blacklist_duration=1)
        packet_hash = "bad_hash"

        pf.blacklist(packet_hash)
        assert pf.is_blacklisted(packet_hash)

        time.sleep(1.1)
        assert not pf.is_blacklisted(packet_hash)

    def test_tracked_packet_pool_is_bounded(self):
        pf = PacketFilter(window_seconds=60, max_tracked_packets=2)

        pf.track_packet("hash1")
        pf.track_packet("hash2")
        pf.track_packet("hash3")

        assert "hash1" not in pf._packet_hashes
        assert "hash2" in pf._packet_hashes
        assert "hash3" in pf._packet_hashes

    def test_blacklist_pool_is_bounded(self):
        pf = PacketFilter(max_blacklist_size=2, blacklist_duration=60)

        pf.blacklist("hash1")
        pf.blacklist("hash2")
        pf.blacklist("hash3")

        assert "hash1" not in pf._blacklist
        assert len(pf._blacklist) == 2

    def test_delay_queue_helpers(self):
        pf = PacketFilter()
        packet_hash = "delayed"

        pf.schedule_delay(packet_hash, delay_seconds=0.2)
        assert pf.is_delay_active(packet_hash)

        time.sleep(0.25)
        assert not pf.is_delay_active(packet_hash)

    def test_cleanup_prunes_all_structures(self):
        pf = PacketFilter(window_seconds=1, blacklist_duration=1)
        pf.track_packet("hash1")
        pf.blacklist("hash2")
        pf.schedule_delay("hash3", delay_seconds=0.5)

        time.sleep(1.1)
        pf.cleanup_old_hashes()

        assert len(pf._packet_hashes) == 0
        assert len(pf._blacklist) == 0
        assert len(pf._delayed_packets) == 0
