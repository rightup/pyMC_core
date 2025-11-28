import hashlib
import struct

from pymc_core.protocol import Packet
from pymc_core.protocol.constants import MAX_HASH_SIZE, PAYLOAD_TYPE_RESPONSE, PAYLOAD_TYPE_TRACE
from pymc_core.protocol.packet_utils import PacketHashingUtils


# Packet tests
def test_packet_creation():
    """Test basic packet creation and properties."""
    packet = Packet()
    assert packet is not None

    # Test header manipulation
    packet.header = 0x12
    assert packet.get_payload_type() == 4  # 0x12 >> 2 = 4 (bits 2-5: 0100)
    assert packet.get_route_type() == 2  # 0x12 & 0x03 = 2 (bits 0-1: 10)

    # Test payload
    test_payload = b"Hello, World!"
    packet.payload = bytearray(test_payload)
    packet.payload_len = len(test_payload)
    assert packet.get_payload() == test_payload


def test_packet_validation():
    """Test packet validation."""
    packet = Packet()
    packet.header = 0x12
    packet.payload = bytearray(b"test")
    packet.payload_len = 4

    # Should validate successfully
    packet._validate_lengths()


def test_trace_packet_hash_matches_meshcore_reference():
    """TRACE packet hashes must include the two-byte path_len like MeshCore."""
    payload = bytes(range(32))
    path_len = 0x0102  # ensure both low/high bytes are exercised
    expected = hashlib.sha256(
        bytes([PAYLOAD_TYPE_TRACE]) + struct.pack("<H", path_len) + payload
    ).digest()[:MAX_HASH_SIZE]

    actual = PacketHashingUtils.calculate_packet_hash(PAYLOAD_TYPE_TRACE, path_len, payload)
    assert actual == expected

    expected_crc = int.from_bytes(expected[:4], "little")
    assert PacketHashingUtils.calculate_crc(PAYLOAD_TYPE_TRACE, path_len, payload) == expected_crc


def test_non_trace_packet_hash_skips_path_len():
    """Non-TRACE packet hashes must not mix in path_len bytes."""
    payload = b"payload"
    path_len = 999  # should be ignored
    expected = hashlib.sha256(bytes([PAYLOAD_TYPE_RESPONSE]) + payload).digest()[:MAX_HASH_SIZE]

    actual = PacketHashingUtils.calculate_packet_hash(PAYLOAD_TYPE_RESPONSE, path_len, payload)
    assert actual == expected
