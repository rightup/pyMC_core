from pymc_core.protocol import Packet


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
