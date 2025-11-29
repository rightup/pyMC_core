import hashlib
import struct

from pymc_core.protocol import Packet
from pymc_core.protocol.constants import (
    MAX_HASH_SIZE,
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_ANON_REQ,
    PAYLOAD_TYPE_CONTROL,
    PAYLOAD_TYPE_GRP_DATA,
    PAYLOAD_TYPE_GRP_TXT,
    PAYLOAD_TYPE_MULTIPART,
    PAYLOAD_TYPE_PATH,
    PAYLOAD_TYPE_RAW_CUSTOM,
    PAYLOAD_TYPE_REQ,
    PAYLOAD_TYPE_RESPONSE,
    PAYLOAD_TYPE_TRACE,
    PAYLOAD_TYPE_TXT_MSG,
    PH_ROUTE_MASK,
    PH_TYPE_MASK,
    PH_TYPE_SHIFT,
    PH_VER_MASK,
    PH_VER_SHIFT,
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_DIRECT,
    ROUTE_TYPE_TRANSPORT_FLOOD,
)
from pymc_core.protocol.packet_utils import PacketHashingUtils
from pymc_core.protocol.utils import PAYLOAD_TYPES as PAYLOAD_TYPE_NAMES, ROUTE_TYPES as ROUTE_TYPE_NAMES


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


def test_transport_packet_round_trip_serialization():
    """Transport packets must encode/decode transport codes in little-endian order."""
    packet = Packet()
    packet.header = ROUTE_TYPE_TRANSPORT_FLOOD  # payload/ver bits left as zero
    packet.transport_codes = [0x1234, 0xBEEF]
    packet.path = bytearray(b"\xAA\xBB")
    packet.path_len = len(packet.path)
    packet.payload = bytearray(b"\x01\x02\x03")
    packet.payload_len = len(packet.payload)

    serialized = packet.write_to()
    expected_prefix = bytes([
        ROUTE_TYPE_TRANSPORT_FLOOD,
        0x34,
        0x12,
        0xEF,
        0xBE,
        packet.path_len,
    ])
    assert serialized.startswith(expected_prefix)

    decoded = Packet()
    assert decoded.read_from(serialized)
    assert decoded.transport_codes == [0x1234, 0xBEEF]
    assert decoded.path == packet.path
    assert decoded.payload == packet.payload


def test_non_transport_packet_round_trip_zeroes_transport_codes():
    """Packets without transport routes must not emit leftover transport codes."""
    packet = Packet()
    packet.header = ROUTE_TYPE_FLOOD
    packet.transport_codes = [0xFFFF, 0xABCD]  # should be ignored when serialized
    packet.path = bytearray(b"\xCC")
    packet.path_len = len(packet.path)
    packet.payload = bytearray(b"\x99")
    packet.payload_len = len(packet.payload)

    serialized = packet.write_to()
    assert serialized == bytes([ROUTE_TYPE_FLOOD, packet.path_len, *packet.path, *packet.payload])

    decoded = Packet()
    assert decoded.read_from(serialized)
    assert decoded.transport_codes == [0, 0]


def test_mark_do_not_retransmit_matches_meshcore_header_sentinel():
    """Marking a packet for no retransmission must clobber the header to 0xFF like MeshCore."""
    packet = Packet()
    packet.header = ROUTE_TYPE_FLOOD
    assert not packet.is_marked_do_not_retransmit()

    packet.mark_do_not_retransmit()
    assert packet.header == 0xFF
    assert packet.is_marked_do_not_retransmit()


def test_header_bitfield_constants_match_meshcore_spec():
    """Header masks/shifts must match mesh::Packet bit layout."""
    assert PH_ROUTE_MASK == 0x03
    assert PH_TYPE_MASK == 0x0F
    assert PH_VER_MASK == 0x03
    assert PH_TYPE_SHIFT == 2
    assert PH_VER_SHIFT == 6


def test_route_type_values_match_meshcore_spec():
    """Route type constants and lookup table must remain aligned with firmware."""
    expected_values = {
        "TRANSPORT_FLOOD": 0x00,
        "FLOOD": 0x01,
        "DIRECT": 0x02,
        "TRANSPORT_DIRECT": 0x03,
    }
    assert ROUTE_TYPE_TRANSPORT_FLOOD == expected_values["TRANSPORT_FLOOD"]
    assert ROUTE_TYPE_FLOOD == expected_values["FLOOD"]
    assert ROUTE_TYPE_DIRECT == expected_values["DIRECT"]
    assert ROUTE_TYPE_TRANSPORT_DIRECT == expected_values["TRANSPORT_DIRECT"]
    assert ROUTE_TYPE_NAMES == {value: name for name, value in expected_values.items()}


def test_payload_type_values_match_meshcore_spec():
    """Payload type constants and names should cover MeshCore assignments."""
    expected_payloads = {
        0x00: (PAYLOAD_TYPE_REQ, "REQ"),
        0x01: (PAYLOAD_TYPE_RESPONSE, "RESPONSE"),
        0x02: (PAYLOAD_TYPE_TXT_MSG, "TXT_MSG"),
        0x03: (PAYLOAD_TYPE_ACK, "ACK"),
        0x04: (PAYLOAD_TYPE_ADVERT, "ADVERT"),
        0x05: (PAYLOAD_TYPE_GRP_TXT, "GRP_TXT"),
        0x06: (PAYLOAD_TYPE_GRP_DATA, "GRP_DATA"),
        0x07: (PAYLOAD_TYPE_ANON_REQ, "ANON_REQ"),
        0x08: (PAYLOAD_TYPE_PATH, "PATH"),
        0x09: (PAYLOAD_TYPE_TRACE, "TRACE"),
        0x0A: (PAYLOAD_TYPE_MULTIPART, "MULTIPART"),
        0x0B: (PAYLOAD_TYPE_CONTROL, "CONTROL"),
        0x0F: (PAYLOAD_TYPE_RAW_CUSTOM, "RAW_CUSTOM"),
    }

    for numeric_value, (constant_value, name) in expected_payloads.items():
        assert constant_value == numeric_value
        assert PAYLOAD_TYPE_NAMES[numeric_value] == name

