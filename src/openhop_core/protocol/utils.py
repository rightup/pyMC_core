"""
Centralized protocol utility functions and lookup tables for mesh network.
"""

import hashlib

from .constants import (
    ADVERT_FLAG_HAS_FEATURE1,
    ADVERT_FLAG_HAS_FEATURE2,
    ADVERT_FLAG_HAS_LOCATION,
    ADVERT_FLAG_HAS_NAME,
    ADVERT_FLAG_IS_CHAT_NODE,
    ADVERT_FLAG_IS_REPEATER,
    ADVERT_FLAG_IS_ROOM_SERVER,
    ADVERT_FLAG_IS_SENSOR,
    PH_ROUTE_MASK,
    PH_TYPE_MASK,
    PH_TYPE_SHIFT,
    PUB_KEY_SIZE,
    SIGNATURE_SIZE,
    TIMESTAMP_SIZE,
)

# Lookup tables
APPDATA_FLAGS = {
    0x01: "is_chat_node",
    0x02: "is_repeater",
    0x04: "is_room_server",
    0x10: "has_location",
    0x20: "has_feature_1",
    0x40: "has_feature_2",
    0x80: "has_name",
}

REQUEST_TYPES = {0x01: "get_status", 0x02: "keepalive", 0x03: "get_telemetry_data"}
TEXT_FLAGS = {
    0x00: "plain_text_message",
    0x01: "cli_command",
    0x02: "signed_plain_text_message",
}
ROUTE_TYPES = {
    0x00: "TRANSPORT_FLOOD",
    0x01: "FLOOD",
    0x02: "DIRECT",
    0x03: "TRANSPORT_DIRECT",
}
PAYLOAD_TYPES = {
    0x00: "REQ",
    0x01: "RESPONSE",
    0x02: "TXT_MSG",
    0x03: "ACK",
    0x04: "ADVERT",
    0x05: "GRP_TXT",
    0x06: "GRP_DATA",
    0x07: "ANON_REQ",
    0x08: "PATH",
    0x09: "TRACE",
    0x0A: "MULTIPART",
    0x0B: "CONTROL",
    0x0F: "RAW_CUSTOM",
}

# Utility functions


def describe_advert_flags(flags: int) -> str:
    labels = []
    if flags & ADVERT_FLAG_IS_CHAT_NODE:
        labels.append("is chat node")
    if flags & ADVERT_FLAG_IS_REPEATER:
        labels.append("is repeater")
    if flags & ADVERT_FLAG_IS_ROOM_SERVER:
        labels.append("is room server")
    if flags & ADVERT_FLAG_IS_SENSOR:
        labels.append("is sensor")
    if flags & ADVERT_FLAG_HAS_LOCATION:
        labels.append("has location")
    if flags & ADVERT_FLAG_HAS_FEATURE1:
        labels.append("has feature 1")
    if flags & ADVERT_FLAG_HAS_FEATURE2:
        labels.append("has feature 2")
    if flags & ADVERT_FLAG_HAS_NAME:
        labels.append("has name")
    return ", ".join(labels) or "none"


def parse_advert_payload(payload: bytes):
    min_len = PUB_KEY_SIZE + TIMESTAMP_SIZE + SIGNATURE_SIZE
    if len(payload) < min_len:
        raise ValueError(
            f"Advert payload too short: {len(payload)} bytes (minimum expected: {min_len})"
        )
    pubkey = payload[:PUB_KEY_SIZE]
    timestamp = int.from_bytes(payload[PUB_KEY_SIZE : PUB_KEY_SIZE + TIMESTAMP_SIZE], "little")
    sig_start = PUB_KEY_SIZE + TIMESTAMP_SIZE
    signature = payload[sig_start : sig_start + SIGNATURE_SIZE]
    appdata = payload[sig_start + SIGNATURE_SIZE :]
    return {
        "pubkey": pubkey.hex(),
        "timestamp": timestamp,
        "signature": signature.hex(),
        "appdata": appdata,
    }


def is_self_advert(payload: bytes, self_public_key: bytes) -> bool:
    """Return True when an ADVERT payload carries our own public key.

    Mesh::onRecvPacket tests ``self_id.matches(id.pub_key)`` in its ADVERT
    branch before wasSeen() and before signature verification (Mesh.cpp:263),
    and never routes the packet on.  A self advert is self-signed, so every
    other check downstream passes it.
    """
    if not self_public_key:
        return False
    return len(payload) >= PUB_KEY_SIZE and payload[:PUB_KEY_SIZE] == self_public_key


def decode_appdata(appdata: bytes) -> dict:
    result = {}
    if len(appdata) < 1:
        raise ValueError("Appdata too short to contain flags")
    flags = appdata[0]
    result["flags"] = flags

    offset = 1
    required_len = 1
    if flags & 0x10:  # has_location
        required_len += 8
    if flags & 0x20:  # has_feature_1
        required_len += 2
    if flags & 0x40:  # has_feature_2
        required_len += 2
    if len(appdata) < required_len:
        raise ValueError(
            f"Advert appdata truncated for required fields: {len(appdata)} bytes available, "
            f"need at least {required_len}"
        )

    # Parse conditional fields based on flags (following the same logic as packet_analyzer)
    if flags & 0x10:  # has_location
        import struct

        lat_raw = struct.unpack("<i", appdata[offset : offset + 4])[0]
        lon_raw = struct.unpack("<i", appdata[offset + 4 : offset + 8])[0]
        result["latitude"] = lat_raw / 1000000.0
        result["longitude"] = lon_raw / 1000000.0
        offset += 8

    if flags & 0x20:  # has_feature_1
        import struct

        result["feature_1"] = struct.unpack("<H", appdata[offset : offset + 2])[0]
        offset += 2

    if flags & 0x40:  # has_feature_2
        import struct

        result["feature_2"] = struct.unpack("<H", appdata[offset : offset + 2])[0]
        offset += 2

    if flags & 0x80:  # has_name
        if len(appdata) > offset:
            # MeshCore stores the advertised name as bounded wire bytes and does
            # not require the display form to be valid UTF-8.
            name_bytes = appdata[offset:].split(b"\x00", 1)[0]
            try:
                name = name_bytes.decode("utf-8")
            except UnicodeDecodeError:
                result["raw_name_bytes"] = name_bytes.hex()
                result["name_decode_error"] = True
                name = name_bytes.decode("utf-8", errors="replace")
            if name:
                result["node_name"] = name

    return result


def determine_contact_type_from_flags(flags: int) -> int:
    from .constants import (
        ADVERT_FLAG_IS_CHAT_NODE,
        ADVERT_FLAG_IS_REPEATER,
        ADVERT_FLAG_IS_ROOM_SERVER,
        ADVERT_FLAG_IS_SENSOR,
    )

    # Extract node type from bits 0-3 (mask with 0x0F)
    node_type = flags & 0x0F

    if node_type == ADVERT_FLAG_IS_ROOM_SERVER:  # 0x03
        return 3  # ADV_TYPE_ROOM
    elif node_type == ADVERT_FLAG_IS_REPEATER:  # 0x02
        return 2  # ADV_TYPE_REPEATER
    elif node_type == ADVERT_FLAG_IS_CHAT_NODE:  # 0x01
        return 1  # ADV_TYPE_CHAT
    elif node_type == ADVERT_FLAG_IS_SENSOR:  # 0x04
        return 4  # ADV_TYPE_SENSOR
    else:
        return 0  # unknown


def get_contact_type_name(contact_type: int) -> str:
    type_names = {
        0: "Unknown",
        1: "Chat Node",
        2: "Repeater",
        3: "Room Server",
        4: "Sensor",
    }
    return type_names.get(contact_type, f"Unknown Type ({contact_type})")


def get_packet_type_name(payload_type: int) -> str:
    """Get human-readable name for a payload type."""
    return PAYLOAD_TYPES.get(payload_type, f"UNKNOWN_{payload_type}")


def get_route_type_name(route_type: int) -> str:
    """Get human-readable name for a route type."""
    return ROUTE_TYPES.get(route_type, f"UNKNOWN_{route_type}")


def format_packet_info(header: int, payload_length: int = 0) -> str:
    """Format packet header information for logging/debugging."""
    payload_type = (header >> PH_TYPE_SHIFT) & PH_TYPE_MASK
    route_type = header & PH_ROUTE_MASK

    type_name = get_packet_type_name(payload_type)
    route_name = get_route_type_name(route_type)

    info = f"Type: {type_name}, Route: {route_name}"
    if payload_length > 0:
        info += f", Size: {payload_length} bytes"

    return info


def normalize_channel_secret(secret: bytes) -> bytes:
    """Pad or truncate a channel PSK to the 32-byte key the firmware stores."""
    secret = bytes(secret or b"")
    if len(secret) < 32:
        return secret + b"\x00" * (32 - len(secret))
    return secret[:32]


def derive_channel_hash(secret: bytes) -> int:
    """1-byte channel hash: first byte of SHA-256 over the effective key.

    Matches MeshCore firmware: a 128-bit key (second 16 bytes zero) hashes
    only the first 16 bytes; otherwise the full 32 bytes are hashed.
    """
    secret = normalize_channel_secret(secret)
    hash_input = secret[:16] if secret[16:32] == b"\x00" * 16 else secret
    return hashlib.sha256(hash_input).digest()[0]
