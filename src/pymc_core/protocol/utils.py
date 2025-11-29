"""
Centralized protocol utility functions and lookup tables for mesh network.
"""

import struct

from .constants import (
    ADVERT_FLAG_HAS_FEATURE1,
    ADVERT_FLAG_HAS_FEATURE2,
    ADVERT_FLAG_HAS_LOCATION,
    ADVERT_FLAG_HAS_NAME,
    ADVERT_FLAG_IS_CHAT_NODE,
    ADVERT_FLAG_IS_REPEATER,
    ADVERT_FLAG_IS_ROOM_SERVER,
    ADVERT_FLAG_IS_SENSOR,
    PUB_KEY_SIZE,
    SIGNATURE_SIZE,
    TIMESTAMP_SIZE,
)

# Lookup tables
APPDATA_FLAGS = {
    ADVERT_FLAG_IS_CHAT_NODE: "is_chat_node",
    ADVERT_FLAG_IS_REPEATER: "is_repeater",
    ADVERT_FLAG_IS_ROOM_SERVER: "is_room_server",
    ADVERT_FLAG_IS_SENSOR: "is_sensor",
    ADVERT_FLAG_HAS_LOCATION: "has_location",
    ADVERT_FLAG_HAS_FEATURE1: "has_feature_1",
    ADVERT_FLAG_HAS_FEATURE2: "has_feature_2",
    ADVERT_FLAG_HAS_NAME: "has_name",
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


def decode_appdata(appdata: bytes) -> dict:
    if len(appdata) < 1:
        raise ValueError("Appdata too short to contain flags")

    result: dict[str, object] = {}
    offset = 0
    flags = appdata[offset]
    result["flags"] = flags
    offset += 1

    def read_bytes(length: int, field: str) -> bytes:
        nonlocal offset
        end = offset + length
        if end > len(appdata):
            raise ValueError(
                f"Appdata indicates {field}, but only {len(appdata) - offset} bytes remain"
            )
        chunk = appdata[offset:end]
        offset = end
        return chunk

    if flags & ADVERT_FLAG_HAS_LOCATION:
        lat_raw, lon_raw = struct.unpack("<ii", read_bytes(8, "latitude/longitude"))
        result["latitude"] = lat_raw / 1_000_000.0
        result["longitude"] = lon_raw / 1_000_000.0

    if flags & ADVERT_FLAG_HAS_FEATURE1:
        (feature_one,) = struct.unpack("<H", read_bytes(2, "feature_1"))
        result["feature_1"] = feature_one

    if flags & ADVERT_FLAG_HAS_FEATURE2:
        (feature_two,) = struct.unpack("<H", read_bytes(2, "feature_2"))
        result["feature_2"] = feature_two

    if flags & ADVERT_FLAG_HAS_NAME:
        name_bytes = appdata[offset:]
        if name_bytes:
            try:
                name = name_bytes.decode("utf-8").rstrip("\x00").strip()
                if name:
                    result["node_name"] = name
            except UnicodeDecodeError:
                result["raw_name_bytes"] = name_bytes.hex()
                result["name_decode_error"] = True

    return result


def determine_contact_type_from_flags(flags: int) -> int:
    from .constants import (
        ADVERT_FLAG_IS_CHAT_NODE,
        ADVERT_FLAG_IS_REPEATER,
        ADVERT_FLAG_IS_ROOM_SERVER,
    )

    is_chat = bool(flags & ADVERT_FLAG_IS_CHAT_NODE)
    is_repeater = bool(flags & ADVERT_FLAG_IS_REPEATER)
    is_room_server = bool(flags & ADVERT_FLAG_IS_ROOM_SERVER)
    if is_room_server:
        return 3  # CONTACT_TYPE_ROOM_SERVER
    elif is_repeater and is_chat:
        return 4  # CONTACT_TYPE_HYBRID
    elif is_repeater:
        return 2  # CONTACT_TYPE_REPEATER
    elif is_chat:
        return 1  # CONTACT_TYPE_CHAT_NODE
    else:
        return 0  # CONTACT_TYPE_UNKNOWN


def get_contact_type_name(contact_type: int) -> str:
    type_names = {
        0: "Unknown",
        1: "Chat Node",
        2: "Repeater",
        3: "Room Server",
        4: "Hybrid Node",
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
    payload_type = header >> 4
    route_type = header & 0x03

    type_name = get_packet_type_name(payload_type)
    route_name = get_route_type_name(route_type)

    info = f"Type: {type_name}, Route: {route_name}"
    if payload_length > 0:
        info += f", Size: {payload_length} bytes"

    return info
