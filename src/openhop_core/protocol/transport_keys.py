"""
Transport Key utilities for mesh packet authentication.

Simple implementation matching the C++ MeshCore transport key functionality:
- Generate 128-bit key from region name (SHA256 of ASCII name)
- Calculate transport codes using HMAC-SHA256
"""

import struct

from .constants import ROUTE_TYPE_TRANSPORT_FLOOD
from .crypto import CryptoUtils


def get_auto_key_for(name: str) -> bytes:
    """
    Generate 128-bit transport key from region name.

    Matches C++ implementation:
    void TransportKeyStore::getAutoKeyFor(uint16_t id, const char* name, TransportKey& dest)

    Args:
        name: Region name (e.g., "#usa" or implicit "usa")

    Returns:
        bytes: 16-byte transport key
    """
    if not name:
        raise ValueError("Region name cannot be empty")

    # Match MeshCore RegionMap behavior: non-hashtag names are treated as
    # implicit auto-hashtag regions by prepending '#'.
    canonical_name = name if name.startswith("#") else f"#{name}"

    if len(canonical_name) > 64:
        raise ValueError("Region name is too long (max 64 characters)")
    key_hash = CryptoUtils.sha256(canonical_name.encode("ascii"))
    return key_hash[:16]  # First 16 bytes (128 bits)


def calc_transport_code(key: bytes, packet) -> int:
    """
    Calculate transport code for a packet.

    Matches C++ implementation:
    uint16_t TransportKey::calcTransportCode(const mesh::Packet* packet) const

    Args:
        key: 16-byte transport key
        packet: Packet with payload_type and payload

    Returns:
        int: 16-bit transport code
    """
    if len(key) != 16:
        raise ValueError(f"Transport key must be 16 bytes, got {len(key)}")
    payload_type = packet.get_payload_type()
    payload_data = packet.get_payload()

    # HMAC input: payload_type (1 byte) + payload
    hmac_data = bytes([payload_type]) + payload_data

    # Calculate HMAC-SHA256
    hmac_digest = CryptoUtils._hmac_sha256(key, hmac_data)

    # Extract first 2 bytes as little-endian uint16 (matches Arduino platform endianness)
    code = struct.unpack("<H", hmac_digest[:2])[0]

    # Reserve codes 0000 and FFFF (matches C++ implementation)
    if code == 0:
        code = 1
    elif code == 0xFFFF:
        code = 0xFFFE

    return code


def scope_packet(pkt, key: bytes) -> None:
    """Attach transport codes for ``key`` and switch FLOOD -> TRANSPORT_FLOOD.

    The single shared scoping primitive: the companion resolver
    (``base_config._apply_flood_scope``), the dispatcher resolver
    (``Dispatcher._apply_flood_scope``) and the reply-scope helper
    (``region_map.apply_reply_scope``) all funnel through this so the wire
    format is computed in exactly one place. The code is (re-)hashed from the
    packet's own payload via :func:`calc_transport_code`, so a reply's code is
    derived from the reply payload, never copied from the request.

    Does not set ``_flood_scope_applied``: the double-scope gate stays the
    responsibility of the calling resolver (which must mark plain-flood
    decisions too).
    """
    pkt.transport_codes[0] = calc_transport_code(key, pkt)
    pkt.transport_codes[1] = 0  # reserved for home region (firmware TODO)
    pkt.header = (pkt.header & ~0x03) | ROUTE_TYPE_TRANSPORT_FLOOD
