"""Frame-body encoders shared by response and push frames."""

import struct
from typing import Optional

from ..constants import (
    CONTACT_NAME_SIZE,
    MAX_PATH_SIZE,
    OUT_PATH_UNKNOWN,
    PUB_KEY_SIZE,
    PUSH_CODE_ADVERT,
    PUSH_CODE_NEW_ADVERT,
)
from ..models import Contact


def _encode_contact_fields(contact: Contact) -> bytes:
    """Encode the contact body shared by RESP_CODE_CONTACT and
    PUSH_CODE_NEW_ADVERT frames: pubkey(32) + adv_type + flags + out_path_len
    + out_path(64) + name(32) + last_advert(4) + lat(4) + lon(4) + lastmod(4).
    """
    pubkey_b = contact.public_key
    if isinstance(pubkey_b, str):
        pubkey_b = bytes.fromhex(pubkey_b)
    if isinstance(pubkey_b, bytes):
        pubkey_b = pubkey_b[:PUB_KEY_SIZE].ljust(PUB_KEY_SIZE, b"\x00")
    else:
        pubkey_b = b"\x00" * PUB_KEY_SIZE
    op = contact.out_path if isinstance(contact.out_path, bytes) else bytes(contact.out_path or [])
    op = op[:MAX_PATH_SIZE].ljust(MAX_PATH_SIZE, b"\x00")
    nb = (
        contact.name.encode("utf-8", errors="replace")
        if isinstance(contact.name, str)
        else (contact.name if isinstance(contact.name, bytes) else b"")
    )[:CONTACT_NAME_SIZE].ljust(CONTACT_NAME_SIZE, b"\x00")
    opl_byte = OUT_PATH_UNKNOWN if contact.out_path_len < 0 else min(contact.out_path_len, 255)
    return (
        pubkey_b
        + bytes([contact.adv_type, contact.flags, opl_byte])
        + op
        + nb
        + struct.pack("<I", contact.last_advert_timestamp)
        + struct.pack("<i", int(contact.gps_lat * 1e6))
        + struct.pack("<i", int(contact.gps_lon * 1e6))
        + struct.pack("<I", contact.lastmod)
    )


def _build_advert_push_frames(contact: Contact) -> tuple[bytes, Optional[bytes]]:
    """Build PUSH_CODE_ADVERT short frame and optional PUSH_CODE_NEW_ADVERT
    full frame from contact.  Thread-safe for ``asyncio.to_thread``."""
    pubkey_b = contact.public_key
    if isinstance(pubkey_b, bytes):
        pubkey_b = pubkey_b[:PUB_KEY_SIZE].ljust(PUB_KEY_SIZE, b"\x00")
    else:
        pubkey_b = b"\x00" * PUB_KEY_SIZE
    short = bytes([PUSH_CODE_ADVERT]) + pubkey_b
    if not contact.name:
        return (short, None)
    full = bytes([PUSH_CODE_NEW_ADVERT]) + _encode_contact_fields(contact)
    return (short, full)
