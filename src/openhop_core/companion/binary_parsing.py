"""Parse binary response payloads by request type (BinaryReqType)."""

from __future__ import annotations

import logging
import struct
from typing import Optional

from .constants import (
    ANON_BASIC_FEAT_BRIDGE_MASK,
    ANON_BASIC_FEAT_DISABLED,
    ANON_REQ_TYPE_BASIC,
    ANON_REQ_TYPE_OWNER,
    ANON_REQ_TYPE_REGIONS,
    CONTACT_NAME_SIZE,
    BinaryReqType,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Historical 73-byte contact record.  It is retained for source compatibility
# with callers that use these helpers directly, but is not a companion-wire
# format: CMD_EXPORT_CONTACT/CMD_IMPORT_CONTACT use signed ADVERT packets.
# pubkey(32) + adv_type(1) + name(32, NUL padded) + lat(i32 µdeg) + lon(i32 µdeg)
# ---------------------------------------------------------------------------
EXPORTED_CONTACT_STRUCT = "<32sB32sii"
EXPORTED_CONTACT_SIZE = struct.calcsize(EXPORTED_CONTACT_STRUCT)  # 73 bytes


def encode_exported_contact(
    pub_key: bytes, adv_type: int, name: str, gps_lat: float, gps_lon: float
) -> bytes:
    """Encode the historical 73-byte contact record."""
    name_field = name.encode("utf-8")[:CONTACT_NAME_SIZE].ljust(CONTACT_NAME_SIZE, b"\x00")
    return struct.pack(
        EXPORTED_CONTACT_STRUCT,
        pub_key,
        adv_type,
        name_field,
        int(gps_lat * 1e6),
        int(gps_lon * 1e6),
    )


def decode_exported_contact(data: bytes) -> Optional[dict]:
    """Decode a historical 73-byte contact record; return None if too short.

    ``name_raw`` preserves the undecoded name bytes (up to the first NUL) for
    callers that re-encode the name on the wire.
    """
    if len(data) < EXPORTED_CONTACT_SIZE:
        return None
    pub_key, adv_type, name_field, lat, lon = struct.unpack_from(EXPORTED_CONTACT_STRUCT, data)
    name_raw = name_field.split(b"\x00")[0]
    return {
        "public_key": pub_key,
        "adv_type": adv_type,
        "name": name_raw.decode("utf-8", errors="replace"),
        "name_raw": name_raw,
        "gps_lat": lat / 1e6,
        "gps_lon": lon / 1e6,
        "lat_microdeg": lat,
        "lon_microdeg": lon,
    }


def parse_binary_response(
    request_type: int,
    data: bytes,
    pubkey_prefix: str = "",
    context: Optional[dict] = None,
) -> Optional[dict]:
    """Parse response_data by request_type. Returns dict or None."""
    context = context or {}
    # Anonymous requests (CMD_SEND_ANON_REQ) all carry request_type 0x07, which
    # collides with BinaryReqType.OWNER_INFO. Disambiguate by the recorded
    # ANON_REQ_TYPE_* sub-type so a regions reply is not parsed as owner info.
    anon_sub_type = context.get("anon_sub_type")
    if anon_sub_type is not None:
        if anon_sub_type == ANON_REQ_TYPE_REGIONS:
            return _parse_regions(data)
        if anon_sub_type == ANON_REQ_TYPE_OWNER:
            return _parse_anon_owner(data)
        if anon_sub_type == ANON_REQ_TYPE_BASIC:
            return _parse_anon_basic(data)
        return {"raw_hex": data.hex(), "anon_sub_type": anon_sub_type}
    if request_type == BinaryReqType.STATUS and len(data) >= 52:
        return _parse_status(data, pubkey_prefix=pubkey_prefix or None)
    if request_type == BinaryReqType.TELEMETRY and len(data) >= 0:
        return _parse_telemetry(data)
    if request_type == BinaryReqType.MMA and len(data) >= 4:
        return _parse_mma(data[4:])  # skip 4-byte header
    if request_type == BinaryReqType.ACL:
        return _parse_acl(data)
    if request_type == BinaryReqType.NEIGHBOURS:
        return _parse_neighbours(data, context or {})
    if request_type == BinaryReqType.OWNER_INFO and len(data) >= 4:
        return _parse_owner_info(data)
    return {"raw_hex": data.hex(), "request_type": request_type}


def _parse_status(data: bytes, pubkey_prefix: Optional[str] = None, offset: int = 0) -> dict:
    """Parse status response (52 bytes)."""
    res = {}
    if pubkey_prefix is None and len(data) >= 8:
        res["pubkey_pre"] = data[2:8].hex()
        offset = 8
    else:
        res["pubkey_pre"] = pubkey_prefix or ""
    res["bat"] = int.from_bytes(data[offset : offset + 2], byteorder="little")
    res["tx_queue_len"] = int.from_bytes(data[offset + 2 : offset + 4], byteorder="little")
    res["noise_floor"] = int.from_bytes(
        data[offset + 4 : offset + 6], byteorder="little", signed=True
    )
    res["last_rssi"] = int.from_bytes(
        data[offset + 6 : offset + 8], byteorder="little", signed=True
    )
    res["nb_recv"] = int.from_bytes(data[offset + 8 : offset + 12], byteorder="little")
    res["nb_sent"] = int.from_bytes(data[offset + 12 : offset + 16], byteorder="little")
    res["airtime"] = int.from_bytes(data[offset + 16 : offset + 20], byteorder="little")
    res["uptime"] = int.from_bytes(data[offset + 20 : offset + 24], byteorder="little")
    res["sent_flood"] = int.from_bytes(data[offset + 24 : offset + 28], byteorder="little")
    res["sent_direct"] = int.from_bytes(data[offset + 28 : offset + 32], byteorder="little")
    res["recv_flood"] = int.from_bytes(data[offset + 32 : offset + 36], byteorder="little")
    res["recv_direct"] = int.from_bytes(data[offset + 36 : offset + 40], byteorder="little")
    res["full_evts"] = int.from_bytes(data[offset + 40 : offset + 42], byteorder="little")
    res["last_snr"] = (
        int.from_bytes(data[offset + 42 : offset + 44], byteorder="little", signed=True) / 4
    )
    res["direct_dups"] = int.from_bytes(data[offset + 44 : offset + 46], byteorder="little")
    res["flood_dups"] = int.from_bytes(data[offset + 46 : offset + 48], byteorder="little")
    res["rx_airtime"] = int.from_bytes(data[offset + 48 : offset + 52], byteorder="little")
    return res


def _parse_telemetry(data: bytes) -> dict:
    """Telemetry: Cayenne LPP or raw. Dict has raw_hex; optional LPP if cayennelpp available."""
    out: dict = {"raw_hex": data.hex()}
    try:
        from cayennelpp import LppFrame

        frame = LppFrame.from_bytes(data)
        out["lpp"] = [
            {"channel": d.channel, "type": d.type_id, "value": d.data} for d in frame.data
        ]
    except Exception:
        logger.debug("Optional LPP parse failed for telemetry", exc_info=True)
    return out


def _parse_mma(data: bytes) -> dict:
    """MMA: LPP min/max/avg or raw."""
    out: dict = {"raw_hex": data.hex()}
    try:
        from cayennelpp import LppFrame

        frame = LppFrame.from_bytes(data)
        out["mma"] = [{"channel": d.channel, "type": d.type_id, "data": d.data} for d in frame.data]
    except Exception:
        logger.debug("Optional LPP parse failed for MMA", exc_info=True)
    return out


def _parse_owner_info(data: bytes) -> dict:
    """Parse GET_OWNER_INFO response: tag(4) + 'version\\nname\\nowner' (variable)."""
    try:
        text = data[4:].decode("utf-8", errors="replace").strip()
        parts = text.split("\n", 2)
        return {
            "tag": int.from_bytes(data[:4], "little"),
            "version": parts[0] if len(parts) > 0 else "",
            "node_name": parts[1] if len(parts) > 1 else "",
            "owner_info": parts[2] if len(parts) > 2 else "",
            "raw_text": text,
        }
    except Exception:
        logger.debug("Owner info parse failed, returning fallback", exc_info=True)
        return {"raw_hex": data.hex(), "request_type": BinaryReqType.OWNER_INFO}


def _parse_regions(data: bytes) -> dict:
    """Parse ANON_REQ_TYPE_REGIONS response: clock(4) + region-name list.

    The responder replies with tag(4) + clock(4) + names; the tag is stripped by
    the caller, so ``data`` is clock(4) + names. Names are a null-terminated,
    comma-separated string ('*' denotes the wildcard region; '#' prefixes are
    already stripped by the firmware's exportNamesTo).
    """
    try:
        clock = int.from_bytes(data[:4], "little") if len(data) >= 4 else 0
        raw = data[4:].split(b"\x00", 1)[0]
        text = raw.decode("utf-8", errors="replace")
        regions = [r for r in text.split(",") if r != ""]
        return {"type": "regions", "clock": clock, "regions": regions}
    except Exception:
        logger.debug("Regions parse failed, returning fallback", exc_info=True)
        return {"raw_hex": data.hex(), "anon_sub_type": ANON_REQ_TYPE_REGIONS}


def _parse_anon_owner(data: bytes) -> dict:
    """Parse ANON_REQ_TYPE_OWNER response: clock(4) + 'name\\nowner'."""
    try:
        clock = int.from_bytes(data[:4], "little") if len(data) >= 4 else 0
        text = data[4:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        parts = text.split("\n", 1)
        return {
            "type": "owner",
            "clock": clock,
            "node_name": parts[0] if len(parts) > 0 else "",
            "owner_info": parts[1] if len(parts) > 1 else "",
        }
    except Exception:
        logger.debug("Anon owner parse failed, returning fallback", exc_info=True)
        return {"raw_hex": data.hex(), "anon_sub_type": ANON_REQ_TYPE_OWNER}


def _parse_anon_basic(data: bytes) -> dict:
    """Parse ANON_REQ_TYPE_BASIC response: clock(4) + feature flags(1)."""
    clock = int.from_bytes(data[:4], "little") if len(data) >= 4 else 0
    features = data[4] if len(data) >= 5 else 0
    bridge_type = features & ANON_BASIC_FEAT_BRIDGE_MASK
    return {
        "type": "basic",
        "clock": clock,
        "features": features,
        "is_bridge": bridge_type != 0,
        "bridge_type": bridge_type,
        "is_disabled": bool(features & ANON_BASIC_FEAT_DISABLED),
    }


def _parse_acl(buf: bytes) -> dict:
    """ACL: 7-byte entries (key 6 + perm 1)."""
    res = []
    i = 0
    while i + 7 <= len(buf):
        key = buf[i : i + 6].hex()
        perm = buf[i + 6]
        if key != "000000000000":
            res.append({"key": key, "perm": perm})
        i += 7
    return {"acl": res}


def _parse_neighbours(data: bytes, context: dict) -> dict:
    """Neighbours: count(2) + results_count(2) + entries (pubkey_prefix + secs_ago(4) + snr(1))."""
    if len(data) < 4:
        return {"raw_hex": data.hex()}
    pk_plen = context.get("pubkey_prefix_length", 6)
    neighbours_count = int.from_bytes(data[0:2], "little", signed=True)
    results_count = int.from_bytes(data[2:4], "little", signed=True)
    neighbours_list = []
    i = 4
    for _ in range(results_count):
        if i + pk_plen + 4 + 1 > len(data):
            break
        pubkey = data[i : i + pk_plen].hex()
        i += pk_plen
        secs_ago = int.from_bytes(data[i : i + 4], "little", signed=True)
        i += 4
        snr = int.from_bytes(data[i : i + 1], "little", signed=True) / 4
        i += 1
        neighbours_list.append({"pubkey": pubkey, "secs_ago": secs_ago, "snr": snr})
    return {
        "neighbours_count": neighbours_count,
        "results_count": results_count,
        "neighbours": neighbours_list,
    }
