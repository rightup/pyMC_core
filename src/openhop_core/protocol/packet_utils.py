"""
Shared utilities for packet construction and validation.
Consolidates common operations between Packet and PacketBuilder classes.
"""

import hashlib
import math
import struct
from typing import Any, List, NamedTuple, Optional, Union

from .constants import (
    MAX_HASH_SIZE,
    MAX_PACKET_PAYLOAD,
    MAX_PATH_SIZE,
    PATH_HASH_COUNT_MASK,
    PATH_HASH_SIZE_SHIFT,
    PAYLOAD_TYPE_TRACE,
    PAYLOAD_VER_1,
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


def coding_rate_denominator(cr: Union[int, float]) -> int:
    """Return the LoRa coding-rate denominator (5..8) for rates 4/5..4/8.

    Accepts either representation in use across configs and radio drivers:
    the public denominator form (5..8) or the legacy index form (1..4,
    meaning 4/5..4/8). Values outside both ranges are clamped to 5..8.
    A value of 4 is unambiguous: it is not a valid denominator, so it
    always means the legacy index for 4/8.
    """
    cr_val = int(cr)
    if 1 <= cr_val <= 4:
        return cr_val + 4
    return max(5, min(8, cr_val))


def calculate_lora_airtime_ms(
    payload_len: int,
    sf: int,
    bw_hz: Union[int, float],
    cr: Union[int, float],
    preamble_symbols: int = 8,
    crc_enabled: bool = True,
    explicit_header: bool = True,
    low_dr_opt: Optional[bool] = None,
) -> float:
    """LoRa time-on-air (ms), matching RadioLib's chip drivers.

    MeshCore firmware airtime is RadioLib ``getTimeOnAir`` (the Semtech
    AN1200.13 formula, with 6.25 sync symbols and a different numerator
    constant for SF5/SF6). ``cr`` accepts either coding-rate representation;
    see ``coding_rate_denominator``. ``payload_len`` is the full on-air byte
    length (use ``Packet.get_raw_length()``).

    When ``low_dr_opt`` is None it follows RadioLib's auto rule — enabled when
    the symbol time is at least 16 ms — which is what firmware nodes use
    (MeshCore never overrides the driver's LDRO auto-configuration). Note this
    differs from the common "SF >= 11 and BW <= 125 kHz" shorthand at some
    settings, e.g. SF12 @ 250 kHz and SF10 @ 62.5 kHz both have 16.384 ms
    symbols and therefore use LDRO on real hardware.
    """
    sf = max(5, min(12, int(sf)))
    bw_hz = float(bw_hz) or 250000.0
    cr_denom = coding_rate_denominator(cr)

    symbol_time_s = (1 << sf) / bw_hz
    if low_dr_opt is None:
        low_dr_opt = symbol_time_s * 1000.0 >= 16.0

    sync_symbols = 6.25 if sf <= 6 else 4.25
    sf_coeff2 = 0 if sf <= 6 else 8
    bit_count = (
        8 * payload_len
        + (16 if crc_enabled else 0)
        - 4 * sf
        + sf_coeff2
        + (20 if explicit_header else 0)
    )
    denom = 4 * (sf - 2) if low_dr_opt else 4 * sf
    payload_symbols = 8 + math.ceil(max(bit_count, 0) / denom) * cr_denom

    total_symbols = preamble_symbols + sync_symbols + payload_symbols
    return total_symbols * symbol_time_s * 1000.0


# Approximate SNR threshold per SF for successful reception (SF7..SF12),
# from MeshCore's RadioLibWrappers (based on Semtech datasheets).
_PACKET_SCORE_SNR_THRESHOLDS = (-7.5, -10.0, -12.5, -15.0, -17.5, -20.0)


def packet_score(snr: float, sf: int, packet_len: int) -> float:
    """Reception-quality score in [0, 1], matching MeshCore ``packetScoreInt``.

    Grades how comfortably a packet was received: 0 when the SNR is at or
    below the per-SF decode threshold, scaling up with SNR margin and down
    with packet length (longer packets are likelier to collide). MeshCore
    feeds this into the flood reception delay (``calcRxDelay``) and returns
    0 for SF below 7. ``packet_len`` is the full on-air byte length.
    """
    if sf < 7:
        return 0.0
    threshold = _PACKET_SCORE_SNR_THRESHOLDS[min(sf, 12) - 7]
    if snr < threshold:
        return 0.0
    snr_margin_rate = (snr - threshold) / 10.0
    collision_penalty = 1.0 - (packet_len / 256.0)
    return max(0.0, min(1.0, snr_margin_rate * collision_penalty))


class FloodRxMetrics(NamedTuple):
    score: float
    air_time_ms: float
    delay_ms: float


def flood_rx_metrics(
    frame_len: int,
    snr: float,
    sf: int,
    bw_hz: Union[int, float],
    cr: Union[int, float],
    preamble_symbols: int = 8,
    *,
    rx_delay_base: float = 0.0,
    min_delay_ms: float = 50.0,
    max_delay_ms: float = 32000.0,
) -> FloodRxMetrics:
    """Shared flood RX scoring/airtime/delay metrics used by core and repeater.

    Uses the MeshCore packet score and airtime formulas. Delay follows the
    Dispatcher calcRxDelay behavior: disabled when rx_delay_base <= 0,
    immediate below min_delay_ms, capped at max_delay_ms.
    """
    score = packet_score(snr, sf, frame_len)
    air_time_ms = calculate_lora_airtime_ms(
        frame_len,
        sf,
        bw_hz,
        cr,
        preamble_symbols,
    )

    if rx_delay_base <= 0.0:
        return FloodRxMetrics(score=score, air_time_ms=air_time_ms, delay_ms=0.0)

    delay_ms = (float(rx_delay_base) ** (0.85 - score) - 1.0) * air_time_ms
    if delay_ms < min_delay_ms:
        delay_ms = 0.0
    else:
        delay_ms = min(delay_ms, max_delay_ms)

    return FloodRxMetrics(score=score, air_time_ms=air_time_ms, delay_ms=delay_ms)


class PacketValidationUtils:
    """Centralized validation utilities for packet operations."""

    @staticmethod
    def validate_routing_path(routing_path: List[Union[str, int, float]]) -> List[int]:
        """
        Validates and normalizes routing path entries.

        Args:
            routing_path: List of path entries (strings, ints, or floats)

        Returns:
            List[int]: Validated path as list of byte values (0-255)

        Raises:
            ValueError: If validation fails
        """
        if not isinstance(routing_path, list):
            raise ValueError(f"routing_path must be a list, got {type(routing_path)}")

        if len(routing_path) > MAX_PATH_SIZE:
            raise ValueError(f"Path length {len(routing_path)} exceeds maximum {MAX_PATH_SIZE}")

        validated_path = []
        for i, item in enumerate(routing_path):
            if isinstance(item, str):
                if len(item) < 2:
                    raise ValueError(
                        f"Path[{i}]: hex string '{item}' too short, need at least 2 characters"
                    )
                hex_part = item[:2]
                if not all(c in "0123456789abcdefABCDEF" for c in hex_part):
                    raise ValueError(f"Path[{i}]: '{hex_part}' contains invalid hex characters")
                byte_val = int(hex_part, 16)
                validated_path.append(byte_val)
            elif isinstance(item, (int, float)):
                byte_val = int(item)
                if not (0 <= byte_val <= 255):
                    raise ValueError(f"Path[{i}]: value {byte_val} out of range (0-255)")
                validated_path.append(byte_val)
            else:
                raise ValueError(
                    f"Path[{i}]: invalid type {type(item)} for value {item}, expected string or int"
                )
        return validated_path

    @staticmethod
    def validate_packet_bounds(idx: int, required: int, data_len: int, error_msg: str) -> None:
        """Check if we have enough data remaining."""
        if idx + required > data_len:
            raise ValueError(error_msg)

    @staticmethod
    def validate_buffer_lengths(
        expected_path_len: int,
        actual_path_len: int,
        expected_payload_len: int,
        actual_payload_len: int,
    ) -> None:
        """Validate that internal length values match actual buffer lengths."""
        if expected_path_len != actual_path_len:
            raise ValueError(
                f"path_len mismatch: expected {expected_path_len}, got {actual_path_len}"
            )
        if expected_payload_len != actual_payload_len:
            raise ValueError(
                f"payload_len mismatch: expected {expected_payload_len}, got {actual_payload_len}"
            )

    @staticmethod
    def validate_payload_size(payload_len: int) -> None:
        """Validate payload doesn't exceed maximum size."""
        if payload_len > MAX_PACKET_PAYLOAD:
            raise ValueError(f"payload too large: {payload_len} > {MAX_PACKET_PAYLOAD}")


class PathUtils:
    """Multi-byte path encoding/decoding matching firmware Packet.h.

    The encoded path_len byte packs both hash size and hop count:
      - Bits 0-5: hash_count (number of hops, 0-63)
      - Bits 6-7: (hash_size - 1), where hash_size is 1, 2, or 3 bytes

    Total path bytes on the wire = hash_count * hash_size.
    For 1-byte hashes the encoded byte equals the raw hop count,
    preserving backward compatibility with legacy packets.
    """

    @staticmethod
    def get_path_hash_size(path_len_byte: int) -> int:
        """Extract per-hop hash size (1, 2, or 3) from the encoded path_len byte."""
        return (path_len_byte >> PATH_HASH_SIZE_SHIFT) + 1

    @staticmethod
    def get_path_hash_count(path_len_byte: int) -> int:
        """Extract hop count (0-63) from the encoded path_len byte."""
        return path_len_byte & PATH_HASH_COUNT_MASK

    @staticmethod
    def get_path_byte_len(path_len_byte: int) -> int:
        """Calculate actual path byte length from the encoded path_len byte."""
        return (path_len_byte & PATH_HASH_COUNT_MASK) * (
            (path_len_byte >> PATH_HASH_SIZE_SHIFT) + 1
        )

    @staticmethod
    def encode_path_len(hash_size: int, hash_count: int) -> int:
        """Encode hash size and hop count into a single path_len byte.

        Hop count is stored in 6 bits (0-63). Values above 63 are invalid and raise.
        """
        if not 0 <= hash_count <= 63:
            raise ValueError(f"hop count must be 0-63 for path_len encoding, got {hash_count}")
        return ((hash_size - 1) << PATH_HASH_SIZE_SHIFT) | (hash_count & PATH_HASH_COUNT_MASK)

    @staticmethod
    def is_valid_path_len(path_len_byte: int) -> bool:
        """Validate an encoded path_len byte.

        Path length in bytes must never exceed MAX_PATH_SIZE (64): at most 64
        one-byte hops, 32 two-byte hops, or 21 three-byte hops. Returns False
        for hash_size == 4 (reserved) or if the total path bytes would exceed
        MAX_PATH_SIZE.
        """
        hash_size = (path_len_byte >> PATH_HASH_SIZE_SHIFT) + 1
        if hash_size > 3:
            return False
        hash_count = path_len_byte & PATH_HASH_COUNT_MASK
        return hash_count * hash_size <= MAX_PATH_SIZE

    @staticmethod
    def is_path_at_max_hops(path_len_byte: int) -> bool:
        """True if path has reached maximum hops for its hash size (do not retransmit).

        Measures hops, not raw bytes. Max hops depend on hash size and MAX_PATH_SIZE:
        - 1-byte hashes: 63 hops (63 bytes)
        - 2-byte hashes: 32 hops (64 bytes)
        - 3-byte hashes: 21 hops (63 bytes)
        """
        if path_len_byte == 0:
            return False
        hash_size = PathUtils.get_path_hash_size(path_len_byte)
        if hash_size > 3:
            return False
        hash_count = path_len_byte & PATH_HASH_COUNT_MASK
        max_hops = min(PATH_HASH_COUNT_MASK, MAX_PATH_SIZE // hash_size)
        return hash_count >= max_hops

    @staticmethod
    def trace_payload_hash_width(flags: int) -> int:
        """Per-hop path hash size inside TRACE payload (Mesh.cpp ``PAYLOAD_TYPE_TRACE``).

        Lower two bits of ``flags`` select width as ``1 << (flags & 0x03)`` bytes per hop
        (1, 2, 4, or 8). This matches companion_radio / ``isHashMatch(..., 1 << path_sz)``.
        It is not the same encoding as ``get_path_hash_size`` for the packet ``path``
        field (1–3 bytes via bits 6–7 of ``path_len``).
        """
        return 1 << (int(flags) & 0x03)


class PacketDataUtils:
    """Centralized data packing and unpacking utilities."""

    @staticmethod
    def pack_timestamp_data(timestamp: int, *data_parts: Any) -> bytes:
        """
        Pack timestamp + variable data parts into bytes.

        Args:
            timestamp: Unix timestamp as 4-byte little-endian
            *data_parts: Variable data to append (int, bytes, str, or other)

        Returns:
            bytes: Packed data starting with timestamp
        """
        result = struct.pack("<I", timestamp)
        for part in data_parts:
            if isinstance(part, int):
                result += bytes([part])
            elif isinstance(part, bytes):
                result += part
            elif isinstance(part, str):
                result += part.encode("utf-8")
            else:
                result += bytes(part)
        return result

    @staticmethod
    def hash_byte(pubkey: bytes) -> int:
        """Extract first byte of public key as hash."""
        if not isinstance(pubkey, bytes) or len(pubkey) == 0:
            raise ValueError("pubkey must be non-empty bytes")
        return pubkey[0]

    @staticmethod
    def hash_bytes(dest_pubkey: bytes, src_pubkey: bytes) -> bytearray:
        """Create hash bytes from destination and source public keys."""
        return bytearray(
            [
                PacketDataUtils.hash_byte(dest_pubkey),
                PacketDataUtils.hash_byte(src_pubkey),
            ]
        )

    @staticmethod
    def calculate_snr_db(raw_snr: int) -> float:
        """Convert raw SNR value to decibels."""
        return raw_snr if raw_snr is not None else 0.0


class PacketHeaderUtils:
    """Centralized header construction and parsing utilities."""

    @staticmethod
    def create_header(
        payload_type: int,
        route_type: int = ROUTE_TYPE_DIRECT,
        version: int = PAYLOAD_VER_1,
    ) -> int:
        """
        Create packet header byte from components.

        Args:
            payload_type: 4-bit payload type (PAYLOAD_TYPE_*)
            route_type: 2-bit route type (ROUTE_TYPE_*)
            version: 2-bit version (PAYLOAD_VER_*)

        Returns:
            int: Complete header byte
        """
        return (
            (route_type & PH_ROUTE_MASK)
            | (payload_type << PH_TYPE_SHIFT)
            | (version << PH_VER_SHIFT)
        )

    @staticmethod
    def parse_header(header: int) -> dict:
        """
        Parse header byte into components.

        Args:
            header: Header byte

        Returns:
            dict: Parsed components (route_type, payload_type, version)
        """
        return {
            "route_type": header & PH_ROUTE_MASK,
            "payload_type": (header >> PH_TYPE_SHIFT) & PH_TYPE_MASK,
            "version": (header >> PH_VER_SHIFT) & PH_VER_MASK,
        }


class PacketHashingUtils:
    """Centralized hashing utilities for packets."""

    @staticmethod
    def calculate_packet_hash(payload_type: int, path_len: int, payload: bytes) -> bytes:
        """
        Calculate packet hash compatible with C++ implementation.

        Args:
            payload_type: Packet payload type
            path_len: Hashed ONLY for TRACE packets (which may revisit a node on
                the return path); excluded for all other types so a rebroadcast
                with a longer path dedups against the original.
            payload: Packet payload bytes

        Returns:
            bytes: SHA256 hash truncated to MAX_HASH_SIZE
        """
        sha = hashlib.sha256()
        sha.update(bytes([payload_type]))
        if payload_type == PAYLOAD_TYPE_TRACE:
            # C++ uses: sha.update(&path_len, sizeof(path_len))  where path_len is uint16_t
            # Must pack as 2-byte little-endian to match C++ on ARM/x86
            sha.update(struct.pack("<H", path_len))
        sha.update(payload)
        return sha.digest()[:MAX_HASH_SIZE]

    @staticmethod
    def calculate_packet_hash_string(
        payload_type: int,
        path_len: int,
        payload: bytes,
        length: Optional[int] = None,
    ) -> str:
        """
        Return upper-case hex string representation of the packet hash.

        Args:
            payload_type: Packet payload type
            path_len: Path length (only used for TRACE packets)
            payload: Packet payload bytes
            length: Optional maximum length of the returned hex string.

        Returns:
            str: Upper-case hex string of the packet hash, optionally truncated.
        """
        raw_hash = PacketHashingUtils.calculate_packet_hash(payload_type, path_len, payload)
        hex_str = raw_hash.hex().upper()
        return hex_str if length is None else hex_str[:length]

    @staticmethod
    def calculate_crc(payload_type: int, path_len: int, payload: bytes) -> int:
        """Calculate 4-byte CRC from packet hash."""
        hash_bytes = PacketHashingUtils.calculate_packet_hash(payload_type, path_len, payload)
        return int.from_bytes(hash_bytes[:4], "little")


class RouteTypeUtils:
    """Utilities for route type handling."""

    ROUTE_MAP = {
        "transport_flood": ROUTE_TYPE_TRANSPORT_FLOOD,
        "flood": ROUTE_TYPE_FLOOD,
        "direct": ROUTE_TYPE_DIRECT,
        "transport_direct": ROUTE_TYPE_TRANSPORT_DIRECT,
    }

    @staticmethod
    def get_route_type_value(route_type: str, has_routing_path: bool = False) -> int:
        """Get numeric route type value with optional transport prefix."""
        if has_routing_path:
            # When path is supplied, use DIRECT routing (don't use transport variants)
            return RouteTypeUtils.ROUTE_MAP.get(route_type, ROUTE_TYPE_DIRECT)
        else:
            # When no path supplied, use FLOOD to build path automatically
            return RouteTypeUtils.ROUTE_MAP.get(route_type, ROUTE_TYPE_FLOOD)


class PacketTimingUtils:
    """Utilities for packet transmission timing calculations."""

    @staticmethod
    def estimate_airtime_ms(packet_length_bytes: int, radio_config: dict = None) -> float:
        """
        Estimate LoRa packet airtime in milliseconds based on packet size and radio parameters.

        Args:
            packet_length_bytes: Total packet length including headers
            radio_config: Radio configuration dict with spreading_factor, bandwidth, etc.
                         Can include 'measured_airtime_ms' for actual measured value

        Returns:
            Estimated airtime in milliseconds
        """
        if radio_config is None:
            radio_config = {
                "spreading_factor": 10,
                "bandwidth": 250000,  # 250kHz
                "coding_rate": 5,
                "preamble_length": 8,
            }

        if "measured_airtime_ms" in radio_config:
            return radio_config["measured_airtime_ms"]

        sf = radio_config.get("spreading_factor", 10)
        bw = radio_config.get("bandwidth", 250000)  # Hz or kHz - convert to Hz if needed
        cr = radio_config.get("coding_rate", 5)
        preamble = radio_config.get("preamble_length", 8)

        # Convert bandwidth to Hz if it's in kHz (values < 1000 are assumed to be kHz)
        if bw < 1000:
            bw = bw * 1000  # Convert kHz to Hz

        airtime_ms = calculate_lora_airtime_ms(packet_length_bytes, sf, bw, cr, preamble)

        # TODO: drop this legacy floor. Firmware reports true sub-50 ms
        # airtimes; callers that need a wait margin already add their own.
        return max(airtime_ms, 50.0)
