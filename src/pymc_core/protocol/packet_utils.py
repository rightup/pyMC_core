"""
Shared utilities for packet construction and validation.
Consolidates common operations between Packet and PacketBuilder classes.
"""

import hashlib
import struct
from typing import Any, List, Union

from .constants import (
    MAX_HASH_SIZE,
    MAX_PACKET_PAYLOAD,
    MAX_PATH_SIZE,
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
            raise ValueError(
                f"Path length {len(routing_path)} exceeds maximum {MAX_PATH_SIZE}"
            )

        validated_path = []
        for i, item in enumerate(routing_path):
            if isinstance(item, str):
                if len(item) < 2:
                    raise ValueError(
                        f"Path[{i}]: hex string '{item}' too short, need at least 2 characters"
                    )
                hex_part = item[:2]
                if not all(c in "0123456789abcdefABCDEF" for c in hex_part):
                    raise ValueError(
                        f"Path[{i}]: '{hex_part}' contains invalid hex characters"
                    )
                byte_val = int(hex_part, 16)
                validated_path.append(byte_val)
            elif isinstance(item, (int, float)):
                byte_val = int(item)
                if not (0 <= byte_val <= 255):
                    raise ValueError(
                        f"Path[{i}]: value {byte_val} out of range (0-255)"
                    )
                validated_path.append(byte_val)
            else:
                raise ValueError(
                    f"Path[{i}]: invalid type {type(item)} for value {item}, expected string or int"
                )
        return validated_path

    @staticmethod
    def validate_packet_bounds(
        idx: int, required: int, data_len: int, error_msg: str
    ) -> None:
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
        return raw_snr / 4.0 if raw_snr is not None else 0.0


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
    def calculate_packet_hash(
        payload_type: int, path_len: int, payload: bytes
    ) -> bytes:
        """
        Calculate packet hash compatible with C++ implementation.

        Args:
            payload_type: Packet payload type
            path_len: Path length (only used for TRACE packets)
            payload: Packet payload bytes

        Returns:
            bytes: SHA256 hash truncated to MAX_HASH_SIZE
        """
        sha = hashlib.sha256()
        sha.update(bytes([payload_type]))
        if payload_type == PAYLOAD_TYPE_TRACE:
            sha.update(bytes([path_len]))
        sha.update(payload)
        return sha.digest()[:MAX_HASH_SIZE]

    @staticmethod
    def calculate_crc(payload_type: int, path_len: int, payload: bytes) -> int:
        """Calculate 4-byte CRC from packet hash."""
        hash_bytes = PacketHashingUtils.calculate_packet_hash(
            payload_type, path_len, payload
        )
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
            return RouteTypeUtils.ROUTE_MAP.get(
                f"transport_{route_type}", ROUTE_TYPE_TRANSPORT_FLOOD
            )
        else:
            return RouteTypeUtils.ROUTE_MAP.get(route_type, ROUTE_TYPE_DIRECT)
