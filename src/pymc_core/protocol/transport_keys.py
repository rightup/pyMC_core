"""Transport key helpers that mirror MeshCore's TransportKeyStore."""

from __future__ import annotations

from collections import deque
import struct
from typing import Iterable, List, Sequence

from .crypto import CryptoUtils

MAX_TKS_ENTRIES = 16


def derive_auto_key(name: str) -> bytes:
    """Derive a 128-bit key from a region hashtag (MeshCore parity)."""

    if not name:
        raise ValueError("Region name cannot be empty")
    if not name.startswith("#"):
        raise ValueError("Region name must start with '#'")
    if len(name) > 64:
        raise ValueError("Region name is too long (max 64 characters)")
    key_hash = CryptoUtils.sha256(name.encode("ascii"))
    return key_hash[:16]


def get_auto_key_for(name: str) -> bytes:
    """Backward-compatible alias for :func:`derive_auto_key`."""

    return derive_auto_key(name)


def calc_transport_code(key: bytes, packet) -> int:
    """Calculate the transport code (HMAC-SHA256, reserve 0x0000/0xFFFF)."""

    if len(key) != 16:
        raise ValueError(f"Transport key must be 16 bytes, got {len(key)}")

    payload_type = packet.get_payload_type()
    payload_data = packet.get_payload()
    hmac_data = bytes([payload_type]) + payload_data
    hmac_digest = CryptoUtils._hmac_sha256(key, hmac_data)
    code = struct.unpack("<H", hmac_digest[:2])[0]

    if code == 0:
        code = 1
    elif code == 0xFFFF:
        code = 0xFFFE

    return code


class TransportKey:
    """Mutable 16-byte transport key with helper methods."""

    __slots__ = ("key",)

    def __init__(self, key: bytes | bytearray | memoryview | None = None) -> None:
        self.key = bytes(16)
        if key is not None:
            self.set_key(key)

    def set_key(self, key: bytes | bytearray | memoryview) -> None:
        data = bytes(key)
        if len(data) != 16:
            raise ValueError(f"Transport key must be 16 bytes, got {len(data)}")
        self.key = data

    def is_null(self) -> bool:
        return all(b == 0 for b in self.key)

    def calc_transport_code(self, packet) -> int:
        return calc_transport_code(self.key, packet)

    def copy(self) -> "TransportKey":
        return TransportKey(self.key)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"TransportKey({self.key.hex()})"


class TransportKeyStore:
    """In-memory cache that mirrors MeshCore's TransportKeyStore behavior."""

    def __init__(self, max_entries: int = MAX_TKS_ENTRIES) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self.max_entries = max_entries
        self._cache: deque[tuple[int, TransportKey]] = deque(maxlen=max_entries)

    # -- cache primitives -------------------------------------------------
    def _put_cache(self, region_id: int, key: TransportKey) -> None:
        self._cache.append((region_id, key.copy()))

    def invalidate_cache(self) -> None:
        self._cache.clear()

    def _cached_keys_for(self, region_id: int) -> List[TransportKey]:
        return [entry.copy() for rid, entry in self._cache if rid == region_id]

    # -- public API -------------------------------------------------------
    def get_auto_key_for(self, region_id: int, name: str) -> TransportKey:
        cached = self._cached_keys_for(region_id)
        if cached:
            return cached[0]

        derived = TransportKey(derive_auto_key(name))
        self._put_cache(region_id, derived)
        return derived.copy()

    def load_keys_for(self, region_id: int, max_num: int | None = None) -> List[TransportKey]:
        keys = self._cached_keys_for(region_id)
        if max_num is not None:
            return keys[:max_num]
        return keys

    def save_keys_for(self, region_id: int, keys: Sequence[bytes | TransportKey]) -> bool:
        if not keys:
            return False
        for key in keys:
            tk = key if isinstance(key, TransportKey) else TransportKey(key)
            self._put_cache(region_id, tk)
        return True

    def remove_keys(self, region_id: int) -> bool:
        original = len(self._cache)
        self._cache = deque([(rid, key) for rid, key in self._cache if rid != region_id], maxlen=self.max_entries)
        return len(self._cache) != original

    def clear(self) -> bool:
        changed = len(self._cache) > 0
        self.invalidate_cache()
        return changed

    def cache_snapshot(self) -> List[tuple[int, TransportKey]]:
        """Return a copy of the cache for diagnostics/testing."""

        return [(rid, key.copy()) for rid, key in self._cache]
