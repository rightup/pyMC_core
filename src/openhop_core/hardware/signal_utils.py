"""Helpers for translating raw radio signal metrics to engineering units."""

from __future__ import annotations

from typing import Optional


def snr_register_to_db(raw_value: Optional[int], *, bits: int = 8) -> float:
    """Convert signed SX126x/SX127x SNR register (value * 4) into dB.

    Args:
        raw_value: Raw register value as read from firmware/packet (unsigned).
        bits: Width, in bits, of the stored value. Defaults to 8-bit registers but
            discovery responses may use 16-bit fields.
    """
    if raw_value is None:
        return 0.0
    if bits <= 0 or bits > 32:
        raise ValueError("bits must be between 1 and 32")

    max_value = 1 << bits
    mask = max_value - 1
    value = raw_value & mask
    sign_bit = 1 << (bits - 1)
    if value >= sign_bit:
        value -= max_value
    return value / 4.0
