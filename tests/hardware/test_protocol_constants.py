"""
Offline tests for the shared openHop Modem wire-protocol primitives.

Verifies CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF, no reflect,
no xor-out) and frame layout produced by `crc16_ccitt` / `build_frame`
against fixed reference vectors so the firmware and both Python drivers
(USB + TCP) cannot drift apart silently.

No network, no hardware — these run in CI on a bare interpreter.

Place this file at:
    tests/hardware/test_protocol_constants.py
"""

import struct

import pytest

from openhop_core.hardware.protocol_constants import (
    CMD_PING,
    CMD_TX_REQUEST,
    PROTO_SYNC,
    build_frame,
    crc16_ccitt,
)

# ───────────────────────── CRC ─────────────────────────────────────


def test_crc_empty_buffer_is_init_value():
    """Empty input → CRC stays at the init value 0xFFFF."""
    assert crc16_ccitt(b"") == 0xFFFF


def test_crc_ccitt_false_canonical_vector():
    """
    Canonical CRC-16/CCITT-FALSE check vector: CRC("123456789") == 0x29B1.

    If this fails, the polynomial, initial value, or bit ordering have
    drifted from the firmware's `crc16_ccitt` in `protocol.h`.
    """
    assert crc16_ccitt(b"123456789") == 0x29B1


def test_crc_single_byte_zero():
    """CRC(0x00) is a stable spot-check: 0xE1F0."""
    assert crc16_ccitt(b"\x00") == 0xE1F0


# ───────────────────────── Frame layout ────────────────────────────


def test_ping_frame_layout():
    """
    PING frame is the simplest case: SYNC | CMD | LEN(2) | CRC(2).
    Empty payload → 6 bytes total, no payload field in between.
    """
    frame = build_frame(CMD_PING)
    assert len(frame) == 6
    assert frame[0] == PROTO_SYNC
    assert frame[1] == CMD_PING
    assert frame[2:4] == b"\x00\x00"  # length = 0, little-endian


@pytest.mark.parametrize("n", [1, 16, 100, 200, 255])
def test_frame_with_payload_total_length(n):
    """Total frame length = 1 (SYNC) + 1 (CMD) + 2 (LEN) + N + 2 (CRC)."""
    payload = b"\xAB" * n
    frame = build_frame(CMD_TX_REQUEST, payload)
    assert len(frame) == 6 + n


def test_payload_passes_through_unchanged():
    """Build a frame and confirm the payload bytes are at the expected offset."""
    payload = bytes(range(100))
    frame = build_frame(CMD_TX_REQUEST, payload)
    assert frame[4 : 4 + 100] == payload


def test_length_field_is_little_endian():
    """
    300-byte payload exercises both LEN bytes. LE encoding of 300 = 0x012C
    → bytes [0x2C, 0x01]. If we serialized big-endian, this would be [0x01, 0x2C].
    """
    payload = b"\x55" * 300
    frame = build_frame(CMD_TX_REQUEST, payload)
    assert frame[2:4] == b"\x2C\x01"


def test_crc_covers_cmd_len_payload_but_not_sync():
    """
    Per protocol.h: CRC is computed over CMD + LEN + PAYLOAD, *not* over SYNC.
    Verify by rebuilding the CRC from the raw bytes we expect it to cover.
    """
    payload = b"hello world"
    frame = build_frame(CMD_TX_REQUEST, payload)

    # Last 2 bytes of the frame are the CRC, little-endian.
    crc_in_frame = struct.unpack("<H", frame[-2:])[0]

    # Everything except SYNC (first byte) and CRC (last 2 bytes) is CRC input.
    covered = frame[1:-2]
    assert crc16_ccitt(covered) == crc_in_frame


def test_crc_is_little_endian_on_the_wire():
    """
    A non-symmetric CRC value lets us distinguish endianness. Build a
    TX_REQUEST with a known payload; expected CRC bytes are the explicit
    LE pair `struct.pack('<H', crc)`.
    """
    payload = b"\x01\x02\x03\x04"
    frame = build_frame(CMD_TX_REQUEST, payload)
    expected_crc = crc16_ccitt(frame[1:-2])
    assert frame[-2:] == struct.pack("<H", expected_crc)


# ───────────────────────── Edge cases ──────────────────────────────


def test_max_payload_size():
    """
    LEN field is u16, so the wire format technically allows 65535-byte
    payloads. The firmware caps at 255 (single-byte buffer optimisation),
    but the framing code itself must handle anything that fits in u16.
    """
    payload = b"\xCC" * 255
    frame = build_frame(CMD_TX_REQUEST, payload)
    assert len(frame) == 6 + 255
    # LEN field correctly encodes 255 as 0x00FF little-endian.
    assert frame[2:4] == b"\xFF\x00"


@pytest.mark.parametrize("cmd", [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF])
def test_frame_preserves_command_byte(cmd):
    """Command byte goes in unchanged regardless of value."""
    frame = build_frame(cmd, b"")
    assert frame[1] == cmd


def test_build_frame_rejects_oversized_payload():
    """
    Payloads larger than 0xFFFF cannot fit in the 16-bit LEN field.
    build_frame() must raise ValueError with a clear message rather than
    letting struct.pack blow up with a generic 'ushort format requires
    0 <= number <= 65535' error.
    """
    with pytest.raises(ValueError, match="exceeds 16-bit LEN field"):
        build_frame(CMD_TX_REQUEST, b"\x00" * 65536)
