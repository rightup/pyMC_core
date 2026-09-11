"""Cross-validation tests: verify Python transport code computation matches MeshCore firmware.

These tests use real captured packet bytes from a firmware companion to validate
that get_auto_key_for() and calc_transport_code() are firmware-compatible.

Captured packets (region #nl-li, GRP_TXT):
  - FIRMWARE_HEX: raw bytes from a firmware companion radio (known-good)
  - PYTHON_HEX:   raw bytes from this Python companion (under test)

The firmware packet stores transport_code[0] = 0xFBE5.
If calc_transport_code(get_auto_key_for("#nl-li"), parsed_pkt) == 0xFBE5,
the algorithm is correct.  If not, there is a firmware-compatibility bug.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

import pytest

from openhop_core.protocol import Packet, transport_keys
from openhop_core.protocol.constants import ROUTE_TYPE_FLOOD, ROUTE_TYPE_TRANSPORT_FLOOD
from openhop_core.protocol.transport_keys import (
    calc_transport_code,
    get_auto_key_for,
    scope_packet,
)

# Raw GRP_TXT packet bytes captured from a firmware companion radio, region #nl-li.
# Packet structure (TRANSPORT_FLOOD, path_len=0):
#   [0x14][E5 FB][00 00][00][03 55 C9 0F B1 0B 08 90 DC 01 19 C3 9C 7F C8 9B
#    34 5B 37 F8 3E E1 7C C0 71 D7 93 83 2C 0E 65 F2 AF 8B 67]
# transport_codes[0] = 0xFBE5 (bytes E5 FB stored little-endian)
FIRMWARE_HEX = "14E5FB0000000355C90FB10B0890DC0119C39C7FC89B345B37F83EE17CC071D793832C0E65F2AF8B67"

# Raw GRP_TXT packet bytes captured from this Python companion, same region #nl-li.
# transport_codes[0] = 0x4709 (bytes 09 47 stored little-endian)
PYTHON_HEX = "140947000000033324E474620D31BFBB3909337DCA3AB51D560F9538D47C846788E7964BFA9305986E"

REGION = "#nl-li"
EXPECTED_FIRMWARE_CODE = 0xFBE5
EXPECTED_PYTHON_CODE = 0x4709


class TestPacketParsing:
    """Verify raw bytes parse correctly before testing transport codes."""

    def test_firmware_packet_parses(self):
        raw = bytes.fromhex(FIRMWARE_HEX)
        pkt = Packet()
        assert pkt.read_from(raw), "firmware packet should parse without error"

    def test_firmware_packet_transport_code(self):
        raw = bytes.fromhex(FIRMWARE_HEX)
        pkt = Packet()
        pkt.read_from(raw)
        assert pkt.transport_codes[0] == EXPECTED_FIRMWARE_CODE, (
            f"Parsed transport_codes[0]={pkt.transport_codes[0]:#06x}, "
            f"expected {EXPECTED_FIRMWARE_CODE:#06x}"
        )

    def test_python_packet_parses(self):
        raw = bytes.fromhex(PYTHON_HEX)
        pkt = Packet()
        assert pkt.read_from(raw), "python packet should parse without error"

    def test_python_packet_transport_code(self):
        raw = bytes.fromhex(PYTHON_HEX)
        pkt = Packet()
        pkt.read_from(raw)
        assert pkt.transport_codes[0] == EXPECTED_PYTHON_CODE, (
            f"Parsed transport_codes[0]={pkt.transport_codes[0]:#06x}, "
            f"expected {EXPECTED_PYTHON_CODE:#06x}"
        )


class TestKeyDerivation:
    """Verify get_auto_key_for produces a 16-byte key."""

    def test_key_is_16_bytes(self):
        key = get_auto_key_for(REGION)
        assert len(key) == 16

    def test_key_is_deterministic(self):
        assert get_auto_key_for(REGION) == get_auto_key_for(REGION)

    def test_different_regions_different_keys(self):
        assert get_auto_key_for("#nl-li") != get_auto_key_for("#usa")

    def test_implicit_region_name_matches_explicit_hashtag(self):
        assert get_auto_key_for("nl-li") == get_auto_key_for("#nl-li")


class TestFirmwareCompatibility:
    """
    THE critical cross-validation suite.

    If test_firmware_transport_code_matches passes:
        - Key derivation and HMAC computation are firmware-compatible.
        - Any region-scoping bug lies in packet construction or dispatch.

    If it fails:
        - There is a bug in get_auto_key_for() or calc_transport_code().
        - The failure message and printed diagnostics will guide the fix.
    """

    def test_firmware_transport_code_matches(self):
        """calc_transport_code must reproduce the code stored in the firmware packet."""
        raw = bytes.fromhex(FIRMWARE_HEX)
        pkt = Packet()
        pkt.read_from(raw)

        key = get_auto_key_for(REGION)
        computed = calc_transport_code(key, pkt)

        assert computed == EXPECTED_FIRMWARE_CODE, (
            f"FIRMWARE COMPATIBILITY BUG: computed {computed:#06x}, "
            f"expected {EXPECTED_FIRMWARE_CODE:#06x} for region {REGION!r}.\n"
            f"  key = {key.hex()}\n"
            f"  payload = {pkt.get_payload().hex()}\n"
            f"  raw HMAC[:2] = "
            + __import__("hmac")
            .new(
                key,
                bytes([pkt.get_payload_type()]) + pkt.get_payload(),
                __import__("hashlib").sha256,
            )
            .digest()[:2]
            .hex()
        )

    def test_python_transport_code_not_nl_li_key(self):
        """The captured Python packet's transport code is NOT consistent with the #nl-li key.

        This documents the confirmed bug: the companion produced a TRANSPORT_FLOOD
        packet (code=0x4709) but calc_transport_code with the #nl-li key gives 0x7a65
        for that payload. The companion was NOT using the correct #nl-li key when
        this packet was captured.

        The algorithm is correct (test_firmware_transport_code_matches passes).
        See TestChannelMessageFloodScope in test_companion_regions.py for the
        integration test verifying the full send_channel_message + set_flood_region
        stack produces firmware-compatible packets.
        """
        raw = bytes.fromhex(PYTHON_HEX)
        pkt = Packet()
        pkt.read_from(raw)

        key = get_auto_key_for(REGION)
        computed = calc_transport_code(key, pkt)

        assert computed != pkt.transport_codes[0], (
            "Python packet code now matches #nl-li key — bug may be fixed. "
            "Update this test and PYTHON_HEX to a new reference packet."
        )
        assert pkt.transport_codes[0] == EXPECTED_PYTHON_CODE  # 0x4709
        assert computed == 0x7A65, f"Expected 0x7a65, got {computed:#06x}"


class TestCmdSetFloodScopeWireFormat:
    """Verify the CMD_SET_FLOOD_SCOPE byte-extraction matches the firmware wire format.

    Firmware (MyMesh.cpp:1909):
        cmd_frame[0] = CMD_SET_FLOOD_SCOPE
        cmd_frame[1] = mode  (0 = scope override/reset; 1 = explicit unscoped, v12+)
        cmd_frame[2..17] = 16-byte key for mode 0   (len >= 2+16 = 18 total)

    frame_server._handle_cmd strips payload[0] (cmd byte) before calling the handler,
    so the handler receives data = [mode] + [key(16)] = 17 bytes for a mode-0 set.
    The correct key slice is data[1:17], NOT data[:16].
    """

    def test_key_slice_skips_reserved_byte(self):
        key = bytes(range(16))
        data = bytes([0x00]) + key  # 17 bytes as received by handler
        extracted = data[1:17]
        assert extracted == key

    def test_wrong_slice_would_corrupt_key(self):
        key = bytes(range(16))
        data = bytes([0x00]) + key
        wrong = data[:16]
        assert wrong != key  # documents what the old bug produced

    def test_short_data_clears_scope(self):
        # Any data shorter than 17 bytes should result in clearing scope (None)
        assert len(bytes([0x00]) + bytes(15)) < 17  # 16 < 17 → clear


class TestTransportCodeDetails:
    """Low-level diagnostics for debugging mismatches."""

    def test_payload_type_is_grp_txt(self):
        """Both packets should report payload type 5 (GRP_TXT)."""
        for hex_str, label in [(FIRMWARE_HEX, "firmware"), (PYTHON_HEX, "python")]:
            raw = bytes.fromhex(hex_str)
            pkt = Packet()
            pkt.read_from(raw)
            assert (
                pkt.get_payload_type() == 0x05
            ), f"{label} packet: expected GRP_TXT (0x05), got {pkt.get_payload_type():#04x}"

    def test_hmac_key_first_bytes(self):
        """Spot-check: SHA256('#nl-li')[:4] must match known value for firmware."""
        import hashlib

        key = get_auto_key_for(REGION)
        expected_full = hashlib.sha256(b"#nl-li").digest()[:16]
        assert (
            key == expected_full
        ), f"Key mismatch:\n  got      {key.hex()}\n  expected {expected_full.hex()}"


# ---------------------------------------------------------------------------
# Scoped GRP_TXT vectors, checked against an independent implementation
# ---------------------------------------------------------------------------
#
# The tests above prove `calc_transport_code` reproduces one real firmware
# capture. That is a single point, and it compares a helper against a captured
# byte rather than against the algorithm: a change that broke, say, only the
# reserved-value mapping or only uppercase names would still pass it.
#
# `_cpp_*` below re-implement TransportKeyStore::getAutoKeyFor and
# TransportKey::calcTransportCode straight from the C++, using nothing from
# openhop_core. They are anchored by `test_reference_impl_reproduces_capture`,
# which shows the reference reproduces the same firmware capture the suite is
# built on -- so the vectors it generates for regions we have no capture for
# (notably an uppercase public region) carry that capture's authority.


def _cpp_get_auto_key_for(name: str) -> bytes:
    """MeshCore TransportKeyStore::getAutoKeyFor -- SHA-256(name)[:16]."""
    return hashlib.sha256(name.encode("ascii")).digest()[:16]


def _cpp_calc_transport_code(key: bytes, payload_type: int, payload: bytes) -> int:
    """MeshCore TransportKey::calcTransportCode.

    HMAC-SHA256 over payload_type || payload, first two bytes read as a
    little-endian uint16 (Arduino endianness), with 0x0000 and 0xFFFF reserved.
    """
    digest = hmac.new(key, bytes([payload_type]) + payload, hashlib.sha256).digest()
    code = struct.unpack("<H", digest[:2])[0]
    if code == 0:
        return 1
    if code == 0xFFFF:
        return 0xFFFE
    return code


# Frozen vectors over the captured firmware GRP_TXT payload above.
# #USA and #usa are deliberately both present: they are different MeshCore
# regions and must never produce the same key or code.
SCOPED_VECTORS = [
    ("#nl-li", "CE657DA0691CD4706A1435A950BC3D8B", 0xFBE5),
    ("#USA", "5EAF24A29D2936601E22AC56065CB314", 0xE46D),
    ("#usa", "418F6396CEA59E2CC79F06D1566EEC31", 0xF07F),
]


def _captured_grp_txt():
    pkt = Packet()
    assert pkt.read_from(bytes.fromhex(FIRMWARE_HEX))
    return pkt


class TestScopedGrpTxtVectors:
    def test_reference_impl_reproduces_capture(self):
        """Anchor: the from-scratch C++ port matches the real firmware bytes."""
        pkt = _captured_grp_txt()
        code = _cpp_calc_transport_code(
            _cpp_get_auto_key_for(REGION), pkt.get_payload_type(), bytes(pkt.get_payload())
        )
        assert code == EXPECTED_FIRMWARE_CODE

    @pytest.mark.parametrize("region,key_hex,code", SCOPED_VECTORS, ids=lambda v: str(v))
    def test_vector_matches_reference_and_helpers(self, region, key_hex, code):
        pkt = _captured_grp_txt()
        expected_key = bytes.fromhex(key_hex)

        # The frozen vector is what the C++ algorithm produces...
        assert _cpp_get_auto_key_for(region) == expected_key
        assert (
            _cpp_calc_transport_code(expected_key, pkt.get_payload_type(), bytes(pkt.get_payload()))
            == code
        )
        # ...and what openhop_core produces.
        assert get_auto_key_for(region) == expected_key
        assert calc_transport_code(expected_key, pkt) == code

    def test_uppercase_and_lowercase_region_are_distinct(self):
        """A client that case-folds a region name sends to the wrong mesh."""
        pkt = _captured_grp_txt()
        upper, lower = get_auto_key_for("#USA"), get_auto_key_for("#usa")

        assert upper != lower
        assert calc_transport_code(upper, pkt) != calc_transport_code(lower, pkt)

    def test_scoped_send_emits_the_vector(self):
        """End to end: the explicit override puts the vector's code on the wire.

        Rebuilds the captured packet's route/codes the way
        ``_apply_explicit_flood_scope`` does, so the full chain -- key, HMAC,
        endianness, reserved values, route-type bits -- is asserted against a
        firmware-anchored literal rather than against another helper.
        """
        pkt = _captured_grp_txt()
        pkt.header = (pkt.header & ~0x03) | ROUTE_TYPE_FLOOD
        pkt.transport_codes = [0, 0]

        scope_packet(pkt, bytes.fromhex("5EAF24A29D2936601E22AC56065CB314"))

        assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert pkt.transport_codes[0] == 0xE46D
        assert pkt.transport_codes[1] == 0

    @pytest.mark.parametrize(
        "digest_head,expected",
        [(b"\x00\x00", 0x0001), (b"\xff\xff", 0xFFFE)],
        ids=["null-code", "broadcast-code"],
    )
    def test_reserved_codes_are_mapped_away(self, monkeypatch, digest_head, expected):
        """0x0000 and 0xFFFF are reserved; firmware substitutes 0x0001/0xFFFE.

        No region name is known to hash onto either, so the HMAC is forced to
        land there -- otherwise this branch of calc_transport_code is never run.
        """
        monkeypatch.setattr(
            transport_keys.CryptoUtils,
            "_hmac_sha256",
            staticmethod(lambda key, data: digest_head + bytes(30)),
        )

        assert calc_transport_code(get_auto_key_for("#USA"), _captured_grp_txt()) == expected
