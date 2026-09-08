"""Tests for AnonRequestHandler / AnonRateLimiter (MeshCore 1.16.0 anon discovery).

Validates parity with firmware ``MyMesh::onAnonDataRecv`` + the regions/owner/
basic anon responders (``examples/simple_repeater/MyMesh.cpp``):
- sub-type 0x00 / >= 0x20 (a password) is delegated to the login handler;
- sub-type 0x01/0x02/0x03, route-direct, produce a RESPONSE datagram prefixed
  with ``sender_timestamp(4) + now_clock(4)``;
- the responders are route-direct only and gated by a shared rate limiter.
"""

import struct

import pytest

from openhop_core.node.handlers.anon_request import (
    ANON_REQ_TYPE_BASIC,
    ANON_REQ_TYPE_OWNER,
    ANON_REQ_TYPE_REGIONS,
    AnonRateLimiter,
    AnonRequestHandler,
)
from openhop_core.node.handlers.login_server import LoginServerHandler
from openhop_core.protocol import CryptoUtils, Identity, LocalIdentity, Packet
from openhop_core.protocol.constants import (
    MAX_PACKET_PAYLOAD,
    PAYLOAD_TYPE_ANON_REQ,
    PAYLOAD_TYPE_RESPONSE,
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
)


class TestAnonRateLimiter:
    def test_default_matches_firmware_anon_limiter(self):
        # Firmware: anon_limiter(4, 180) — max 4 per fixed 3-minute window.
        rl = AnonRateLimiter()
        assert rl._maximum == 4
        assert rl._secs == 180.0

    def test_allows_up_to_cap_then_blocks_within_window(self):
        rl = AnonRateLimiter(maximum=4, secs=180)
        # First call (start_timestamp=0) resets the window to now=1000.
        assert [rl.allow(1000.0) for _ in range(6)] == [True, True, True, True, False, False]

    def test_fixed_window_resets_after_secs(self):
        rl = AnonRateLimiter(maximum=2, secs=180)
        assert rl.allow(1000.0) is True  # reset -> count 1
        assert rl.allow(1000.0) is True  # count 2
        assert rl.allow(1000.0) is False  # count 3 > 2 -> deny
        # Still denied just before the window edge (1000 + 180 = 1180).
        assert rl.allow(1179.0) is False
        # At/after the window edge the counter resets fully.
        assert rl.allow(1180.0) is True


class TestAnonRequestHandler:
    def setup_method(self):
        self.server_identity = LocalIdentity()
        self.client_identity_local = LocalIdentity()

        self.auth_callback = lambda *a, **k: (True, 0x03)
        self.login_handler = LoginServerHandler(
            local_identity=self.server_identity,
            log_fn=lambda *_: None,
            authenticate_callback=self.auth_callback,
            is_room_server=False,
        )

        self.limiter = AnonRateLimiter(maximum=4, secs=180)
        self.handler = AnonRequestHandler(
            local_identity=self.server_identity,
            log_fn=lambda *_: None,
            login_handler=self.login_handler,
            anon_limiter=self.limiter,
            region_names_fn=lambda: "*,VHF,USA",
            owner_info_fn=lambda: ("repeater-1", "owner@example.com"),
            features_fn=lambda: 0x80,
            clock_fn=lambda: 1_700_000_000,
        )

        self.sent = []
        self.handler.set_send_packet_callback(lambda pkt, delay: self.sent.append((pkt, delay)))

    # -- request builders ---------------------------------------------------

    def _shared_secret(self):
        server_id = Identity(self.server_identity.get_public_key())
        return server_id.calc_shared_secret(self.client_identity_local.get_private_key())

    def _build_packet(self, plaintext: bytes, route_type="direct"):
        shared_secret = self._shared_secret()
        aes_key = shared_secret[:16]
        encrypted = CryptoUtils.encrypt_then_mac(aes_key, shared_secret, plaintext)

        server_pubkey = self.server_identity.get_public_key()
        payload = (
            bytes([server_pubkey[0]]) + self.client_identity_local.get_public_key() + encrypted
        )
        route = ROUTE_TYPE_FLOOD if route_type == "flood" else ROUTE_TYPE_DIRECT
        pkt = Packet()
        pkt.header = (PAYLOAD_TYPE_ANON_REQ << 2) | route
        pkt.payload = bytearray(payload)
        pkt.payload_len = len(payload)
        pkt.path = bytearray()
        pkt.path_len = 0
        return pkt

    def _build_login(self, password="admin123", route_type="flood"):
        plaintext = struct.pack("<I", 1234) + password.encode() + b"\x00"
        return self._build_packet(plaintext, route_type)

    def _build_discovery(self, subtype, route_type="direct", reply_path_byte=0x00):
        # timestamp(4) + subtype(1) + reply_path_byte(1) + (empty reply path)
        plaintext = struct.pack("<I", 4321) + bytes([subtype, reply_path_byte])
        return self._build_packet(plaintext, route_type)

    def _decrypt_response(self, response_pkt):
        client_id = Identity(self.client_identity_local.get_public_key())
        shared_secret = client_id.calc_shared_secret(self.server_identity.get_private_key())
        aes_key = shared_secret[:16]
        encrypted_part = bytes(response_pkt.payload[2:])
        return CryptoUtils.mac_then_decrypt(aes_key, shared_secret, encrypted_part)

    # -- dispatch: login regression ----------------------------------------

    @pytest.mark.asyncio
    async def test_password_subtype_routes_to_login(self):
        """A real password (>= 0x20 first byte) must still log in (item 1 regression)."""
        await self.handler(self._build_login(password="admin123", route_type="flood"))
        assert len(self.sent) == 1
        # Login flood reply is a PATH packet, not a RESPONSE datagram.
        assert self.sent[0][0].get_payload_type() != PAYLOAD_TYPE_RESPONSE

    @pytest.mark.asyncio
    async def test_zero_subtype_routes_to_login(self):
        """Empty password (sub-type byte 0x00) routes to login, not discovery."""
        await self.handler(self._build_login(password="", route_type="flood"))
        assert len(self.sent) == 1

    @pytest.mark.asyncio
    async def test_room_server_login_bypasses_subtype_dispatch(self):
        """Room-server login payload uses byte 4 as sync_since[0], not anon sub-type."""
        room_login_handler = LoginServerHandler(
            local_identity=self.server_identity,
            log_fn=lambda *_: None,
            authenticate_callback=self.auth_callback,
            is_room_server=True,
        )
        room_handler = AnonRequestHandler(
            local_identity=self.server_identity,
            log_fn=lambda *_: None,
            login_handler=room_login_handler,
            anon_limiter=self.limiter,
            region_names_fn=lambda: "*,VHF,USA",
            owner_info_fn=lambda: ("repeater-1", "owner@example.com"),
            features_fn=lambda: 0x80,
            clock_fn=lambda: 1_700_000_000,
        )
        sent = []
        room_handler.set_send_packet_callback(lambda pkt, delay: sent.append((pkt, delay)))

        # sync_since low byte 0x14 used to be misread as an unknown anon sub-type.
        plaintext = struct.pack("<II", 4321, 0x12345614) + b"\x00"
        await room_handler(self._build_packet(plaintext, route_type="flood"))

        assert len(sent) == 1

    # -- consume-vs-forward return contract (#353) --------------------------

    @pytest.mark.asyncio
    async def test_returns_true_when_decrypted_for_us(self):
        """A request that decrypts for our identity is consumed (return True)."""
        assert (await self.handler(self._build_login(route_type="flood"))).authenticated is True
        assert (
            await self.handler(self._build_discovery(ANON_REQ_TYPE_REGIONS))
        ).authenticated is True

    @pytest.mark.asyncio
    async def test_returns_true_when_for_us_but_reply_declined(self):
        """Rate-limited / non-direct discovery is still ours — consume, don't forward."""
        # Non-direct discovery: firmware only answers direct, but it decrypted for us.
        assert (
            await self.handler(self._build_discovery(ANON_REQ_TYPE_OWNER, route_type="flood"))
        ).authenticated is True
        assert self.sent == []
        # Exhaust the limiter, then a direct discovery is declined but still consumed.
        for _ in range(4):
            self.limiter.allow(1000.0)
        assert (
            await self.handler(self._build_discovery(ANON_REQ_TYPE_OWNER))
        ).authenticated is True

    @pytest.mark.asyncio
    async def test_returns_false_on_dest_hash_mismatch(self):
        """A packet addressed to a different identity is not ours (forward)."""
        pkt = self._build_login(route_type="flood")
        pkt.payload[0] = (pkt.payload[0] + 1) & 0xFF  # break the dest-hash match
        assert (await self.handler(pkt)).authenticated is False

    @pytest.mark.asyncio
    async def test_returns_false_on_decrypt_failure_collision(self):
        """dest hash matches ours but HMAC fails (hash collision): not ours, forward (#353)."""
        pkt = self._build_login(route_type="flood")
        pkt.payload[-1] ^= 0xFF  # corrupt ciphertext/MAC so decryption fails
        assert (await self.handler(pkt)).authenticated is False
        assert self.sent == []

    @pytest.mark.asyncio
    async def test_returns_false_on_short_payload(self):
        pkt = Packet()
        pkt.header = (PAYLOAD_TYPE_ANON_REQ << 2) | ROUTE_TYPE_FLOOD
        pkt.payload = bytearray([0x01, 0x02])
        pkt.payload_len = 2
        pkt.path = bytearray()
        pkt.path_len = 0
        assert (await self.handler(pkt)).authenticated is False

    # -- regions / owner / basic responders --------------------------------

    @pytest.mark.asyncio
    async def test_regions_reply(self):
        await self.handler(self._build_discovery(ANON_REQ_TYPE_REGIONS))
        assert len(self.sent) == 1
        pkt, delay = self.sent[0]
        assert delay == 300
        assert pkt.get_payload_type() == PAYLOAD_TYPE_RESPONSE
        assert pkt.is_route_direct()

        body = self._decrypt_response(pkt)
        assert body[:4] == struct.pack("<I", 4321)  # echoed sender timestamp
        assert struct.unpack("<I", body[4:8])[0] == 1_700_000_000  # our clock
        # Block cipher zero-pads; the trailing nulls act as a C-string terminator
        # (firmware excludes the null from reply_len, same as exportNamesTo).
        assert body[8:].split(b"\x00")[0].decode() == "*,VHF,USA"

    @pytest.mark.asyncio
    async def test_regions_reply_truncates_oversized_list_at_comma(self):
        """A huge region list is truncated to fit a packet, on a comma boundary."""
        self.handler.region_names_fn = lambda: ",".join(f"REGION{i:03d}" for i in range(60))
        await self.handler(self._build_discovery(ANON_REQ_TYPE_REGIONS))
        assert len(self.sent) == 1  # still replied (not dropped)

        body = self._decrypt_response(self.sent[0][0])
        names = body[8:].split(b"\x00")[0].decode()
        # Truncated, no partial/empty trailing name, and packet stayed within limits.
        assert names.startswith("REGION000,")
        assert not names.endswith(",")
        assert all(part.startswith("REGION") for part in names.split(","))
        assert self.sent[0][0].payload_len <= MAX_PACKET_PAYLOAD

    @pytest.mark.asyncio
    async def test_owner_reply(self):
        await self.handler(self._build_discovery(ANON_REQ_TYPE_OWNER))
        body = self._decrypt_response(self.sent[0][0])
        assert body[:4] == struct.pack("<I", 4321)
        assert body[8:].split(b"\x00")[0].decode() == "repeater-1\nowner@example.com"

    @pytest.mark.asyncio
    async def test_basic_reply_features_byte(self):
        await self.handler(self._build_discovery(ANON_REQ_TYPE_BASIC))
        body = self._decrypt_response(self.sent[0][0])
        # reply_len is 9 (8-byte prefix + features); block cipher pads the rest.
        assert body[8] == 0x80  # forwarding-disabled flag

    @pytest.mark.asyncio
    async def test_discovery_requires_route_direct(self):
        """Firmware only answers these sub-types when route-direct."""
        await self.handler(self._build_discovery(ANON_REQ_TYPE_REGIONS, route_type="flood"))
        assert self.sent == []

    @pytest.mark.asyncio
    async def test_reply_path_is_encoded_on_response(self):
        """A non-empty reply path is carried on the direct response packet."""
        # reply_path_byte: 1-byte hashes (hash_size 1 => high bits 0), 2 hops => 0x02
        plaintext = struct.pack("<I", 4321) + bytes([ANON_REQ_TYPE_REGIONS, 0x02, 0xAA, 0xBB])
        await self.handler(self._build_packet(plaintext, route_type="direct"))
        pkt = self.sent[0][0]
        assert pkt.path_len == 0x02
        assert bytes(pkt.path[: pkt.get_path_byte_len()]) == b"\xaa\xbb"

    @pytest.mark.asyncio
    async def test_rate_limiter_caps_discovery_replies(self):
        for _ in range(6):
            await self.handler(self._build_discovery(ANON_REQ_TYPE_OWNER))
        assert len(self.sent) == 4  # limiter cap

    @pytest.mark.asyncio
    async def test_wrong_dest_hash_ignored(self):
        pkt = self._build_discovery(ANON_REQ_TYPE_REGIONS)
        pkt.payload[0] = (self.server_identity.get_public_key()[0] + 1) & 0xFF
        await self.handler(pkt)
        assert self.sent == []
