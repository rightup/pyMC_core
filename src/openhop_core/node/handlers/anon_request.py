"""Anonymous-request dispatch handler for repeaters/room servers.

Mirrors the firmware ``MyMesh::onAnonDataRecv`` (``simple_repeater/MyMesh.cpp``):
a single ``PAYLOAD_TYPE_ANON_REQ`` packet is decrypted and the first byte after
the 4-byte timestamp (``data[4]``) selects the handler:

- ``0`` or ``>= 0x20`` -> login request (delegated to the wrapped
  :class:`LoginServerHandler`, unchanged).
- ``ANON_REQ_TYPE_REGIONS`` (0x01) -> comma-separated region names.
- ``ANON_REQ_TYPE_OWNER`` (0x02) -> ``"node_name\nowner_info"``.
- ``ANON_REQ_TYPE_BASIC`` (0x03) -> clock + a feature-flags byte.

For room-server identities, firmware parity is different from repeaters:
``simple_room_server/MyMesh.cpp`` treats all ``PAYLOAD_TYPE_ANON_REQ`` packets
as login payloads (timestamp + sync_since + password), so this handler bypasses
sub-type dispatch and delegates directly to ``LoginServerHandler`` when
``login_handler.is_room_server`` is true.

The regions/owner/basic responders only answer route-direct requests and are
gated behind a shared :class:`AnonRateLimiter` (mirroring the firmware
``anon_limiter``) so the node does not become a flood amplifier.

This is a pure protocol handler: the application supplies the actual data
(region names, owner info, feature flags, clock) via callbacks.
"""

import struct
import time
from typing import Callable, Optional, Tuple

from ...protocol import CryptoUtils, Identity, Packet, PacketBuilder
from ...protocol.constants import (
    ANON_REQ_TYPE_BASIC,
    ANON_REQ_TYPE_OWNER,
    ANON_REQ_TYPE_REGIONS,
    MAX_PACKET_PAYLOAD,
    PAYLOAD_TYPE_ANON_REQ,
    PAYLOAD_TYPE_RESPONSE,
)
from ...protocol.packet_utils import PathUtils
from ...protocol.region_map import apply_reply_scope
from .base import BaseHandler
from .login_server import LoginServerHandler
from .result import HandlerResult

# Server response delay (ms) — matches firmware SERVER_RESPONSE_DELAY.
SERVER_RESPONSE_DELAY_MS = 300


class AnonRateLimiter:
    """Fixed-window limiter for anonymous discovery replies.

    Direct port of the firmware ``RateLimiter`` (``simple_repeater/RateLimiter.h``),
    configured to match ``anon_limiter(4, 180)`` — at most 4 replies per fixed
    3-minute window. One instance is shared across all identities so the node's
    total anon-reply rate is bounded regardless of which identity is targeted.
    """

    def __init__(self, maximum: int = 4, secs: float = 180.0):
        self._maximum = maximum
        self._secs = secs
        self._start_timestamp = 0.0
        self._count = 0

    def allow(self, now: Optional[float] = None) -> bool:
        """Return ``True`` if under the cap, else ``False`` (mirrors RateLimiter.h)."""
        if now is None:
            now = time.time()
        if now < self._start_timestamp + self._secs:
            self._count += 1
            if self._count > self._maximum:
                return False  # deny
        else:  # window expired -> reset
            self._start_timestamp = now
            self._count = 1
        return True


class AnonRequestHandler(BaseHandler):
    """Decrypts ANON_REQ packets and dispatches on the sub-type byte.

    Wraps an existing :class:`LoginServerHandler` so the login/password path is
    byte-for-byte unchanged; the new regions/owner/basic responders are handled
    here using application-supplied data callbacks.
    """

    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_ANON_REQ

    def __init__(
        self,
        local_identity,
        log_fn: Callable[[str], None],
        login_handler: LoginServerHandler,
        anon_limiter: AnonRateLimiter,
        *,
        region_names_fn: Optional[Callable[[], str]] = None,
        owner_info_fn: Optional[Callable[[], Tuple[str, str]]] = None,
        features_fn: Optional[Callable[[], int]] = None,
        clock_fn: Optional[Callable[[], int]] = None,
    ):
        """Initialize the dispatcher.

        Args:
            local_identity: Server's local identity.
            log_fn: Logging function.
            login_handler: Existing login handler to delegate password logins to.
            anon_limiter: Shared rate limiter for regions/owner/basic replies.
            region_names_fn: Returns the comma-separated region-names string.
            owner_info_fn: Returns ``(node_name, owner_info)``.
            features_fn: Returns the feature-flags byte (bit0 = bridge,
                bit7 = forwarding disabled).
            clock_fn: Returns the current clock as a Unix timestamp (seconds).
        """
        self.local_identity = local_identity
        self.log = log_fn
        self.login_handler = login_handler
        self.anon_limiter = anon_limiter
        self.region_names_fn = region_names_fn
        self.owner_info_fn = owner_info_fn
        self.features_fn = features_fn
        self.clock_fn = clock_fn or (lambda: int(time.time()))
        self._send_packet_callback: Optional[Callable[[Packet, int], None]] = None

    def set_send_packet_callback(self, callback: Callable[[Packet, int], None]):
        """Set callback for sending response packets: ``callback(packet, delay_ms)``."""
        self._send_packet_callback = callback
        # Keep the wrapped login handler wired through the same sender.
        self.login_handler.set_send_packet_callback(callback)

    async def __call__(self, packet: Packet) -> HandlerResult:
        """Handle an ANON_REQ packet: decrypt, then dispatch on the sub-type byte.

        Returns an authenticated HandlerResult when the request was decrypted for
        this identity — i.e. it is genuinely addressed to us and the caller should
        consume it (this holds even when we decline to answer, e.g. a rate-limited
        or non-direct discovery query). Returns a not-for-us result when it was not
        for us (wrong dest hash, or an HMAC failure from a dest-hash collision) so
        the caller may forward/re-flood it.
        """
        # Flipped to True once decryption succeeds; used by the outer handler so a
        # post-decrypt error still counts as "for us" while a pre-decrypt error forwards.
        for_us = False
        try:
            # Parse ANON_REQ: dest_hash(1) + client_pubkey(32) + encrypted_data
            if len(packet.payload) < 34:
                return HandlerResult.not_for_us()

            dest_hash = packet.payload[0]
            our_hash = self.local_identity.get_public_key()[0]
            if dest_hash != our_hash:
                return HandlerResult.not_for_us()  # Not for us

            client_pubkey = bytes(packet.payload[1:33])
            encrypted_data = bytes(packet.payload[33:])

            client_identity = Identity(client_pubkey)
            shared_secret = client_identity.calc_shared_secret(
                self.local_identity.get_private_key()
            )
            aes_key = shared_secret[:16]

            try:
                plaintext = CryptoUtils.mac_then_decrypt(aes_key, shared_secret, encrypted_data)
            except Exception as e:
                self.log(f"[AnonReq] Failed to decrypt request: {e}")
                return HandlerResult.not_for_us()

            # Decryption succeeded: this ANON_REQ is genuinely for us. Consume it
            # from here on regardless of sub-type or whether we choose to reply.
            for_us = True

            # Firmware parity (simple_room_server): room servers do not subtype
            # dispatch ANON_REQ by plaintext byte 4. Their login payload is:
            # timestamp(4) + sync_since(4) + password...
            # so byte 4 is sync_since[0], not an anon request code.
            if getattr(self.login_handler, "is_room_server", False):
                await self.login_handler(packet)
                return HandlerResult.consumed()

            if len(plaintext) < 5:
                # Too short to carry a sub-type byte; treat as login (let it
                # apply its own length checks).
                await self.login_handler(packet)
                return HandlerResult.consumed()

            subtype = plaintext[4]

            # Login request: sub-type 0x00 or any printable ASCII (>= 0x20),
            # i.e. an actual password. Delegate verbatim to the login handler.
            if subtype == 0x00 or subtype >= 0x20:
                await self.login_handler(packet)
                return HandlerResult.consumed()

            # Regions/owner/basic discovery: route-direct only (firmware parity).
            if subtype in (ANON_REQ_TYPE_REGIONS, ANON_REQ_TYPE_OWNER, ANON_REQ_TYPE_BASIC):
                kind = {
                    ANON_REQ_TYPE_REGIONS: "regions",
                    ANON_REQ_TYPE_OWNER: "owner",
                    ANON_REQ_TYPE_BASIC: "basic",
                }[subtype]
                client_hex = client_pubkey[:4].hex()
                if not packet.is_route_direct():
                    self.log(
                        f"[AnonReq] {kind} request from {client_hex} ignored "
                        f"(not route-direct — firmware only answers direct)"
                    )
                    return HandlerResult.consumed()
                if not self.anon_limiter.allow(time.time()):
                    self.log(f"[AnonReq] {kind} request from {client_hex} rate limited, dropping")
                    return HandlerResult.consumed()
                self.log(f"[AnonReq] {kind} request from {client_hex} -> replying")
                await self._handle_discovery(
                    packet, client_identity, shared_secret, subtype, plaintext
                )
                return HandlerResult.consumed()

            # Unknown/invalid sub-type: ignore.
            self.log(f"[AnonReq] Unknown anon sub-type 0x{subtype:02X}, ignoring")
            return HandlerResult.consumed()

        except Exception as e:
            self.log(f"[AnonReq] Error handling anon request: {e}")
            return HandlerResult(authenticated=for_us)

    async def _handle_discovery(
        self,
        packet: Packet,
        client_identity: Identity,
        shared_secret: bytes,
        subtype: int,
        plaintext: bytes,
    ) -> None:
        """Build and send a regions/owner/basic discovery reply."""
        # plaintext layout: timestamp(4) + subtype(1) + reply_path_byte(1) + reply_path...
        sender_timestamp = bytes(plaintext[:4])  # echoed back verbatim as a tag
        now_clock = int(self.clock_fn()) & 0xFFFFFFFF

        # Reply-path descriptor follows the sub-type byte. Firmware relies on its
        # ``data[len] = 0`` terminator; mirror that by treating a missing
        # descriptor byte as zero (no reply path, zero-hop direct).
        reply_path_byte = plaintext[5] if len(plaintext) > 5 else 0
        reply_path_len = reply_path_byte & 0x3F
        hash_size = (reply_path_byte >> 6) + 1
        path_bytes = bytes(plaintext[6 : 6 + reply_path_len * hash_size])

        # Common prefix: sender_timestamp(4) + now_clock(4)
        reply = bytearray(sender_timestamp)
        reply += struct.pack("<I", now_clock)

        if subtype == ANON_REQ_TYPE_REGIONS:
            names = self.region_names_fn() if self.region_names_fn else ""
            name_bytes = names.encode("utf-8", errors="ignore")
            # Firmware caps the export at ``sizeof(reply_data) - 12`` and truncates
            # to fit (RegionMap::exportNamesTo). Mirror that, trimming at a comma
            # boundary so we never emit a partial region name (leave headroom for
            # the 8-byte prefix + MAC + block-cipher padding).
            max_names = MAX_PACKET_PAYLOAD - 24
            if len(name_bytes) > max_names:
                name_bytes = name_bytes[:max_names]
                cut = name_bytes.rfind(b",")
                name_bytes = name_bytes[:cut] if cut > 0 else name_bytes
            reply += name_bytes
        elif subtype == ANON_REQ_TYPE_OWNER:
            node_name, owner = self.owner_info_fn() if self.owner_info_fn else ("", "")
            reply += f"{node_name}\n{owner}".encode("utf-8", errors="ignore")
        elif subtype == ANON_REQ_TYPE_BASIC:
            features = self.features_fn() if self.features_fn else 0
            reply.append(features & 0xFF)
        else:
            return

        self._send_response(
            packet,
            client_identity,
            shared_secret,
            bytes(reply),
            reply_path_len,
            hash_size,
            path_bytes,
        )

    def _send_response(
        self,
        packet: Packet,
        client_identity: Identity,
        shared_secret: bytes,
        reply_data: bytes,
        reply_path_len: int,
        hash_size: int,
        path_bytes: bytes,
    ) -> None:
        """Encode and dispatch the RESPONSE packet (path-return for flood, direct otherwise)."""
        if self._send_packet_callback is None:
            self.log("[AnonReq] No send packet callback set, cannot send response")
            return

        try:
            if packet.is_route_flood():
                # Fallback: tell the sender the path TO here and carry the reply.
                client_hash = client_identity.get_public_key()[0]
                server_hash = self.local_identity.get_public_key()[0]
                in_path = (
                    list(packet.path[: packet.get_path_byte_len()]) if packet.path_len > 0 else []
                )
                response_pkt = PacketBuilder.create_path_return(
                    dest_hash=client_hash,
                    src_hash=server_hash,
                    secret=shared_secret,
                    path=in_path,
                    extra_type=PAYLOAD_TYPE_RESPONSE,
                    extra=reply_data,
                    path_len_encoded=(packet.path_len if packet.path_len > 0 else None),
                )
                # Accumulate this reply's path at the *request's* hash width.
                # Firmware: sendFloodReply(path, SERVER_RESPONSE_DELAY,
                # packet->getPathHashSize()) (simple_repeater onAnonDataRecv).
                # The node's own path_hash_mode governs self-originated floods,
                # not replies, so mark it applied to keep the dispatcher default
                # from stamping over the mirror. Distinct from ``hash_size``
                # above, which is the client's *reply-path* descriptor.
                #
                # This branch is currently unreachable: every discovery sub-type
                # is gated route-direct in ``__call__`` (firmware gates all three
                # the same way), and the login sub-type is delegated to
                # LoginServerHandler, which mirrors the width itself. Kept correct
                # so relaxing that gate cannot silently reintroduce the mismatch.
                in_hash_size = (
                    PathUtils.get_path_hash_size(packet.path_len)
                    if PathUtils.is_valid_path_len(packet.path_len)
                    else 1
                )
                response_pkt.apply_path_hash_mode(in_hash_size - 1, mark_applied=True)
            else:
                # Direct reply routed along the path supplied in the request.
                response_pkt = PacketBuilder.create_datagram(
                    ptype=PAYLOAD_TYPE_RESPONSE,
                    dest=client_identity,
                    local_identity=self.local_identity,
                    secret=shared_secret,
                    plaintext=reply_data,
                    route_type="direct",
                )
                if reply_path_len > 0 and path_bytes:
                    encoded = PathUtils.encode_path_len(hash_size, reply_path_len)
                    response_pkt.set_path(path_bytes, encoded)

            # Scope the flood path-return reply to the region the request arrived
            # under; a direct reply captures no region and stays plain.
            apply_reply_scope(response_pkt, packet)

            self._send_packet_callback(response_pkt, SERVER_RESPONSE_DELAY_MS)
            route = "flood" if packet.is_route_flood() else "direct"
            self.log(
                f"[AnonReq] queued RESPONSE ({len(reply_data)}B, {route}, "
                f"+{SERVER_RESPONSE_DELAY_MS}ms)"
            )
        except Exception as e:
            self.log(f"[AnonReq] Failed to send response: {e}")
