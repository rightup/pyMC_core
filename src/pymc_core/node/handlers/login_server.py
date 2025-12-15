"""Server-side login handler for mesh network authentication.

Handles ANON_REQ login packets from clients, validates passwords, manages
access control lists (ACL), and sends authentication responses.

This is the server-side counterpart to login_response.py (client-side).

Note: This handler requires ClientInfo and ClientACL classes to be provided
by the application. See examples/login_server.py for a complete implementation.
"""

import random
import struct
import time
from typing import Callable, Optional

from ...protocol import CryptoUtils, Identity, Packet, PacketBuilder
from ...protocol.constants import (
    PAYLOAD_TYPE_ANON_REQ,
    PAYLOAD_TYPE_RESPONSE,
    PUB_KEY_SIZE,
)
from .base import BaseHandler

# Response codes
RESP_SERVER_LOGIN_OK = 0x00 # Login successful

# Permission levels
PERM_ACL_GUEST = 0x01
PERM_ACL_ADMIN = 0x02
PERM_ACL_ROLE_MASK = 0x03

# Firmware version
FIRMWARE_VER_LEVEL = 1


class LoginServerHandler(BaseHandler):
    """
    Server-side handler for ANON_REQ login packets.

    Validates client credentials, manages ACL, and sends authentication responses.
    Implements the same functionality as handleLoginReq() in C++ firmware.

    Expected request format from client:
    - dest_hash (1 byte): Server's public key hash
    - client_pubkey (32 bytes): Client's public key
    - encrypted_data: Contains timestamp (4 bytes) + password (variable)

    Response format sent to client:
    - timestamp (4 bytes): Server response timestamp
    - response_code (1 byte): RESP_SERVER_LOGIN_OK (0x00) for success
    - keep_alive_interval (1 byte): Legacy field, set to 0
    - is_admin (1 byte): 1 if admin, 0 if guest
    - permissions (1 byte): Full permission bits
    - random_blob (4 bytes): Random data for packet uniqueness
    - firmware_version (1 byte): Firmware version level
    """

    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_ANON_REQ

    def __init__(
        self,
        local_identity,
        log_fn: Callable[[str], None],
        acl,  # ClientACL instance from application
        admin_password: str = "password",
        guest_password: str = "",
    ):
        """
        Initialize login server handler.

        Args:
            local_identity: Server's local identity
            log_fn: Logging function
            acl: ClientACL instance for managing authenticated clients
            admin_password: Password for admin access
            guest_password: Password for guest access (empty to disable)
        """
        self.local_identity = local_identity
        self.log = log_fn
        self.admin_password = admin_password
        self.guest_password = guest_password
        self.acl = acl

        # Callbacks
        self._on_login_success: Optional[Callable] = None
        self._on_login_failure: Optional[Callable[[Identity, str], None]] = None
        self._send_packet_callback: Optional[Callable[[Packet, int], None]] = None

    def set_login_callbacks(
        self,
        on_success: Optional[Callable] = None,
        on_failure: Optional[Callable[[Identity, str], None]] = None,
    ):
        """Set callbacks for login events.
        
        Args:
            on_success: Callback(client, is_admin) called on successful login
            on_failure: Callback(sender_identity, reason) called on failed login
        """
        self._on_login_success = on_success
        self._on_login_failure = on_failure

    def set_send_packet_callback(self, callback: Callable[[Packet, int], None]):
        """Set callback for sending response packets."""
        self._send_packet_callback = callback

    def get_acl(self):
        """Get the access control list."""
        return self.acl

    async def __call__(self, packet: Packet) -> None:
        """Handle ANON_REQ login packet from client."""
        try:
            # Parse ANON_REQ structure:
            # dest_hash(1) + client_pubkey(32) + encrypted_data
            if len(packet.payload) < 34:
                self.log("[LoginServer] ANON_REQ packet too short")
                return

            dest_hash = packet.payload[0]
            client_pubkey = bytes(packet.payload[1:33])
            encrypted_data = bytes(packet.payload[33:])

            # Verify this is for us
            our_hash = self.local_identity.get_public_key()[0]
            if dest_hash != our_hash:
                return  # Not for us

            # Create client identity
            client_identity = Identity(client_pubkey)

            # Calculate shared secret for decryption
            shared_secret = client_identity.calc_shared_secret(
                self.local_identity.get_private_key()
            )
            aes_key = shared_secret[:16]

            # Decrypt the login request
            try:
                plaintext = CryptoUtils.mac_then_decrypt(aes_key, shared_secret, encrypted_data)
            except Exception as e:
                self.log(f"[LoginServer] Failed to decrypt login request: {e}")
                if self._on_login_failure:
                    self._on_login_failure(client_identity, "Decryption failed")
                return

            if len(plaintext) < 4:
                self.log("[LoginServer] Decrypted data too short")
                return

            # Parse plaintext: timestamp(4) + password(variable)
            client_timestamp = struct.unpack("<I", plaintext[:4])[0]
            password_bytes = plaintext[4:]

            # Null-terminate password
            null_idx = password_bytes.find(b"\x00")
            if null_idx >= 0:
                password_bytes = password_bytes[:null_idx]
            password = password_bytes.decode("utf-8", errors="ignore")

            self.log(
                f"[LoginServer] Login request from {client_pubkey[:6].hex()}... "
                f"password={'<empty>' if not password else '<provided>'}"
            )

            # Handle login request
            reply_len = await self._handle_login_request(
                client_identity,
                shared_secret,
                client_timestamp,
                password,
                packet.is_route_flood(),
            )

            if reply_len == 0:
                self.log("[LoginServer] Login request rejected")
                return

            # Send response packet
            await self._send_login_response(
                client_identity, shared_secret, packet.is_route_flood(), reply_len
            )

        except Exception as e:
            self.log(f"[LoginServer] Error handling login packet: {e}")

    async def _handle_login_request(
        self,
        sender: Identity,
        secret: bytes,
        sender_timestamp: int,
        password: str,
        is_flood: bool,
    ) -> int:
        """
        Handle login request and generate response data.

        Returns:
            int: Length of response data in self.reply_data, or 0 if rejected
        """
        client = None
        sender_pubkey = sender.get_public_key()[:PUB_KEY_SIZE]

        # Check for blank password (ACL-only authentication)
        if not password:
            client = self.acl.get_client(sender_pubkey)
            if client is None:
                self.log("[LoginServer] Blank password, sender not in ACL")
                if self._on_login_failure:
                    self._on_login_failure(sender, "Not in ACL")
                return 0

        # Validate password if client not found in ACL
        if client is None:
            perms = 0

            if password == self.admin_password:
                perms = PERM_ACL_ADMIN
                self.log("[LoginServer] Admin password validated")
            elif self.guest_password and password == self.guest_password:
                perms = PERM_ACL_GUEST
                self.log("[LoginServer] Guest password validated")
            else:
                self.log(f"[LoginServer] Invalid password: {password}")
                if self._on_login_failure:
                    self._on_login_failure(sender, "Invalid password")
                return 0

            # Add client to ACL
            client = self.acl.put_client(sender, 0)
            if client is None:
                self.log("[LoginServer] FATAL: ACL full, cannot add client")
                if self._on_login_failure:
                    self._on_login_failure(sender, "ACL full")
                return 0

            # Check for replay attack
            if sender_timestamp <= client.last_timestamp:
                self.log("[LoginServer] Possible login replay attack!")
                if self._on_login_failure:
                    self._on_login_failure(sender, "Replay attack detected")
                return 0

            # Update client info
            self.log("[LoginServer] Login success!")
            client.last_timestamp = sender_timestamp
            client.last_activity = int(time.time())
            client.last_login_success = int(time.time())
            client.permissions &= ~PERM_ACL_ROLE_MASK
            client.permissions |= perms
            client.shared_secret = secret

            # Notify success
            if self._on_login_success:
                self._on_login_success(client, client.is_admin())

        # If received via flood, need to rediscover path
        if is_flood:
            client.out_path_len = -1

        # Build response data (13 bytes total)
        # timestamp(4) + response_code(1) + keep_alive(1) + is_admin(1) +
        # permissions(1) + random(4) + firmware_ver(1)
        current_time = int(time.time())
        self.reply_data = bytearray(13)

        struct.pack_into("<I", self.reply_data, 0, current_time)  # timestamp
        self.reply_data[4] = RESP_SERVER_LOGIN_OK  # response code
        self.reply_data[5] = 0  # legacy keep-alive interval
        self.reply_data[6] = 1 if client.is_admin() else 0  # is_admin flag
        self.reply_data[7] = client.permissions  # full permissions byte
        struct.pack_into("<I", self.reply_data, 8, random.randint(0, 0xFFFFFFFF))  # random blob
        self.reply_data[12] = FIRMWARE_VER_LEVEL  # firmware version

        return 13

    async def _send_login_response(
        self, client_identity: Identity, shared_secret: bytes, is_flood: bool, reply_len: int
    ):
        """Send login response packet to client."""
        if self._send_packet_callback is None:
            self.log("[LoginServer] No send packet callback set, cannot send response")
            return

        try:
            # Create RESPONSE packet with encrypted reply data
            response_pkt = PacketBuilder.create_datagram(
                PAYLOAD_TYPE_RESPONSE,
                client_identity,
                self.local_identity,
                shared_secret,
                bytes(self.reply_data[:reply_len]),
                route_type="flood" if is_flood else "direct",
            )

            # Send with delay (matches C++ SERVER_RESPONSE_DELAY)
            delay_ms = 300
            self._send_packet_callback(response_pkt, delay_ms)

            self.log(
                f"[LoginServer] Sent login response to "
                f"{client_identity.get_public_key()[:6].hex()}..."
            )

        except Exception as e:
            self.log(f"[LoginServer] Failed to send login response: {e}")
