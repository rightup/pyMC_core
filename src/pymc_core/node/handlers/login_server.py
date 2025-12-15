"""Server-side login handler for mesh network authentication.

Handles ANON_REQ login packets from clients, decrypts credentials, and sends
authentication responses based on application-provided authentication logic.

This is the server-side counterpart to login_response.py (client-side).

Note: This is a pure protocol handler. Authentication logic (password validation,
ACL management) should be implemented in the application.
See examples/login_server.py for a complete implementation.
"""

import random
import struct
import time
from typing import Callable, Optional

from ...protocol import CryptoUtils, Identity, Packet, PacketBuilder
from ...protocol.constants import PAYLOAD_TYPE_ANON_REQ, PAYLOAD_TYPE_RESPONSE
from .base import BaseHandler

# Response codes
RESP_SERVER_LOGIN_OK = 0x00  # Login successful
RESP_SERVER_LOGIN_FAILED = 0x01  # Login failed

# Firmware version
FIRMWARE_VER_LEVEL = 1


class LoginServerHandler(BaseHandler):
    """
    Server-side handler for ANON_REQ login packets.

    This handler performs protocol-level operations:
    - Decrypts login requests
    - Calls application authentication callback
    - Builds and sends encrypted responses

    Authentication logic (passwords, ACL, permissions) is delegated to the application.

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
        authenticate_callback: Callable[[Identity, bytes, str, int], tuple[bool, int]],
    ):
        """
        Initialize login server handler.

        Args:
            local_identity: Server's local identity
            log_fn: Logging function
            authenticate_callback: Function(client_identity, shared_secret, password, timestamp)
                                   Returns: (success: bool, permissions: int)
        """
        self.local_identity = local_identity
        self.log = log_fn
        self.authenticate = authenticate_callback
        self._send_packet_callback: Optional[Callable[[Packet, int], None]] = None

    def set_send_packet_callback(self, callback: Callable[[Packet, int], None]):
        """Set callback for sending response packets."""
        self._send_packet_callback = callback

    async def __call__(self, packet: Packet) -> None:
        """Handle ANON_REQ login packet from client."""
        try:
            # Debug: Log packet routing info
            path_data = list(packet.path[: packet.path_len]) if packet.path_len > 0 else []
            self.log(
                f"[LoginServer] Packet route flood: {packet.is_route_flood()}, "
                f"path_len: {packet.path_len}, path: {path_data}"
            )

            # Parse ANON_REQ structure: dest_hash(1) + client_pubkey(32) + encrypted_data
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

            # Create client identity and calculate shared secret
            client_identity = Identity(client_pubkey)
            shared_secret = client_identity.calc_shared_secret(
                self.local_identity.get_private_key()
            )
            aes_key = shared_secret[:16]

            # Decrypt the login request
            try:
                plaintext = CryptoUtils.mac_then_decrypt(aes_key, shared_secret, encrypted_data)
            except Exception as e:
                self.log(f"[LoginServer] Failed to decrypt login request: {e}")
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

            # Call application authentication logic
            success, permissions = self.authenticate(
                client_identity, shared_secret, password, client_timestamp
            )

            if success:
                self.log("[LoginServer] Authentication successful")
                # Send success response
                await self._send_login_response(
                    client_identity,
                    shared_secret,
                    packet.is_route_flood(),
                    RESP_SERVER_LOGIN_OK,
                    permissions,
                    packet,
                )
            else:
                self.log("[LoginServer] Authentication failed")
                # Optionally send failure response (or just ignore)
                # Most implementations just ignore failed attempts

        except Exception as e:
            self.log(f"[LoginServer] Error handling login packet: {e}")

    async def _send_login_response(
        self,
        client_identity: Identity,
        shared_secret: bytes,
        is_flood: bool,
        response_code: int,
        permissions: int,
        original_packet: Packet = None,
    ):
        """Build and send login response packet to client."""
        if self._send_packet_callback is None:
            self.log("[LoginServer] No send packet callback set, cannot send response")
            return

        try:
            # Build response data (13 bytes total)
            # timestamp(4) + response_code(1) + keep_alive(1) + is_admin(1) +
            # permissions(1) + random(4) + firmware_ver(1)
            reply_data = bytearray(13)
            current_time = int(time.time())

            struct.pack_into("<I", reply_data, 0, current_time)  # timestamp
            reply_data[4] = response_code  # response code
            reply_data[5] = 0  # legacy keep-alive interval
            # is_admin: check if permission bits include admin bit (0x02)
            reply_data[6] = 1 if (permissions & 0x02) else 0
            reply_data[7] = permissions  # full permissions byte
            struct.pack_into("<I", reply_data, 8, random.randint(0, 0xFFFFFFFF))  # random blob
            reply_data[12] = FIRMWARE_VER_LEVEL  # firmware version

            # Create response packet - different types based on original routing
            if is_flood and original_packet:
                # If original request came via flood, send PATH packet with return path
                client_hash = client_identity.get_public_key()[0]
                server_hash = self.local_identity.get_public_key()[0]
                path_list = (
                    list(original_packet.path[: original_packet.path_len])
                    if original_packet.path_len > 0
                    else []
                )

                self.log(
                    f"[LoginServer] Creating PATH response: "
                    f"client_hash=0x{client_hash:02X}, "
                    f"server_hash=0x{server_hash:02X}, path={path_list}"
                )

                response_pkt = PacketBuilder.create_path_return(
                    dest_hash=client_hash,
                    src_hash=server_hash,
                    secret=shared_secret,
                    path=path_list,
                    extra_type=PAYLOAD_TYPE_RESPONSE,
                    extra=bytes(reply_data),
                )
                packet_type_name = "PATH"
            else:
                # If original request was direct, send regular RESPONSE packet
                self.log(
                    f"[LoginServer] Creating RESPONSE datagram: "
                    f"is_flood={is_flood}, "
                    f"path_len={original_packet.path_len if original_packet else 'None'}"
                )

                response_pkt = PacketBuilder.create_datagram(
                    PAYLOAD_TYPE_RESPONSE,
                    client_identity,
                    self.local_identity,
                    shared_secret,
                    bytes(reply_data),
                    route_type="flood",  # Always use flood for sending (matches C++)
                )
                packet_type_name = "RESPONSE"

            # Send with delay (matches C++ SERVER_RESPONSE_DELAY)
            delay_ms = 300
            self._send_packet_callback(response_pkt, delay_ms)

            self.log(
                f"[LoginServer] Sent login response ({packet_type_name}) to "
                f"{client_identity.get_public_key()[:6].hex()}..."
            )

        except Exception as e:
            self.log(f"[LoginServer] Failed to send login response: {e}")
