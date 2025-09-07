import hashlib
import logging
import struct
import time
from typing import Any, Optional, Sequence, Union

from . import CryptoUtils, Packet
from .constants import (
    ADVERT_FLAG_HAS_FEATURE1,
    ADVERT_FLAG_HAS_FEATURE2,
    ADVERT_FLAG_HAS_LOCATION,
    ADVERT_FLAG_HAS_NAME,
    ADVERT_FLAG_IS_CHAT_NODE,
    CIPHER_BLOCK_SIZE,
    CONTACT_TYPE_ROOM_SERVER,
    MAX_PACKET_PAYLOAD,
    MAX_PATH_SIZE,
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_ANON_REQ,
    PAYLOAD_TYPE_GRP_DATA,
    PAYLOAD_TYPE_GRP_TXT,
    PAYLOAD_TYPE_PATH,
    PAYLOAD_TYPE_REQ,
    PAYLOAD_TYPE_RESPONSE,
    PAYLOAD_TYPE_TRACE,
    PAYLOAD_TYPE_TXT_MSG,
    PAYLOAD_VER_1,
    REQ_TYPE_GET_TELEMETRY_DATA,
    TELEM_PERM_BASE,
    TELEM_PERM_ENVIRONMENT,
    TELEM_PERM_LOCATION,
)
from .identity import Identity, LocalIdentity
from .packet_utils import PacketDataUtils, PacketHeaderUtils, PacketValidationUtils, RouteTypeUtils

logger = logging.getLogger(__name__)


class PacketBuilder:
    """
    Factory class for building mesh network packets with encryption and routing.

    Provides static methods to construct various types of mesh network packets
    including text messages, advertisements, acknowledgements, and protocol requests.
    Handles encryption, authentication, and proper packet formatting for the mesh protocol.

    All methods are static and thread-safe. Packets are constructed with proper
    headers, encryption, and routing information for reliable mesh communication.
    """

    @staticmethod
    def _hash_byte(pubkey: bytes) -> int:
        """Compute hash byte from public key for packet addressing."""
        return PacketDataUtils.hash_byte(pubkey)

    @staticmethod
    def _create_packet(header: int, payload: bytes) -> Packet:
        """Create a packet with the given header and payload."""
        pkt = Packet()
        pkt.header = header
        pkt.payload = bytearray(payload)
        pkt.payload_len = len(payload)
        return pkt

    @staticmethod
    def _hash_bytes(pubkey: bytes, local_identity: LocalIdentity) -> bytearray:
        """Compute hash bytes for packet authentication using public key and local identity."""
        return PacketDataUtils.hash_bytes(pubkey, local_identity.get_public_key())

    @staticmethod
    def _encrypt_payload(aes_key: bytes, shared_secret: bytes, plaintext: bytes) -> bytes:
        """Encrypt plaintext payload using AES key and shared secret."""
        return CryptoUtils.encrypt_then_mac(aes_key, shared_secret, plaintext)

    @staticmethod
    def _get_route_type_value(route_type: str, has_routing_path: bool = False) -> int:
        """Get route type value with optional routing path flag."""
        return RouteTypeUtils.get_route_type_value(route_type, has_routing_path)

    @staticmethod
    def _get_timestamp() -> int:
        """Get current timestamp for packet timing."""
        return int(time.time())

    @staticmethod
    def _calc_shared_secret_and_key(
        contact: Any, local_identity: LocalIdentity
    ) -> tuple[bytes, bytes]:
        """Calculate shared secret and AES key from contact - reduces duplication."""
        pubkey = bytes.fromhex(contact.public_key)
        peer_identity = Identity(pubkey)
        shared_secret = peer_identity.calc_shared_secret(local_identity.get_private_key())
        aes_key = shared_secret[:16]
        return shared_secret, aes_key

    @staticmethod
    def _create_header(
        payload_type: int,
        route_type: str = "direct",
        has_routing_path: bool = False,
        version: int = PAYLOAD_VER_1,
    ) -> int:
        """Create packet header with payload type, route type, and version."""
        route_value = RouteTypeUtils.get_route_type_value(route_type, has_routing_path)
        return PacketHeaderUtils.create_header(payload_type, route_value, version)

    @staticmethod
    def _create_encrypted_payload(
        contact: Any, local_identity: LocalIdentity, plaintext: bytes
    ) -> tuple[bytes, bytes, bytes]:
        """Create encrypted payload for contact-based packets with authentication."""
        shared_secret, aes_key = PacketBuilder._calc_shared_secret_and_key(contact, local_identity)
        encrypted = PacketBuilder._encrypt_payload(aes_key, shared_secret, plaintext)
        payload = (
            PacketBuilder._hash_bytes(bytes.fromhex(contact.public_key), local_identity) + encrypted
        )
        return payload, shared_secret, aes_key

    @staticmethod
    def _pack_timestamp_data(timestamp: int, *data_parts) -> bytes:
        """Pack timestamp with additional data parts into bytes."""
        return PacketDataUtils.pack_timestamp_data(timestamp, *data_parts)

    @staticmethod
    def _validate_routing_path(routing_path: list) -> list:
        """Extract and centralize the 30-line path validation logic."""
        return PacketValidationUtils.validate_routing_path(routing_path)

    @staticmethod
    def _encode_advert_data(
        name: str,
        lat: float = 0.0,
        lon: float = 0.0,
        feature1: int = 0,
        feature2: int = 0,
        flags: int = 0,
    ) -> bytes:
        """Encodes advertisement metadata including location and features."""
        buf = bytearray()

        # Set flags based on what data is provided
        final_flags = flags
        if lat != 0.0 or lon != 0.0:
            final_flags |= ADVERT_FLAG_HAS_LOCATION
        if feature1 != 0:
            final_flags |= ADVERT_FLAG_HAS_FEATURE1
        if feature2 != 0:
            final_flags |= ADVERT_FLAG_HAS_FEATURE2
        if name:
            final_flags |= ADVERT_FLAG_HAS_NAME

        buf.append(final_flags)

        # Add location data if present
        if final_flags & ADVERT_FLAG_HAS_LOCATION:
            lat_int = int(lat * 1000000)
            lon_int = int(lon * 1000000)
            buf += struct.pack("<i", lat_int)
            buf += struct.pack("<i", lon_int)

        # Add feature data if present
        if final_flags & ADVERT_FLAG_HAS_FEATURE1:
            buf += struct.pack("<H", feature1)

        if final_flags & ADVERT_FLAG_HAS_FEATURE2:
            buf += struct.pack("<H", feature2)

        # Add name if present
        if final_flags & ADVERT_FLAG_HAS_NAME:
            name_bytes = name.encode("utf-8")[:31] + b"\x00"
            buf += name_bytes.ljust(32, b"\x00")
        else:
            buf += bytes(32)

        return bytes(buf)

    @staticmethod
    def create_ack(
        pubkey: bytes, timestamp: int, attempt: int, text: Union[str, bytes, memoryview]
    ) -> Packet:
        """
        Create an acknowledgement packet for message delivery confirmation.

        Generates a compact ACK packet that confirms receipt of a message with
        the specified timestamp and attempt number. The ACK includes a truncated
        hash for efficient validation.

        Args:
            pubkey: 32-byte public key of the message sender.
            timestamp: Unix timestamp from the original message.
            attempt: Retry attempt number (0-3) from the original message.
            text: Confirmation text or additional ACK data.

        Returns:
            Packet: ACK packet ready for transmission.

        Raises:
            ValueError: If pubkey is not exactly 32 bytes.

        Example:
            ```python
            pubkey = bytes(32)  # 32-byte public key
            packet = PacketBuilder.create_ack(pubkey, 1234567890, 0, "delivered")
            packet.get_payload_type()
            # Returns: 2
            ```
        """
        if not isinstance(pubkey, bytes) or len(pubkey) != 32:
            raise ValueError("pubkey must be 32 bytes")

        text_bytes = (
            text.strip("\x00").encode("utf-8")
            if isinstance(text, str)
            else bytes(text).strip(b"\x00")
        )
        temp = PacketBuilder._pack_timestamp_data(timestamp, attempt, text_bytes)
        digest = CryptoUtils.sha256(temp + pubkey)

        header = PacketBuilder._create_header(PAYLOAD_TYPE_ACK)
        return PacketBuilder._create_packet(header, digest[:4])

    @staticmethod
    def create_self_advert(
        local_identity: Any,
        name: str,
        lat: float = 0.0,
        lon: float = 0.0,
        feature1: int = 0,
        feature2: int = 0,
        route_type: str = "flood",
    ) -> Packet:
        """
        Create a self-advertisement packet for the local node.

        Convenience method that creates an advertisement packet with the
        IS_CHAT_NODE flag set, announcing the local node's presence.

        Args:
            local_identity: Local node identity for signing.
            name: Display name for the node.
            lat: Latitude in decimal degrees.
            lon: Longitude in decimal degrees.
            feature1: First feature flag value.
            feature2: Second feature flag value.
            route_type: Routing method ("flood" or "direct").

        Returns:
            Packet: Signed advertisement packet with chat node flag.
        """
        return PacketBuilder.create_advert(
            local_identity,
            name,
            lat,
            lon,
            feature1,
            feature2,
            ADVERT_FLAG_IS_CHAT_NODE,
            route_type,
        )

    @staticmethod
    def create_advert(
        local_identity: Any,
        name: str,
        lat: float = 0.0,
        lon: float = 0.0,
        feature1: int = 0,
        feature2: int = 0,
        flags: int = ADVERT_FLAG_IS_CHAT_NODE,
        route_type: str = "flood",
    ) -> Packet:
        """
        Create a user advertisement packet with location and feature information.

        Generates a signed advertisement packet announcing the node's presence,
        location, and capabilities to the mesh network. The packet includes
        cryptographic signatures for authenticity.

        Args:
            local_identity: Local node identity for signing the advertisement.
            name: Display name for the node (max 31 characters).
            lat: Latitude in decimal degrees (optional).
            lon: Longitude in decimal degrees (optional).
            feature1: First feature flag value (optional).
            feature2: Second feature flag value (optional).
            flags: Advertisement flags (default: chat node).
            route_type: Routing method ("flood" or "direct").

        Returns:
            Packet: Signed advertisement packet ready for broadcast.

        Example:
            ```python
            from pymc_core.protocol.identity import LocalIdentity
            identity = LocalIdentity()
            packet = PacketBuilder.create_advert(identity, "MyNode", 37.7749, -122.4194)
            packet.get_payload_type()
            # Returns: 3
            ```
        """
        timestamp = PacketBuilder._get_timestamp()
        pubkey = local_identity.get_public_key()
        ts_bytes = struct.pack("<I", timestamp)
        appdata = PacketBuilder._encode_advert_data(name, lat, lon, feature1, feature2, flags)

        # Sign the first part of the payload (pubkey + timestamp + first 32 bytes of appdata)
        body_to_sign = pubkey + ts_bytes + appdata[:32]
        signature = local_identity.sign(body_to_sign)

        # Create payload: pubkey + timestamp + signature + appdata
        payload = pubkey + ts_bytes + signature + appdata

        header = PacketBuilder._create_header(PAYLOAD_TYPE_ADVERT, route_type)
        return PacketBuilder._create_packet(header, payload)

    @staticmethod
    def create_flood_advert(*args, **kwargs) -> Packet:
        """
        Create an advertisement packet with flood routing.

        Convenience method that creates an advertisement with route_type="flood".
        All other arguments are passed through to create_advert().

        Returns:
            Packet: Advertisement packet configured for flood routing.
        """
        return PacketBuilder.create_advert(*args, **kwargs, route_type="flood")

    @staticmethod
    def create_direct_advert(*args, **kwargs) -> Packet:
        """
        Create an advertisement packet with direct routing.

        Convenience method that creates an advertisement with route_type="direct".
        All other arguments are passed through to create_advert().

        Returns:
            Packet: Advertisement packet configured for direct routing.
        """
        return PacketBuilder.create_advert(*args, **kwargs, route_type="direct")

    @staticmethod
    def create_datagram(
        ptype: int,
        dest: Identity,
        local_identity: LocalIdentity,
        secret: bytes,
        plaintext: bytes,
        route_type: str = "direct",
    ) -> Packet:
        """
        Create an encrypted datagram packet for secure communication.

        Generates a generic encrypted packet for text messages, requests, or responses
        with end-to-end encryption using the provided secret.

        Args:
            ptype: Payload type (TXT_MSG, REQ, or RESPONSE).
            dest: Destination identity for the packet.
            local_identity: Local node identity for authentication.
            secret: Shared secret for encryption.
            plaintext: Unencrypted payload data.
            route_type: Routing method ("direct" or "flood").

        Returns:
            Packet: Encrypted datagram packet ready for transmission.

        Raises:
            ValueError: If payload type is not supported.

        Example:
            ```python
            from pymc_core.protocol.identity import Identity, LocalIdentity
            dest = Identity(bytes(32))
            local = LocalIdentity()
            secret = bytes(32)
            packet = PacketBuilder.create_datagram(0, dest, local, secret, b"hello")
            packet.get_payload_type()
            # Returns: 0
            ```
        """
        if ptype not in (PAYLOAD_TYPE_TXT_MSG, PAYLOAD_TYPE_REQ, PAYLOAD_TYPE_RESPONSE):
            raise ValueError("invalid payload type")

        aes_key = CryptoUtils.sha256(secret)
        cipher = PacketBuilder._encrypt_payload(aes_key, secret, plaintext)
        payload = PacketBuilder._hash_bytes(dest.get_public_key(), local_identity) + cipher

        header = PacketBuilder._create_header(ptype, route_type)
        return PacketBuilder._create_packet(header, payload)

    @staticmethod
    def create_anon_req(
        dest: Any,
        local_identity: LocalIdentity,
        shared_secret: bytes,
        plaintext: bytes,
        route_type: str = "transport_flood",
    ) -> Packet:
        """
        Create an anonymous request packet for unauthenticated communication.

        Generates a packet for anonymous requests that don't require full
        authentication, such as initial contact or public services.

        Args:
            dest: Destination identity or contact.
            local_identity: Local node identity.
            shared_secret: Pre-computed shared secret for encryption.
            plaintext: Unencrypted request data.
            route_type: Routing method (default: transport_flood).

        Returns:
            Packet: Anonymous request packet with encryption.
        """
        header = PacketBuilder._create_header(PAYLOAD_TYPE_ANON_REQ, route_type)

        dest_hash = PacketBuilder._hash_byte(dest.get_public_key())
        aes_key = shared_secret[:16]
        cipher = PacketBuilder._encrypt_payload(aes_key, shared_secret, plaintext)
        payload = bytearray([dest_hash]) + local_identity.get_public_key() + cipher

        pkt = PacketBuilder._create_packet(header, payload)
        pkt.path_len = 0
        pkt.path = bytearray()
        return pkt

    @staticmethod
    def create_login_packet(contact: Any, local_identity: LocalIdentity, password: str) -> Packet:
        """
        Create a login packet for repeater authentication.

        Generates an encrypted login packet containing credentials for
        authenticating with a repeater node or room server.

        Args:
            contact: Contact information for the repeater.
            local_identity: Local node identity for encryption.
            password: Authentication password (truncated to 15 chars).

        Returns:
            Packet: Encrypted login packet ready for transmission.
        """
        timestamp = PacketBuilder._get_timestamp()
        password_truncated = password[:15]
        password_bytes = password_truncated.encode("utf-8")

        is_room = getattr(contact, "type", 0) == CONTACT_TYPE_ROOM_SERVER

        if is_room:
            sync_since = getattr(contact, "sync_since", 0)  # Use contact's sync_since or 0
            plaintext = PacketBuilder._pack_timestamp_data(
                timestamp, struct.pack("<I", sync_since), password_bytes
            )
        else:
            plaintext = PacketBuilder._pack_timestamp_data(timestamp, password_bytes)

        contact_pubkey = bytes.fromhex(contact.public_key)
        contact_identity = Identity(contact_pubkey)
        shared_secret = contact_identity.calc_shared_secret(local_identity.get_private_key())

        return PacketBuilder.create_anon_req(
            contact_identity, local_identity, shared_secret, plaintext, "direct"
        )

    @staticmethod
    def create_group_datagram(
        group_name: str,
        local_identity: LocalIdentity,
        message: str,
        sender_name: str = "Unknown",
        channels_config: Optional[Any] = None,
    ) -> Packet:
        """
        Create an encrypted group message for a specified channel.

        Generates a group message packet encrypted with the channel's shared secret,
        allowing secure communication within a named group or channel.

        Args:
            group_name: Name of the channel to send the message to.
            local_identity: Local node identity (unused in group messages).
            message: Message text to send to the group.
            sender_name: Display name of the sender (default: "Unknown").
            channels_config: List of channel configurations with secrets.

        Returns:
            Packet: Encrypted group message packet.

        Raises:
            ValueError: If channels_config is None or channel not found.

        Example:
            ```python
            channels = [{"name": "general", "secret": "secret123"}]
            from pymc_core.protocol.identity import LocalIdentity
            identity = LocalIdentity()
            packet = PacketBuilder.create_group_datagram(
                "general", identity, "Hello group!", "Alice", channels)
            packet.get_payload_type()
            # Returns: 6
            ```
        """
        if channels_config is None:
            raise ValueError(
                "channels_config parameter is required - protocol layer cannot access database"
            )

        channel = next((ch for ch in channels_config if ch.get("name") == group_name), None)
        if not channel:
            raise ValueError(f"Channel '{group_name}' not found in provided channels_config")

        secret_bytes = (
            bytes.fromhex(channel["secret"])
            if isinstance(channel["secret"], str)
            else channel["secret"].encode("utf-8")
        )
        channel_hash = hashlib.sha256(secret_bytes).digest()[0]
        secret_bytes = (secret_bytes + b"\x00" * 32)[:32]

        timestamp, flags = PacketBuilder._get_timestamp(), 0x00
        content = f"{sender_name}: {message}".encode("utf-8")
        plaintext = PacketBuilder._pack_timestamp_data(timestamp, flags, content)

        ciphertext = CryptoUtils._aes_encrypt(secret_bytes[:16], plaintext)
        mac = CryptoUtils._hmac_sha256(secret_bytes, ciphertext)[:2]
        payload = bytearray([channel_hash]) + mac + ciphertext

        header = PacketBuilder._create_header(PAYLOAD_TYPE_GRP_TXT)
        return PacketBuilder._create_packet(header, payload)

    @staticmethod
    def create_group_data_packet(
        ptype: int,
        channel_hash: int,
        channel_secret: bytes,
        plaintext: bytes,
        secret: bytes,
    ) -> Packet:
        """
        Create a group packet with generic encrypted data.

        Generates a group packet for text messages or data with channel-specific
        encryption using the provided shared secret.

        Args:
            ptype: Payload type (GRP_TXT or GRP_DATA).
            channel_hash: Single byte hash identifying the channel.
            channel_secret: Channel-specific encryption secret.
            plaintext: Unencrypted data to send.
            secret: Additional secret for encryption.

        Returns:
            Packet: Encrypted group data packet.

        Raises:
            ValueError: If payload type is not supported for groups.
        """
        if ptype not in (PAYLOAD_TYPE_GRP_TXT, PAYLOAD_TYPE_GRP_DATA):
            raise ValueError("invalid payload type")

        aes_key = CryptoUtils.sha256(secret)
        cipher = PacketBuilder._encrypt_payload(aes_key, secret, plaintext)
        payload = bytearray([channel_hash]) + cipher

        header = PacketBuilder._create_header(ptype)
        return PacketBuilder._create_packet(header, payload)

    @staticmethod
    def create_trace(
        tag: int, auth_code: int, flags: int, path: Optional[Sequence[int]] = None
    ) -> Packet:
        """
        Create a trace packet for network diagnostics and path discovery.

        Generates a trace packet that can follow network paths for debugging
        and network topology discovery. Compatible with C++ implementation.

        Args:
            tag: Random identifier set by initiator (uint32_t).
            auth_code: Optional authentication code (uint32_t).
            flags: Control flags for trace behavior (uint8_t).
            path: Optional list of node IDs for the trace path.

        Returns:
            Packet: Trace packet with proper wire format.

        Example:
            ```python
            packet = PacketBuilder.create_trace(12345, 0, 1, [1, 2, 3])
            packet.get_payload_type()
            # Returns: 7
            ```
        """
        # Create base payload: tag(4) + auth_code(4) + flags(1)
        payload = struct.pack("<IIB", tag, auth_code, flags)

        # Append path to payload if provided
        if path:
            payload += bytes(path)

        # Create packet with proper structure
        pkt = Packet()
        pkt.header = PacketBuilder._create_header(PAYLOAD_TYPE_TRACE, route_type="direct")
        pkt.path_len = 0  # No routing path in packet path field
        pkt.path = bytearray()  # Empty routing path
        pkt.payload = bytearray(payload)
        pkt.payload_len = len(payload)
        return pkt

    @staticmethod
    def create_path_return(
        dest_hash: int,
        src_hash: int,
        secret: bytes,
        path: Sequence[int],
        extra_type: int = 0xFF,
        extra: bytes = b"",
    ) -> Packet:
        """
        Create a secure return path packet with optional metadata.

        Generates an encrypted packet containing a return path for secure
        two-way communication, with optional additional data.

        Args:
            dest_hash: Destination node hash (1 byte).
            src_hash: Source node hash (1 byte).
            secret: Shared secret for encryption.
            path: Sequence of node hashes for the return path.
            extra_type: Type identifier for extra data (default: 0xFF).
            extra: Additional binary data to include.

        Returns:
            Packet: Encrypted return path packet.

        Raises:
            ValueError: If combined path and extra data exceed packet limits.
        """
        if len(path) + len(extra) + 5 > (MAX_PACKET_PAYLOAD - 2 - CIPHER_BLOCK_SIZE):
            raise ValueError("Combined path/extra too long")

        inner = bytes([len(path)]) + bytes(path) + bytes([extra_type]) + extra
        cipher = PacketBuilder._encrypt_payload(CryptoUtils.sha256(secret), secret, inner)
        payload = bytearray([dest_hash, src_hash]) + cipher

        header = PacketBuilder._create_header(PAYLOAD_TYPE_PATH)
        return PacketBuilder._create_packet(header, payload)

    @staticmethod
    def create_text_message(
        contact: Any,
        local_identity: LocalIdentity,
        message: str,
        attempt: int = 0,
        message_type: str = "direct",
        out_path: Optional[list] = None,
    ) -> tuple[Packet, int]:
        """
        Create a secure text message with encryption and CRC validation.

        Generates an encrypted text message packet with proper authentication,
        CRC calculation for ACK verification, and optional routing path.

        Args:
            contact: The contact to send the message to.
            local_identity: The local node identity for encryption.
            message: The message text to send.
            attempt: The attempt number for retries (0-3).
            message_type: The message routing type ("direct" or "flood").
            out_path: The optional routing path for directed messages.

        Returns:
            tuple: (packet, crc) - The encrypted packet and CRC for ACK verification.

        Example:
            ```python
            from pymc_core.protocol.identity import LocalIdentity
            identity = LocalIdentity()
            contact = type('Contact', (), {'public_key': '00'*32, 'out_path': []})()
            packet, crc = PacketBuilder.create_text_message(
                contact, identity, "Hello!", 0, "direct")
            packet.get_payload_type()
            # Returns: 0
            ```
        """
        attempt &= 0x03
        timestamp = PacketBuilder._get_timestamp()

        # Use  timestamp+data packing
        plaintext = PacketBuilder._pack_timestamp_data(timestamp, attempt, message, b"\x00")

        # Use  encryption and payload creation
        payload, shared_secret, aes_key = PacketBuilder._create_encrypted_payload(
            contact, local_identity, plaintext
        )

        # Calculate CRC using centralized packing
        crc_input = PacketBuilder._pack_timestamp_data(timestamp, attempt, message)
        ack_crc = int.from_bytes(
            CryptoUtils.sha256(crc_input + local_identity.get_public_key())[:4],
            "little",
        )

        # Use  path validation
        routing_path = (
            out_path if out_path is not None else (contact.out_path if contact.out_path else [])
        )
        routing_path = PacketBuilder._validate_routing_path(routing_path)

        # Create packet with validated path
        pkt = Packet()
        has_path = bool(routing_path and len(routing_path) > 0)
        pkt.header = PacketBuilder._create_header(PAYLOAD_TYPE_TXT_MSG, message_type, has_path)

        if routing_path and len(routing_path) > 0:
            if len(routing_path) > MAX_PATH_SIZE:
                logger.warning(
                    f"Path length {len(routing_path)} exceeds maximum {MAX_PATH_SIZE}, truncating"
                )
                routing_path = routing_path[:MAX_PATH_SIZE]
            pkt.path = bytearray(routing_path)
            pkt.path_len = len(pkt.path)
        else:
            pkt.path_len, pkt.path = 0, bytearray()

        pkt.payload = bytearray(payload)
        pkt.payload_len = len(payload)
        return pkt, ack_crc
        attempt &= 0x03
        timestamp = PacketBuilder._get_timestamp()

        # Use  timestamp+data packing
        plaintext = PacketBuilder._pack_timestamp_data(timestamp, attempt, message, b"\x00")

        # Use  encryption and payload creation
        payload, shared_secret, aes_key = PacketBuilder._create_encrypted_payload(
            contact, local_identity, plaintext
        )

        # Calculate CRC using centralized packing
        crc_input = PacketBuilder._pack_timestamp_data(timestamp, attempt, message)
        ack_crc = int.from_bytes(
            CryptoUtils.sha256(crc_input + local_identity.get_public_key())[:4],
            "little",
        )

        # Use  path validation
        routing_path = (
            out_path if out_path is not None else (contact.out_path if contact.out_path else [])
        )
        routing_path = PacketBuilder._validate_routing_path(routing_path)

        # Create packet with validated path
        pkt = Packet()
        has_path = bool(routing_path and len(routing_path) > 0)
        pkt.header = PacketBuilder._create_header(PAYLOAD_TYPE_TXT_MSG, message_type, has_path)

        if routing_path and len(routing_path) > 0:
            if len(routing_path) > MAX_PATH_SIZE:
                logger.warning(
                    f"Path length {len(routing_path)} exceeds maximum {MAX_PATH_SIZE}, truncating"
                )
                routing_path = routing_path[:MAX_PATH_SIZE]

            pkt.path = bytearray(routing_path)
            pkt.path_len = len(pkt.path)
        else:
            pkt.path_len, pkt.path = 0, bytearray()

        pkt.payload = bytearray(payload)
        pkt.payload_len = len(payload)
        return pkt, ack_crc

    @staticmethod
    def create_protocol_request(
        contact: Any,
        local_identity: LocalIdentity,
        protocol_code: int,
        data: bytes = b"",
        timestamp: Optional[int] = None,
    ) -> tuple[Packet, int]:
        """
        Create a protocol request packet for repeater commands.

        Generates an encrypted protocol request for administrative commands
        or special operations with repeaters and infrastructure nodes.

        Args:
            contact: The repeater contact to send the request to.
            local_identity: The local node identity for encryption.
            protocol_code: The protocol command code.
            data: Additional binary data for the request.
            timestamp: Optional timestamp (uses current time if None).

        Returns:
            tuple: (packet, timestamp) - The created packet and the timestamp used.

        Example:
            ```python
            from pymc_core.protocol.identity import LocalIdentity
            identity = LocalIdentity()
            contact = type('Contact', (), {'public_key': '00'*32})()
            packet, ts = PacketBuilder.create_protocol_request(
                contact, identity, 1, b"data")
            packet.get_payload_type()
            # Returns: 4
            ```
        """
        if timestamp is None:
            timestamp = PacketBuilder._get_timestamp()

        # Use  timestamp+data packing
        plaintext = PacketBuilder._pack_timestamp_data(timestamp, protocol_code, data)

        # Use  encryption and payload creation
        payload, shared_secret, aes_key = PacketBuilder._create_encrypted_payload(
            contact, local_identity, plaintext
        )

        header = PacketBuilder._create_header(PAYLOAD_TYPE_REQ)
        packet = PacketBuilder._create_packet(header, payload)
        return packet, timestamp

    @staticmethod
    def create_logout_packet(contact: Any, local_identity: LocalIdentity) -> tuple[Packet, int]:
        """
        Create a logout packet for repeater authentication.

        Generates a logout message to terminate an authenticated session
        with a repeater node.

        Args:
            contact: The repeater contact to logout from.
            local_identity: The local node identity for encryption.

        Returns:
            tuple: (packet, crc) - The logout packet and CRC for verification.
        """
        return PacketBuilder.create_text_message(
            contact, local_identity, "logout", attempt=0, message_type="direct"
        )

    # ---------- Telemetry  ----------

    @staticmethod
    def _compute_inverse_perm_mask(
        want_base=True, want_location=True, want_environment=True
    ) -> int:
        remove_mask = 0
        if not want_base:
            remove_mask |= TELEM_PERM_BASE
        if not want_location:
            remove_mask |= TELEM_PERM_LOCATION
        if not want_environment:
            remove_mask |= TELEM_PERM_ENVIRONMENT
        return remove_mask & 0xFF

    @staticmethod
    def create_telem_request(
        contact: Any,
        local_identity: LocalIdentity,
        *,
        want_base: bool = True,
        want_location: bool = True,
        want_environment: bool = True,
        include_entropy: bool = True,
        route_type: str = "direct",
    ) -> tuple[Packet, int]:
        """
        Create a telemetry request packet for sensor data collection.

        Generates a request for telemetry data from a node, allowing selective
        retrieval of base metrics, location data, and environmental sensors.

        Args:
            contact: The node to request telemetry from.
            local_identity: The local node identity for encryption.
            want_base: Include basic telemetry metrics.
            want_location: Include location/GPS data.
            want_environment: Include environmental sensors.
            include_entropy: Include entropy/randomness data.
            route_type: Routing method ("direct" or "flood").

        Returns:
            tuple: (packet, timestamp) - The telemetry request packet and timestamp.

        Example:
            ```python
            from pymc_core.protocol.identity import LocalIdentity
            identity = LocalIdentity()
            contact = type('Contact', (), {'public_key': '00'*32})()
            packet, ts = PacketBuilder.create_telem_request(
                contact, identity, want_location=False)
            packet.get_payload_type()
            # Returns: 4
            ```
        """
        inv = PacketBuilder._compute_inverse_perm_mask(want_base, want_location, want_environment)

        return PacketBuilder.create_protocol_request(
            contact=contact,
            local_identity=local_identity,
            protocol_code=REQ_TYPE_GET_TELEMETRY_DATA,
            data=bytes([inv]),  # Just the permission mask as additional data
        )
