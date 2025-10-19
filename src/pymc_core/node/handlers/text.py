import asyncio
import struct

from ...protocol import CryptoUtils, Identity, Packet, PacketBuilder, PacketTimingUtils
from ...protocol.constants import PAYLOAD_TYPE_TXT_MSG, PAYLOAD_TYPE_ACK
from .base import BaseHandler


class TextMessageHandler(BaseHandler):
    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_TXT_MSG

    def __init__(
        self,
        local_identity,
        contacts,
        log_fn,
        send_packet_fn,
        event_service=None,
        radio_config=None,
    ):
        self.local_identity = local_identity
        self.contacts = contacts
        self.log = log_fn
        self.send_packet = send_packet_fn
        self.event_service = event_service  # Event service for broadcasting
        self.command_response_callback = None  # Callback for command responses
        self.radio_config = radio_config or {}  # Radio configuration for airtime calculations

    def set_command_response_callback(self, callback):
        """Set callback function for command responses."""
        self.command_response_callback = callback

    async def __call__(self, packet: Packet) -> None:
        if len(packet.payload) < 4:
            self.log("TXT_MSG payload too short to decrypt")
            return

        src_hash = packet.payload[1]
        matched_contact = None
        for contact in self.contacts.contacts:
            try:
                if bytes.fromhex(contact.public_key)[0] == src_hash:
                    matched_contact = contact
                    break
            except Exception as err:
                self.log(f"Error reading contact key: {err}")

        if not matched_contact:
            self.log(f"No contact found for src hash: {src_hash:02X}")
            return

        peer_id = Identity(bytes.fromhex(matched_contact.public_key))
        shared_secret = peer_id.calc_shared_secret(
            self.local_identity.get_private_key()
        )
        aes_key = shared_secret[:16]
        payload = packet.payload[2:]  # Skip dest_hash and src_hash

        try:
            decrypted = CryptoUtils.mac_then_decrypt(aes_key, shared_secret, payload)
        except Exception as err:
            self.log(f"Decryption failed: {err}")
            return

        if len(decrypted) < 5:  # timestamp(4) + flags(1) minimum
            self.log("Decrypted message too short for CRC calculation")
            return

        # Extract fields from decrypted data
        timestamp = decrypted[:4]  # First 4 bytes are the timestamp
        flags = decrypted[4]  # 5th byte contains flags
        attempt = flags & 0x03  # Last 2 bits are the attempt number
        message_body = decrypted[5:]  # Rest is the message content

        pubkey = bytes.fromhex(matched_contact.public_key)
        timestamp_int = int.from_bytes(timestamp, "little")

        # Determine message routing type from packet header
        route_type = packet.header & 0x03  # Route type is in bits 0-1
        is_flood = route_type == 1  # ROUTE_TYPE_FLOOD = 1
        
        self.log(f"Processing message - route_type: {route_type}, is_flood: {is_flood}, timestamp: {timestamp_int}")

        # Create appropriate ACK response
        if is_flood:
            # FLOOD messages use PATH ACK responses with ACK hash in extra payload
            text_bytes = message_body.rstrip(b"\x00")
            
            # Calculate ACK hash using standard method (same as DIRECT messages)
            pack_data = PacketBuilder._pack_timestamp_data(timestamp_int, attempt, text_bytes)
            ack_hash = CryptoUtils.sha256(pack_data + pubkey)[:4]
            
            # Create PATH ACK response
            incoming_path = list(packet.path if hasattr(packet, 'path') else [])
            
            ack_packet = PacketBuilder.create_path_return(
                dest_hash=PacketBuilder._hash_byte(pubkey),
                src_hash=PacketBuilder._hash_byte(self.local_identity.get_public_key()),
                secret=shared_secret,
                path=incoming_path,
                extra_type=PAYLOAD_TYPE_ACK,
                extra=ack_hash
            )

         
            ack_airtime = PacketTimingUtils.estimate_airtime_ms(len(ack_packet.write_to()), self.radio_config)
            ack_timeout_ms = PacketTimingUtils.calc_flood_timeout_ms(ack_airtime) / 1000.0  # Convert to seconds

        else:
            # DIRECT messages use discrete ACK packets
            ack_packet = PacketBuilder.create_ack(
                pubkey=pubkey,
                timestamp=timestamp_int,
                attempt=attempt,
                text=message_body.rstrip(b"\x00"),
            )

          
            ack_airtime = PacketTimingUtils.estimate_airtime_ms(len(ack_packet.write_to()), self.radio_config)
            # For direct ACKs, path_len is typically 0 (direct response)
            ack_timeout_ms = PacketTimingUtils.calc_direct_timeout_ms(ack_airtime, 0) / 1000.0  # Convert to seconds

        async def send_delayed_ack():
            await asyncio.sleep(ack_timeout_ms)
            try:
                await self.send_packet(ack_packet, wait_for_ack=False)
                self.log(f"ACK packet sent successfully (delayed {ack_timeout_ms*1000:.1f}ms) for timestamp {timestamp_int}")
            except Exception as ack_send_error:
                self.log(f"Failed to send ACK packet: {ack_send_error}")

        # Schedule ACK to be sent after delay (non-blocking)
        asyncio.create_task(send_delayed_ack())

        decoded_msg = message_body.decode("utf-8", "replace")
        self.log(f"Received TXT_MSG: {decoded_msg}")

        # Check if this is a command response (if callback is set)
        if self.command_response_callback:
            try:
                self.command_response_callback(decoded_msg, matched_contact)
                self.log(
                    f"Command response captured from {matched_contact.name}: {decoded_msg}"
                )
                # Don't save command responses to regular message database
                return
            except Exception as e:
                self.log(f"Error in command response callback: {e}")
                # Continue with normal message processing if callback fails

        # Save the incoming message by publishing event for app to handle
        message_timestamp = timestamp_int

        # Create message event data for the app to handle storage and deduplication
        normalized_timestamp = (message_timestamp // 1000) * 1000
        content_hash = (
            hash(f"{matched_contact.name}_{decoded_msg}_{normalized_timestamp}")
            & 0xFFFFFFFF
        )
        message_id = f"rx_{normalized_timestamp}_{content_hash:08x}"

        # Publish new message event - let app handle storage and deduplication
        if self.event_service:
            try:
                from ..events import MeshEvents

                message_data = {
                    "message_id": message_id,
                    "contact_name": matched_contact.name,
                    "contact_pubkey": matched_contact.public_key,
                    "message_text": decoded_msg,
                    "is_outgoing": False,
                    "timestamp": message_timestamp,
                    "delivery_status": "received",
                    "network_info": {
                        "rssi": packet.rssi,
                        "snr": packet.snr,
                        "hops": 1,
                    },
                    "sender_name": matched_contact.name,
                    "is_read": False,
                }

                # Publish new message event for app to handle database storage
                self.event_service.publish_sync(MeshEvents.NEW_MESSAGE, message_data)
                self.log(f"TextHandler: Published new message event: {message_id}")

            except Exception as broadcast_error:
                self.log(f"Failed to publish new message event: {broadcast_error}")

        # Set packet.decrypted for ACK processing
        packet.decrypted = {"text": decoded_msg}
