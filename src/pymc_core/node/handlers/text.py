import asyncio

from ...protocol import CryptoUtils, Identity, Packet, PacketBuilder
from ...protocol.constants import PAYLOAD_TYPE_TXT_MSG
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
    ):
        self.local_identity = local_identity
        self.contacts = contacts
        self.log = log_fn
        self.send_packet = send_packet_fn
        self.event_service = event_service  # Event service for broadcasting
        self.command_response_callback = None  # Callback for command responses

    def set_command_response_callback(self, callback):
        """Set callback function for command responses."""
        self.command_response_callback = callback

    async def __call__(self, packet: Packet) -> None:
        self.log("   TEXT handler called: processing TXT_MSG packet")
        self.log(f"   Payload length: {len(packet.payload) if packet.payload else 0}")
        if hasattr(packet, "_rssi"):
            self.log(
                f"   RSSI: {packet._rssi}dBm, SNR: {getattr(packet, '_snr', 'N/A')}dB"
            )

        if len(packet.payload) < 4:
            self.log("TXT_MSG payload too short to decrypt")
            return

        src_hash = packet.payload[1]
        matched_contact = None
        self.log(f"FULL hex of payload: {packet.payload.hex()}")
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

        self.log(
            f"Matched contact: {matched_contact.name} ({matched_contact.public_key[:8]}…)"
        )

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

        # Strip null terminator for ACK calculation (like firmware)
        message_text_for_ack = message_body.rstrip(b"\x00")

        pubkey = bytes.fromhex(matched_contact.public_key)

        ack_packet = PacketBuilder.create_ack(
            pubkey=pubkey,
            timestamp=int.from_bytes(timestamp, "little"),
            attempt=attempt,
            text=message_text_for_ack,  # Use stripped version for ACK
        )

        # Send ACK with logging
        self.log("Sending ACK for message")
        for _ in range(1):
            await self.send_packet(ack_packet, wait_for_ack=False)
            await asyncio.sleep(0.5)

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
        message_timestamp = int.from_bytes(timestamp, "little")

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
