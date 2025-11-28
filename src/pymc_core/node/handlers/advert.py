import time

from ...protocol import Identity, Packet, decode_appdata
from ...protocol.constants import (
    MAX_ADVERT_DATA_SIZE,
    PAYLOAD_TYPE_ADVERT,
    PUB_KEY_SIZE,
    SIGNATURE_SIZE,
    TIMESTAMP_SIZE,
    describe_advert_flags,
)
from ...protocol.utils import determine_contact_type_from_flags
from .base import BaseHandler


class AdvertHandler(BaseHandler):
    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_ADVERT

    def __init__(self, contacts, log_fn, identity=None, event_service=None):
        self.contacts = contacts
        self.log = log_fn
        self.identity = identity
        self.event_service = event_service

    def _extract_advert_components(self, packet: Packet):
        payload = packet.get_payload()
        header_len = PUB_KEY_SIZE + TIMESTAMP_SIZE + SIGNATURE_SIZE
        if len(payload) < header_len:
            self.log(
                f"Advert payload too short ({len(payload)} bytes, expected at least {header_len})"
            )
            return None

        sig_offset = PUB_KEY_SIZE + TIMESTAMP_SIZE
        pubkey = payload[:PUB_KEY_SIZE]
        timestamp = payload[PUB_KEY_SIZE:sig_offset]
        signature = payload[sig_offset : sig_offset + SIGNATURE_SIZE]
        appdata = payload[sig_offset + SIGNATURE_SIZE :]

        if len(appdata) > MAX_ADVERT_DATA_SIZE:
            self.log(
                f"Advert appdata too large ({len(appdata)} bytes); truncating to {MAX_ADVERT_DATA_SIZE}"
            )
            appdata = appdata[:MAX_ADVERT_DATA_SIZE]

        return pubkey, timestamp, signature, appdata

    def _verify_advert_signature(
        self, pubkey: bytes, timestamp: bytes, appdata: bytes, signature: bytes
    ) -> bool:
        try:
            peer_identity = Identity(pubkey)
        except Exception as exc:
            self.log(f"Unable to construct peer identity: {exc}")
            return False

        signed_region = pubkey + timestamp + appdata
        if not peer_identity.verify(signed_region, signature):
            return False
        return True

    async def __call__(self, packet: Packet) -> None:
        components = self._extract_advert_components(packet)
        if not components:
            return

        pubkey_bytes, timestamp_bytes, signature_bytes, appdata = components
        pubkey_hex = pubkey_bytes.hex()

        if not self._verify_advert_signature(pubkey_bytes, timestamp_bytes, appdata, signature_bytes):
            self.log(f"Rejecting advert with invalid signature (pubkey={pubkey_hex[:8]}...)")
            return

        if self.identity and pubkey_bytes == self.identity.get_public_key():
            self.log("Ignoring self advert packet")
            return

        self.log("<<< Advert packet received >>>")

        if self.contacts is not None:
            self.log(f"Processing advert for pubkey: {pubkey_hex}")
            contact = next((c for c in self.contacts.contacts if c.public_key == pubkey_hex), None)
            if contact:
                self.log(f"Peer identity already known: {contact.name}")
                contact.last_advert = int(time.time())
            else:
                self.log(f"<<< New contact discovered (pubkey={pubkey_hex[:8]}...) >>>")
                decoded = decode_appdata(appdata)

                # Extract name from decoded data
                name = decoded.get("node_name") or decoded.get("name")

                # Require valid name - ignore packet if no name present
                if not name:
                    self.log(f"Ignoring advert packet without name (pubkey={pubkey_hex[:8]}...)")
                    return

                self.log(f"Processing contact with name: {name}")
                lon = decoded.get("lon") or 0.0
                lat = decoded.get("lat") or 0.0
                flags_int = decoded.get("flags", 0)
                flags = describe_advert_flags(flags_int)
                contact_type = determine_contact_type_from_flags(flags_int)

                new_contact_data = {
                    "type": contact_type,
                    "name": name,
                    "longitude": lon,
                    "latitude": lat,
                    "flags": flags,
                    "public_key": pubkey_hex,
                    "last_advert": int(time.time()),
                }

                self.contacts.add_contact(new_contact_data)

                # Publish new contact event
                if self.event_service:
                    try:
                        from ..events import MeshEvents

                        self.event_service.publish_sync(MeshEvents.NEW_CONTACT, new_contact_data)
                    except Exception as broadcast_error:
                        self.log(f"Failed to publish new contact event: {broadcast_error}")
