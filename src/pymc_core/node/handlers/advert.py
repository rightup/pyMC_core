import time

from ...protocol import Packet, decode_appdata
from ...protocol.constants import PAYLOAD_TYPE_ADVERT, PUB_KEY_SIZE, describe_advert_flags
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

    async def __call__(self, packet: Packet) -> None:
        pubkey_bytes = packet.payload[:PUB_KEY_SIZE]
        pubkey_hex = pubkey_bytes.hex()

        self.log("<<< Advert packet received >>>")

        if self.contacts is not None:
            self.log(f"Processing advert for pubkey: {pubkey_hex}")
            contact = next((c for c in self.contacts.contacts if c.public_key == pubkey_hex), None)
            if contact:
                self.log(f"Peer identity already known: {contact.name}")
                contact.last_advert = int(time.time())
            else:
                self.log(f"<<< New contact discovered (pubkey={pubkey_hex[:8]}...) >>>")
                appdata = packet.get_payload_app_data()
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
