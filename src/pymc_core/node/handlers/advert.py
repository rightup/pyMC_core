import time
from typing import Any, Dict, Optional

from ...protocol import Identity, Packet, decode_appdata
from ...protocol.constants import (
    MAX_ADVERT_DATA_SIZE,
    PAYLOAD_TYPE_ADVERT,
    PUB_KEY_SIZE,
    SIGNATURE_SIZE,
    TIMESTAMP_SIZE,
    describe_advert_flags,
)
from ...protocol.utils import determine_contact_type_from_flags, get_contact_type_name
from .base import BaseHandler


class AdvertHandler(BaseHandler):
    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_ADVERT

    def __init__(self, log_fn):
        self.log = log_fn

    def _extract_advert_components(self, packet: Packet):
        """Extract and validate advert packet components."""
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
                f"Advert appdata too large ({len(appdata)} bytes). "
                f"Truncating to {MAX_ADVERT_DATA_SIZE}"
            )
            appdata = appdata[:MAX_ADVERT_DATA_SIZE]

        return pubkey, timestamp, signature, appdata

    def _verify_advert_signature(
        self, pubkey: bytes, timestamp: bytes, appdata: bytes, signature: bytes
    ) -> bool:
        """Verify the cryptographic signature of the advert packet."""
        try:
            if len(pubkey) != PUB_KEY_SIZE:
                self.log(
                    f"Invalid public key length: {len(pubkey)} bytes (expected {PUB_KEY_SIZE})"
                )
                return False

            if len(signature) != SIGNATURE_SIZE:
                self.log(
                    f"Invalid signature length: {len(signature)} bytes (expected {SIGNATURE_SIZE})"
                )
                return False

            peer_identity = Identity(pubkey)
        except ValueError as exc:
            self.log(f"Malformed public key in advert - invalid key format: {exc}")
            return False
        except Exception as exc:
            exc_type = type(exc).__name__
            self.log(
                f"Cryptographic error constructing identity from public key: " f"{exc_type}: {exc}"
            )
            return False

        signed_region = pubkey + timestamp + appdata
        if not peer_identity.verify(signed_region, signature):
            pubkey_prefix = pubkey[:8].hex()
            self.log(f"Signature verification failed for advert " f"(pubkey={pubkey_prefix}...)")
            return False
        return True

    async def __call__(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """Process advert packet and return parsed data with signature verification."""
        try:
            # Extract and validate packet components
            components = self._extract_advert_components(packet)
            if not components:
                return None

            pubkey_bytes, timestamp_bytes, signature_bytes, appdata = components
            pubkey_hex = pubkey_bytes.hex()

            # Verify cryptographic signature
            if not self._verify_advert_signature(
                pubkey_bytes, timestamp_bytes, appdata, signature_bytes
            ):
                self.log(f"Rejecting advert with invalid signature (pubkey={pubkey_hex[:8]}...)")
                return None

            self.log(f"Processing advert for pubkey: {pubkey_hex[:16]}...")

            # Decode application data
            decoded = decode_appdata(appdata)

            # Extract name from decoded data
            name = decoded.get("node_name") or decoded.get("name")
            if not name:
                self.log(f"Ignoring advert without name (pubkey={pubkey_hex[:8]}...)")
                return None

            # Extract location and flags
            lon = decoded.get("longitude") or decoded.get("lon") or 0.0
            lat = decoded.get("latitude") or decoded.get("lat") or 0.0
            flags_int = decoded.get("flags", 0)
            flags_description = describe_advert_flags(flags_int)
            contact_type_id = determine_contact_type_from_flags(flags_int)
            contact_type = get_contact_type_name(contact_type_id)

            # Build parsed advert data
            advert_data = {
                "public_key": pubkey_hex,
                "name": name,
                "longitude": lon,
                "latitude": lat,
                "flags": flags_int,
                "flags_description": flags_description,
                "contact_type_id": contact_type_id,
                "contact_type": contact_type,
                "timestamp": int(time.time()),
                "snr": packet._snr if hasattr(packet, "_snr") else 0.0,
                "rssi": packet._rssi if hasattr(packet, "_rssi") else 0,
                "valid": True,
            }

            self.log(f"Parsed advert: {name} ({contact_type})")
            return advert_data

        except Exception as e:
            self.log(f"Error parsing advert packet: {e}")
            return None
