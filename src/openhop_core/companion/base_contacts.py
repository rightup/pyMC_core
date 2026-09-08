"""Contact, channel, path, and advert-store logic of CompanionBase."""

from __future__ import annotations

import logging
import time
from typing import Optional

from ..protocol import Packet, PacketBuilder, is_self_advert
from ..protocol.constants import (
    ADVERT_FLAG_HAS_LOCATION,
    ADVERT_FLAG_HAS_NAME,
    PAYLOAD_TYPE_ADVERT,
    ROUTE_TYPE_FLOOD,
)
from ..protocol.packet_utils import PathUtils
from .base_support import adv_type_to_flags
from .constants import (
    ADV_TYPE_CHAT,
    ADV_TYPE_NONE,
    ADV_TYPE_REPEATER,
    ADV_TYPE_ROOM,
    ADV_TYPE_SENSOR,
    ADVERT_LOC_SHARE,
    AUTOADD_CHAT,
    AUTOADD_OVERWRITE_OLDEST,
    AUTOADD_REPEATER,
    AUTOADD_ROOM,
    AUTOADD_SENSOR,
)
from .models import AdvertPath, Channel, Contact

logger = logging.getLogger("CompanionBase")


class _ContactChannelMixin:
    """Part of :class:`CompanionBase` (see companion_base.py)."""

    # -------------------------------------------------------------------------
    # Contact Management
    # -------------------------------------------------------------------------

    def get_contacts(self, since: int = 0) -> list[Contact]:
        """Return all contacts, optionally filtered by modification time.

        Transient/anon contacts (ADV_TYPE_NONE) created for non-contact anon
        requests are excluded — they are never synced to the app, mirroring the
        firmware contacts iterator in MyMesh::checkSerialInterface.
        """
        return [c for c in self.contacts.get_all(since=since) if c.adv_type != ADV_TYPE_NONE]

    def get_contact_count(self) -> int:
        """Return the total real-contact count (firmware getNumContacts()).

        Independent of any ``since`` filter; used for the CONTACTS_START total.
        Excludes transient/anon entries, mirroring get_contacts.
        """
        return self.contacts.count()

    def get_contact_by_key(self, pub_key: bytes) -> Optional[Contact]:
        """Look up a contact by its full 32-byte public key."""
        return self.contacts.get_by_key(pub_key)

    def get_contact_by_name(self, name: str) -> Optional[Contact]:
        """Look up a contact by name, returning the full Contact or None."""
        proxy = self.contacts.get_by_name(name)
        if proxy:
            return self.contacts.get_by_key(proxy.public_key_bytes)
        return None

    def add_update_contact(self, contact: Contact) -> bool:
        """Add or update a contact, setting lastmod if unset."""
        if contact.lastmod == 0:
            contact.lastmod = int(time.time())
        return self.contacts.add(contact)

    def remove_contact(self, pub_key: bytes) -> bool:
        """Remove a contact by public key."""
        return self.contacts.remove(pub_key)

    def export_contact(self, pub_key: Optional[bytes] = None) -> Optional[bytes]:
        """Export a signed MeshCore ADVERT for self or a stored peer.

        MeshCore makes peer exports from the raw, verified ADVERT blob retained
        when that contact was received.  The self export is the sole exception:
        the firmware creates and signs a fresh flood ADVERT for the local node.
        """
        if pub_key is None:
            flags = adv_type_to_flags(self.prefs.adv_type) | ADVERT_FLAG_HAS_NAME
            lat, lon = 0.0, 0.0
            if self.prefs.advert_loc_policy == ADVERT_LOC_SHARE:
                flags |= ADVERT_FLAG_HAS_LOCATION
                lat, lon = self.prefs.latitude, self.prefs.longitude
            packet = PacketBuilder.create_advert(
                local_identity=self._identity,
                name=self.prefs.node_name,
                lat=lat,
                lon=lon,
                flags=flags,
                route_type="flood",
            )
            return packet.write_to()
        contact = self.contacts.get_by_key(pub_key)
        if not contact or not contact.last_advert_packet:
            return None
        return bytes(contact.last_advert_packet)

    def import_contact(self, packet_data: bytes) -> bool:
        """Queue a raw ADVERT for normal verified advert handling.

        This intentionally follows ``BaseChatMesh::importContact``: command
        success means the packet parsed and is an ADVERT, not that its signature
        was accepted.  Signature validation, contact policy, and storage happen
        through the regular advert handler in a deferred loopback task.
        """
        try:
            raw_packet = bytes(packet_data)
            packet = Packet()
            if not packet.read_from(raw_packet):
                return False
        except (IndexError, TypeError, ValueError) as exc:
            logger.warning("Invalid contact import packet: %s", exc)
            return False

        if packet.get_payload_type() != PAYLOAD_TYPE_ADVERT:
            logger.warning("Import packet is not an ADVERT")
            return False

        # MeshCore ORs the flood route bit before its pending loopback.  Do not
        # re-parse serialized bytes after this mutation: an imported direct
        # packet may change route encoding, while firmware keeps the parsed
        # Packet object intact for onRecvPacket().
        packet.header |= ROUTE_TYPE_FLOOD
        try:
            self._spawn_background_task(
                self._loopback_imported_advert(packet), "import contact loopback"
            )
        except RuntimeError:
            # The firmware command runs from its event loop; a synchronous
            # caller without one cannot faithfully queue the deferred loopback.
            logger.warning("Cannot import contact without a running event loop")
            return False
        return True

    async def _loopback_imported_advert(self, packet: Packet) -> None:
        """Deliver an imported ADVERT through the normal verified handler."""
        payload = packet.get_payload()
        if is_self_advert(payload, self._identity.get_public_key()):
            # Mesh::onRecvPacket ignores a self ADVERT after import, while the
            # command itself has already succeeded because its packet parsed.
            return
        handler = self._get_advert_handler()
        if handler is None:
            logger.error("No advert handler available for imported contact")
            return
        await handler(packet)

    # -------------------------------------------------------------------------
    # Path & Routing
    # -------------------------------------------------------------------------

    def reset_path(self, pub_key: bytes) -> bool:
        """Reset the outbound routing path for a contact."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return False
        contact.out_path_len = -1
        contact.out_path = b""
        self.contacts.update(contact)
        return True

    def get_advert_path(self, pub_key_prefix: bytes) -> Optional[AdvertPath]:
        """Look up a cached advert path by public key prefix."""
        return self.path_cache.get_by_prefix(pub_key_prefix)

    # -------------------------------------------------------------------------
    # Channel Management
    # -------------------------------------------------------------------------

    def get_channel(self, idx: int) -> Optional[Channel]:
        """Return the channel at the given index, or None."""
        return self.channels.get(idx)

    def set_channel(self, idx: int, name: str, secret: bytes) -> bool:
        """Set a channel at the given index with name and 32-byte secret."""
        # MeshCore DataStore uses 32-byte secret; GroupTextHandler uses up to 32 for HMAC
        if len(secret) < 32:
            secret = secret + b"\x00" * (32 - len(secret))
        elif len(secret) > 32:
            secret = secret[:32]
        ok = self.channels.set(idx, Channel(name=name[:32], secret=secret))
        if ok:
            ch = self.channels.get(idx)
            self._schedule_fire_callbacks("channel_updated", idx, ch)
        return ok

    def remove_channel(self, idx: int) -> bool:
        """Remove the channel at the given index. Fires on_channel_updated(idx, None)."""
        ok = self.channels.remove(idx)
        if ok:
            self._schedule_fire_callbacks("channel_updated", idx, None)
        return ok

    # -------------------------------------------------------------------------
    # Auto-Add Configuration
    # -------------------------------------------------------------------------

    def get_autoadd_config(self) -> int:
        """Return the current auto-add configuration bitmask."""
        return self.prefs.autoadd_config

    def get_autoadd_max_hops(self) -> int:
        """Return the auto-add maximum-hop limit (0 = no limit)."""
        return self.prefs.autoadd_max_hops

    def set_autoadd_config(self, config: int, max_hops: Optional[int] = None) -> None:
        """Set the auto-add configuration bitmask and optional max-hop limit.

        Mirrors firmware CMD_SET_AUTOADD_CONFIG: the config byte is always
        stored; the max-hop byte is optional and capped at 64 when present.
        """
        self.prefs.autoadd_config = config
        if max_hops is not None:
            self.prefs.autoadd_max_hops = min(max_hops, 64)
        self._save_prefs()

    # Map ADV_TYPE_* → AUTOADD_* bitmask bits (mirrors C++ shouldAutoAddContactType)
    _AUTOADD_TYPE_MAP: dict[int, int] = {
        ADV_TYPE_CHAT: AUTOADD_CHAT,  # 1 → 0x02
        ADV_TYPE_REPEATER: AUTOADD_REPEATER,  # 2 → 0x04
        ADV_TYPE_ROOM: AUTOADD_ROOM,  # 3 → 0x08
        ADV_TYPE_SENSOR: AUTOADD_SENSOR,  # 4 → 0x10
    }

    def should_auto_add_contact_type(self, contact_type: int) -> bool:
        """Check if a contact type should be auto-added based on current preferences.

        Mirrors C++ MyMesh::shouldAutoAddContactType (MyMesh.cpp:281-304).
        """
        # manual_add_contacts bit 0 == 0  →  auto-add ALL types
        if (self.prefs.manual_add_contacts & 1) == 0:
            return True
        # Selective mode: check the type-specific bit in autoadd_config
        type_bit = self._AUTOADD_TYPE_MAP.get(contact_type, 0)
        return bool(self.prefs.autoadd_config & type_bit) if type_bit else False

    def should_overwrite_when_full(self) -> bool:
        """Check if overwrite-oldest is enabled. Mirrors C++ shouldOverwriteWhenFull."""
        return bool(self.prefs.autoadd_config & AUTOADD_OVERWRITE_OLDEST)

    async def _apply_advert_to_stores(
        self,
        contact: Contact,
        inbound_path: Optional[bytes] = None,
        *,
        path_len_encoded: Optional[int] = None,
    ) -> Optional[Contact]:
        """Apply advert to ContactStore and PathCache. Shared by Bridge and NODE_DISCOVERED.

        Mirrors C++ BaseChatMesh::onAdvertRecv (existing update, auto-add filter,
        overwrite when full). Returns the Contact if added or updated, None otherwise.
        Path cache is updated for all valid contacts (pub_key >= 7, name non-empty).

        Args:
            path_len_encoded: Encoded path_len byte from the packet. If None,
                falls back to len(inbound_path) (assumes 1-byte hashes).
        """
        try:
            if len(contact.public_key) < 7 or not contact.name:
                return None
            inbound_path = inbound_path or b""
            advert_path_len = (
                path_len_encoded if path_len_encoded is not None else len(inbound_path)
            )
            self.path_cache.update(
                AdvertPath(
                    public_key_prefix=contact.public_key[:7],
                    name=contact.name,
                    path_len=advert_path_len,
                    path=inbound_path,
                    recv_timestamp=int(time.time()),
                )
            )
            existing = self.contacts.get_by_key(contact.public_key)
            if existing is not None:
                contact.out_path_len = existing.out_path_len
                contact.out_path = existing.out_path
                contact.flags = existing.flags
                contact.sync_since = existing.sync_since
                if contact.last_advert_packet is None:
                    contact.last_advert_packet = existing.last_advert_packet
                self.contacts.update(contact)
                return contact
            if not self.should_auto_add_contact_type(contact.adv_type):
                logger.debug("Auto-add filtered: type %d not allowed", contact.adv_type)
                return None
            # Hop-count cap (BaseChatMesh::onAdvertRecv): for a new contact, reject
            # auto-add when the advert is at least ``autoadd_max_hops`` hops away.
            # 0 = no limit; 1 = direct only (0 hops). Existing contacts are updated
            # above regardless. The caller still notifies the client for every
            # valid advert, matching the firmware's onDiscoveredContact.
            max_hops = self.prefs.autoadd_max_hops
            if max_hops > 0:
                if path_len_encoded is not None:
                    hop_count = PathUtils.get_path_hash_count(path_len_encoded)
                else:
                    hop_count = len(inbound_path)
                if hop_count >= max_hops:
                    logger.debug("Auto-add filtered: %d hops >= max_hops %d", hop_count, max_hops)
                    return None
            if self.should_overwrite_when_full() and self.contacts.is_full():
                ok, overwritten = self.contacts.add_or_overwrite(contact)
                if ok and overwritten:
                    await self._fire_callbacks("contact_deleted", overwritten)
                elif not ok:
                    await self._fire_callbacks("contacts_full")
                return contact if ok else None
            added = self.contacts.add(contact)
            if not added and self.contacts.is_full():
                await self._fire_callbacks("contacts_full")
            return contact if added else None
        except Exception as e:
            logger.error("Error applying advert to stores: %s", e)
            return None
