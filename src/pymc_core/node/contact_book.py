from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from ..protocol import (
    CONTACT_TYPE_CHAT_NODE,
    CONTACT_TYPE_HYBRID,
    CONTACT_TYPE_REPEATER,
    CONTACT_TYPE_ROOM_SERVER,
    CONTACT_TYPE_UNKNOWN,
)


@dataclass
class ContactPermissions:
    allow_cli: bool = False
    allow_telemetry: bool = False
    allow_bridge: bool = False


@dataclass
class ContactRecord:
    public_key: str
    name: str = ""
    contact_type: int = CONTACT_TYPE_UNKNOWN
    flags: int = 0
    longitude: float = 0.0
    latitude: float = 0.0
    last_advert: int = 0
    tags: set[str] = field(default_factory=set)
    permissions: ContactPermissions = field(default_factory=ContactPermissions)

    def src_hash(self) -> Optional[int]:
        try:
            return bytes.fromhex(self.public_key)[0]
        except Exception:
            return None


@dataclass
class ContactBookPreferences:
    allow_read_only: bool = False
    bridge_enabled: bool = False


class ContactBook:
    """Contact store with MeshCore-style ACL helpers."""

    def __init__(
        self,
        contacts: Optional[Iterable[ContactRecord | dict]] = None,
        prefs: Optional[ContactBookPreferences] = None,
    ) -> None:
        self.prefs = prefs or ContactBookPreferences()
        self.contacts: List[ContactRecord] = []
        if contacts:
            for entry in contacts:
                self.add_contact(entry)

    # ------------------------------------------------------------------
    # Contact CRUD
    # ------------------------------------------------------------------
    def add_contact(self, contact: ContactRecord | dict) -> ContactRecord:
        record = self._normalize_contact(contact)
        existing = self.get_by_public_key(record.public_key)
        if existing:
            self._update_contact(existing, record)
            return existing

        self._apply_default_permissions(record)
        self.contacts.append(record)
        return record

    def list_contacts(self) -> List[ContactRecord]:
        return list(self.contacts)

    def get_by_public_key(self, pubkey_hex: str) -> Optional[ContactRecord]:
        for contact in self.contacts:
            if contact.public_key.lower() == pubkey_hex.lower():
                return contact
        return None

    def get_by_hash(self, hash_byte: int) -> Optional[ContactRecord]:
        for contact in self.contacts:
            if contact.src_hash() == hash_byte:
                return contact
        return None

    def get_by_name(self, name: str) -> Optional[ContactRecord]:
        for contact in self.contacts:
            if contact.name == name:
                return contact
        return None

    def remove_contact(self, pubkey_hex: str) -> bool:
        before = len(self.contacts)
        self.contacts = [c for c in self.contacts if c.public_key.lower() != pubkey_hex.lower()]
        return len(self.contacts) != before

    # ------------------------------------------------------------------
    # Preferences / ACL management
    # ------------------------------------------------------------------
    def update_preferences(
        self,
        *,
        allow_read_only: Optional[bool] = None,
        bridge_enabled: Optional[bool] = None,
    ) -> None:
        if allow_read_only is not None:
            self.prefs.allow_read_only = allow_read_only
        if bridge_enabled is not None:
            self.prefs.bridge_enabled = bridge_enabled
        for contact in self.contacts:
            self._apply_default_permissions(contact, overwrite=False)

    def set_permissions(
        self,
        pubkey_hex: str,
        *,
        allow_cli: Optional[bool] = None,
        allow_telemetry: Optional[bool] = None,
        allow_bridge: Optional[bool] = None,
    ) -> None:
        contact = self.get_by_public_key(pubkey_hex)
        if not contact:
            raise ValueError(f"Unknown contact {pubkey_hex}")
        if allow_cli is not None:
            contact.permissions.allow_cli = allow_cli
        if allow_telemetry is not None:
            contact.permissions.allow_telemetry = allow_telemetry
        if allow_bridge is not None:
            contact.permissions.allow_bridge = allow_bridge

    # ------------------------------------------------------------------
    # Permission helpers
    # ------------------------------------------------------------------
    def can_execute_cli(self, contact: ContactRecord | int | str) -> bool:
        record = self._resolve_contact(contact)
        return bool(record and record.permissions.allow_cli)

    def can_receive_telemetry(self, contact: ContactRecord | int | str) -> bool:
        record = self._resolve_contact(contact)
        return bool(record and record.permissions.allow_telemetry)

    def can_use_bridge(self, contact: ContactRecord | int | str) -> bool:
        record = self._resolve_contact(contact)
        return bool(record and record.permissions.allow_bridge)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _normalize_contact(self, contact: ContactRecord | dict) -> ContactRecord:
        if isinstance(contact, ContactRecord):
            return contact

        return ContactRecord(
            public_key=contact["public_key"],
            name=contact.get("name", ""),
            contact_type=contact.get("type", contact.get("contact_type", CONTACT_TYPE_UNKNOWN)),
            flags=contact.get("flags", 0),
            longitude=contact.get("longitude", 0.0),
            latitude=contact.get("latitude", 0.0),
            last_advert=contact.get("last_advert", 0),
        )

    def _update_contact(self, dest: ContactRecord, src: ContactRecord) -> None:
        dest.name = src.name or dest.name
        dest.contact_type = src.contact_type or dest.contact_type
        dest.flags = src.flags or dest.flags
        dest.longitude = src.longitude or dest.longitude
        dest.latitude = src.latitude or dest.latitude
        dest.last_advert = src.last_advert or dest.last_advert
        if src.tags:
            dest.tags.update(src.tags)
        if src.permissions != dest.permissions:
            dest.permissions = src.permissions

    def _apply_default_permissions(self, contact: ContactRecord, *, overwrite: bool = True) -> None:
        if overwrite:
            perms = ContactPermissions()
        else:
            perms = contact.permissions
            perms.allow_cli = False
            perms.allow_telemetry = False
            perms.allow_bridge = False
        if contact.contact_type in (CONTACT_TYPE_ROOM_SERVER, CONTACT_TYPE_HYBRID):
            perms.allow_cli = True
            perms.allow_telemetry = True
        elif contact.contact_type == CONTACT_TYPE_CHAT_NODE and self.prefs.allow_read_only:
            perms.allow_cli = True
        if self.prefs.bridge_enabled and contact.contact_type in (
            CONTACT_TYPE_ROOM_SERVER,
            CONTACT_TYPE_HYBRID,
        ):
            perms.allow_bridge = True
        contact.permissions = perms

    def _resolve_contact(self, ref: ContactRecord | int | str) -> Optional[ContactRecord]:
        if isinstance(ref, ContactRecord):
            return ref
        if isinstance(ref, int):
            return self.get_by_hash(ref)
        return self.get_by_public_key(ref)