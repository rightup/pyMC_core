"""Contact command handlers (get/add/remove/reset/import/export/share)."""

import logging
import struct
import time

from ...protocol.packet_utils import PathUtils
from ..constants import (
    CONTACT_NAME_SIZE,
    ERR_CODE_ILLEGAL_ARG,
    ERR_CODE_NOT_FOUND,
    ERR_CODE_TABLE_FULL,
    MAX_PATH_SIZE,
    OUT_PATH_UNKNOWN,
    PUB_KEY_SIZE,
    RESP_CODE_ADVERT_PATH,
    RESP_CODE_CONTACT,
    RESP_CODE_CONTACTS_START,
    RESP_CODE_END_OF_CONTACTS,
    RESP_CODE_EXPORT_CONTACT,
)
from ..models import Contact
from .frames import _encode_contact_fields

logger = logging.getLogger("CompanionFrameServer")


class _ContactCommandsMixin:
    """Contact-related _cmd_* handlers of :class:`CompanionFrameServer`."""

    async def _cmd_get_contacts(self, data: bytes) -> None:
        since = struct.unpack("<I", data[:4])[0] if len(data) >= 4 else 0
        contacts = self.bridge.get_contacts(since=since)
        # Firmware reports the total contact-table count here (MyMesh
        # CMD_GET_CONTACTS uses getNumContacts()), independent of the 'since'
        # filter; only the emitted frames and the end watermark are filtered.
        total = self.bridge.get_contact_count()
        self._write_frame(bytes([RESP_CODE_CONTACTS_START]) + struct.pack("<I", total))
        for i, c in enumerate(contacts):
            self._write_contact_frame(c)
        most_recent = max((c.lastmod for c in contacts), default=0)
        self._write_frame(bytes([RESP_CODE_END_OF_CONTACTS]) + struct.pack("<I", most_recent))

    def _write_contact_frame(self, c: Contact) -> None:
        """Encode and write a single RESP_CODE_CONTACT frame."""
        self._write_frame(bytes([RESP_CODE_CONTACT]) + _encode_contact_fields(c))

    async def _cmd_get_contact_by_key(self, data: bytes) -> None:
        if len(data) < PUB_KEY_SIZE:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pubkey = data[:PUB_KEY_SIZE]
        contact = (
            self.bridge.contacts.get_by_key(pubkey)
            if hasattr(self.bridge.contacts, "get_by_key")
            else None
        )
        if not contact:
            self._write_err(ERR_CODE_NOT_FOUND)
            return
        self._write_contact_frame(contact)

    async def _cmd_add_update_contact(self, data: bytes) -> None:
        if len(data) < 36:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pubkey = data[0:PUB_KEY_SIZE]
        adv_type = data[32]
        flags = data[33]
        # The wire byte is uint8_t (MeshCore CMD_ADD_UPDATE_CONTACT): its top two
        # bits encode the per-hop hash width, so values 0x80-0xFE are valid paths.
        # Read it unsigned and map only the 0xFF sentinel to the internal
        # unknown-path representation (-1).
        out_path_len = struct.unpack_from("<B", data, 34)[0]
        if out_path_len == OUT_PATH_UNKNOWN:
            out_path_len = -1
        out_path_end = 35 + MAX_PATH_SIZE
        path_field = data[35 : min(len(data), out_path_end)]
        # MeshCore copies all 64 bytes from the frame, but only the byte count
        # encoded in out_path_len is part of the route. A zero byte within that
        # range is a valid hash byte, not fixed-field padding.
        path_byte_len = PathUtils.get_path_byte_len(out_path_len) if out_path_len >= 0 else 0
        out_path = path_field[:path_byte_len]
        name_start = 35 + MAX_PATH_SIZE
        name_end = name_start + CONTACT_NAME_SIZE
        if len(data) >= name_end:
            name_raw = data[name_start:name_end]
        elif len(data) > name_start:
            name_raw = data[name_start : len(data)].ljust(CONTACT_NAME_SIZE, b"\x00")
        else:
            name_raw = b"\x00" * CONTACT_NAME_SIZE
        name = name_raw.split(b"\x00")[0].decode("utf-8", errors="replace")
        last_advert = 0
        if len(data) >= name_end + 4:
            last_advert = struct.unpack_from("<I", data, name_end)[0]
        gps_lat, gps_lon = 0.0, 0.0
        if len(data) >= name_end + 4 + 8:
            gps_lat = struct.unpack_from("<i", data, name_end + 4)[0] / 1e6
            gps_lon = struct.unpack_from("<i", data, name_end + 8)[0] / 1e6
        lastmod = int(time.time())
        if len(data) >= name_end + 4 + 12:
            lastmod = struct.unpack_from("<I", data, name_end + 12)[0]
        contact = Contact(
            public_key=pubkey,
            name=name,
            adv_type=adv_type,
            flags=flags,
            out_path_len=out_path_len,
            out_path=out_path,
            last_advert_timestamp=last_advert,
            lastmod=lastmod,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
        )
        ok = self.bridge.add_update_contact(contact)
        # Keep command/response parity: return a single frame for CMD_ADD_UPDATE_CONTACT.
        # Sending an extra RESP_CODE_CONTACT frame can desync some companion clients.
        self._write_ok() if ok else self._write_err(ERR_CODE_TABLE_FULL)
        if ok:
            try:
                await self._save_contacts()
            except Exception as e:
                logger.warning("Save contacts after add/update failed: %s", e)

    async def _cmd_remove_contact(self, data: bytes) -> None:
        if len(data) < 32:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pubkey = data[:32]
        ok = self.bridge.remove_contact(pubkey)
        if ok:
            try:
                await self._save_contacts()
            except Exception as e:
                logger.warning("Save contacts after remove failed: %s", e)
        self._write_ok() if ok else self._write_err(ERR_CODE_NOT_FOUND)

    async def _cmd_reset_path(self, data: bytes) -> None:
        if len(data) < 32:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pubkey = data[:32]
        ok = self.bridge.reset_path(pubkey)
        self._write_ok() if ok else self._write_err(ERR_CODE_NOT_FOUND)

    async def _cmd_get_advert_path(self, data: bytes) -> None:
        if len(data) < 1 + PUB_KEY_SIZE:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pub_key = data[1 : 1 + PUB_KEY_SIZE]
        prefix = pub_key[:7]
        # Bridge methods used from command handlers must not block the event loop;
        # if a subclass adds sync I/O here, run it via asyncio.to_thread().
        found = (
            self.bridge.get_advert_path(prefix)
            if getattr(self.bridge, "get_advert_path", None)
            else None
        )
        if not found:
            self._write_err(ERR_CODE_NOT_FOUND)
            return
        path_bytes = getattr(found, "path", None) or b""
        if not isinstance(path_bytes, bytes):
            path_bytes = bytes(path_bytes)
        path_len_encoded = getattr(found, "path_len", 0) or 0
        path_byte_len = PathUtils.get_path_byte_len(path_len_encoded)
        recv_ts = getattr(found, "recv_timestamp", 0)
        frame = (
            bytes([RESP_CODE_ADVERT_PATH])
            + struct.pack("<I", recv_ts)
            + bytes([path_len_encoded])
            + path_bytes[:path_byte_len]
        )
        self._write_frame(frame)

    async def _cmd_import_contact(self, data: bytes) -> None:
        ok = self.bridge.import_contact(data)
        self._write_ok() if ok else self._write_err(ERR_CODE_ILLEGAL_ARG)

    async def _cmd_share_contact(self, data: bytes) -> None:
        if len(data) < PUB_KEY_SIZE:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pubkey = data[:PUB_KEY_SIZE]
        # NOT_FOUND only when the contact is absent; an existing contact whose
        # advert cannot be built or sent is TABLE_FULL, matching MeshCore
        # CMD_SHARE_CONTACT / shareContactZeroHop.
        if self.bridge.get_contact_by_key(pubkey) is None:
            self._write_err(ERR_CODE_NOT_FOUND)
            return
        ok = await self.bridge.share_contact(pubkey)
        self._write_ok() if ok else self._write_err(ERR_CODE_TABLE_FULL)

    async def _cmd_export_contact(self, data: bytes) -> None:
        pubkey = data[:PUB_KEY_SIZE] if len(data) >= PUB_KEY_SIZE else None
        raw = self.bridge.export_contact(pubkey)
        if raw is None:
            self._write_err(ERR_CODE_NOT_FOUND)
            return
        self._write_frame(bytes([RESP_CODE_EXPORT_CONTACT]) + raw)
