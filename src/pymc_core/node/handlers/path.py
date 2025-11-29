"""Path packet handler for mesh network routing."""

from typing import Any, Callable, Optional

from ...protocol import CryptoUtils, Identity, Packet
from ...protocol.constants import PAYLOAD_TYPE_PATH, PAYLOAD_TYPE_RESPONSE


class PathHandler:
    """Decrypt PATH packets, update cached routes, and surface extras."""

    def __init__(
        self,
        log_fn: Callable[[str], None],
        *,
        local_identity: Any = None,
        contact_book: Any = None,
        ack_handler=None,
        protocol_response_handler=None,
    ):
        self._log = log_fn
        self._local_identity = local_identity
        self._contact_book = contact_book
        self._ack_handler = ack_handler
        self._protocol_response_handler = protocol_response_handler

    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_PATH

    def set_ack_handler(self, ack_handler):
        """Set the ACK handler for processing bundled/encrypted ACKs in PATH packets."""
        self._ack_handler = ack_handler

    async def __call__(self, pkt: Packet) -> None:
        """Handle incoming PATH packet: decrypt, update contact path, route extras."""
        try:
            decoded = self._decode_path_payload(pkt)
            if not decoded:
                return

            # Surface decrypted payload for downstream consumers (ACK/analysis)
            if not isinstance(pkt.decrypted, dict):
                pkt.decrypted = {}
            pkt.decrypted["path_inner"] = decoded["raw_inner"]
            pkt.decrypted["path_meta"] = {
                "path": decoded["path"],
                "extra_type": decoded["extra_type"],
                "src_hash": decoded["src_hash"],
            }

            self._update_contact_path(decoded)
            await self._handle_response_extra(decoded)

            if self._ack_handler:
                ack_crc = await self._ack_handler.process_path_ack_variants(pkt)
                if ack_crc is not None:
                    await self._ack_handler._notify_ack_received(ack_crc)

            self._run_packet_analysis(pkt)
            self._log_basic_path_stats(decoded)

        except Exception as e:
            self._log(f"Error in PATH handler: {e}")
            import traceback

            self._log(traceback.format_exc())

    def _decode_path_payload(self, pkt: Packet) -> Optional[dict]:
        if not self._local_identity or not self._contact_book:
            self._log("PATH handler missing identity/contact book; skipping decrypt")
            return None

        payload = pkt.payload
        if len(payload) < 2:
            self._log("PATH packet missing dest/src hashes")
            return None

        dest_hash, src_hash = payload[0], payload[1]
        local_hash = self._local_identity.get_public_key()[0]
        if dest_hash != local_hash:
            self._log(
                f"PATH packet dest hash mismatch (dest=0x{dest_hash:02X}, local=0x{local_hash:02X})"
            )
            return None

        contact = getattr(self._contact_book, "get_by_hash", lambda _: None)(src_hash)
        if not contact:
            self._log(f"PATH packet from unknown contact hash 0x{src_hash:02X}")
            return None

        try:
            peer_identity = Identity(bytes.fromhex(contact.public_key))
            shared_secret = peer_identity.calc_shared_secret(
                self._local_identity.get_private_key()
            )
            aes_key = shared_secret[:16]
            decrypted = CryptoUtils.mac_then_decrypt(aes_key, shared_secret, payload[2:])
        except Exception as err:
            self._log(f"PATH payload decryption failed: {err}")
            return None

        if not decrypted:
            self._log("PATH payload decrypted to empty data")
            return None
        if len(decrypted) < 1:
            self._log("PATH payload missing path length byte")
            return None

        path_len = decrypted[0]
        if len(decrypted) < 1 + path_len:
            self._log(
                f"PATH payload truncated for path_len={path_len} (have {len(decrypted)})"
            )
            return None

        path_bytes = list(int(b) & 0xFF for b in decrypted[1 : 1 + path_len])
        extra_offset = 1 + path_len
        extra_type: Optional[int] = None
        extra_payload = b""
        if len(decrypted) > extra_offset:
            extra_type = decrypted[extra_offset]
            extra_payload = bytes(decrypted[extra_offset + 1 :])

        return {
            "dest_hash": dest_hash,
            "src_hash": src_hash,
            "contact": contact,
            "path": path_bytes,
            "extra_type": extra_type,
            "extra_payload": extra_payload,
            "raw_inner": bytes(decrypted),
        }

    def _update_contact_path(self, decoded: dict) -> None:
        contact = decoded.get("contact")
        path = decoded.get("path") or []
        if not contact or not path:
            return

        updater = getattr(self._contact_book, "update_out_path", None)
        if callable(updater):
            updater(contact, path)
            self._log(
                f"Updated cached path for contact hash 0x{decoded['src_hash']:02X}: {path}"
            )

    async def _handle_response_extra(self, decoded: dict) -> None:
        if decoded.get("extra_type") != PAYLOAD_TYPE_RESPONSE:
            return
        if not self._protocol_response_handler:
            self._log("PATH response extra ignored (no protocol handler)")
            return

        extra_payload: bytes = decoded.get("extra_payload", b"")
        if not extra_payload:
            self._log("PATH response extra empty; nothing to deliver")
            return

        await self._protocol_response_handler.handle_plaintext_response(
            decoded["src_hash"], decoded.get("contact"), extra_payload
        )

    def _run_packet_analysis(self, pkt: Packet) -> None:
        try:
            dispatcher = getattr(self, "_dispatcher", None)
            if dispatcher and getattr(dispatcher, "packet_analysis_callback", None):
                dispatcher.packet_analysis_callback(pkt)
                self._log("PATH packet analysis delegated to app")
        except Exception as exc:
            self._log(f"PATH packet analysis failed: {exc}")

    def _log_basic_path_stats(self, decoded: dict) -> None:
        path = decoded.get("path") or []
        extra_type = decoded.get("extra_type")
        self._log(
            f"PATH packet: hops={len(path)}, extra_type="
            f"{('0x%02X' % extra_type) if extra_type is not None else 'none'}"
        )
