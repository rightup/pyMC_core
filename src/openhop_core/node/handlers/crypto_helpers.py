"""Shared contact-based decryption helpers for encrypted mesh payloads."""

from typing import Any, Iterable, Iterator, Tuple

from ...protocol import CryptoUtils, Identity
from ...protocol.constants import PUB_KEY_SIZE


def iter_decrypt_by_src_hash(
    contacts: Iterable[Any],
    src_hash: int,
    local_identity: Any,
    encrypted: bytes,
) -> Iterator[Tuple[Any, bytes, bytes, bytes]]:
    """Try to decrypt *encrypted* with each contact whose public key starts
    with *src_hash* (the firmware's "try all hash matches" pattern).

    Uses the same ECDH shared secret as login (libsodium
    ed25519_pk_to_curve25519 + scalarmult; AES key = secret[:16]) and
    MAC-then-decrypt, matching firmware ``createPathReturn(..., secret, ...)``.

    Yields ``(contact, contact_pubkey, shared_secret, decrypted)`` for every
    contact that decrypts successfully; callers keep iterating when their own
    content validation of ``decrypted`` fails.
    """
    for contact in contacts:
        try:
            pk = contact.public_key
            pub = pk if isinstance(pk, bytes) else bytes.fromhex(pk)
            if len(pub) != PUB_KEY_SIZE or pub[0] != src_hash:
                continue
            peer_id = Identity(pub)
            shared_secret = peer_id.calc_shared_secret(local_identity.get_private_key())
            aes_key = shared_secret[:16]
            decrypted = CryptoUtils.mac_then_decrypt(aes_key, shared_secret, encrypted)
        except Exception:
            continue
        yield contact, pub, shared_secret, decrypted
