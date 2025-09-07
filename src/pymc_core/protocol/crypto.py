import hashlib
import hmac

from Crypto.Cipher import AES
from nacl.bindings import (
    crypto_scalarmult,
    crypto_scalarmult_base,
    crypto_sign_ed25519_pk_to_curve25519,
    crypto_sign_ed25519_sk_to_curve25519,
)

CIPHER_MAC_SIZE = 2  # matches firmware
CIPHER_BLOCK_SIZE = 16


class CryptoUtils:
    @staticmethod
    def sha256(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    @staticmethod
    def _hmac_sha256(key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()

    @staticmethod
    def _aes_encrypt(key: bytes, data: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_ECB)

        # Pad to match decryption expectations (block-aligned input)
        pad_len = (CIPHER_BLOCK_SIZE - (len(data) % CIPHER_BLOCK_SIZE)) % CIPHER_BLOCK_SIZE
        if pad_len > 0:
            data += b"\x00" * pad_len

        return cipher.encrypt(data)

    @staticmethod
    def _aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_ECB)
        return b"".join(
            cipher.decrypt(ciphertext[i : i + CIPHER_BLOCK_SIZE])
            for i in range(0, len(ciphertext), CIPHER_BLOCK_SIZE)
        )

    @staticmethod
    def encrypt_then_mac(key_aes: bytes, shared_secret: bytes, plaintext: bytes) -> bytes:
        ciphertext = CryptoUtils._aes_encrypt(key_aes, plaintext)
        mac = CryptoUtils._hmac_sha256(shared_secret, ciphertext)[:CIPHER_MAC_SIZE]
        return mac + ciphertext

    @staticmethod
    def mac_then_decrypt(aes_key: bytes, shared_secret: bytes, data: bytes) -> bytes:
        """
        Match the C++ firmware:
        - HMAC-SHA256 with shared_secret (32B)
        - MAC is 2 bytes
        - AES-128 ECB decrypt
        """
        if len(data) <= CIPHER_MAC_SIZE:
            raise ValueError("Data too short to contain MAC + ciphertext")

        mac = data[:CIPHER_MAC_SIZE]
        ciphertext = data[CIPHER_MAC_SIZE:]

        expected_mac = CryptoUtils._hmac_sha256(shared_secret, ciphertext)[:CIPHER_MAC_SIZE]
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("Invalid HMAC")

        decrypted = CryptoUtils._aes_decrypt(aes_key, ciphertext)

        return decrypted

    @staticmethod
    def scalarmult(private_key: bytes, public_key: bytes) -> bytes:
        """ECDH shared secret calculation (X25519)."""
        return crypto_scalarmult(private_key, public_key)

    @staticmethod
    def ed25519_pk_to_x25519(ed25519_public_key: bytes) -> bytes:
        """Convert Ed25519 public key to X25519 public key."""
        return crypto_sign_ed25519_pk_to_curve25519(ed25519_public_key)

    @staticmethod
    def ed25519_sk_to_x25519(ed25519_private_key: bytes) -> bytes:
        """Convert Ed25519 private key to X25519 private key."""
        return crypto_sign_ed25519_sk_to_curve25519(ed25519_private_key)

    @staticmethod
    def scalarmult_base(private_key: bytes) -> bytes:
        """Generate X25519 public key from private key."""
        return crypto_scalarmult_base(private_key)
