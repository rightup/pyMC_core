"""CIPHER_MAC_SIZE must be a single source of truth (2 bytes), matching the
firmware wire MAC, which is HMAC-SHA256 truncated to 2 bytes."""

import hashlib
import hmac

import openhop_core.protocol as protocol
import openhop_core.protocol.constants as constants
import openhop_core.protocol.crypto as crypto
from openhop_core.protocol.crypto import CryptoUtils


def test_cipher_mac_size_is_2_everywhere():
    assert protocol.CIPHER_MAC_SIZE == 2
    assert constants.CIPHER_MAC_SIZE == 2
    assert crypto.CIPHER_MAC_SIZE == 2


def test_encrypt_then_mac_truncates_hmac_to_2_bytes():
    aes_key = b"0123456789abcdef"  # 16 bytes for AES
    shared_secret = b"0123456789abcdef0123456789abcdef"  # 32 bytes for HMAC
    plaintext = b"Hello, World!"

    encrypted = CryptoUtils.encrypt_then_mac(aes_key, shared_secret, plaintext)

    # Ciphertext is plaintext padded up to an AES block boundary.
    pad_len = (16 - (len(plaintext) % 16)) % 16
    ciphertext_len = len(plaintext) + pad_len

    mac = encrypted[:2]
    ciphertext = encrypted[2:]
    expected_mac = hmac.new(shared_secret, ciphertext, hashlib.sha256).digest()[:2]

    assert mac == expected_mac
    assert len(encrypted) == 2 + ciphertext_len


def test_mac_then_decrypt_round_trip():
    aes_key = b"0123456789abcdef"
    shared_secret = b"0123456789abcdef0123456789abcdef"
    plaintext = b"Hello, World!"

    encrypted = CryptoUtils.encrypt_then_mac(aes_key, shared_secret, plaintext)
    decrypted = CryptoUtils.mac_then_decrypt(aes_key, shared_secret, encrypted)

    assert decrypted.rstrip(b"\x00") == plaintext
