from pymc_core import CryptoUtils


# CryptoUtils tests
def test_crypto_utils_sha256():
    """Test SHA256 hashing."""
    data = b"Hello, World!"
    hash_result = CryptoUtils.sha256(data)
    assert len(hash_result) == 32

    # Same data should produce same hash
    hash_result2 = CryptoUtils.sha256(data)
    assert hash_result == hash_result2

    # Different data should produce different hash
    hash_result3 = CryptoUtils.sha256(b"Different data")
    assert hash_result != hash_result3


def test_crypto_utils_encrypt_then_mac():
    """Test encrypt-then-MAC functionality."""
    aes_key = b"0123456789abcdef"  # 16 bytes for AES
    shared_secret = b"0123456789abcdef0123456789abcdef"  # 32 bytes for HMAC
    plaintext = b"Hello, World!"

    # Encrypt-then-MAC
    encrypted = CryptoUtils.encrypt_then_mac(aes_key, shared_secret, plaintext)
    assert encrypted is not None
    assert len(encrypted) > len(plaintext)  # Should include MAC

    # MAC-then-decrypt (reverse operation)
    decrypted = CryptoUtils.mac_then_decrypt(aes_key, shared_secret, encrypted)
    # Remove padding (null bytes at the end)
    decrypted = decrypted.rstrip(b"\x00")
    assert decrypted == plaintext


def test_crypto_utils_key_exchange():
    """Test ECDH key exchange utilities."""
    from pymc_core import LocalIdentity

    # Create two identities for key exchange
    alice = LocalIdentity()
    bob = LocalIdentity()

    # Get the X25519 keys directly (they're already converted)
    alice_private_x25519 = alice.get_private_key()
    alice_public_x25519 = alice.get_shared_public_key()
    bob_private_x25519 = bob.get_private_key()
    bob_public_x25519 = bob.get_shared_public_key()

    # Perform ECDH
    alice_shared = CryptoUtils.scalarmult(alice_private_x25519, bob_public_x25519)
    bob_shared = CryptoUtils.scalarmult(bob_private_x25519, alice_public_x25519)

    # Both should compute the same shared secret
    assert alice_shared == bob_shared
    assert len(alice_shared) == 32
