from pymc_core import LocalIdentity
from pymc_core.protocol.identity import Identity


# LocalIdentity tests
def test_local_identity_creation():
    """Test creating a LocalIdentity with and without seed."""
    # Test with random seed
    identity1 = LocalIdentity()
    assert identity1 is not None
    assert identity1.get_public_key() is not None
    assert len(identity1.get_public_key()) == 32  # Ed25519 public key length

    # Test with specific seed (must be exactly 32 bytes)
    seed = b"test_seed_1234567890123456789012"  # 32 bytes exactly
    identity2 = LocalIdentity(seed)
    assert identity2 is not None
    assert identity2.get_public_key() is not None

    # Same seed should produce same identity
    identity3 = LocalIdentity(seed)
    assert identity2.get_public_key() == identity3.get_public_key()


def test_local_identity_methods():
    """Test LocalIdentity methods."""
    identity = LocalIdentity()

    # Test address generation
    address = identity.get_address_bytes()
    assert len(address) == 1

    # Test private key
    private_key = identity.get_private_key()
    assert len(private_key) == 32

    # Test shared public key
    shared_pub = identity.get_shared_public_key()
    assert len(shared_pub) == 32

    # Test signing
    message = b"Hello, World!"
    signature = identity.sign(message)
    assert len(signature) == 64  # Ed25519 signature length

    # Test verification
    assert identity.verify(message, signature)
    assert not identity.verify(message + b"x", signature)


def test_identity_verification():
    """Test Identity verification with different identities."""
    identity1 = LocalIdentity()
    identity2 = LocalIdentity()

    message = b"Test message"
    signature1 = identity1.sign(message)

    # Should verify with correct identity
    assert identity1.verify(message, signature1)

    # Should not verify with wrong identity
    assert not identity2.verify(message, signature1)


# Integration test
def test_full_identity_workflow():
    """Test a complete identity workflow."""
    # Create two identities
    alice = LocalIdentity()
    bob = LocalIdentity()

    # Alice signs a message
    message = b"Hello Bob!"
    signature = alice.sign(message)

    # Bob verifies the signature using Alice's public key
    alice_identity = Identity(alice.get_public_key())
    assert alice_identity.verify(message, signature)

    # Test ECDH key exchange
    alice_private = alice.get_private_key()
    bob_public = bob.get_public_key()

    # In real scenario, this would generate shared secret
    assert len(alice_private) == 32
    assert len(bob_public) == 32
