from typing import Optional

from nacl.exceptions import BadSignatureError
from nacl.public import PublicKey
from nacl.signing import SigningKey, VerifyKey

from . import CryptoUtils

# ---------------------------------------------------------------------------
# Identity classes -----------------------------------------------------------
# ---------------------------------------------------------------------------


class Identity:
    """
    Represents a peer's public identity for cryptographic operations.

    Handles Ed25519 public key operations including signature verification
    and ECDH shared secret computation. Instances are immutable and thread-safe.
    """

    def __init__(self, ed25519_public_key: bytes):
        """
        Initialise an Identity instance for a peer.

        Creates an identity object from the peer's Ed25519 public key,
        enabling signature verification and shared secret computation.

        Args:
            ed25519_public_key: The peer's 32-byte Ed25519 public key.
        """
        self.verify_key = VerifyKey(ed25519_public_key)
        self.x25519_pubkey = PublicKey(CryptoUtils.ed25519_pk_to_x25519(ed25519_public_key))

    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify a signature against a message using the peer's public key.

        Args:
            message: The original message bytes.
            signature: The signature to verify.

        Returns:
            True if the signature is valid, False otherwise.
        """
        try:
            self.verify_key.verify(message, signature)
            return True
        except BadSignatureError:
            return False

    def get_public_key(self) -> bytes:
        """
        Get the Ed25519 public key for this identity.

        Returns:
            The 32-byte Ed25519 public key.
        """
        return self.verify_key.encode()

    def calc_shared_secret(self, local_private_x25519: bytes) -> bytes:
        """
        Compute the ECDH shared secret with a local private key.

        Args:
            local_private_x25519: The local X25519 private key.

        Returns:
            The 32-byte shared secret for encryption.
        """
        return CryptoUtils.scalarmult(local_private_x25519, self.x25519_pubkey.encode())


# ---------------------------------------------------------------------------
# LocalIdentity class --------------------------------------------------------
# ---------------------------------------------------------------------------


class LocalIdentity(Identity):
    """
    Represents the local node's cryptographic identity with full key access.

    Extends Identity with private key operations for signing and ECDH.
    Generates or derives Ed25519 and X25519 key pairs for secure communication.
    """

    def __init__(self, seed: Optional[bytes] = None):
        """
        Initialise a LocalIdentity instance with signing and encryption keys.

        Creates a local identity with Ed25519 and X25519 key pairs for
        digital signatures and ECDH key agreement. If no seed is provided,
        generates a new random key pair.

        Args:
            seed: Optional 32-byte seed for deterministic key generation.
        """
        self.signing_key = SigningKey(seed) if seed else SigningKey.generate()
        self.verify_key = self.signing_key.verify_key

        # Build 64-byte Ed25519 secret key: seed + pub
        ed25519_pub = self.verify_key.encode()
        ed25519_sk = self.signing_key.encode() + ed25519_pub

        # X25519 keypair for ECDH
        self._x25519_private = CryptoUtils.ed25519_sk_to_x25519(ed25519_sk)
        self._x25519_public = CryptoUtils.scalarmult_base(self._x25519_private)

        # Initialise base class with Ed25519 pubkey
        super().__init__(ed25519_pub)

    def get_address_bytes(self) -> bytes:
        """
        Get the address bytes derived from the public key.

        Returns:
            The first byte of SHA256 hash of the public key, used as address.
        """
        # Address is the first byte of SHA256(pubkey)
        return CryptoUtils.sha256(self.get_public_key())[:1]

    def get_private_key(self) -> bytes:
        """
        Get the X25519 private key for ECDH operations.

        Returns:
            The 32-byte X25519 private key.
        """
        return self._x25519_private

    def get_shared_public_key(self) -> bytes:
        """
        Get the X25519 public key for ECDH operations.

        Returns:
            The 32-byte X25519 public key.
        """
        return self._x25519_public

    def sign(self, message: bytes) -> bytes:
        """
        Sign a message with the Ed25519 private key.

        Args:
            message: The message to sign.

        Returns:
            The 64-byte Ed25519 signature.
        """
        return self.signing_key.sign(message).signature
