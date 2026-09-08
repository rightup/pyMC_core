"""Tests for shared protocol helpers in openhop_core.protocol.utils."""

from openhop_core.protocol import LocalIdentity
from openhop_core.protocol.constants import PUB_KEY_SIZE
from openhop_core.protocol.utils import is_self_advert


def test_is_self_advert_matches_only_the_full_public_key():
    """Mesh::onRecvPacket compares the whole key (Mesh.cpp:263), not a prefix."""
    identity = LocalIdentity()
    self_key = identity.get_public_key()
    payload = self_key + b"\x78\x56\x34\x12" + b"\x00" * 64 + b"\x81SelfNode"

    assert is_self_advert(payload, self_key) is True

    other_key = bytearray(self_key)
    other_key[-1] ^= 0x01
    assert is_self_advert(bytes(other_key) + payload[PUB_KEY_SIZE:], self_key) is False

    # A payload too short to hold a full public key can never be ours.
    assert is_self_advert(self_key[:-1], self_key) is False

    # No identity to compare against: never claim the advert.
    assert is_self_advert(payload, b"") is False
