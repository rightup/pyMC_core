import asyncio

import pytest

from openhop_core.companion import CompanionBridge
from openhop_core.companion.contact_store import ContactStore
from openhop_core.companion.models import Contact
from openhop_core.node.handlers.protocol_response import ProtocolResponseHandler
from openhop_core.protocol import CryptoUtils, Identity, LocalIdentity, Packet
from openhop_core.protocol.constants import (
    PAYLOAD_TYPE_PATH,
    PAYLOAD_TYPE_RESPONSE,
    ROUTE_TYPE_DIRECT,
)
from openhop_core.protocol.packet_utils import PathUtils

LOCAL_IDENTITY = LocalIdentity(bytes(32))
FIRST_COLLIDING_PEER = LocalIdentity(bytes([0x0C]) + bytes(31))
SECOND_COLLIDING_PEER = LocalIdentity(bytes([0x16]) + bytes(31))

# Captured from MeshCore's Utils::encryptThenMAC using the real Crypto library
# (not Core's CryptoUtils).  The plaintexts are the firmware's wire layouts:
#
#   direct: tag=0x12345678 (little-endian) + b"MC"
#   path:   path_len=0x02 + a1b2 + RESPONSE + tag + b"PATH"
#
# The first two payload bytes are the destination and source public-key hashes.
MESHCORE_DIRECT_RESPONSE_PAYLOAD = bytes.fromhex("3b2ede75eb1c951669d7d8fb80f7f645231922e3")
MESHCORE_PATH_RESPONSE_PAYLOAD = bytes.fromhex("3b2ecba44f1b13af1dd17913b5a204ef4a62c61d")
MESHCORE_RESPONSE_TAG = 0x12345678


def _contacts_with_colliding_peers():
    assert FIRST_COLLIDING_PEER.get_public_key()[0] == SECOND_COLLIDING_PEER.get_public_key()[0]
    contacts = ContactStore()
    contacts.add(Contact(public_key=FIRST_COLLIDING_PEER.get_public_key(), name="First"))
    contacts.add(Contact(public_key=SECOND_COLLIDING_PEER.get_public_key(), name="Second"))
    return contacts


def _response_packet(local_identity, peer_identity, tag, data=b"ok", path=None):
    shared_secret = Identity(peer_identity.get_public_key()).calc_shared_secret(
        local_identity.get_private_key()
    )
    response = tag.to_bytes(4, "little") + data
    if path is None:
        plaintext = response
        payload_type = PAYLOAD_TYPE_RESPONSE
    else:
        path_len = PathUtils.encode_path_len(1, len(path))
        plaintext = bytes([path_len]) + path + bytes([PAYLOAD_TYPE_RESPONSE]) + response
        payload_type = PAYLOAD_TYPE_PATH

    packet = Packet()
    packet.header = (payload_type << 2) | ROUTE_TYPE_DIRECT
    packet.path_len = 0
    packet.path = bytearray()
    packet.payload = bytearray(
        bytes([local_identity.get_public_key()[0], peer_identity.get_public_key()[0]])
        + CryptoUtils.encrypt_then_mac(shared_secret[:16], shared_secret, plaintext)
    )
    packet.payload_len = len(packet.payload)
    return packet


def _meshcore_response_packet(payload_type, payload):
    """Build a packet around a static MeshCore-produced encrypted payload."""
    packet = Packet()
    packet.header = (payload_type << 2) | ROUTE_TYPE_DIRECT
    packet.path_len = 0
    packet.path = bytearray()
    packet.payload = bytearray(payload)
    packet.payload_len = len(packet.payload)
    return packet


class _PacketInjector:
    def __init__(self):
        self.packets = []

    async def __call__(self, packet, wait_for_ack=False, expected_crc=None):
        self.packets.append(packet)
        return True


@pytest.mark.asyncio
async def test_colliding_contacts_resolve_only_their_authenticated_tagged_waiters():
    contacts = _contacts_with_colliding_peers()
    handler = ProtocolResponseHandler(lambda _message: None, LOCAL_IDENTITY, contacts)
    first_tag = 0x10203040
    second_tag = 0x50607080
    callbacks = []

    handler.set_response_callback(
        FIRST_COLLIDING_PEER.get_public_key(),
        first_tag,
        lambda success, text, parsed: callbacks.append(("first", success, text, parsed)),
    )
    handler.set_response_callback(
        SECOND_COLLIDING_PEER.get_public_key(),
        second_tag,
        lambda success, text, parsed: callbacks.append(("second", success, text, parsed)),
    )

    await handler(_response_packet(LOCAL_IDENTITY, SECOND_COLLIDING_PEER, second_tag, b"second"))
    await handler(_response_packet(LOCAL_IDENTITY, FIRST_COLLIDING_PEER, first_tag, b"first"))

    assert [(name, success, text) for name, success, text, _parsed in callbacks] == [
        ("second", True, "second"),
        ("first", True, "first"),
    ]
    assert handler._response_waiters == {}


@pytest.mark.asyncio
async def test_same_tag_for_colliding_contacts_stays_isolated_by_authenticated_key():
    contacts = _contacts_with_colliding_peers()
    handler = ProtocolResponseHandler(lambda _message: None, LOCAL_IDENTITY, contacts)
    tag = 0x01020304
    callbacks = []

    handler.set_response_callback(
        FIRST_COLLIDING_PEER.get_public_key(),
        tag,
        lambda success, text, _parsed: callbacks.append(("first", success, text)),
    )
    handler.set_response_callback(
        SECOND_COLLIDING_PEER.get_public_key(),
        tag,
        lambda success, text, _parsed: callbacks.append(("second", success, text)),
    )

    await handler(_response_packet(LOCAL_IDENTITY, SECOND_COLLIDING_PEER, tag, b"second"))
    assert callbacks == [("second", True, "second")]
    assert set(handler._response_waiters) == {(FIRST_COLLIDING_PEER.get_public_key(), tag)}

    await handler(_response_packet(LOCAL_IDENTITY, FIRST_COLLIDING_PEER, tag, b"first"))

    assert callbacks == [("second", True, "second"), ("first", True, "first")]
    assert handler._response_waiters == {}


@pytest.mark.asyncio
async def test_same_contact_waiters_are_separated_by_tag_and_ignore_stale_responses():
    contacts = _contacts_with_colliding_peers()
    handler = ProtocolResponseHandler(lambda _message: None, LOCAL_IDENTITY, contacts)
    peer_key = FIRST_COLLIDING_PEER.get_public_key()
    first_tag = 0x11111111
    second_tag = 0x22222222
    callbacks = []

    handler.set_response_callback(
        peer_key,
        first_tag,
        lambda success, text, _parsed: callbacks.append(("first", success, text)),
    )
    handler.set_response_callback(
        peer_key,
        second_tag,
        lambda success, text, _parsed: callbacks.append(("second", success, text)),
    )

    await handler(_response_packet(LOCAL_IDENTITY, FIRST_COLLIDING_PEER, 0xDEADBEEF, b"stale"))
    assert callbacks == []
    assert len(handler._response_waiters) == 2

    await handler(_response_packet(LOCAL_IDENTITY, FIRST_COLLIDING_PEER, second_tag, b"second"))
    await handler(_response_packet(LOCAL_IDENTITY, FIRST_COLLIDING_PEER, first_tag, b"first"))
    await handler(_response_packet(LOCAL_IDENTITY, FIRST_COLLIDING_PEER, first_tag, b"duplicate"))

    assert callbacks == [("second", True, "second"), ("first", True, "first")]
    assert handler._response_waiters == {}


@pytest.mark.asyncio
async def test_path_response_binary_callback_uses_the_authenticated_colliding_contact():
    contacts = _contacts_with_colliding_peers()
    handler = ProtocolResponseHandler(lambda _message: None, LOCAL_IDENTITY, contacts)
    binary_responses = []
    handler.set_binary_response_callback(
        lambda tag, data, path_info: binary_responses.append((tag, data, path_info))
    )
    tag = 0x12345678
    out_path = b"\xA1\xB2"

    await handler(
        _response_packet(
            LOCAL_IDENTITY,
            SECOND_COLLIDING_PEER,
            tag,
            b"path-response",
            path=out_path,
        )
    )

    assert len(binary_responses) == 1
    tag_bytes, response_data, path_info = binary_responses[0]
    assert tag_bytes == tag.to_bytes(4, "little")
    assert response_data.startswith(b"path-response")
    # path_info carries the ENCODED path_len bytes alongside the path bytes:
    # (out_len_byte, out_path, in_len_byte, in_path, matched_pubkey). Here the
    # packet arrived with an empty inbound path, so in_len_byte is 0.
    assert path_info == (
        PathUtils.encode_path_len(1, len(out_path)),
        out_path,
        0,
        b"",
        SECOND_COLLIDING_PEER.get_public_key(),
    )
    assert contacts.get_by_key(SECOND_COLLIDING_PEER.get_public_key()).out_path == out_path
    assert contacts.get_by_key(FIRST_COLLIDING_PEER.get_public_key()).out_path == b""


@pytest.mark.asyncio
async def test_protocol_response_pathinfo_carries_encoded_lens():
    """The PATH branch must preserve the ENCODED out path_len byte (raw_decrypted[0])
    and the inbound encoded byte (pkt.path_len) verbatim, not a raw byte count."""
    contacts = _contacts_with_colliding_peers()
    handler = ProtocolResponseHandler(lambda _message: None, LOCAL_IDENTITY, contacts)
    binary_responses = []
    handler.set_binary_response_callback(
        lambda tag, data, path_info: binary_responses.append((tag, data, path_info))
    )
    tag = 0x12345678
    # Outbound: 2-byte hashes, 2 hops -> encoded 0x42, 4 path bytes on the wire.
    out_path = b"\xA1\xB2\xC3\xD4"
    out_len_byte = PathUtils.encode_path_len(2, 2)
    assert out_len_byte == 0x42

    shared_secret = Identity(SECOND_COLLIDING_PEER.get_public_key()).calc_shared_secret(
        LOCAL_IDENTITY.get_private_key()
    )
    response = tag.to_bytes(4, "little") + b"path-response"
    plaintext = bytes([out_len_byte]) + out_path + bytes([PAYLOAD_TYPE_RESPONSE]) + response
    packet = Packet()
    packet.header = (PAYLOAD_TYPE_PATH << 2) | ROUTE_TYPE_DIRECT
    # Inbound path: 2-byte hashes, 1 hop -> encoded 0x41, 2 path bytes.
    in_len_byte = PathUtils.encode_path_len(2, 1)
    assert in_len_byte == 0x41
    packet.path_len = in_len_byte
    packet.path = bytearray(b"\xEE\xFF")
    packet.payload = bytearray(
        bytes([LOCAL_IDENTITY.get_public_key()[0], SECOND_COLLIDING_PEER.get_public_key()[0]])
        + CryptoUtils.encrypt_then_mac(shared_secret[:16], shared_secret, plaintext)
    )
    packet.payload_len = len(packet.payload)

    await handler(packet)

    assert len(binary_responses) == 1
    _tag_bytes, _response_data, path_info = binary_responses[0]
    assert path_info == (
        out_len_byte,
        out_path,
        in_len_byte,
        b"\xEE\xFF",
        SECOND_COLLIDING_PEER.get_public_key(),
    )


@pytest.mark.asyncio
async def test_meshcore_direct_response_fixture_routes_through_companion_receive_pipeline():
    injector = _PacketInjector()
    bridge = CompanionBridge(LOCAL_IDENTITY, injector)
    bridge.contacts.add(Contact(public_key=FIRST_COLLIDING_PEER.get_public_key(), name="First"))
    bridge.contacts.add(Contact(public_key=SECOND_COLLIDING_PEER.get_public_key(), name="Second"))
    handler = bridge._get_protocol_response_handler()
    callbacks = []
    handler.set_response_callback(
        SECOND_COLLIDING_PEER.get_public_key(),
        MESHCORE_RESPONSE_TAG,
        lambda success, text, _parsed: callbacks.append((success, text)),
    )

    result = await bridge.process_received_packet(
        _meshcore_response_packet(PAYLOAD_TYPE_RESPONSE, MESHCORE_DIRECT_RESPONSE_PAYLOAD)
    )

    assert result.authenticated is True
    assert callbacks == [(True, "MC")]
    assert handler._response_waiters == {}


@pytest.mark.asyncio
async def test_meshcore_path_response_fixture_routes_through_companion_receive_pipeline():
    injector = _PacketInjector()
    bridge = CompanionBridge(LOCAL_IDENTITY, injector)
    bridge.contacts.add(Contact(public_key=FIRST_COLLIDING_PEER.get_public_key(), name="First"))
    bridge.contacts.add(Contact(public_key=SECOND_COLLIDING_PEER.get_public_key(), name="Second"))
    handler = bridge._get_protocol_response_handler()
    callbacks = []
    handler.set_response_callback(
        SECOND_COLLIDING_PEER.get_public_key(),
        MESHCORE_RESPONSE_TAG,
        lambda success, text, _parsed: callbacks.append((success, text)),
    )

    result = await bridge.process_received_packet(
        _meshcore_response_packet(PAYLOAD_TYPE_PATH, MESHCORE_PATH_RESPONSE_PAYLOAD)
    )

    assert result.authenticated is True
    assert callbacks == [(True, "PATH")]
    assert handler._response_waiters == {}
    assert (
        bridge.contacts.get_by_key(SECOND_COLLIDING_PEER.get_public_key()).out_path == b"\xA1\xB2"
    )


@pytest.mark.asyncio
async def test_first_protocol_send_failure_clears_the_registered_response_waiter():
    async def reject_packet(_packet, wait_for_ack=False, expected_crc=None):
        return False

    bridge = CompanionBridge(LOCAL_IDENTITY, reject_packet)
    bridge.contacts.add(Contact(public_key=FIRST_COLLIDING_PEER.get_public_key(), name="First"))

    started = await bridge._start_status_request(FIRST_COLLIDING_PEER.get_public_key())

    assert started == {"success": False, "error": "send_failed", "reason": "Send failed"}
    assert bridge._get_protocol_response_handler()._response_waiters == {}


@pytest.mark.asyncio
async def test_concurrent_companion_requests_to_colliding_contacts_complete_independently():
    injector = _PacketInjector()
    bridge = CompanionBridge(LOCAL_IDENTITY, injector)
    bridge.contacts.add(Contact(public_key=FIRST_COLLIDING_PEER.get_public_key(), name="First"))
    bridge.contacts.add(Contact(public_key=SECOND_COLLIDING_PEER.get_public_key(), name="Second"))
    bridge._response_timeout_s = lambda _packet, _proxy: 1.0
    handler = bridge._get_protocol_response_handler()

    first = await bridge._start_status_request(FIRST_COLLIDING_PEER.get_public_key())
    second = await bridge._start_telemetry_request(SECOND_COLLIDING_PEER.get_public_key())
    assert first["success"] is True
    assert second["success"] is True

    await handler(
        _response_packet(
            LOCAL_IDENTITY,
            SECOND_COLLIDING_PEER,
            second["sent"].expected_ack,
            b"second",
        )
    )
    await handler(
        _response_packet(
            LOCAL_IDENTITY,
            FIRST_COLLIDING_PEER,
            first["sent"].expected_ack,
            b"first",
        )
    )

    first_result, second_result = await asyncio.gather(first["task"], second["task"])
    assert first_result["success"] is True
    assert first_result["repeater"] == "First"
    assert first_result["response_text"] == "first"
    assert second_result["success"] is True
    assert second_result["contact"] == "Second"
    assert second_result["response_text"] == "second"
    assert handler._response_waiters == {}


@pytest.mark.asyncio
async def test_retry_keeps_the_first_tag_live_until_a_late_response_arrives():
    injector = _PacketInjector()
    bridge = CompanionBridge(LOCAL_IDENTITY, injector)
    bridge.contacts.add(Contact(public_key=FIRST_COLLIDING_PEER.get_public_key(), name="First"))
    bridge._response_timeout_s = lambda _packet, _proxy: 0.01
    handler = bridge._get_protocol_response_handler()
    first_tag = None

    async def send_and_reply_on_second_attempt(packet, wait_for_ack=False, expected_crc=None):
        nonlocal first_tag
        injector.packets.append(packet)
        shared_secret = Identity(FIRST_COLLIDING_PEER.get_public_key()).calc_shared_secret(
            LOCAL_IDENTITY.get_private_key()
        )
        request_plaintext = CryptoUtils.mac_then_decrypt(
            shared_secret[:16], shared_secret, bytes(packet.payload[2:])
        )
        sent_tag = int.from_bytes(request_plaintext[:4], "little")
        if first_tag is None:
            first_tag = sent_tag
        else:
            await handler(
                _response_packet(LOCAL_IDENTITY, FIRST_COLLIDING_PEER, first_tag, b"late")
            )
        return True

    bridge._send_packet = send_and_reply_on_second_attempt
    result = await bridge.send_status_request(FIRST_COLLIDING_PEER.get_public_key(), timeout=1.0)

    assert len(injector.packets) == 2
    assert result["success"] is True
    assert result["response_text"] == "late"
    assert handler._response_waiters == {}
