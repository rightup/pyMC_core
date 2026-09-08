"""Firmware-aligned tests for companion ADVERT import and export."""

import asyncio
from unittest.mock import AsyncMock

import pytest
from nacl.signing import VerifyKey

from openhop_core.companion.companion_bridge import CompanionBridge
from openhop_core.companion.companion_radio import CompanionRadio
from openhop_core.companion.constants import (
    AUTOADD_REPEATER,
    ERR_CODE_ILLEGAL_ARG,
    RESP_CODE_ERR,
    RESP_CODE_EXPORT_CONTACT,
    RESP_CODE_OK,
)
from openhop_core.companion.frame_server import CompanionFrameServer
from openhop_core.companion.models import Contact
from openhop_core.protocol import Identity, LocalIdentity, Packet, PacketBuilder
from openhop_core.protocol.constants import PAYLOAD_TYPE_ADVERT, ROUTE_TYPE_FLOOD

# Literal MeshCore Packet::writeTo layout: header | path_len | pubkey |
# timestamp (LE) | Ed25519 signature | advert appdata.  This uses RFC 8032's
# fixed test seed, but is intentionally embedded rather than built through
# OpenHop's PacketBuilder so the packet-layout/signature contract is independent.
MESHCORE_ADVERT_WIRE = bytes.fromhex(
    "1100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    "7856341200844b4710c3083898f85b990be03edd18c9c4d05b82590915f72d3f04"
    "ac2eefc5446a5379bf25fbbbc7fcab87570e7552ed7d30def3291ea495be646cb1"
    "ef078146776d566563"
)
MESHCORE_ADVERT_PUBKEY = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)


class _Radio:
    def __init__(self):
        self.rx_callback = None

    def set_rx_callback(self, callback):
        self.rx_callback = callback

    async def send(self, _data: bytes):
        return True

    def get_last_rssi(self):
        return -70

    def get_last_snr(self):
        return 5.0


async def _drain_loopback() -> None:
    """Allow the loopback task and its EventService task to complete."""
    for _ in range(3):
        await asyncio.sleep(0)


def _bridge() -> CompanionBridge:
    return CompanionBridge(LocalIdentity(), AsyncMock(return_value=True))


def test_meshcore_advert_fixture_has_independent_signed_wire_layout():
    packet = Packet()
    assert packet.read_from(MESHCORE_ADVERT_WIRE)
    assert packet.write_to() == MESHCORE_ADVERT_WIRE
    assert packet.get_payload_type() == PAYLOAD_TYPE_ADVERT
    assert packet.get_route_type() == ROUTE_TYPE_FLOOD

    payload = packet.get_payload()
    pubkey, timestamp, signature, appdata = (
        payload[:32],
        payload[32:36],
        payload[36:100],
        payload[100:],
    )
    assert pubkey == MESHCORE_ADVERT_PUBKEY
    assert timestamp == bytes.fromhex("78563412")
    assert appdata == b"\x81FwmVec"
    VerifyKey(pubkey).verify(pubkey + timestamp + appdata, signature)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ("bridge", "radio"))
async def test_valid_meshcore_advert_imports_through_verified_handler_and_reexports_exactly(kind):
    companion = _bridge() if kind == "bridge" else CompanionRadio(_Radio(), LocalIdentity())

    # MeshCore returns success once parsing/type validation has queued loopback.
    assert companion.import_contact(MESHCORE_ADVERT_WIRE) is True
    await _drain_loopback()

    contact = companion.get_contact_by_key(MESHCORE_ADVERT_PUBKEY)
    assert contact is not None
    assert contact.name == "FwmVec"
    assert contact.last_advert_packet == MESHCORE_ADVERT_WIRE
    assert companion.export_contact(MESHCORE_ADVERT_PUBKEY) == MESHCORE_ADVERT_WIRE


@pytest.mark.asyncio
async def test_import_success_is_deferred_but_forged_advert_never_creates_contact():
    bridge = _bridge()
    forged = bytearray(MESHCORE_ADVERT_WIRE)
    forged[-1] ^= 0x01  # appdata changes without updating the signed region

    # Firmware importContact succeeds here because this is a parseable ADVERT;
    # Mesh::onRecvPacket rejects it when the queued loopback verifies its signature.
    assert bridge.import_contact(bytes(forged)) is True
    await _drain_loopback()
    assert bridge.get_contact_by_key(MESHCORE_ADVERT_PUBKEY) is None


@pytest.mark.asyncio
async def test_import_uses_normal_autoadd_policy_instead_of_direct_store_mutation():
    bridge = _bridge()
    bridge.prefs.manual_add_contacts = 1
    bridge.prefs.autoadd_config = AUTOADD_REPEATER

    assert bridge.import_contact(MESHCORE_ADVERT_WIRE) is True
    await _drain_loopback()
    assert bridge.get_contact_by_key(MESHCORE_ADVERT_PUBKEY) is None


@pytest.mark.asyncio
async def test_import_contact_of_own_advert_is_still_ignored():
    """Importing our own advert reports success (the packet parsed) but never
    reaches the advert handler, matching Mesh::onRecvPacket (Mesh.cpp:263)."""
    identity = LocalIdentity()
    bridge = CompanionBridge(identity, AsyncMock(return_value=True))
    handler = AsyncMock()
    bridge._get_advert_handler = lambda: handler

    assert bridge.import_contact(PacketBuilder.create_advert(identity, "Me").write_to()) is True
    await _drain_loopback()

    handler.assert_not_awaited()
    assert bridge.get_contact_by_key(identity.get_public_key()) is None


def test_legacy_export_record_and_non_advert_are_rejected_before_loopback():
    bridge = _bridge()
    legacy_record = b"\x03" * 32 + b"\x01" + b"Legacy\x00".ljust(32, b"\x00") + b"\x00" * 8
    non_advert = b"\x09\x00\x00"  # flood ACK packet with a one-byte payload

    assert len(legacy_record) == 73
    assert bridge.import_contact(legacy_record) is False
    assert bridge.import_contact(non_advert) is False


def test_self_export_is_a_fresh_signed_flood_advert():
    identity = LocalIdentity()
    bridge = CompanionBridge(identity, AsyncMock(return_value=True), node_name="SelfExport")

    raw = bridge.export_contact()
    assert raw is not None
    packet = Packet()
    assert packet.read_from(raw)
    assert packet.get_payload_type() == PAYLOAD_TYPE_ADVERT
    assert packet.get_route_type() == ROUTE_TYPE_FLOOD
    payload = packet.get_payload()
    pubkey, timestamp, signature, appdata = (
        payload[:32],
        payload[32:36],
        payload[36:100],
        payload[100:],
    )
    assert pubkey == identity.get_public_key()
    assert Identity(pubkey).verify(pubkey + timestamp + appdata, signature)


@pytest.mark.asyncio
async def test_frame_commands_export_raw_peer_advert_and_keep_firmware_import_response_semantics():
    bridge = _bridge()
    bridge.contacts.add(
        Contact(
            public_key=MESHCORE_ADVERT_PUBKEY,
            name="FwmVec",
            last_advert_packet=MESHCORE_ADVERT_WIRE,
        )
    )
    server = CompanionFrameServer(bridge, "fixture", port=0)
    written: list[bytes] = []
    server._write_frame = written.append

    await server._cmd_export_contact(MESHCORE_ADVERT_PUBKEY)
    assert written == [bytes([RESP_CODE_EXPORT_CONTACT]) + MESHCORE_ADVERT_WIRE]

    written.clear()
    await server._cmd_import_contact(MESHCORE_ADVERT_WIRE)
    assert written == [bytes([RESP_CODE_OK])]
    await _drain_loopback()

    written.clear()
    await server._cmd_import_contact(b"\x09\x00\x00")
    assert written == [bytes([RESP_CODE_ERR, ERR_CODE_ILLEGAL_ARG])]
