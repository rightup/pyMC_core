"""Tests for companion flood-scope / region support."""

from __future__ import annotations

import pytest

from openhop_core.companion import CompanionRadio
from openhop_core.companion.models import Channel
from openhop_core.protocol import LocalIdentity, Packet, PacketBuilder
from openhop_core.protocol.constants import (
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_FLOOD,
)
from openhop_core.protocol.transport_keys import calc_transport_code, get_auto_key_for

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_flood_packet() -> Packet:
    """Create a minimal flood-routed advert packet for testing."""
    identity = LocalIdentity()
    return PacketBuilder.create_advert(
        local_identity=identity,
        name="test",
        route_type="flood",
    )


def _make_direct_packet() -> Packet:
    """Create a minimal direct-routed advert packet for testing."""
    identity = LocalIdentity()
    return PacketBuilder.create_advert(
        local_identity=identity,
        name="test",
        route_type="direct",
    )


class MockRadio:
    """Minimal mock radio for CompanionRadio."""

    def __init__(self):
        self.rx_callback = None
        self.sent: list[bytes] = []

    def set_rx_callback(self, callback):
        self.rx_callback = callback

    async def send(self, data: bytes) -> bool:
        self.sent.append(data)
        return True


def _make_companion() -> CompanionRadio:
    """Create a CompanionRadio with a mock radio for testing."""
    radio = MockRadio()
    identity = LocalIdentity()
    return CompanionRadio(radio=radio, identity=identity, node_name="test")


# ---------------------------------------------------------------------------
# _apply_flood_scope unit tests
# ---------------------------------------------------------------------------


class TestApplyFloodScope:
    def test_sets_transport_codes_on_flood_packet(self):
        companion = _make_companion()
        key = get_auto_key_for("#usa")
        companion.set_flood_scope(key)
        pkt = _make_flood_packet()

        companion._apply_flood_scope(pkt)

        assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert pkt.transport_codes[0] != 0
        assert pkt.transport_codes[1] == 0

    def test_transport_code_matches_calc(self):
        companion = _make_companion()
        key = get_auto_key_for("#test-region")
        companion.set_flood_scope(key)
        pkt = _make_flood_packet()

        expected_code = calc_transport_code(key, pkt)
        companion._apply_flood_scope(pkt)

        assert pkt.transport_codes[0] == expected_code

    def test_noop_when_no_key_set(self):
        companion = _make_companion()
        pkt = _make_flood_packet()
        original_header = pkt.header

        companion._apply_flood_scope(pkt)

        assert pkt.header == original_header
        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
        assert pkt.transport_codes == [0, 0]

    def test_noop_on_direct_packet(self):
        companion = _make_companion()
        key = get_auto_key_for("#usa")
        companion.set_flood_scope(key)
        pkt = _make_direct_packet()
        original_header = pkt.header

        companion._apply_flood_scope(pkt)

        assert pkt.header == original_header
        assert pkt.get_route_type() == ROUTE_TYPE_DIRECT
        assert pkt.transport_codes == [0, 0]


# ---------------------------------------------------------------------------
# set_flood_region tests
# ---------------------------------------------------------------------------


class TestSetFloodRegion:
    def test_derives_key_with_hash_prefix(self):
        companion = _make_companion()
        companion.set_flood_region("#usa")
        assert companion._flood_transport_key == get_auto_key_for("#usa")

    def test_auto_adds_hash_prefix(self):
        companion = _make_companion()
        companion.set_flood_region("usa")
        assert companion._flood_transport_key == get_auto_key_for("#usa")

    def test_clear_with_none(self):
        companion = _make_companion()
        companion.set_flood_region("usa")
        assert companion._flood_transport_key is not None
        companion.set_flood_region(None)
        assert companion._flood_transport_key is None

    def test_same_key_with_or_without_prefix(self):
        c1 = _make_companion()
        c2 = _make_companion()
        c1.set_flood_region("europe")
        c2.set_flood_region("#europe")
        assert c1._flood_transport_key == c2._flood_transport_key


# ---------------------------------------------------------------------------
# set_flood_scope tests
# ---------------------------------------------------------------------------


class TestSetFloodScope:
    def test_stores_16_byte_key(self):
        companion = _make_companion()
        key = b"\x01" * 16
        companion.set_flood_scope(key)
        assert companion._flood_transport_key == key

    def test_truncates_longer_key(self):
        companion = _make_companion()
        key = b"\x02" * 32
        companion.set_flood_scope(key)
        assert companion._flood_transport_key == b"\x02" * 16

    def test_clear_with_none(self):
        companion = _make_companion()
        companion.set_flood_scope(b"\x01" * 16)
        companion.set_flood_scope(None)
        assert companion._flood_transport_key is None


# ---------------------------------------------------------------------------
# CompanionRadio dispatcher sync
# ---------------------------------------------------------------------------


class TestRadioDispatcherSync:
    def test_set_flood_scope_syncs_to_dispatcher(self):
        companion = _make_companion()
        key = get_auto_key_for("#test")
        companion.set_flood_scope(key)
        assert companion.node.dispatcher.flood_transport_key == key

    def test_set_flood_region_syncs_to_dispatcher(self):
        companion = _make_companion()
        companion.set_flood_region("test")
        expected = get_auto_key_for("#test")
        assert companion.node.dispatcher.flood_transport_key == expected

    def test_clear_syncs_to_dispatcher(self):
        companion = _make_companion()
        companion.set_flood_scope(b"\x01" * 16)
        assert companion.node.dispatcher.flood_transport_key is not None
        companion.set_flood_scope(None)
        assert companion.node.dispatcher.flood_transport_key is None

    def test_set_flood_unscoped_clears_dispatcher_mirror(self):
        companion = _make_companion()
        companion.set_flood_scope(b"\x01" * 16)
        companion.set_flood_unscoped()
        assert companion.node.dispatcher.flood_transport_key is None


# ---------------------------------------------------------------------------
# Explicit-unscoped mode (firmware CMD_SET_FLOOD_SCOPE_KEY mode 1, FW #2492)
# ---------------------------------------------------------------------------


class TestFloodUnscoped:
    def test_unscoped_leaves_plain_flood_and_marks_packet(self):
        companion = _make_companion()
        companion.set_flood_scope(b"\x01" * 16)
        companion.set_flood_unscoped()
        pkt = _make_flood_packet()

        companion._apply_flood_scope(pkt)

        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
        assert pkt.transport_codes == [0, 0]
        assert pkt._flood_scope_applied

    def test_dispatcher_skips_companion_marked_packet(self):
        """A stale dispatcher-level key must not re-scope a packet the
        companion layer deliberately left as plain flood."""
        companion = _make_companion()
        dispatcher = companion.node.dispatcher
        dispatcher.flood_transport_key = b"\x01" * 16
        pkt = _make_flood_packet()
        pkt._flood_scope_applied = True

        dispatcher._apply_flood_scope(pkt)

        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
        assert pkt.transport_codes == [0, 0]

    @pytest.mark.asyncio
    async def test_unscoped_send_stays_plain_flood_end_to_end(self):
        """set_flood_scope(K) then unscoped mode: the transmitted packet must
        be a plain flood (firmware checks send_unscoped before send_scope)."""
        radio = MockRadio()
        identity = LocalIdentity()
        companion = CompanionRadio(radio=radio, identity=identity, node_name="unscoped")
        companion.channels.set(0, Channel(name="test-ch", secret=b"\xAB" * 16))
        companion.set_flood_region("usa")
        companion.set_flood_unscoped()

        await companion.start()
        try:
            await companion.send_channel_message(0, "hello")
        finally:
            await companion.stop()

        assert len(radio.sent) > 0
        raw = radio.sent[-1]
        pkt = Packet()
        pkt.read_from(raw)
        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
        assert pkt.transport_codes == [0, 0]


# ---------------------------------------------------------------------------
# Default flood scope semantics
# ---------------------------------------------------------------------------


class TestDefaultFloodScope:
    def test_zero_key_default_is_reported_but_null_at_send(self):
        """Firmware persists and echoes a named default with an all-zero key
        (GET checks only the name); the null-key check happens at send time."""
        companion = _make_companion()
        companion.set_default_flood_scope("usa", b"\x00" * 16)

        assert companion.get_default_flood_scope() == ("usa", b"\x00" * 16)
        assert companion._resolve_flood_transport_key() is None

        pkt = _make_flood_packet()
        companion._apply_flood_scope(pkt)
        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD

    def test_default_scope_used_when_no_override(self):
        companion = _make_companion()
        key = get_auto_key_for("#usa")
        companion.set_default_flood_scope("usa", key)
        pkt = _make_flood_packet()

        expected_code = calc_transport_code(key, pkt)
        companion._apply_flood_scope(pkt)

        assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert pkt.transport_codes[0] == expected_code

    def test_apply_default_flood_scope_ignores_override(self):
        companion = _make_companion()
        default_key = get_auto_key_for("#usa")
        companion.set_default_flood_scope("usa", default_key)
        companion.set_flood_region("europe")  # transient override
        pkt = _make_flood_packet()

        expected_code = calc_transport_code(default_key, pkt)
        companion._apply_default_flood_scope(pkt)

        assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert pkt.transport_codes[0] == expected_code

    def test_apply_default_flood_scope_null_default_stays_plain(self):
        companion = _make_companion()
        companion.set_flood_region("europe")  # transient override, no default
        pkt = _make_flood_packet()

        companion._apply_default_flood_scope(pkt)

        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
        assert pkt.transport_codes == [0, 0]
        assert pkt._flood_scope_applied


# ---------------------------------------------------------------------------
# Integration: advertise with flood scope
# ---------------------------------------------------------------------------


class TestAdvertiseWithFloodScope:
    @pytest.mark.asyncio
    async def test_advertise_flood_uses_default_scope(self):
        """Flood adverts are scoped with the persisted default scope (firmware
        CMD_SEND_SELF_ADVERT builds the scope from prefs.default_scope_key)."""
        radio = MockRadio()
        identity = LocalIdentity()
        companion = CompanionRadio(radio=radio, identity=identity, node_name="scoped")
        companion.set_default_flood_scope("usa", get_auto_key_for("#usa"))

        await companion.start()
        try:
            await companion.advertise(flood=True)
        finally:
            await companion.stop()

        assert len(radio.sent) > 0
        raw = radio.sent[-1]
        pkt = Packet()
        pkt.read_from(raw)
        assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert pkt.transport_codes[0] != 0
        assert pkt.transport_codes[1] == 0

    @pytest.mark.asyncio
    async def test_advertise_flood_ignores_transient_override(self):
        """Firmware flood adverts bypass the transient send_scope override:
        with an override set but no default scope, the advert stays plain."""
        radio = MockRadio()
        identity = LocalIdentity()
        companion = CompanionRadio(radio=radio, identity=identity, node_name="scoped")
        companion.set_flood_region("usa")  # transient override only

        await companion.start()
        try:
            await companion.advertise(flood=True)
        finally:
            await companion.stop()

        assert len(radio.sent) > 0
        raw = radio.sent[-1]
        pkt = Packet()
        pkt.read_from(raw)
        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
        assert pkt.transport_codes == [0, 0]

    @pytest.mark.asyncio
    async def test_advertise_flood_without_scope_sends_normal_flood(self):
        radio = MockRadio()
        identity = LocalIdentity()
        companion = CompanionRadio(radio=radio, identity=identity, node_name="noscope")
        # No flood scope set

        await companion.start()
        try:
            await companion.advertise(flood=True)
        finally:
            await companion.stop()

        assert len(radio.sent) > 0
        raw = radio.sent[-1]
        pkt = Packet()
        pkt.read_from(raw)
        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
        assert pkt.transport_codes == [0, 0]


# ---------------------------------------------------------------------------
# Integration: GRP_TXT channel message with flood scope (firmware compat)
# ---------------------------------------------------------------------------


class TestChannelMessageFloodScope:
    """Verify send_channel_message produces firmware-compatible scoped packets.

    This is the key integration test: when set_flood_region("#nl-li") is used
    and a channel message is sent, the outgoing packet must be TRANSPORT_FLOOD
    and the transport code must match calc_transport_code(#nl-li key, packet).

    A firmware repeater's findMatch() re-derives the code from the region key
    and the received payload — if they don't match the packet is dropped.
    """

    @pytest.mark.asyncio
    async def test_channel_message_produces_transport_flood(self):
        radio = MockRadio()
        identity = LocalIdentity()
        companion = CompanionRadio(radio=radio, identity=identity, node_name="scoped")
        companion.channels.set(0, Channel(name="test-ch", secret=b"\xAB" * 16))
        companion.set_flood_region("#nl-li")

        await companion.start()
        try:
            await companion.send_channel_message(0, "hello")
        finally:
            await companion.stop()

        assert len(radio.sent) > 0, "Expected at least one packet sent"
        raw = radio.sent[-1]
        pkt = Packet()
        pkt.read_from(raw)
        assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert pkt.transport_codes[0] != 0
        assert pkt.transport_codes[1] == 0

    @pytest.mark.asyncio
    async def test_channel_message_transport_code_matches_nl_li_key(self):
        """Transport code stored in the packet must equal what the repeater would compute.

        This is the definitive firmware-compatibility test for GRP_TXT scoping.
        The repeater calls calcTransportCode(get_auto_key_for("#nl-li"), pkt)
        and compares with pkt.transport_codes[0]. If they differ, the packet is dropped.
        """
        radio = MockRadio()
        identity = LocalIdentity()
        companion = CompanionRadio(radio=radio, identity=identity, node_name="scoped")
        companion.channels.set(0, Channel(name="test-ch", secret=b"\xAB" * 16))
        companion.set_flood_region("#nl-li")

        await companion.start()
        try:
            await companion.send_channel_message(0, "hello")
        finally:
            await companion.stop()

        assert len(radio.sent) > 0
        raw = radio.sent[-1]
        pkt = Packet()
        pkt.read_from(raw)

        key = get_auto_key_for("#nl-li")
        expected_code = calc_transport_code(key, pkt)
        assert pkt.transport_codes[0] == expected_code, (
            f"Transport code mismatch: stored {pkt.transport_codes[0]:#06x}, "
            f"computed {expected_code:#06x}. "
            "The companion is not using the #nl-li key for GRP_TXT packets."
        )

    @pytest.mark.asyncio
    async def test_channel_message_no_scope_sends_normal_flood(self):
        radio = MockRadio()
        identity = LocalIdentity()
        companion = CompanionRadio(radio=radio, identity=identity, node_name="noscope")
        companion.channels.set(0, Channel(name="test-ch", secret=b"\xAB" * 16))
        # No flood scope

        await companion.start()
        try:
            await companion.send_channel_message(0, "hello")
        finally:
            await companion.stop()

        assert len(radio.sent) > 0
        raw = radio.sent[-1]
        pkt = Packet()
        pkt.read_from(raw)
        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
        assert pkt.transport_codes == [0, 0]
