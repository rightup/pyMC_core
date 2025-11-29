import struct
from unittest.mock import AsyncMock, MagicMock

import pytest

# from pymc_core.node.events import MeshEvents  # Not currently used
from pymc_core.node.contact_book import ContactBook
from pymc_core.node.handlers import (
    AckHandler,
    AdvertHandler,
    BaseHandler,
    ControlHandler,
    GroupTextHandler,
    LoginResponseHandler,
    PathHandler,
    ProtocolResponseHandler,
    TextMessageHandler,
    TraceHandler,
)
from pymc_core.protocol import LocalIdentity, Packet, PacketBuilder
from pymc_core.protocol.constants import (
    ADV_TYPE_REPEATER,
    ADV_TYPE_SENSOR,
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_ANON_REQ,
    PAYLOAD_TYPE_CONTROL,
    PAYLOAD_TYPE_GRP_TXT,
    PAYLOAD_TYPE_MULTIPART,
    PAYLOAD_TYPE_PATH,
    PAYLOAD_TYPE_RESPONSE,
    PAYLOAD_TYPE_TRACE,
    PAYLOAD_TYPE_TXT_MSG,
    PH_TYPE_SHIFT,
    PUB_KEY_SIZE,
    SIGNATURE_SIZE,
    TIMESTAMP_SIZE,
)


# Mock classes for testing
class MockContact:
    def __init__(self, public_key="0123456789abcdef0123456789abcdef", name="mock"):
        self.public_key = public_key
        self.name = name
        self.last_advert = 0


class MockContactBook:
    def __init__(self):
        self.contacts = []
        self.added_contacts = []

    def add_contact(self, contact_data):
        self.added_contacts.append(contact_data)


class MockDispatcher:
    def __init__(self):
        self.local_identity = LocalIdentity()
        self.contact_book = MockContactBook()
        self._waiting_acks = {}
        self._find_contact_by_hash = AsyncMock(return_value=MockContact())


class MockEventService:
    def __init__(self):
        self.publish = AsyncMock()
        self.publish_sync = MagicMock()


# Base Handler Tests
def test_base_handler_is_abstract():
    """Test that BaseHandler cannot be instantiated directly."""
    with pytest.raises(TypeError):
        BaseHandler()


# ACK Handler Tests
class TestAckHandler:
    def setup_method(self):
        self.log_fn = MagicMock()
        self.dispatcher = MockDispatcher()
        self.handler = AckHandler(self.log_fn, self.dispatcher)
        self.handler.set_dispatcher(self.dispatcher)

    def test_payload_type(self):
        """Test ACK handler payload type."""
        assert AckHandler.payload_type() == PAYLOAD_TYPE_ACK

    def test_ack_handler_initialization(self):
        """Test ACK handler initialization."""
        assert self.handler.log == self.log_fn
        assert self.handler.dispatcher == self.dispatcher
        assert self.handler._ack_received_callback is None

    def test_set_ack_received_callback(self):
        """Test setting ACK received callback."""
        callback = MagicMock()
        self.handler.set_ack_received_callback(callback)
        assert self.handler._ack_received_callback == callback

    @pytest.mark.asyncio
    async def test_process_discrete_ack_valid(self):
        """Test processing a valid discrete ACK packet."""
        # Create packet with 4-byte CRC payload
        packet = Packet()
        packet.payload = bytearray(b"\x78\x56\x34\x12")  # CRC 0x12345678

        crc = await self.handler.process_discrete_ack(packet)
        assert crc == 0x12345678
        self.log_fn.assert_called()

    @pytest.mark.asyncio
    async def test_process_discrete_ack_invalid_length(self):
        """Test processing ACK packet with invalid length."""
        packet = Packet()
        packet.payload = bytearray(b"\x12\x34")  # Too short

        crc = await self.handler.process_discrete_ack(packet)
        assert crc is None
        self.log_fn.assert_called()

    @pytest.mark.asyncio
    async def test_call_discrete_ack(self):
        """Test calling ACK handler with discrete ACK packet."""
        # Create packet with 4-byte CRC payload
        packet = Packet()
        packet.payload = bytearray(b"\x78\x56\x34\x12")  # CRC 0x12345678

        callback = MagicMock()
        self.handler.set_ack_received_callback(callback)

        await self.handler(packet)

        callback.assert_called_once_with(0x12345678)

    @pytest.mark.asyncio
    async def test_process_multipart_ack_valid(self):
        """Test decoding of multipart ACK payloads."""
        packet = Packet()
        packet.payload = bytearray(b"\x13\x78\x56\x34\x12")
        packet.payload_len = len(packet.payload)

        crc = await self.handler.process_multipart_ack(packet)
        assert crc == 0x12345678

    @pytest.mark.asyncio
    async def test_call_multipart_ack(self):
        """Ensure multipart ACK packets trigger dispatcher callback."""
        packet = Packet()
        packet.payload = bytearray(b"\x13\x78\x56\x34\x12")
        packet.payload_len = len(packet.payload)
        packet.header = PAYLOAD_TYPE_MULTIPART << PH_TYPE_SHIFT

        callback = MagicMock()
        self.handler.set_ack_received_callback(callback)

        await self.handler(packet)

        callback.assert_called_once_with(0x12345678)


# Text Message Handler Tests
class TestTextMessageHandler:
    def setup_method(self):
        self.local_identity = LocalIdentity()
        self.contacts = MockContactBook()
        self.log_fn = MagicMock()
        self.send_packet_fn = AsyncMock()
        self.event_service = MockEventService()
        self.handler = TextMessageHandler(
            self.local_identity,
            self.contacts,
            self.log_fn,
            self.send_packet_fn,
            self.event_service,
        )

    def test_payload_type(self):
        """Test text message handler payload type."""
        assert TextMessageHandler.payload_type() == PAYLOAD_TYPE_TXT_MSG

    def test_text_handler_initialization(self):
        """Test text message handler initialization."""
        assert self.handler.local_identity == self.local_identity
        assert self.handler.contacts == self.contacts
        assert self.handler.log == self.log_fn
        assert self.handler.send_packet == self.send_packet_fn
        assert self.handler.event_service == self.event_service

    def test_set_command_response_callback(self):
        """Test setting command response callback."""
        callback = MagicMock()
        self.handler.set_command_response_callback(callback)
        assert self.handler.command_response_callback == callback

    @pytest.mark.asyncio
    async def test_call_with_short_payload(self):
        """Test calling text handler with payload too short to decrypt."""
        packet = Packet()
        packet.payload = bytearray(b"\x12\x34")  # Too short

        await self.handler(packet)

        # Should return early without processing
        self.log_fn.assert_called()

class TestTextHandlerACL:
    @pytest.mark.asyncio
    async def test_cli_command_blocked_without_permission(self, monkeypatch):
        local_identity = LocalIdentity()
        contacts = ContactBook()
        peer = LocalIdentity()
        record = contacts.add_contact(
            {
                "public_key": peer.get_public_key().hex(),
                "name": "peer",
                "type": 1,
            }
        )
        contacts.set_permissions(record.public_key, allow_cli=False)

        log_fn = MagicMock()
        send_packet = AsyncMock()
        handler = TextMessageHandler(local_identity, contacts, log_fn, send_packet, None)

        dest_hash = local_identity.get_public_key()[0]
        src_hash = record.src_hash()
        packet = Packet()
        packet.payload = bytearray([dest_hash, src_hash]) + bytearray(b"\x00" * 16)
        packet.payload_len = len(packet.payload)
        packet.header = 0

        plaintext = (1234).to_bytes(4, "little") + bytes([0x01]) + b"reboot"
        monkeypatch.setattr(
            "pymc_core.node.handlers.text.CryptoUtils.mac_then_decrypt",
            lambda *args, **kwargs: plaintext,
        )

        await handler(packet)

        send_packet.assert_not_called()
        log_fn.assert_called()


class TestProtocolResponseACL:
    @pytest.mark.asyncio
    async def test_telemetry_blocked_when_not_allowed(self, monkeypatch):
        contacts = ContactBook()
        local_identity = LocalIdentity()
        peer = LocalIdentity()
        record = contacts.add_contact(
            {
                "public_key": peer.get_public_key().hex(),
                "name": "peer",
                "type": 1,
            }
        )
        contacts.set_permissions(record.public_key, allow_telemetry=False)

        log_fn = MagicMock()
        handler = ProtocolResponseHandler(log_fn, local_identity, contacts)

        captured = []

        def callback(success, text, parsed):
            captured.append((success, text, parsed))

        src_hash = record.src_hash()
        handler.set_response_callback(src_hash, callback)

        packet = Packet()
        dest_hash = local_identity.get_public_key()[0]
        packet.payload = bytearray([dest_hash, src_hash]) + bytearray(b"\x00" * 8)
        packet.payload_len = len(packet.payload)
        packet.header = (PAYLOAD_TYPE_PATH << 2)

        plaintext = (4321).to_bytes(4, "little") + b"\x01\x02\x03"
        monkeypatch.setattr(
            "pymc_core.node.handlers.protocol_response.CryptoUtils.mac_then_decrypt",
            lambda *args, **kwargs: plaintext,
        )

        await handler(packet)

        assert captured, "Expected callback to be invoked"
        success, text, parsed = captured[0]
        assert success is False
        assert text == "Telemetry blocked by ACL"
        assert parsed == {"type": "telemetry", "acl_blocked": True}


# Advert Handler Tests
class TestAdvertHandler:
    def setup_method(self):
        self.contacts = MockContactBook()
        self.log_fn = MagicMock()
        self.local_identity = LocalIdentity()
        self.event_service = MockEventService()
        self.handler = AdvertHandler(
            self.contacts, self.log_fn, self.local_identity, self.event_service
        )

    def test_payload_type(self):
        """Test advert handler payload type."""
        assert AdvertHandler.payload_type() == PAYLOAD_TYPE_ADVERT

    def test_advert_handler_initialization(self):
        """Test advert handler initialization."""
        assert self.handler.contacts == self.contacts
        assert self.handler.log == self.log_fn
        assert self.handler.identity == self.local_identity
        assert self.handler.event_service == self.event_service

    @pytest.mark.asyncio
    async def test_advert_handler_accepts_valid_signature(self):
        remote_identity = LocalIdentity()
        packet = PacketBuilder.create_advert(remote_identity, "RemoteNode")

        await self.handler(packet)

        assert len(self.contacts.added_contacts) == 1
        added_contact = self.contacts.added_contacts[0]
        assert added_contact["public_key"] == remote_identity.get_public_key().hex()

    @pytest.mark.asyncio
    async def test_advert_handler_rejects_invalid_signature(self):
        remote_identity = LocalIdentity()
        packet = PacketBuilder.create_advert(remote_identity, "RemoteNode")
        appdata_offset = PUB_KEY_SIZE + TIMESTAMP_SIZE + SIGNATURE_SIZE + 5
        if appdata_offset >= packet.payload_len:
            appdata_offset = packet.payload_len - 1
        packet.payload[appdata_offset] ^= 0x01

        await self.handler(packet)

        assert len(self.contacts.added_contacts) == 0
        assert any(
            "invalid signature" in call.args[0].lower()
            for call in self.log_fn.call_args_list
            if call.args
        )

    @pytest.mark.asyncio
    async def test_advert_handler_ignores_self_advert(self):
        packet = PacketBuilder.create_advert(self.local_identity, "SelfNode")

        await self.handler(packet)

        assert len(self.contacts.added_contacts) == 0
        assert any(
            "self advert" in call.args[0].lower()
            for call in self.log_fn.call_args_list
            if call.args
        )


# Path Handler Tests
class TestPathHandler:
    def setup_method(self):
        self.log_fn = MagicMock()
        self.ack_handler = AckHandler(self.log_fn)
        self.protocol_response_handler = MagicMock()
        self.handler = PathHandler(self.log_fn, self.ack_handler, self.protocol_response_handler)

    def test_payload_type(self):
        """Test path handler payload type."""
        assert PathHandler.payload_type() == PAYLOAD_TYPE_PATH

    def test_path_handler_initialization(self):
        """Test path handler initialization."""
        assert self.handler._log == self.log_fn
        assert self.handler._ack_handler == self.ack_handler
        assert self.handler._protocol_response_handler == self.protocol_response_handler


# Group Text Handler Tests
class TestGroupTextHandler:
    def setup_method(self):
        self.local_identity = LocalIdentity()
        self.contacts = MockContactBook()
        self.log_fn = MagicMock()
        self.send_packet_fn = AsyncMock()
        self.event_service = MockEventService()
        self.handler = GroupTextHandler(
            self.local_identity, self.contacts, self.log_fn, self.send_packet_fn
        )
        # GroupTextHandler doesn't take event_service in constructor

    def test_payload_type(self):
        """Test group text handler payload type."""
        assert GroupTextHandler.payload_type() == PAYLOAD_TYPE_GRP_TXT

    def test_group_text_handler_initialization(self):
        """Test group text handler initialization."""
        assert self.handler.local_identity == self.local_identity
        assert self.handler.contacts == self.contacts
        assert self.handler.log == self.log_fn
        assert self.handler.send_packet == self.send_packet_fn
        # GroupTextHandler doesn't store event_service


# Login Response Handler Tests
class TestLoginResponseHandler:
    def setup_method(self):
        self.contacts = MockContactBook()
        self.log_fn = MagicMock()
        self.send_packet_fn = AsyncMock()
        self.local_identity = LocalIdentity()
        self.handler = LoginResponseHandler(self.local_identity, self.contacts, self.log_fn)

    def test_payload_type(self):
        """Test login response handler payload type."""
        assert LoginResponseHandler.payload_type() == PAYLOAD_TYPE_RESPONSE

    def test_login_response_handler_initialization(self):
        """Test login response handler initialization."""
        assert self.handler.contacts == self.contacts
        assert self.handler.log == self.log_fn
        assert self.handler.local_identity == self.local_identity
        assert self.handler.local_identity == self.local_identity

class TestControlHandler:
    def setup_method(self):
        self.log_fn = MagicMock()
        self.handler = ControlHandler(self.log_fn)

    def test_payload_type(self):
        assert ControlHandler.payload_type() == PAYLOAD_TYPE_CONTROL

    @pytest.mark.asyncio
    async def test_discovery_request_callback_receives_details(self):
        captured: list[dict] = []

        def on_request(data: dict):
            captured.append(data)

        self.handler.set_request_callback(on_request)

        pkt = Packet()
        tag = 0xA1B2C3D4
        since = 1_700_000_000
        filter_mask = (1 << ADV_TYPE_REPEATER) | (1 << ADV_TYPE_SENSOR)
        payload = bytearray()
        payload.append(0x80 | 0x01)
        payload.append(filter_mask)
        payload.extend(struct.pack("<I", tag))
        payload.extend(struct.pack("<I", since))
        pkt.payload = payload
        pkt.payload_len = len(payload)
        pkt.path_len = 0
        pkt._snr = 9.25
        pkt._rssi = -48

        await self.handler(pkt)

        assert captured, "request callback not invoked"
        data = captured[0]
        assert data["tag"] == tag
        assert data["filter_mask"] == filter_mask
        assert data["requested_types"] == [ADV_TYPE_REPEATER, ADV_TYPE_SENSOR]
        assert data["requested_type_names"] == ["repeater", "sensor"]
        assert data["since"] == since
        assert data["since_active"] is True
        assert data["prefix_only"] is True
        assert data["snr"] == pkt._snr
        assert data["raw_snr"] == pkt._snr
        assert data["rssi"] == pkt._rssi
        assert data["payload_len"] == len(payload)
        assert "unknown_filter_bits" not in data

    @pytest.mark.asyncio
    async def test_discovery_response_callback_full_key(self):
        captured: list[dict] = []
        tag = 0x01020304

        def on_response(data: dict):
            captured.append(data)

        self.handler.set_response_callback(tag, on_response)

        pub_key = bytes(range(32))
        inbound_snr = 6.25
        payload = bytearray()
        payload.append(0x90 | ADV_TYPE_REPEATER)
        payload.append(int(inbound_snr * 4) & 0xFF)
        payload.extend(struct.pack("<I", tag))
        payload.extend(pub_key)

        pkt = Packet()
        pkt.payload = payload
        pkt.payload_len = len(payload)
        pkt.path_len = 0
        pkt._snr = 7.5
        pkt._rssi = -63

        await self.handler(pkt)

        assert captured, "response callback not invoked"
        data = captured[0]
        assert data["node_type"] == ADV_TYPE_REPEATER
        assert data["node_type_name"] == "repeater"
        assert data["inbound_snr"] == pytest.approx(inbound_snr)
        assert data["response_snr"] == pytest.approx(pkt._snr)
        assert data["raw_response_snr"] == pkt._snr
        assert data["rssi"] == pkt._rssi
        assert data["prefix_only"] is False
        assert data["key_length"] == 32
        assert data["pub_key_bytes"] == pub_key
        assert data["pub_key_prefix_bytes"] == pub_key[:8]
        assert data["pub_key_prefix"] == pub_key[:8].hex()
        assert self.handler._response_callbacks == {}

    @pytest.mark.asyncio
    async def test_discovery_response_callback_prefix_key(self):
        captured: list[dict] = []
        tag = 0x0BADBEEF

        def on_response(data: dict):
            captured.append(data)

        self.handler.set_response_callback(tag, on_response)

        pub_key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")[:8]
        inbound_snr = -2.5
        payload = bytearray()
        payload.append(0x90 | ADV_TYPE_SENSOR)
        payload.append(int(inbound_snr * 4) & 0xFF)
        payload.extend(struct.pack("<I", tag))
        payload.extend(pub_key)

        pkt = Packet()
        pkt.payload = payload
        pkt.payload_len = len(payload)
        pkt.path_len = 0
        pkt._snr = -1.25
        pkt._rssi = -71

        await self.handler(pkt)

        assert captured, "response callback not invoked"
        data = captured[0]
        assert data["node_type"] == ADV_TYPE_SENSOR
        assert data["node_type_name"] == "sensor"
        assert data["inbound_snr"] == pytest.approx(inbound_snr)
        assert data["response_snr"] == pytest.approx(pkt._snr)
        assert data["prefix_only"] is True
        assert data["key_length"] == 8
        assert data["pub_key_bytes"] == pub_key
        assert data["pub_key_prefix_bytes"] == pub_key
        assert data["pub_key_prefix"] == pub_key.hex()


# Protocol Response Handler Tests
class TestProtocolResponseHandler:
    def setup_method(self):
        self.contacts = MockContactBook()
        self.log_fn = MagicMock()
        self.send_packet_fn = AsyncMock()
        self.local_identity = LocalIdentity()
        self.handler = ProtocolResponseHandler(self.log_fn, self.local_identity, self.contacts)

    def test_payload_type(self):
        """Test protocol response handler payload type."""
        assert ProtocolResponseHandler.payload_type() == PAYLOAD_TYPE_PATH

    def test_protocol_response_handler_initialization(self):
        """Test protocol response handler initialization."""
        assert self.handler._contact_book == self.contacts
        assert self.handler._log == self.log_fn
        assert self.handler._local_identity == self.local_identity


# Trace Handler Tests
class TestTraceHandler:
    def setup_method(self):
        self.log_fn = MagicMock()
        self.local_identity = LocalIdentity()
        self.handler = TraceHandler(self.log_fn)

    def test_payload_type(self):
        """Test trace handler payload type."""
        assert TraceHandler.payload_type() == PAYLOAD_TYPE_TRACE

    def test_trace_handler_initialization(self):
        """Test trace handler initialization."""
        assert self.handler._log == self.log_fn


# Integration Tests
@pytest.mark.asyncio
async def test_all_handlers_have_correct_payload_types():
    """Test that all handlers have unique and correct payload types."""
    handlers = [
        (AckHandler, PAYLOAD_TYPE_ACK),
        (TextMessageHandler, PAYLOAD_TYPE_TXT_MSG),
        (AdvertHandler, PAYLOAD_TYPE_ADVERT),
        (PathHandler, PAYLOAD_TYPE_PATH),
        (GroupTextHandler, PAYLOAD_TYPE_GRP_TXT),
        (LoginResponseHandler, PAYLOAD_TYPE_RESPONSE),
        (
            ProtocolResponseHandler,
            PAYLOAD_TYPE_PATH,
        ),  # Protocol responses come as PATH packets
        (TraceHandler, PAYLOAD_TYPE_TRACE),
    ]

    payload_types = []
    for handler_class, expected_type in handlers:
        payload_type = handler_class.payload_type()
        assert payload_type == expected_type
        payload_types.append(payload_type)

    # Check for uniqueness (except for LoginResponseHandler and
    # ProtocolResponseHandler which share RESPONSE)
    unique_types = set(payload_types)
    assert (
        len(unique_types) == len(payload_types) - 1
    )  # -1 because two handlers share RESPONSE type


@pytest.mark.asyncio
async def test_handlers_can_be_called():
    """Test that all handlers can be instantiated and called without errors."""
    local_identity = LocalIdentity()
    contacts = MockContactBook()
    log_fn = MagicMock()
    send_packet_fn = AsyncMock()
    event_service = MockEventService()

    handlers = [
        AckHandler(log_fn),
        TextMessageHandler(local_identity, contacts, log_fn, send_packet_fn, event_service),
        AdvertHandler(contacts, log_fn, local_identity, event_service),
        PathHandler(log_fn),
        GroupTextHandler(local_identity, contacts, log_fn, send_packet_fn),
        LoginResponseHandler(local_identity, contacts, log_fn),
        ProtocolResponseHandler(log_fn, local_identity, contacts),
        TraceHandler(log_fn),
    ]

    # Create a minimal packet for testing
    packet = Packet()
    packet.payload = bytearray(b"test_payload")

    # All handlers should be callable without raising exceptions
    for handler in handlers:
        try:
            await handler(packet)
        except Exception as e:
            # Some handlers may raise exceptions due to incomplete setup,
            # but they should be callable
            assert isinstance(e, (ValueError, AttributeError, TypeError))  # Expected exceptions


# AnonReqResponseHandler Tests (separate from LoginResponseHandler)
def test_anon_req_response_handler():
    """Test AnonReqResponseHandler can be imported and has correct payload type."""
    from pymc_core.node.handlers import AnonReqResponseHandler

    # Should have same payload type as anonymous requests
    assert AnonReqResponseHandler.payload_type() == PAYLOAD_TYPE_ANON_REQ
