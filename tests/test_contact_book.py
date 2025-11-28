import pytest

from pymc_core.node.contact_book import ContactBook, ContactBookPreferences
from pymc_core.protocol import (
    CONTACT_TYPE_CHAT_NODE,
    CONTACT_TYPE_HYBRID,
    CONTACT_TYPE_ROOM_SERVER,
)


def _pubkey(prefix: int) -> str:
    return (bytes([prefix]) + b"\xAA" * 31).hex()


def test_room_server_gets_cli_and_telemetry_by_default():
    book = ContactBook()
    record = book.add_contact({"public_key": _pubkey(0x21), "type": CONTACT_TYPE_ROOM_SERVER})

    assert book.can_execute_cli(record)
    assert book.can_receive_telemetry(record)
    assert book.can_use_bridge(record) is False


def test_allow_read_only_enables_cli_for_chat_nodes():
    prefs = ContactBookPreferences(allow_read_only=True)
    book = ContactBook(prefs=prefs)
    record = book.add_contact({"public_key": _pubkey(0x11), "type": CONTACT_TYPE_CHAT_NODE})

    assert book.can_execute_cli(record)
    assert book.can_receive_telemetry(record) is False


def test_bridge_permission_tracks_preference():
    prefs = ContactBookPreferences(bridge_enabled=True)
    book = ContactBook(prefs=prefs)
    record = book.add_contact({"public_key": _pubkey(0x33), "type": CONTACT_TYPE_HYBRID})

    assert book.can_use_bridge(record)

    book.update_preferences(bridge_enabled=False)
    assert book.can_use_bridge(record) is False


def test_set_permissions_overrides_defaults():
    book = ContactBook()
    record = book.add_contact({"public_key": _pubkey(0x44), "type": CONTACT_TYPE_CHAT_NODE})

    assert book.can_execute_cli(record) is False

    book.set_permissions(record.public_key, allow_cli=True, allow_telemetry=True)

    assert book.can_execute_cli(record)
    assert book.can_receive_telemetry(record)


def test_get_by_hash_and_remove():
    book = ContactBook()
    record = book.add_contact({"public_key": _pubkey(0x55), "name": "peer"})

    retrieved = book.get_by_hash(record.src_hash())
    assert retrieved is record

    removed = book.remove_contact(record.public_key)
    assert removed is True
    assert book.list_contacts() == []


def test_add_contact_dict_preserves_fields():
    book = ContactBook()
    data = {
        "public_key": _pubkey(0x66),
        "name": "sensor",
        "type": CONTACT_TYPE_CHAT_NODE,
        "longitude": 1.23,
        "latitude": 4.56,
        "flags": 0xAA,
    }
    record = book.add_contact(data)

    assert record.name == "sensor"
    assert record.longitude == pytest.approx(1.23)
    assert record.latitude == pytest.approx(4.56)
    assert record.flags == 0xAA
