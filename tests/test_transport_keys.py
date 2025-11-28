import pytest

from pymc_core.protocol import Packet
from pymc_core.protocol.transport_keys import (
    TransportKey,
    TransportKeyStore,
    calc_transport_code,
    derive_auto_key,
)


@pytest.fixture
def sample_packet() -> Packet:
    pkt = Packet()
    pkt.header = (1 << 6) | (0 << 4) | (3 << 2) | 0
    pkt.payload = bytearray(b"hello world")
    pkt.payload_len = len(pkt.payload)
    pkt.path_len = 0
    return pkt


def test_calc_transport_code_matches_reference(sample_packet):
    key = bytes(range(16))
    assert calc_transport_code(key, sample_packet) == 0x8D7B


def test_transport_key_wrapper_matches_function(sample_packet):
    key = bytes(range(16))
    tk = TransportKey(key)
    assert tk.calc_transport_code(sample_packet) == calc_transport_code(key, sample_packet)


def test_calc_transport_code_reserves_zero_and_ffff(sample_packet, monkeypatch):
    called = {"data": None}

    def fake_hmac(key, data):
        called["data"] = data
        return b"\x00\x00" + b"\x00" * 30

    monkeypatch.setattr(
        "pymc_core.protocol.transport_keys.CryptoUtils._hmac_sha256",
        fake_hmac,
    )
    assert calc_transport_code(bytes(range(16)), sample_packet) == 1

    def fake_hmac_ff(key, data):
        return b"\xFF\xFF" + b"\x00" * 30

    monkeypatch.setattr(
        "pymc_core.protocol.transport_keys.CryptoUtils._hmac_sha256",
        fake_hmac_ff,
    )
    assert calc_transport_code(bytes(range(16)), sample_packet) == 0xFFFE


@pytest.mark.parametrize(
    "name",
    ["", "usa", "#" + "a" * 65],
)
def test_derive_auto_key_validation(name):
    with pytest.raises(ValueError):
        derive_auto_key(name)


def test_key_store_auto_key_caches(monkeypatch):
    store = TransportKeyStore(max_entries=4)
    calls = {"count": 0}

    def fake_derive(name):
        calls["count"] += 1
        return b"A" * 16

    monkeypatch.setattr(
        "pymc_core.protocol.transport_keys.derive_auto_key",
        fake_derive,
    )

    first = store.get_auto_key_for(17, "#test")
    second = store.get_auto_key_for(17, "#other")

    assert first.key == second.key == b"A" * 16
    assert calls["count"] == 1


def test_key_store_save_load_remove():
    store = TransportKeyStore(max_entries=2)
    key_a = bytes.fromhex("00" * 15 + "01")
    key_b = bytes.fromhex("00" * 15 + "02")

    assert store.save_keys_for(1, [key_a, TransportKey(key_b)])
    loaded = store.load_keys_for(1)
    assert len(loaded) == 2
    assert {k.key for k in loaded} == {key_a, key_b}

    assert store.remove_keys(1)
    assert store.load_keys_for(1) == []

    assert store.clear() is False  # already empty


def test_key_store_cache_bounds():
    store = TransportKeyStore(max_entries=3)
    for region_id in range(6):
        store.save_keys_for(region_id, [bytes([region_id % 256]) * 16])

    snapshot = store.cache_snapshot()
    assert len(snapshot) == 3
    assert [rid for rid, _ in snapshot] == [3, 4, 5]
