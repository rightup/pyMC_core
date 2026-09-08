"""Tests for resolve_max_tx_power_dbm capability resolution."""

from __future__ import annotations

from openhop_core.companion.radio_capabilities import resolve_max_tx_power_dbm


def test_callable_getter_wins_over_attribute_and_settings():
    class _Radio:
        max_tx_power_dbm = 5

        def get_max_tx_power_dbm(self):
            return 30

    assert resolve_max_tx_power_dbm(_Radio(), {"max_tx_power_dbm": 10}) == 30


def test_attribute_used_when_no_getter():
    class _Radio:
        max_tx_power_dbm = 17

    assert resolve_max_tx_power_dbm(_Radio(), {"max_tx_power": 10}) == 17


def test_settings_max_tx_power_dbm_spelling():
    assert resolve_max_tx_power_dbm(object(), {"max_tx_power_dbm": 12}) == 12


def test_settings_max_tx_power_spelling():
    assert resolve_max_tx_power_dbm(object(), {"max_tx_power": 8}) == 8


def test_none_when_nothing_declares_a_limit():
    assert resolve_max_tx_power_dbm(object(), {}) is None
    assert resolve_max_tx_power_dbm(object()) is None


def test_raising_getter_falls_through_to_attribute():
    class _Radio:
        max_tx_power_dbm = 14

        def get_max_tx_power_dbm(self):
            raise RuntimeError("backend unavailable")

    assert resolve_max_tx_power_dbm(_Radio()) == 14


def test_invalid_getter_value_falls_through_to_settings():
    class _Radio:
        def get_max_tx_power_dbm(self):
            return "not-a-number"

    assert resolve_max_tx_power_dbm(_Radio(), {"max_tx_power_dbm": 11}) == 11


def test_non_numeric_attribute_falls_through_to_settings():
    class _Radio:
        max_tx_power_dbm = "not-a-number"

    assert resolve_max_tx_power_dbm(_Radio(), {"max_tx_power": 9}) == 9
