"""Push-callback ownership on a companion bridge.

The bridge is shared: a frame server, an app-facing event stream and any
host-side subscriber all register on the same lists. Each must be able to
retract its own subscriptions without taking the others down with it.
"""

import asyncio

import pytest

from openhop_core.companion import CompanionBridge
from openhop_core.companion.frame_server import CompanionFrameServer
from openhop_core.protocol import LocalIdentity, Packet


class _Injector:
    async def __call__(self, pkt: Packet, **kwargs) -> bool:
        return True


def _bridge() -> CompanionBridge:
    return CompanionBridge(LocalIdentity(), _Injector())


def _subs(bridge, event_name):
    return bridge._push_callbacks[event_name]


class TestAddRemovePushCallback:
    def test_add_then_remove(self):
        bridge = _bridge()

        def cb(*args):
            pass

        assert bridge.add_push_callback("advert_received", cb) is True
        assert cb in _subs(bridge, "advert_received")
        assert bridge.remove_push_callback("advert_received", cb) is True
        assert cb not in _subs(bridge, "advert_received")

    def test_add_is_idempotent(self):
        """Two subsystems wanting the same event must not double-fire it."""
        bridge = _bridge()

        def cb(*args):
            pass

        assert bridge.add_push_callback("advert_received", cb) is True
        assert bridge.add_push_callback("advert_received", cb) is False
        assert _subs(bridge, "advert_received").count(cb) == 1

    def test_bound_methods_dedupe_per_instance(self):
        """Bound methods are fresh objects per attribute access but compare
        equal, which is what the frame server's setup relies on."""
        bridge = _bridge()

        class Owner:
            def handler(self, *args):
                pass

        a, b = Owner(), Owner()
        assert bridge.add_push_callback("advert_received", a.handler) is True
        assert bridge.add_push_callback("advert_received", a.handler) is False
        assert bridge.add_push_callback("advert_received", b.handler) is True
        assert len(_subs(bridge, "advert_received")) == 2

    def test_remove_unknown_callback_is_false(self):
        bridge = _bridge()
        assert bridge.remove_push_callback("advert_received", lambda *a: None) is False

    def test_unknown_event_raises(self):
        bridge = _bridge()
        with pytest.raises(KeyError, match="not_an_event"):
            bridge.add_push_callback("not_an_event", lambda *a: None)

    def test_remove_leaves_other_subscribers_alone(self):
        bridge = _bridge()
        kept, dropped = (lambda *a: None), (lambda *a: None)
        bridge.add_push_callback("advert_received", kept)
        bridge.add_push_callback("advert_received", dropped)

        bridge.remove_push_callback("advert_received", dropped)

        assert _subs(bridge, "advert_received") == [kept]


class TestLegacyRegistration:
    def test_legacy_registration_is_idempotent(self):
        """The legacy registrars wrap the callback in an adapter closure; a
        fresh one per call would stack duplicates that dedupe cannot catch."""
        bridge = _bridge()

        def legacy(*args):
            pass

        bridge.on_message_received(legacy)
        bridge.on_message_received(legacy)

        assert len(_subs(bridge, "message_event")) == 1

    def test_distinct_legacy_callbacks_each_register(self):
        bridge = _bridge()
        bridge.on_message_received(lambda *a: None)
        bridge.on_message_received(lambda *a: None)
        assert len(_subs(bridge, "message_event")) == 2

    def test_clear_resets_the_adapter_memo(self):
        """Otherwise a re-registration after a clear would reuse a cached
        adapter and appear registered while the list is empty."""
        bridge = _bridge()

        def legacy(*args):
            pass

        bridge.on_message_received(legacy)
        bridge.clear_push_callbacks()
        assert _subs(bridge, "message_event") == []

        bridge.on_message_received(legacy)
        assert len(_subs(bridge, "message_event")) == 1


@pytest.mark.asyncio
class TestFrameServerOwnsOnlyItsOwn:
    async def test_client_connect_does_not_unsubscribe_the_host(self):
        """The regression: an app-facing subscriber (the repeater's SSE stream)
        used to go silent the moment a companion app connected over TCP."""
        bridge = _bridge()
        seen = []
        bridge.on_advert_received(lambda *args: seen.append(args))
        server = CompanionFrameServer(bridge, "hash", port=0)

        server._setup_push_callbacks()

        assert len(_subs(bridge, "advert_received")) == 2
        await bridge._fire_callbacks("advert_received", "contact")
        assert seen == [("contact",)]

    async def test_reconnect_does_not_stack_the_server_subscriptions(self):
        bridge = _bridge()
        server = CompanionFrameServer(bridge, "hash", port=0)

        server._setup_push_callbacks()
        server._setup_push_callbacks()
        server._setup_push_callbacks()

        assert len(_subs(bridge, "advert_received")) == 1
        assert len(_subs(bridge, "message_event")) == 1

    async def test_host_registered_handler_is_not_duplicated_by_setup(self):
        """A host may subscribe the server's own handler before a client connects
        (the repeater does this to persist messages with no client attached)."""
        bridge = _bridge()
        server = CompanionFrameServer(bridge, "hash", port=0)
        bridge.on_message_event(server._on_message_event)

        server._setup_push_callbacks()

        assert len(_subs(bridge, "message_event")) == 1

    async def test_stop_retracts_the_server_subscriptions(self):
        bridge = _bridge()
        kept = []
        bridge.on_advert_received(lambda *args: kept.append(args))
        server = CompanionFrameServer(bridge, "hash", port=0)
        server._setup_push_callbacks()

        await server.stop()

        assert len(_subs(bridge, "advert_received")) == 1
        assert server._on_advert_received not in _subs(bridge, "advert_received")

    async def test_a_replacement_server_subscribes_exactly_once(self):
        """Stop-then-rebuild is how a host restarts a companion's frame server."""
        bridge = _bridge()
        first = CompanionFrameServer(bridge, "hash", port=0)
        first._setup_push_callbacks()
        await first.stop()

        second = CompanionFrameServer(bridge, "hash", port=0)
        second._setup_push_callbacks()

        assert len(_subs(bridge, "message_event")) == 1
        assert _subs(bridge, "message_event") == [second._on_message_event]


@pytest.mark.asyncio
class TestFireCallbacks:
    async def test_unsubscribing_during_dispatch_is_safe(self):
        """Dispatch awaits, so a handler can resubscribe or leave mid-loop."""
        bridge = _bridge()
        calls = []

        async def first(*args):
            calls.append("first")
            bridge.remove_push_callback("advert_received", second)
            await asyncio.sleep(0)

        async def second(*args):
            calls.append("second")

        bridge.add_push_callback("advert_received", first)
        bridge.add_push_callback("advert_received", second)

        await bridge._fire_callbacks("advert_received", "x")

        assert calls == ["first", "second"]
        assert _subs(bridge, "advert_received") == [first]
