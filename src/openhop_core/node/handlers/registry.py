"""Handler registry for creating and wiring standard MeshCore protocol handlers.

Both the :class:`Dispatcher` and :class:`CompanionBridge` need the same core
set of handlers — this module provides a shared factory so handler creation
and cross-wiring only lives in one place.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from .advert import AdvertHandler
from .group_text import GroupTextHandler
from .login_response import LoginResponseHandler
from .path import PathHandler
from .protocol_response import ProtocolResponseHandler
from .return_path import RETURN_PATH_DEFAULT_SF, ReturnPathTeacher
from .text import TextMessageHandler


@dataclass
class CoreHandlers:
    """Bundle of the core protocol handlers shared by Dispatcher and Bridge."""

    text_handler: TextMessageHandler
    advert_handler: AdvertHandler
    group_text_handler: GroupTextHandler
    protocol_response_handler: ProtocolResponseHandler
    login_response_handler: LoginResponseHandler
    path_handler: PathHandler
    return_path_teacher: ReturnPathTeacher


def create_core_handlers(
    *,
    identity: Any,
    contacts: Any,
    channels: Any,
    event_service: Any,
    send_packet_fn: Callable,
    log_fn: Callable,
    node_name: str,
    radio_config: Optional[dict] = None,
    ack_handler: Any = None,
    group_packet_seen_callback: Optional[Callable[[Any], bool]] = None,
) -> CoreHandlers:
    """Create and wire the standard set of MeshCore protocol handlers.

    This is the single source of truth for handler construction.  Both
    :meth:`Dispatcher.register_default_handlers` and
    :class:`CompanionBridge.__init__` delegate here.

    Args:
        identity: The local identity for encryption/signing.
        contacts: Contact storage.
        channels: Channel database.
        event_service: Event service for broadcasting mesh events.
        send_packet_fn: Async callable to send a packet (the transport).
        log_fn: Logging callable (``str -> None``).
        node_name: Human-readable node name.
        radio_config: Optional radio configuration dict.
        ack_handler: ACK handler instance (varies between Dispatcher and
            Bridge).  If ``None``, the :class:`PathHandler` is constructed
            without ACK forwarding.
        group_packet_seen_callback: Optional shared full-hash cache callback
            for companion group text/data loopback suppression.
    """

    # Shared by both response handlers so the per-contact re-teach cooldown is
    # accounted once, not once per handler. Its transmit path is wired later,
    # via ProtocolResponseHandler.set_packet_injector.
    #
    # The spreading factor is read through a callable, not captured: it sets the
    # demodulator SNR limit every copy's margin is measured against, and a radio
    # reconfigure at runtime must move that limit with it. Falls back to SF7 when
    # the host supplies no radio config.
    def _sf_from_radio_config() -> int:
        return int((radio_config or {}).get("spreading_factor", RETURN_PATH_DEFAULT_SF))

    return_path_teacher = ReturnPathTeacher(
        log_fn, identity, contacts, sf_getter=_sf_from_radio_config
    )

    protocol_response_handler = ProtocolResponseHandler(
        log_fn, identity, contacts, return_path_teacher=return_path_teacher
    )

    login_response_handler = LoginResponseHandler(
        identity, contacts, log_fn, return_path_teacher=return_path_teacher
    )
    login_response_handler.set_protocol_response_handler(protocol_response_handler)
    protocol_response_handler.set_login_response_handler(login_response_handler)

    path_handler = PathHandler(
        log_fn,
        ack_handler,
        protocol_response_handler,
        login_response_handler,
    )

    text_handler = TextMessageHandler(
        identity,
        contacts,
        log_fn,
        send_packet_fn,
        event_service,
        radio_config,
    )

    advert_handler = AdvertHandler(log_fn, event_service=event_service, local_identity=identity)

    group_text_handler = GroupTextHandler(
        identity,
        contacts,
        log_fn,
        send_packet_fn,
        channels,
        event_service,
        group_packet_seen_callback,
    )

    return CoreHandlers(
        text_handler=text_handler,
        advert_handler=advert_handler,
        group_text_handler=group_text_handler,
        protocol_response_handler=protocol_response_handler,
        login_response_handler=login_response_handler,
        path_handler=path_handler,
        return_path_teacher=return_path_teacher,
    )
