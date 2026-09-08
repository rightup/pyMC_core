"""Companion frame protocol server package.

The public entry point is :class:`CompanionFrameServer`; the implementation is
split across transport, push, and command-handler mixin modules.
"""

from .frames import _build_advert_push_frames, _encode_contact_fields  # noqa: F401
from .server import CompanionFrameServer

__all__ = ["CompanionFrameServer"]
