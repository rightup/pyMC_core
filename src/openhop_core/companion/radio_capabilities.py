"""Resolve a radio backend's maximum TX power for companion SELF_INFO."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any, Optional

logger = logging.getLogger("radio_capabilities")


def resolve_max_tx_power_dbm(
    source: Any, settings: Optional[Mapping[str, Any]] = None
) -> Optional[int]:
    """Return the maximum TX power a backend declares, or None.

    Resolution order: a callable ``get_max_tx_power_dbm()`` on ``source``, a
    ``max_tx_power_dbm`` attribute on ``source``, then a ``max_tx_power_dbm``
    or ``max_tx_power`` entry in ``settings``. Each candidate is coerced with
    ``int()``; a malformed value is logged and skipped so resolution falls
    through to the next source. None means nothing declared a limit and the
    caller should apply its own generic default.
    """
    getter = getattr(source, "get_max_tx_power_dbm", None)
    if callable(getter):
        try:
            value = getter()
        except Exception as e:
            logger.warning("Could not get radio maximum TX power: %s", e)
        else:
            if value is not None:
                try:
                    return int(value)
                except (TypeError, ValueError):
                    logger.warning("Radio reported an invalid maximum TX power: %r", value)

    value = getattr(source, "max_tx_power_dbm", None)
    if value is not None:
        try:
            return int(value)
        except (TypeError, ValueError):
            logger.warning("Radio reported an invalid maximum TX power: %r", value)

    if settings:
        value = settings.get("max_tx_power_dbm", settings.get("max_tx_power"))
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                logger.warning("Configured maximum TX power is invalid: %r", value)

    return None
