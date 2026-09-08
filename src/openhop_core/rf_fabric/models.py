"""RF Fabric receive models.

One physical radio reception is represented as a single ``RadioReception``.
Runtime delivery is one radio-edge event per ``RFIngress`` (one reception).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class RadioReception:
    """One reception observed on a single radio endpoint."""

    data: bytes
    rssi: Optional[int] = None
    snr: Optional[float] = None
    radio_id: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RFIngress:
    """One fabric-level receive event (one ``RadioReception`` per physical RX)."""

    receptions: tuple[RadioReception, ...]

    def __post_init__(self) -> None:
        if len(self.receptions) < 1:
            raise ValueError(
                "RFIngress requires at least one RadioReception; " f"got {len(self.receptions)}"
            )

    @property
    def reception(self) -> RadioReception:
        """First / sole reception carried by this ingress."""
        return self.receptions[0]

    @classmethod
    def from_reception(cls, reception: RadioReception) -> "RFIngress":
        """Build an ingress that carries exactly one reception."""
        return cls(receptions=(reception,))
