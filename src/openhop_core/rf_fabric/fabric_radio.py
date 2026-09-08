"""FabricRadio: LoRaRadio-shaped adapter over an RFFabric.

Supports one or many underlying radios while presenting the legacy surface
``Dispatcher`` already uses (``set_rx_callback``, ``send``, RSSI/SNR).
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional, Sequence, Tuple, Union

from ..hardware.base import LoRaRadio
from .fabric import RFFabric

logger = logging.getLogger("FabricRadio")

RadioSpec = Union[Any, Tuple[Any, str]]


class FabricRadio(LoRaRadio):
    """Present an RFFabric as a single legacy ``LoRaRadio``.

    Receive path:
      physical radio(s) → RFFabric (one RFIngress / one RadioReception each)
                       → FabricRadio legacy callback (fires exactly once per RX)
                       → Dispatcher._on_packet_received
    """

    def __init__(
        self,
        fabric: Optional[RFFabric] = None,
        *,
        radio: Any = None,
        radio_id: str = "radio0",
        radios: Optional[Sequence[RadioSpec]] = None,
        default_radio_id: Optional[str] = None,
    ) -> None:
        """
        Args:
            fabric: Existing fabric to wrap. If omitted, a new fabric is created.
            radio: Optional single radio to register immediately.
            radio_id: Id used when registering ``radio``.
            radios: Optional sequence of radios or ``(radio, radio_id)`` pairs.
            default_radio_id: Default TX radio when multiple are registered.
        """
        self.fabric = fabric if fabric is not None else RFFabric()
        self.rx_callback: Optional[Callable[..., Any]] = None

        specs = list(radios or [])
        if radio is not None:
            specs.insert(0, (radio, radio_id))

        for spec in specs:
            r, rid = self._normalize_spec(spec, fallback_id=radio_id)
            already = False
            for existing_id, existing in self.fabric.radios.items():
                if existing is r:
                    already = True
                    if rid != existing_id:
                        logger.debug(
                            "Radio already registered as %s; requested %s",
                            existing_id,
                            rid,
                        )
                    break
            if already:
                continue
            if rid in self.fabric.radios and self.fabric.radios[rid] is not r:
                raise ValueError(f"Fabric already has a different radio registered as {rid!r}")
            if rid not in self.fabric.radios:
                self.fabric.register_radio(r, radio_id=rid)

        if default_radio_id is not None:
            self.fabric.set_default_radio(default_radio_id)

        self._radio_id = self.fabric.default_radio_id or radio_id

        # Bridge fabric legacy path to this adapter's callback.
        self.fabric.set_legacy_rx_callback(self._on_fabric_rx)
        self.fabric.arm()

    @staticmethod
    def _normalize_spec(spec: RadioSpec, *, fallback_id: str) -> tuple[Any, str]:
        if isinstance(spec, tuple) and len(spec) == 2:
            return spec[0], str(spec[1])
        return spec, fallback_id

    # ------------------------------------------------------------------
    # LoRaRadio interface
    # ------------------------------------------------------------------

    def begin(self) -> Any:
        results = []
        for rid, radio in self.fabric.radios.items():
            if hasattr(radio, "begin"):
                results.append((rid, radio.begin()))
        if not results:
            return True
        return all(r is None or bool(r) for _, r in results)

    async def send(self, data: bytes, *, radio_id: Optional[str] = None) -> Any:
        return await self.fabric.send(data, radio_id=radio_id)

    async def wait_for_rx(self) -> bytes:
        radio = self.fabric.radio
        if radio is not None and hasattr(radio, "wait_for_rx"):
            return await radio.wait_for_rx()
        raise RuntimeError("Underlying radio does not support wait_for_rx()")

    def sleep(self) -> None:
        for radio in self.fabric.radios.values():
            if hasattr(radio, "sleep"):
                try:
                    radio.sleep()
                except Exception:
                    logger.debug("sleep() failed on %s", type(radio).__name__, exc_info=True)

    def get_last_rssi(self) -> int:
        return self.fabric.get_last_rssi()

    def get_last_snr(self) -> float:
        return self.fabric.get_last_snr()

    def set_rx_callback(self, callback: Optional[Callable[..., Any]]) -> None:
        """Register the legacy single-shot RX callback used by Dispatcher."""
        self.rx_callback = callback

    def set_ingress_callback(self, callback: Optional[Callable[..., Any]]) -> None:
        """Optional subscriber for structured RFIngress events."""
        self.fabric.set_ingress_callback(callback)

    def set_default_radio(self, radio_id: str) -> None:
        self.fabric.set_default_radio(radio_id)

    @property
    def last_rx_radio_id(self):
        return self.fabric.last_rx_radio_id

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _on_fabric_rx(
        self,
        data: bytes,
        rssi: Optional[int] = None,
        snr: Optional[float] = None,
    ) -> None:
        cb = self.rx_callback
        if cb is None:
            return
        try:
            cb(data, rssi, snr)
        except TypeError:
            cb(data)

    def __getattr__(self, name: str) -> Any:
        """Pass radio settings (spreading_factor, bandwidth, …) through."""
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self.fabric, name)
