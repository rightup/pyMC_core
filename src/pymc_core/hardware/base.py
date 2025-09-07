from abc import ABC, abstractmethod


class LoRaRadio(ABC):
    @abstractmethod
    def begin(self):
        """Initialise the radio module."""
        pass

    @abstractmethod
    async def send(self, data: bytes):
        """Send a packet asynchronously."""
        pass

    @abstractmethod
    async def wait_for_rx(self) -> bytes:
        """Wait for a packet to be received asynchronously."""
        pass

    @abstractmethod
    def sleep(self):
        """Put the radio into low-power mode."""
        pass

    @abstractmethod
    def get_last_rssi(self) -> int:
        """Return last received RSSI in dBm."""
        pass

    @abstractmethod
    def get_last_snr(self) -> float:
        """Return last received SNR in dB."""
        pass
