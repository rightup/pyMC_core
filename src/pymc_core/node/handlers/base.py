from abc import ABC, abstractmethod


class BaseHandler(ABC):
    @staticmethod
    @abstractmethod
    def payload_type() -> int:
        """Return the payload type this handler processes"""
        pass

    @abstractmethod
    async def __call__(self, packet):
        pass
