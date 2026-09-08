from abc import ABC, abstractmethod
from typing import Any, Optional


class BaseHandler(ABC):
    @staticmethod
    @abstractmethod
    def payload_type() -> int:
        """Return the payload type this handler processes"""
        pass

    @abstractmethod
    async def __call__(self, packet) -> Optional[Any]:
        pass
