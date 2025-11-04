"""
PyMC_Core - A Python MeshCore library with SPI LoRa radio support
Clean, simple API for building mesh network applications.
"""

__version__ = "1.0.4"

# Core mesh functionality
from .node.node import MeshNode
from .protocol.crypto import CryptoUtils
from .protocol.identity import LocalIdentity
from .protocol.packet import Packet

__all__ = [
    # Core API
    "MeshNode",
    "LocalIdentity",
    "Packet",
    "CryptoUtils",
    # Version
    "__version__",
]


# End of mesh package exports
