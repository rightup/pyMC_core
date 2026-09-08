"""RF Fabric: multi-radio transport layer.

Provides an optional multi-radio fabric without changing legacy
``Dispatcher(existing_radio)`` behaviour.

- N radios may register on one ``RFFabric``.
- Each physical receive yields one ``RFIngress`` containing one
  ``RadioReception`` tagged with ``radio_id``.
- TX uses a default radio or an explicit ``radio_id``.
- Mesh dedup across radios remains the Dispatcher's job.
"""

from .fabric import RFFabric
from .fabric_radio import FabricRadio
from .models import RadioReception, RFIngress

__all__ = [
    "FabricRadio",
    "RFFabric",
    "RFIngress",
    "RadioReception",
]
