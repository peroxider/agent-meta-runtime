"""agent-meta-runtime: reflective + evolvable agent meta-runtime.

Normative baseline: ``docs/Agent_Meta_Runtime_Requirements_Design_v0.1.md`` (v0.1-r11).
Layering (§41.3): domain -> ports -> application; adapters/interfaces/sdk are
configured at the edge. Domain never imports adapters, sqlite3, IPython or grpc.
"""

from __future__ import annotations

__version__ = "0.1.0.dev1"

