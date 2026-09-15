"""Path bootstrap so acceptance proofs can import the trace scenarios."""

from __future__ import annotations

import sys
from pathlib import Path

_TRACE_DIR = Path(__file__).resolve().parent.parent / "trace"
if str(_TRACE_DIR) not in sys.path:
    sys.path.insert(0, str(_TRACE_DIR))
