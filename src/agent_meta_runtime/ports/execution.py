"""Execution Backend port (§37.0.3, §41.27).

The port mirrors the frozen eight-RPC backend session contract. Adapters
implement it over the protobuf DTOs from
:mod:`agent_meta_runtime.protocols._v1` and raise :class:`StableError` with
registry codes; transport-level failures map through
:mod:`agent_meta_runtime.protocols.backend_wire`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from ..domain.ids import validate_id

__all__ = ["ExecutionBackend", "ExecutionOutcome"]


@dataclass(frozen=True, slots=True)
class ExecutionOutcome:
    """Executor terminal data; contains Artifact identity, never native values."""

    status: str
    usage_jcs: bytes = b""
    error_jcs: bytes = b""
    result_artifact_id: str = ""

    def __post_init__(self):
        if self.status not in ("SUCCEEDED", "FAILED", "CANCELLED"):
            raise ValueError("executor outcome must be terminal")
        if not isinstance(self.usage_jcs, bytes) or not isinstance(self.error_jcs, bytes):
            raise ValueError("executor outcome bytes are required")
        if len(self.usage_jcs) + len(self.error_jcs) > 64 * 1024:
            raise ValueError("executor outcome metadata exceeds its ceiling")
        if not isinstance(self.result_artifact_id, str):
            raise ValueError("executor Artifact identity must be a string")
        if self.error_jcs and (self.result_artifact_id or self.status == "SUCCEEDED"):
            raise ValueError("executor outcome conflicts with its error")
        if self.result_artifact_id:
            validate_id(self.result_artifact_id)
            if not self.result_artifact_id.startswith("artifact://") or self.status != "SUCCEEDED":
                raise ValueError("executor result requires a successful Artifact outcome")


@runtime_checkable
class ExecutionBackend(Protocol):
    """Async backend session surface (§37.0.3, §41.27)."""

    def capabilities(self) -> dict[str, Any]:
        """Honest capability/feature profile; never fakes isolation (§37.0.2)."""
        ...

    async def negotiate(self, hello: Any) -> Any:
        """ClientHello → BackendSession with negotiated version/features."""
        ...

    async def submit(self, request: Any) -> Any:
        """ExecutionRequest → ExecutionHandle; idempotent on
        dedupe_scope + request_id + payload_hash."""
        ...

    async def await_activity(self, handle: Any, deadline_at_us: int) -> Any:
        """Block until terminal or deadline; DEADLINE_EXCEEDED carries the
        current typed snapshot in its details."""
        ...

    async def cancel(self, request: Any) -> Any:
        """CancelRequest → CancelReport; terminal_confirmed only after the
        worker process tree exit is observed."""
        ...

    async def inspect(self, handle: Any) -> Any:
        """ExecutionHandle → ExecutionSnapshot."""
        ...

    async def reconcile(self, request: Any) -> Any:
        """ReconcileRequest → ReconcileReport (bindings + orphans)."""
        ...

    async def acknowledge_terminal(self, request: Any) -> Any:
        """TerminalAck → AckReport; replay-safe, hash-checked."""
        ...

    async def close_session(self, session: Any) -> Any:
        """BackendSession → CloseReport; advisory, in-flight work continues."""
        ...
