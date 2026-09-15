"""Execution Backend port (§37.0.3, §41.27).

The port mirrors the frozen eight-RPC backend session contract. Adapters
implement it over the protobuf DTOs from
:mod:`agent_meta_runtime.protocols._v1` and raise :class:`StableError` with
registry codes; transport-level failures map through
:mod:`agent_meta_runtime.protocols.backend_wire`.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

__all__ = ["ExecutionBackend"]


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
