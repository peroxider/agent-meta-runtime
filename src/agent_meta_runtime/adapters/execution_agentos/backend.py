"""AgentOS client and fake provider contract gate (§41.27, §41.41, §41.48.2).

The production AgentOS daemon is explicitly out of v0.1 scope. What v0.1 must
prove is the *contract*: a second provider speaking the same framed eight-RPC
session protocol, backed by a durable file/SQLite request ledger, behaves
identically to the Portable backend. ``AgentOSFakeProvider`` reuses the
Portable request ledger and worker flow behind the MANAGED profile and
answers serialized ``RpcEnvelope`` frames exactly as a daemon would.
``AgentOSClient`` is the client half: every call builds the frozen envelope
(UUIDv7 request id, registry method name, payload bytes) and either unpacks
the response payload or raises the mapped ``StableError`` from ``RpcError``.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from ...domain.errors import ErrorCode, StableError
from ...protocols._v1 import execution_backend_pb2 as eb
from ...protocols._v1 import transport_pb2 as transport
from ...protocols.backend_wire import (
    build_envelope,
    error_from_rpc,
    error_to_rpc,
    new_request_id,
)
from ..execution_portable.backend import PortableBackend

__all__ = ["AgentOSClient", "AgentOSFakeProvider"]

_METHOD_PREFIX = "agent_meta.execution_backend.v1.Backend."

_OPERATIONS: dict[str, str] = {
    "Negotiate": "negotiate",
    "Submit": "submit",
    "Await": "await_activity",
    "Cancel": "cancel",
    "Inspect": "inspect",
    "Reconcile": "reconcile",
    "AcknowledgeTerminal": "acknowledge_terminal",
    "CloseSession": "close_session",
}


class AgentOSFakeProvider:
    """Fake AgentOS daemon with the same durable provider contract (§41.48.2).

    Wraps a MANAGED-profile PortableBackend: durable SQLite request ledger,
    worker directories, create-new claims, and the cancellation ladder. The
    feature profile stays honest — the fake never claims isolation features
    the portable flow does not provide (§41.48.4).
    """

    def __init__(
        self,
        data_dir: Path,
        *,
        backend_id: str = "backend://agentos-fake",
        clock: Any = None,
        poll_interval_s: float = 0.02,
    ) -> None:
        self._core = PortableBackend(
            Path(data_dir),
            backend_id=backend_id,
            profile="MANAGED",
            clock=clock,
            poll_interval_s=poll_interval_s,
        )

    def capabilities(self) -> dict[str, Any]:
        return self._core.capabilities()

    async def dispatch(self, raw: bytes) -> bytes:
        """Parse one serialized request envelope, answer with one response.

        Unknown methods, non-request envelopes, and missing payloads map to
        ``RpcError`` frames (INTERNAL / INVALID_ARGUMENT) rather than raising.
        """

        request = transport.RpcEnvelope()
        request.ParseFromString(raw)
        if request.is_response:
            return self._error_frame(request, StableError(
                code=ErrorCode.INTERNAL,
                message="provider received a response envelope",
            )).SerializeToString()
        operation = _OPERATIONS.get(request.method.removeprefix(_METHOD_PREFIX))
        if operation is None or not request.method.startswith(_METHOD_PREFIX):
            return self._error_frame(request, StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message=f"unknown method: {request.method}",
            )).SerializeToString()
        if not request.HasField("payload"):
            return self._error_frame(request, StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="request envelope carries no payload",
            )).SerializeToString()
        try:
            handler = getattr(self._core, operation)
            payload = bytes(request.payload)
            if operation == "negotiate":
                message = eb.ClientHello()
            elif operation == "submit":
                message = eb.ExecutionRequest()
            elif operation == "cancel":
                message = eb.CancelRequest()
            elif operation == "reconcile":
                message = eb.ReconcileRequest()
            elif operation == "acknowledge_terminal":
                message = eb.TerminalAck()
            elif operation == "close_session":
                message = eb.BackendSession()
            else:
                # Await/Inspect carry the ExecutionHandle directly.
                message = eb.ExecutionHandle()
            message.ParseFromString(payload)
            if operation == "await_activity":
                result = await handler(message, request.deadline_at_us)
            else:
                result = await handler(message)
            response = build_envelope(
                method=request.method,
                payload=result.SerializeToString(),
                is_response=True,
                request_id=request.request_id,
            )
            return response.SerializeToString()
        except StableError as exc:
            return self._error_frame(request, exc).SerializeToString()

    def _error_frame(self, request: transport.RpcEnvelope, exc: StableError) -> transport.RpcEnvelope:
        return build_envelope(
            method=request.method,
            error=error_to_rpc(exc, correlation_id=request.request_id),
            is_response=True,
            request_id=request.request_id,
        )


class AgentOSClient:
    """Client half of the framed backend session contract (§41.27, §41.41).

    Frames every RPC as a serialized ``RpcEnvelope`` and raises the mapped
    ``StableError`` when the provider answers with an ``RpcError`` frame.
    """

    def __init__(self, provider: AgentOSFakeProvider) -> None:
        self._provider = provider
        self._session: eb.BackendSession | None = None

    async def _call(self, name: str, payload: bytes, deadline_at_us: int = 0) -> bytes:
        envelope = build_envelope(
            method=_METHOD_PREFIX + name,
            payload=payload,
            request_id=new_request_id(),
            deadline_at_us=deadline_at_us,
        )
        raw = await self._provider.dispatch(envelope.SerializeToString())
        response = transport.RpcEnvelope()
        response.ParseFromString(raw)
        if not response.is_response:
            raise StableError(
                code=ErrorCode.INTERNAL,
                message="provider returned a non-response envelope",
            )
        if response.HasField("error"):
            raise error_from_rpc(response.error)
        return bytes(response.payload)

    async def negotiate(self, hello: eb.ClientHello) -> eb.BackendSession:
        session = eb.BackendSession()
        session.ParseFromString(await self._call("Negotiate", hello.SerializeToString()))
        self._session = session
        return session

    async def submit(self, request: eb.ExecutionRequest) -> eb.ExecutionHandle:
        handle = eb.ExecutionHandle()
        handle.ParseFromString(await self._call("Submit", request.SerializeToString()))
        return handle

    async def await_activity(
        self, handle: eb.ExecutionHandle, deadline_at_us: int
    ) -> eb.ExecutionResult:
        result = eb.ExecutionResult()
        result.ParseFromString(
            await self._call(
                "Await", handle.SerializeToString(), deadline_at_us=deadline_at_us
            )
        )
        return result

    async def inspect(self, handle: eb.ExecutionHandle) -> eb.ExecutionSnapshot:
        snapshot = eb.ExecutionSnapshot()
        snapshot.ParseFromString(await self._call("Inspect", handle.SerializeToString()))
        return snapshot

    async def cancel(self, request: eb.CancelRequest) -> eb.CancelReport:
        report = eb.CancelReport()
        report.ParseFromString(await self._call("Cancel", request.SerializeToString()))
        return report

    async def reconcile(self, request: eb.ReconcileRequest) -> eb.ReconcileReport:
        report = eb.ReconcileReport()
        report.ParseFromString(await self._call("Reconcile", request.SerializeToString()))
        return report

    async def acknowledge_terminal(self, request: eb.TerminalAck) -> eb.AckReport:
        report = eb.AckReport()
        report.ParseFromString(
            await self._call("AcknowledgeTerminal", request.SerializeToString())
        )
        return report

    async def close_session(self, session: eb.BackendSession | None = None) -> eb.CloseReport:
        if session is None:
            if self._session is None:
                raise StableError(
                    code=ErrorCode.FAILED_PRECONDITION, message="no open session"
                )
            session = self._session
        report = eb.CloseReport()
        report.ParseFromString(await self._call("CloseSession", session.SerializeToString()))
        return report
