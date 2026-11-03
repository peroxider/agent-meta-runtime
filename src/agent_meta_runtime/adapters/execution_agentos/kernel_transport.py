"""Kernel transport seam for the AgentOS bridge (§0, §4).

``KernelTransport`` is the single async seam between the bridge translation
layer and ``agentos.kernel.v1``: one serialized unary request in, one
serialized response out, keyed by the RPC name on the frozen
``agentos.kernel.v1.AgentOSKernel`` service. Kernel-side ``KernelError``
failures surface as :class:`KernelRpcError`; connection-layer failures raise
``StableError(BACKEND_UNAVAILABLE)`` directly (§1.2).

``GrpcKernelTransport`` is the production implementation: gRPC over UDS via
``grpc.aio`` (optional ``agentos`` extra; imported lazily so the contract
gate runs without it). Tests inject an in-process transport implementing the
same seam.
"""

from __future__ import annotations

import asyncio
from typing import Any, Protocol

from ...domain.errors import ErrorCode, StableError
from ...protocols._kernel_v1 import common_pb2 as kcommon

__all__ = ["KernelRpcError", "KernelTransport", "GrpcKernelTransport"]

_KERNEL_ERROR_TYPE_URL_SUFFIX = "agentos.kernel.v1.KernelError"

_GRPC_DEADLINE_EXCEEDED = 4  # grpc.StatusCode.DEADLINE_EXCEEDED.value[0]


class KernelRpcError(Exception):
    """A kernel-side ``KernelError`` carried over the transport (§35.2)."""

    def __init__(
        self,
        code: int,
        message: str,
        *,
        retryable: bool = False,
        metadata: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = int(code)
        self.message = message
        self.retryable = bool(retryable)
        self.metadata = dict(metadata or {})


class KernelTransport(Protocol):
    """Unary kernel call seam: serialized request bytes in, response out."""

    async def call(self, method: str, request: bytes) -> bytes: ...

    def close(self) -> None: ...


def _kernel_error_from_status_payload(payload: bytes) -> KernelRpcError | None:
    """Unwrap ``grpc-status-details-bin`` → google.rpc.Status → KernelError.

    ``google.rpc.status_pb2`` ships with ``googleapis-common-protos`` (part of
    the ``agentos`` extra); without it the detail payload cannot be unwrapped
    and the caller falls back to the gRPC status code.
    """

    try:
        from google.rpc import status_pb2
    except ModuleNotFoundError:  # pragma: no cover - covered with the extra
        return None
    status = status_pb2.Status()
    status.ParseFromString(payload)
    for detail in status.details:
        if detail.type_url.endswith(_KERNEL_ERROR_TYPE_URL_SUFFIX):
            kerr = kcommon.KernelError()
            kerr.ParseFromString(detail.value)
            return KernelRpcError(
                int(kerr.code),
                kerr.message,
                retryable=kerr.retryable,
                metadata=dict(kerr.metadata),
            )
    return None


class GrpcKernelTransport:
    """Production transport: ``agentos.kernel.v1`` unary RPCs over gRPC/UDS."""

    def __init__(self, endpoint: str, *, timeout_s: float | None = None) -> None:
        self._endpoint = endpoint
        self._timeout_s = timeout_s
        self._grpc: Any = None
        self._channel: Any = None

    def _ensure_channel(self) -> Any:
        if self._channel is None:
            try:
                import grpc.aio
            except ModuleNotFoundError as exc:
                raise StableError(
                    code=ErrorCode.BACKEND_UNAVAILABLE,
                    message="grpcio is not installed; install the 'agentos' extra",
                ) from exc
            self._grpc = grpc
            self._channel = grpc.aio.insecure_channel(self._endpoint)
        return self._channel

    async def call(self, method: str, request: bytes) -> bytes:
        channel = self._ensure_channel()
        # Resolve the module only after the lazy import above: on the very
        # first call self._grpc is still None, and the except clause must
        # map the failure to BACKEND_UNAVAILABLE, not crash (§1.2).
        grpc = self._grpc
        invoker = channel.unary_unary(
            f"/agentos.kernel.v1.AgentOSKernel/{method}",
            request_serializer=lambda raw: raw,
            response_deserializer=bytes,
        )
        try:
            return await invoker(request, timeout=self._timeout_s)
        except grpc.aio.AioRpcError as exc:
            status_code = exc.code().value[0]
            if status_code == _GRPC_DEADLINE_EXCEEDED:
                raise KernelRpcError(
                    kcommon.DEADLINE_EXCEEDED, exc.details() or "kernel deadline exceeded"
                ) from exc
            for key, value in exc.trailing_metadata() or ():
                if key == "grpc-status-details-bin":
                    kerr = _kernel_error_from_status_payload(bytes(value))
                    if kerr is not None:
                        raise kerr from exc
            raise StableError(
                code=ErrorCode.BACKEND_UNAVAILABLE,
                message=f"kernel transport failure on {method}",
                details={"grpc_status": exc.code().name},
            ) from exc

    def close(self) -> None:
        if self._channel is not None:
            channel, self._channel, self._grpc = self._channel, None, None
            # grpc.aio Channel.close() is a coroutine; schedule it on the
            # running loop when there is one, run a fresh loop otherwise.
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                asyncio.run(channel.close())
            else:
                loop.create_task(channel.close())
