"""GrpcKernelTransport coverage (the production seam the in-process gate
fakes out): a live ``grpc.aio`` server over UDS exercising the happy path,
the §1.2 connection-failure mapping on the *first* call (where the lazy
import has not yet resolved), KernelError unwrapping, and close semantics.
Skipped when the ``agentos`` extra (grpcio) is not installed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

grpc = pytest.importorskip("grpc", reason="grpcio not installed")  # noqa: F841

import google.protobuf.any_pb2  # noqa: E402,F401
from google.rpc import status_pb2 as google_rpc  # noqa: E402,F401

from agent_meta_runtime.adapters.execution_agentos.kernel_transport import (  # noqa: E402
    GrpcKernelTransport,
    KernelRpcError,
)
from agent_meta_runtime.domain.errors import ErrorCode, StableError  # noqa: E402
from agent_meta_runtime.protocols._kernel_v1 import common_pb2 as kcommon  # noqa: E402
from agent_meta_runtime.protocols._kernel_v1 import service_pb2 as kservice  # noqa: E402


class _HelloHandler(grpc.GenericRpcHandler):
    """Routes ``/Hello`` to a behavior; every other method is unimplemented."""

    def __init__(self, behavior: Any) -> None:
        self._behavior = behavior

    def service(self, handler_call_details: Any) -> Any:
        if handler_call_details.method.endswith("/Hello"):
            return grpc.unary_unary_rpc_method_handler(self._behavior)
        return None


async def _echo_hello(request: bytes, context: Any) -> bytes:
    response = kservice.HelloResponse(
        selected_abi_version="v1",
        kernel_instance_id="transport-test",
    )
    return response.SerializeToString()


class _AbortStatus(grpc.Status):
    """Concrete ``grpc.Status`` for ``abort_with_status`` (ABC upstream)."""

    def __init__(self, code: Any, details: str, trailing_metadata: Any) -> None:
        self.code = code
        self.details = details
        self.trailing_metadata = trailing_metadata


async def _kernel_error_hello(request: bytes, context: Any) -> bytes:
    kerr = kcommon.KernelError(
        code=kcommon.ADMISSION_REJECTED,
        message="admission rejected by test kernel",
        retryable=True,
        metadata={"cause": "test"},
    )
    detail = google.protobuf.any_pb2.Any(
        type_url="type.googleapis.com/agentos.kernel.v1.KernelError",
        value=kerr.SerializeToString(),
    )
    status = google_rpc.Status(details=[detail])
    await context.abort_with_status(
        _AbortStatus(
            grpc.StatusCode.FAILED_PRECONDITION,
            "kernel error",
            (("grpc-status-details-bin", status.SerializeToString()),),
        )
    )


async def _serve(tmp_path: Path, behavior: Any) -> str:
    server = grpc.aio.server()
    server.add_generic_rpc_handlers((_HelloHandler(behavior),))
    socket_path = tmp_path / f"kernel-{len(list(tmp_path.iterdir()))}.sock"
    bound = server.add_insecure_port(f"unix://{socket_path}")
    assert bound, "could not bind UDS server socket"
    await server.start()
    # The caller must keep the server referenced: an unreferenced grpc.aio
    # server is garbage-collected and its socket disappears mid-test.
    return f"unix://{socket_path}", server


async def test_roundtrip_over_uds(tmp_path: Path) -> None:
    endpoint, server = await _serve(tmp_path, _echo_hello)
    transport = GrpcKernelTransport(endpoint, timeout_s=10.0)
    try:
        raw = await transport.call("Hello", kservice.HelloRequest().SerializeToString())
        response = kservice.HelloResponse()
        response.ParseFromString(raw)
        assert response.kernel_instance_id == "transport-test"
    finally:
        transport.close()
        await server.stop(0)


async def test_first_call_connection_failure_maps_to_backend_unavailable(
    tmp_path: Path,
) -> None:
    # No server at the endpoint: the FIRST call must raise the §1.2
    # connection-layer StableError, not an AttributeError from the lazy
    # import path.
    transport = GrpcKernelTransport(f"unix://{tmp_path}/absent.sock", timeout_s=2.0)
    try:
        with pytest.raises(StableError) as excinfo:
            await transport.call("Hello", b"")
        assert excinfo.value.code == ErrorCode.BACKEND_UNAVAILABLE
    finally:
        transport.close()


async def test_kernel_error_detail_unwraps_to_kernel_rpc_error(tmp_path: Path) -> None:
    endpoint, server = await _serve(tmp_path, _kernel_error_hello)
    transport = GrpcKernelTransport(endpoint, timeout_s=10.0)
    try:
        with pytest.raises(KernelRpcError) as excinfo:
            await transport.call("Hello", kservice.HelloRequest().SerializeToString())
        assert excinfo.value.code == kcommon.ADMISSION_REJECTED
        assert excinfo.value.retryable is True
        assert excinfo.value.metadata == {"cause": "test"}
    finally:
        transport.close()
        await server.stop(0)


async def test_close_before_use_and_reuse_is_safe() -> None:
    transport = GrpcKernelTransport("unix:///nonexistent-kernel.sock")
    transport.close()  # no channel yet: no-op, no exception
    transport.close()  # idempotent
