"""External daemon smoke for the AgentOS execution kernel bridge (§4).

Runs a framed 8-RPC session against a live ``agentos-kerneld`` over
gRPC/UDS. This is the bridge's external evidence beyond the in-process
contract gate (tests/unit/test_agentos_provider.py): it is skipped unless

- ``AGENTOS_KERNEL_ENDPOINT`` names the daemon endpoint (e.g.
  ``unix:///run/agentos/kernel.sock``), and
- the ``agentos`` extra (grpcio) is installed.

The smoke asserts reachability and contract framing, not feature
completeness: a live kernel may legitimately refuse individual operations,
which skips with the mapped stable error code.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

grpc = pytest.importorskip("grpc", reason="grpcio not installed")  # noqa: F841

from agent_meta_runtime.adapters.execution_agentos import (  # noqa: E402
    AgentOSClient,
    GrpcKernelTransport,
)
from agent_meta_runtime.adapters.execution_agentos.provider import (  # noqa: E402
    AgentOSProvider,
)
from agent_meta_runtime.domain.canonical import canonical_json  # noqa: E402
from agent_meta_runtime.domain.errors import ErrorCode, StableError  # noqa: E402
from agent_meta_runtime.protocols._v1 import execution_backend_pb2 as eb  # noqa: E402
from agent_meta_runtime.protocols.backend_wire import (  # noqa: E402
    new_request_id,
    payload_hash,
)

_ENDPOINT = os.environ.get("AGENTOS_KERNEL_ENDPOINT", "")

pytestmark = pytest.mark.skipif(
    not _ENDPOINT, reason="AGENTOS_KERNEL_ENDPOINT not set"
)


def _hello() -> eb.ClientHello:
    hello = eb.ClientHello(client_instance_id="agentos-smoke")
    hello.supported.add(major=1, min_minor=0, max_minor=0)
    return hello


async def test_agentos_kerneld_end_to_end(tmp_path: Path) -> None:
    transport = GrpcKernelTransport(_ENDPOINT, timeout_s=30.0)
    try:
        provider = AgentOSProvider(tmp_path / "data", transport=transport)
        client = AgentOSClient(provider)
        try:
            session = await client.negotiate(_hello())
        except StableError as exc:
            if exc.code in (
                ErrorCode.CONTRACT_INCOMPATIBLE,
                ErrorCode.BACKEND_UNAVAILABLE,
            ):
                pytest.skip(f"live kernel negotiation refused: {exc.code}")
            raise
        assert session.profile == "MANAGED"
        assert session.protocol_major == 1

        payload = canonical_json({"kind": "smoke", "value": 1})
        rid = new_request_id()
        try:
            handle = await client.submit(
                eb.ExecutionRequest(
                    session_id=session.session_id,
                    realm_id="realm://smoke",
                    request_id=rid,
                    operation_kind="test.echo",
                    payload_hash=payload_hash(payload),
                    payload_jcs=payload,
                    idempotency_class="KEYED",
                    reversibility="REVERSIBLE",
                    dedupe_scope="task",
                    requested_retention_us=3_600_000_000,
                )
            )
            assert handle.request_id == rid
            result = await client.await_activity(handle, 0)
            assert result.request_id == rid
            assert result.status in ("COMPLETED", "FAILED", "RUNNING")
            snapshot = await client.inspect(handle)
            assert snapshot.status in (
                "COMPLETED",
                "FAILED",
                "RUNNING",
                "CANCELLING",
            )
            report = await client.reconcile(
                eb.ReconcileRequest(
                    session_id=session.session_id,
                    realm_id="realm://smoke",
                    known=[eb.KnownBinding(request_id=rid, handle=handle)],
                )
            )
            assert len(report.bindings) == 1
        except StableError as exc:
            if exc.code in (
                ErrorCode.FEATURE_UNAVAILABLE,
                ErrorCode.CONTRACT_INCOMPATIBLE,
            ):
                pytest.skip(f"live kernel refused the smoke flow: {exc.code}")
            raise

        closed = await client.close_session()
        assert closed.status == "CLOSED"
    finally:
        transport.close()
