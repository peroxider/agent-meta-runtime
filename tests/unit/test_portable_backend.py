"""Step 04 tests: portable request ledger + PortableBackend end-to-end
(§41.48.2, §41.27)."""

from __future__ import annotations

import hashlib
import json
import uuid

import pytest

from agent_meta_runtime.adapters.execution_portable import (
    PORTABLE_DB_APPLICATION_ID,
    PORTABLE_DB_USER_VERSION,
    PortableBackend,
    PortableRequestLedger,
)
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.protocols._v1 import execution_backend_pb2 as eb
from agent_meta_runtime.protocols._v1 import transport_pb2 as transport


def make_request(rid, *, kind="test.echo", payload=None, rev="REVERSIBLE", session="sess"):
    body = json.dumps(payload if payload is not None else {"hello": "world"}, sort_keys=True).encode()
    return eb.ExecutionRequest(
        session_id=session,
        realm_id="realm://main",
        request_id=rid,
        operation_kind=kind,
        payload_hash=hashlib.sha256(body).hexdigest(),
        payload_jcs=body,
        idempotency_class="KEYED",
        reversibility=rev,
        dedupe_scope="t",
        requested_retention_us=3_600_000_000,
    )


def make_hello():
    return eb.ClientHello(
        supported=[transport.VersionRange(major=1, min_minor=0, max_minor=0)],
        client_instance_id="t",
    )


def test_ledger_pragmas_and_strict_ddl(tmp_path) -> None:
    ledger = PortableRequestLedger(str(tmp_path / "portable.db"), backend_id="b")
    conn = ledger._conn
    assert conn.execute("PRAGMA application_id").fetchone()[0] == PORTABLE_DB_APPLICATION_ID
    assert conn.execute("PRAGMA user_version").fetchone()[0] == PORTABLE_DB_USER_VERSION
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    ddl = conn.execute(
        "SELECT sql FROM sqlite_master WHERE name='requests'"
    ).fetchone()[0]
    assert "CHECK" in ddl and "TERMINAL" in ddl and "STRICT" in ddl.upper() or "STRICT" in ddl


def test_ledger_submit_idempotent_and_conflict(tmp_path) -> None:
    ledger = PortableRequestLedger(str(tmp_path / "portable.db"), backend_id="b")
    rid = str(uuid.uuid4())
    first = ledger.submit(
        request_id=rid, realm_id="realm://main", operation_kind="test.echo",
        payload_hash="a" * 64, payload_jcs=b"{}", idempotency_class="KEYED",
        reversibility="REVERSIBLE", request_relpath=f"workloads/{rid}/request.jcs",
        now_us=1, requested_retention_us=1000,
    )
    assert first["created"] is True
    again = ledger.submit(
        request_id=rid, realm_id="realm://main", operation_kind="test.echo",
        payload_hash="a" * 64, payload_jcs=b"{}", idempotency_class="KEYED",
        reversibility="REVERSIBLE", request_relpath=f"workloads/{rid}/request.jcs",
        now_us=2, requested_retention_us=1000,
    )
    assert again["created"] is False
    with pytest.raises(StableError) as exc:
        ledger.submit(
            request_id=rid, realm_id="realm://main", operation_kind="test.echo",
            payload_hash="b" * 64, payload_jcs=b"{}", idempotency_class="KEYED",
            reversibility="REVERSIBLE", request_relpath=f"workloads/{rid}/request.jcs",
            now_us=3, requested_retention_us=1000,
        )
    assert exc.value.code == ErrorCode.IDEMPOTENCY_CONFLICT


def test_ledger_terminal_idempotent_and_stale_conflict(tmp_path) -> None:
    ledger = PortableRequestLedger(str(tmp_path / "portable.db"), backend_id="b")
    rid = str(uuid.uuid4())
    ledger.submit(
        request_id=rid, realm_id="realm://main", operation_kind="test.echo",
        payload_hash="a" * 64, payload_jcs=b"{}", idempotency_class="KEYED",
        reversibility="REVERSIBLE", request_relpath=f"workloads/{rid}/request.jcs",
        now_us=1, requested_retention_us=1000,
    )
    ledger.mark_terminal(rid, result_hash="h1", result_jcs=b'{"s":1}', now_us=2)
    ledger.mark_terminal(rid, result_hash="h1", result_jcs=b'{"s":1}', now_us=3)  # replay
    with pytest.raises(StableError) as exc:
        ledger.mark_terminal(rid, result_hash="h2", result_jcs=b'{"s":2}', now_us=4)
    assert exc.value.code == ErrorCode.REVISION_CONFLICT
    retained = ledger.acknowledge_terminal(rid, result_hash="h1", retained_until_us=99, now_us=5)
    assert retained == 99
    with pytest.raises(StableError):
        ledger.acknowledge_terminal(rid, result_hash="nope", retained_until_us=99, now_us=6)


async def test_backend_negotiate_honest_features(tmp_path) -> None:
    backend = PortableBackend(tmp_path, poll_interval_s=0.02)
    caps = backend.capabilities()
    assert caps["profile"] == "PORTABLE"
    assert caps["features"]["network_isolation"] == "UNSUPPORTED"
    session = await backend.negotiate(make_hello())
    assert session.profile == "PORTABLE"
    limits = json.loads(bytes(session.limits_jcs).decode())
    assert limits["task_workspace_bytes"] == 512 * 1024 * 1024


async def test_backend_rejects_invalid_requests(tmp_path) -> None:
    backend = PortableBackend(tmp_path, poll_interval_s=0.02)
    request = make_request(str(uuid.uuid4()))
    request.payload_hash = "0" * 64
    with pytest.raises(StableError) as exc:
        await backend.submit(request)
    assert exc.value.code == ErrorCode.INVALID_ARGUMENT
    with pytest.raises(StableError) as exc2:
        await backend.submit(make_request(str(uuid.uuid4()), kind="fs.real"))
    assert exc2.value.code == ErrorCode.FEATURE_UNAVAILABLE
    with pytest.raises(StableError) as exc3:
        await backend.submit(make_request(str(uuid.uuid4()), rev="IRREVERSIBLE"))
    assert exc3.value.code == ErrorCode.FEATURE_UNAVAILABLE
    with pytest.raises(StableError) as exc4:
        await backend.submit(make_request("not-a-uuid"))
    assert exc4.value.code == ErrorCode.INVALID_ARGUMENT


async def test_backend_end_to_end_idempotent_cancel_reconcile(tmp_path) -> None:
    backend = PortableBackend(tmp_path, poll_interval_s=0.02)
    session = await backend.negotiate(make_hello())
    rid = str(uuid.uuid4())
    handle = await backend.submit(make_request(rid))
    assert handle.request_id == rid
    result = await backend.await_activity(handle, 0)
    assert result.status == "SUCCEEDED"
    # idempotent replay
    handle2 = await backend.submit(make_request(rid))
    assert handle2.request_id == rid
    with pytest.raises(StableError) as exc:
        await backend.submit(make_request(rid, payload={"x": 2}))
    assert exc.value.code == ErrorCode.IDEMPOTENCY_CONFLICT
    # cancel of an already-terminal request reports the result status
    report = await backend.cancel(eb.CancelRequest(handle=handle, mode="GRACEFUL", deadline_at_us=0))
    assert report.terminal_confirmed and report.status == "SUCCEEDED"
    # reconcile sees the terminal binding
    rec = await backend.reconcile(
        eb.ReconcileRequest(session_id="sess", realm_id="realm://main",
                            known=[eb.KnownBinding(request_id=rid, handle=handle)])
    )
    assert rec.bindings[0].status == "TERMINAL"
    assert rec.bindings[0].terminal.status == "SUCCEEDED"
    ack = await backend.acknowledge_terminal(
        eb.TerminalAck(session_id="sess", request_id=rid, result_hash=result.result_hash)
    )
    assert ack.status == "ACKNOWLEDGED"
    closed = await backend.close_session(session)
    assert closed.status == "CLOSED"
    with pytest.raises(StableError) as exc2:
        await backend.submit(make_request(str(uuid.uuid4()), session=session.session_id))
    assert exc2.value.code == ErrorCode.FAILED_PRECONDITION


async def test_backend_cancel_running_worker_then_reconcile(tmp_path) -> None:
    backend = PortableBackend(tmp_path, poll_interval_s=0.02)
    rid = str(uuid.uuid4())
    handle = await backend.submit(
        make_request(rid, kind="test.sleep", payload={"seconds": 30})
    )
    report = await backend.cancel(eb.CancelRequest(handle=handle, mode="GRACEFUL", deadline_at_us=0))
    assert report.terminal_confirmed and report.status == "CANCELLED"
    # a fabricated orphan workload shows up in reconcile
    rid3 = str(uuid.uuid4())
    backend._ledger.submit(
        request_id=rid3, realm_id="realm://main", operation_kind="test.echo",
        payload_hash="a" * 64, payload_jcs=b"{}", idempotency_class="KEYED",
        reversibility="REVERSIBLE", request_relpath=f"workloads/{rid3}/request.jcs",
        now_us=1, requested_retention_us=1000,
    )
    rec = await backend.reconcile(
        eb.ReconcileRequest(session_id="sess", realm_id="realm://main")
    )
    orphan_ids = [o.request_id for o in rec.orphans]
    assert rid3 in orphan_ids
    actions = {o.request_id: o.recommended_action for o in rec.orphans}
    assert actions[rid3] == "RESUBMIT_TO_RECOVER"


async def test_backend_await_unknown_fails_closed(tmp_path) -> None:
    backend = PortableBackend(tmp_path, poll_interval_s=0.02)
    rid = str(uuid.uuid4())
    handle = await backend.submit(
        make_request(rid, kind="test.sleep", payload={"seconds": 30})
    )
    backend._ledger.mark_unknown(rid, now_us=1, reason="test")
    with pytest.raises(StableError) as exc:
        await backend.await_activity(handle, 0)
    assert exc.value.code == ErrorCode.EXTERNAL_EFFECT_UNKNOWN
    # clean up the still-running worker
    report = await backend.cancel(eb.CancelRequest(handle=handle, mode="FORCE", deadline_at_us=0))
    assert report.terminal_confirmed


async def test_resubmit_respawns_prepared_request_without_claim(tmp_path) -> None:
    """Crash between ledger COMMIT and worker spawn (§41.48.2, AC-M43):

    the replayed Submit must re-spawn a PREPARED request that has no claim
    and no result, and the request must converge to SUCCEEDED.
    """

    backend = PortableBackend(tmp_path, poll_interval_s=0.02)
    rid = str(uuid.uuid4())
    request = make_request(rid)
    # Simulate the crash: ledger insert only, no worker spawn.
    backend._ledger.submit(
        request_id=rid,
        realm_id=request.realm_id,
        operation_kind=request.operation_kind,
        payload_hash=request.payload_hash,
        payload_jcs=bytes(request.payload_jcs),
        idempotency_class=request.idempotency_class,
        reversibility=request.reversibility,
        request_relpath=f"workloads/{rid}/request.jcs",
        now_us=1,
        requested_retention_us=request.requested_retention_us,
    )
    # Daemon restart: a fresh backend over the same data dir replays Submit.
    restarted = PortableBackend(tmp_path, poll_interval_s=0.02)
    handle = await restarted.submit(request)
    assert handle.request_id == rid
    result = await restarted.await_activity(handle, 0)
    assert result.status == "SUCCEEDED"
    # Idempotency preserved: one workload dir, replay does not re-run.
    handle2 = await restarted.submit(request)
    assert handle2.request_id == rid
    result2 = await restarted.await_activity(handle2, 0)
    assert result2.status == "SUCCEEDED"
    workload_dir = tmp_path / "backend" / "workloads" / rid
    assert workload_dir.is_dir()
    assert [p.name for p in (tmp_path / "backend" / "workloads").iterdir()] == [rid]
