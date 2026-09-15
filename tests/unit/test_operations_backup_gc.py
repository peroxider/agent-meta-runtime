"""Step 09.1 gate: Backup/Restore/GC store use cases and wire surface (§41.47)."""

from __future__ import annotations

import json
import sqlite3

import pytest

from agent_meta_runtime.adapters.cas import FilesystemCas
from agent_meta_runtime.adapters.store.backup import (
    BACKUP_MANIFEST_NAME,
    create_backup,
    restore_backup,
    run_upgrade,
    validate_backup_destination,
)
from agent_meta_runtime.adapters.store.gc import (
    apply_gc_quarantine,
    build_gc_plan,
    commit_gc_plan,
    move_quarantined_to_trash,
    purge_expired_trash,
    validate_gc_plan,
)
from agent_meta_runtime.adapters.store.initializer import initialize_store
from agent_meta_runtime.domain.canonical import now_us, sha256_hex
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.interfaces.cli.init import run_init
from agent_meta_runtime.protocols._v1 import public_pb2 as pub
from conftest import ACTOR, make_command

REALM = "realm://main"
DAY = 24 * 60 * 60 * 1_000_000


def _data_env(tmp_path, name: str):
    data_dir = tmp_path / name
    run_init(data_dir)
    conn = sqlite3.connect(data_dir / "meta.db")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn, data_dir


def _insert_running_operation(conn):
    conn.execute(
        "INSERT INTO operations(operation_id, realm_id, kind, command_id, status,"
        " request_json, created_at_us, started_at_us)"
        " VALUES ('operation://pending1', ?, 'backup', 'task://c1', 'RUNNING', x'7B7D', 1, 1)",
        (REALM,),
    )
    conn.commit()


def _seed_orphan(conn, cas: FilesystemCas, *, age_us: int, tag: bytes):
    from agent_meta_runtime.domain.canonical import canonical_json

    body = tag
    relpath = cas.put(body)
    artifact_id = "artifact://sha256/" + sha256_hex(body)
    conn.execute(
        "INSERT INTO artifacts(artifact_id, kind, media_type, size_bytes,"
        " schema_version, created_by, created_at_us, parents_json, manifest_json,"
        " integrity_status)"
        " VALUES (?, 'code', 'application/octet-stream', ?, 1, ?, ?, x'5B5D', ?, 'VALID')",
        (
            artifact_id,
            len(body),
            ACTOR,
            now_us() - age_us,
            canonical_json({"storage_relpath": relpath, "size_bytes": len(body)}),
        ),
    )
    conn.commit()
    return artifact_id


def _run_free(conn, mutator):
    from agent_meta_runtime.adapters.store.uow import execute_command
    from agent_meta_runtime.domain.deadline import Deadline

    result = execute_command(
        conn, make_command(REALM), mutator, deadline=Deadline.after(5_000_000)
    )
    if hasattr(result, "error"):
        raise result.error
    return dict(result.receipt)


# -- backup / restore -----------------------------------------------------------


def test_backup_restore_round_trip_quarantine_and_fact(tmp_path):
    conn, data_dir = _data_env(tmp_path, "data")
    _insert_running_operation(conn)
    dest = tmp_path / "backup-1"
    outcome = create_backup(conn, data_dir, dest)
    assert outcome.manifest["manifest_version"] == 1
    assert outcome.manifest["realm_id"] == REALM
    relpaths = {entry["relpath"] for entry in outcome.manifest["files"]}
    assert "meta.db" in relpaths
    assert any(r.startswith("artifacts/") for r in relpaths)
    assert any(r.startswith("keys/") for r in relpaths)
    assert (dest / BACKUP_MANIFEST_NAME).is_file()

    # Restore refuses a non-empty target...
    with pytest.raises(StableError) as occupied:
        restore_backup(dest, data_dir)
    assert occupied.value.code == ErrorCode.FAILED_PRECONDITION
    # ...and a tampered backup payload (bytes restored afterwards).
    blob = next(
        p
        for p in sorted((dest / "artifacts").rglob("*"))
        if p.is_file()
    )
    original = blob.read_bytes()
    blob.write_bytes(b"tampered")
    empty = tmp_path / "restored"
    empty.mkdir()
    try:
        with pytest.raises(StableError) as tampered:
            restore_backup(dest, empty)
        assert tampered.value.code == ErrorCode.INTEGRITY_ERROR
    finally:
        blob.write_bytes(original)

    # Honest restore into a fresh empty directory.
    fresh = tmp_path / "fresh"
    report = restore_backup(dest, fresh)
    assert report["realm_id"] == REALM
    restored = sqlite3.connect(fresh / "meta.db")
    try:
        status = restored.execute(
            "SELECT status FROM operations WHERE operation_id = 'operation://pending1'"
        ).fetchone()[0]
        assert status == "FAILED_RECOVERY"
        fact = restored.execute(
            "SELECT COUNT(*) FROM facts WHERE event_type = 'backup_snapshot_restored'"
        ).fetchone()[0]
        assert fact == 1
        head = restored.execute(
            "SELECT fact_hash FROM facts ORDER BY seq DESC LIMIT 1"
        ).fetchone()[0]
        realm_head = restored.execute(
            "SELECT fact_head_hash FROM realms WHERE realm_id = ?", (REALM,)
        ).fetchone()[0]
        assert head == realm_head
    finally:
        restored.close()
    conn.close()


def test_backup_destination_gates(tmp_path):
    conn, data_dir = _data_env(tmp_path, "data")
    with pytest.raises(StableError) as inside:
        validate_backup_destination(data_dir, data_dir / "backups" / "snap")
    assert inside.value.code == ErrorCode.FAILED_PRECONDITION
    (tmp_path / "exists").mkdir()
    with pytest.raises(StableError) as existing:
        validate_backup_destination(data_dir, tmp_path / "exists")
    assert existing.value.code == ErrorCode.FAILED_PRECONDITION
    with pytest.raises(StableError) as relative:
        validate_backup_destination(data_dir, "rel-dest")
    assert relative.value.code == ErrorCode.INVALID_ARGUMENT
    conn.close()


def test_backup_refused_when_not_quiescent(tmp_path):
    conn, data_dir = _data_env(tmp_path, "data")
    conn.execute(
        "INSERT INTO execution_bindings(backend_id, semantic_id, incarnation,"
        " request_id, payload_hash, handle_bytes, session_id, status,"
        " last_observed_at_us)"
        " VALUES ('backend://portable', 'action://a', 1, 'req-1', 'h', x'00',"
        " 'sess-1', 'RUNNING', 1)"
    )
    conn.commit()
    with pytest.raises(StableError) as excinfo:
        create_backup(conn, data_dir, tmp_path / "bk")
    assert excinfo.value.code == ErrorCode.FAILED_PRECONDITION
    assert "LIVE_EXECUTIONS" in str(excinfo.value.details)
    conn.close()


def test_upgrade_preflight_up_to_date(tmp_path):
    conn, data_dir = _data_env(tmp_path, "data")
    report = run_upgrade(conn, data_dir)
    assert report["status"] == "UP_TO_DATE"
    assert report["pending_migrations"] == 0
    conn.close()


# -- GC -------------------------------------------------------------------------


def test_gc_plan_commit_sweep_and_purge(tmp_path):
    conn, data_dir = _data_env(tmp_path, "data")
    cas = FilesystemCas(data_dir)
    orphan = _seed_orphan(conn, cas, age_us=DAY + 1, tag=b"orphan-bytes")
    held = _seed_orphan(conn, cas, age_us=DAY + 1, tag=b"held-bytes")
    revision = int(
        conn.execute(
            "SELECT current_meta_revision FROM realms WHERE realm_id = ?", (REALM,)
        ).fetchone()[0]
    )
    built = build_gc_plan(
        conn,
        cas,
        data_dir,
        realm_id=REALM,
        expected_meta_revision=revision,
        legal_hold_artifact_ids=(held,),
    )
    assert built["plan"]["candidate_artifact_ids"] == [orphan]

    # Wrong revision observation is refused.
    with pytest.raises(StableError) as conflict:
        build_gc_plan(
            conn, cas, data_dir, realm_id=REALM, expected_meta_revision=revision + 5
        )
    assert conflict.value.code == ErrorCode.REVISION_CONFLICT

    _run_free(
        conn,
        commit_gc_plan(
            realm_id=REALM,
            plan_artifact_id=built["plan_artifact_id"],
            storage_relpath=built["storage_relpath"],
            size_bytes=int(built["size_bytes"]),
            candidate_count=len(built["plan"]["candidate_artifact_ids"]),
        ),
    )
    assert conn.execute(
        "SELECT COUNT(*) FROM artifacts WHERE artifact_id = ?",
        (built["plan_artifact_id"],),
    ).fetchone()[0] == 1
    assert conn.execute(
        "SELECT COUNT(*) FROM facts WHERE event_type = 'gc_plan_recorded'"
    ).fetchone()[0] == 1

    # The plan's own recording transaction is allowed; the sweep may proceed.
    entries = validate_gc_plan(
        conn, cas, plan_artifact_id=built["plan_artifact_id"], realm_id=REALM
    )
    assert [e["artifact_id"] for e in entries] == [orphan]

    # Any OTHER interleaved mutation after the plan makes it stale: record a
    # second plan, then run an unrelated command and re-check.
    current = int(
        conn.execute(
            "SELECT current_meta_revision FROM realms WHERE realm_id = ?", (REALM,)
        ).fetchone()[0]
    )
    later = build_gc_plan(
        conn,
        cas,
        data_dir,
        realm_id=REALM,
        expected_meta_revision=current,
        legal_hold_artifact_ids=(held,),
    )
    _run_free(
        conn,
        commit_gc_plan(
            realm_id=REALM,
            plan_artifact_id=later["plan_artifact_id"],
            storage_relpath=later["storage_relpath"],
            size_bytes=int(later["size_bytes"]),
            candidate_count=len(later["plan"]["candidate_artifact_ids"]),
        ),
    )
    _run_free(conn, lambda txn: {"noop": True})
    with pytest.raises(StableError) as stale:
        validate_gc_plan(
            conn, cas, plan_artifact_id=later["plan_artifact_id"], realm_id=REALM
        )
    assert stale.value.code == ErrorCode.FAILED_PRECONDITION

    _run_free(conn, apply_gc_quarantine(entries, operation_id="operation://gc1"))
    trash_dir = move_quarantined_to_trash(data_dir, entries)
    manifest = json.loads(
        bytes(
            conn.execute(
                "SELECT manifest_json FROM artifacts WHERE artifact_id = ?", (orphan,)
            ).fetchone()[0]
        ).decode("utf-8")
    )
    assert not (data_dir / "artifacts" / manifest["storage_relpath"]).exists()
    assert (trash_dir / manifest["storage_relpath"]).exists()
    assert conn.execute(
        "SELECT integrity_status FROM artifacts WHERE artifact_id = ?", (orphan,)
    ).fetchone()[0] == "MISSING"
    assert conn.execute(
        "SELECT COUNT(*) FROM facts WHERE event_type = 'artifact_gc_quarantined'"
    ).fetchone()[0] == 1

    purged = purge_expired_trash(conn, data_dir, retention_us=1)
    assert orphan in purged["purged_artifacts"]
    assert not trash_dir.exists()
    conn.close()


def test_gc_plan_empty_right_after_init(tmp_path):
    conn, data_dir = _data_env(tmp_path, "data")
    cas = FilesystemCas(data_dir)
    revision = int(
        conn.execute(
            "SELECT current_meta_revision FROM realms WHERE realm_id = ?", (REALM,)
        ).fetchone()[0]
    )
    built = build_gc_plan(
        conn, cas, data_dir, realm_id=REALM, expected_meta_revision=revision
    )
    # Every bootstrap artifact is marked through the epoch registry.
    assert built["plan"]["candidate_artifact_ids"] == []
    conn.close()


# -- wire surface ---------------------------------------------------------------


def test_operations_surface_over_wire(tmp_path):
    import asyncio
    import time
    import types

    from agent_meta_runtime.adapters.store import bootstrap_realm
    from agent_meta_runtime.domain.ids import new_uuid7
    from agent_meta_runtime.interfaces.local_api.connection import LocalConnection
    from agent_meta_runtime.interfaces.local_api.handlers import PublicApiHandlers
    from agent_meta_runtime.interfaces.local_api.server import LocalApiServer
    from agent_meta_runtime.interfaces.local_api.staging import ChunkedStaging

    async def test(env):
        dest = tmp_path / "wire-backup"
        envelope = {
            "command_id": "task://" + new_uuid7(),
            "realm_id": env.realm,
            "actor_id": ACTOR,
            "authority_grant_id": None,
            "expected_meta_revision": None,
            "causal_parent_action_id": None,
            "payload_type": "operations.backup/v1",
            "payload_schema_version": 1,
            "payload": {"absolute_destination": str(dest)},
            "auth_nonce": None,
            "auth_issued_at_us": None,
            "auth_signature": None,
        }
        response = await env.client.call(
            "agent_meta.public.v1.Operations.Backup",
            pub.CommandRequest(command_envelope_jcs=json.dumps(envelope).encode()),
            pub.MutationResponse,
        )
        resource = json.loads(bytes(response.resource_jcs))
        assert resource["status"] == "SUCCEEDED"
        assert resource["destination"] == str(dest)
        assert (dest / BACKUP_MANIFEST_NAME).is_file()
        operation_id = resource["operation_id"]

        got = await env.client.call(
            "agent_meta.public.v1.Operations.GetOperation",
            pub.GetOperationRequest(operation_id=operation_id),
            pub.ResourceResponse,
        )
        assert json.loads(bytes(got.resource_jcs))["status"] == "SUCCEEDED"

        waited = await env.client.call(
            "agent_meta.public.v1.Operations.WaitOperation",
            pub.WaitOperationRequest(operation_id=operation_id, wait_deadline_at_us=0),
            pub.ResourceResponse,
        )
        assert json.loads(bytes(waited.resource_jcs))["operation_id"] == operation_id

        facts = env.conn.execute(
            "SELECT COUNT(*) FROM facts WHERE event_type = 'backup_created'"
        ).fetchone()[0]
        assert facts == 1

    class Env:
        pass

    async def body():
        data_dir = tmp_path / "wire-data"
        data_dir.mkdir()
        env = Env()
        env.db_path = data_dir / "meta.db"
        env.conn = initialize_store(env.db_path)
        env.realm = REALM
        bootstrap_realm(env.conn, env.realm, "epoch://" + new_uuid7())
        env.cas = FilesystemCas(data_dir)
        env.staging = ChunkedStaging(env.cas, now_us=lambda: time.time_ns() // 1000)
        handlers = PublicApiHandlers(
            env.conn,
            data_dir=data_dir,
            realm_id=env.realm,
            db_path=env.db_path,
            cas=env.cas,
            staging=env.staging,
            readiness=lambda: types.SimpleNamespace(
                core_ready=True, serving_ready=True, core_reasons=[], serving_reasons=[]
            ),
            now_us=lambda: time.time_ns() // 1000,
        )
        env.server = LocalApiServer(
            data_dir,
            handlers=handlers.handlers(),
            now_us=lambda: time.time_ns() // 1000,
        )
        socket_path = await env.server.start()
        env.client = LocalConnection(socket_path)
        await env.client.connect()
        try:
            return await test(env)
        finally:
            await env.client.close()
            await env.server.close()
            env.conn.close()

    asyncio.run(body())
