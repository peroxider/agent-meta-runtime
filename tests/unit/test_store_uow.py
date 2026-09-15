"""Step 01 gate: command transaction, idempotency, fact chain (§41.34.4/§41.35)."""

from __future__ import annotations

import sqlite3

import pytest

from agent_meta_runtime.adapters.store import connect_store, execute_command
from agent_meta_runtime.adapters.store.uow import RejectedResult
from agent_meta_runtime.domain import facts as fact_chain
from agent_meta_runtime.domain.deadline import Deadline
from agent_meta_runtime.domain.envelope import CommandEnvelope
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.ids import new_uuid7
from agent_meta_runtime.ports.repositories import FactAppendRequest, OutboxRequest

ACTOR = "principal://operator-root/01900000-0000-7000-8000-000000000000"
DEADLINE = Deadline.after(5_000_000)


def _envelope(**overrides) -> CommandEnvelope:
    base = dict(
        command_id="task://" + new_uuid7(),
        realm_id="realm://main",
        actor_id=ACTOR,
        authority_grant_id=None,
        expected_meta_revision=0,
        causal_parent_action_id=None,
        payload_type="operations.reconcile/v1",
        payload_schema_version=1,
        payload={"realm_id": "realm://main"},
        auth_nonce=None,
        auth_issued_at_us=None,
        auth_signature=None,
    )
    base.update(overrides)
    return CommandEnvelope(**base)


def _mutator(payload: dict = {"ok": True}, with_outbox: bool = True):
    def run(tx) -> dict:
        fact_id = tx.append_fact(
            FactAppendRequest(
                entity_type="runtime",
                entity_id="realm://main",
                event_type="runtime_initialized",
                schema_version=1,
                payload=payload,
                occurred_at_us=1_700_000_000_000_000,
                actor_id=ACTOR,
            )
        )
        receipt = {"fact_id": fact_id}
        if with_outbox:
            receipt["outbox_id"] = tx.enqueue_outbox(
                OutboxRequest(
                    kind="reconcile",
                    dedupe_key="rk-" + fact_id[-12:],
                    payload={"fact_id": fact_id},
                    available_at_us=1,
                )
            )
        return receipt

    return run


def test_commit_writes_fact_outbox_meta_revision(store) -> None:
    conn, realm, _ = store
    result = execute_command(conn, _envelope(), _mutator(), deadline=DEADLINE)
    assert result.meta_revision == 1
    assert result.first_seq == 1 and result.last_seq == 1
    fact = conn.execute(
        "SELECT seq, prev_fact_hash, fact_hash, payload_json, transaction_id"
        " FROM facts WHERE fact_id = ?",
        (result.fact_ids[0],),
    ).fetchone()
    assert fact[0] == 1
    assert fact[1] == fact_chain.GENESIS_FACT_HEAD
    head = conn.execute(
        "SELECT fact_head_hash, next_seq, current_meta_revision FROM realms"
        " WHERE realm_id = ?",
        (realm,),
    ).fetchone()
    assert head[0] == fact[2] and head[1] == 2 and head[2] == 1
    outbox = conn.execute("SELECT state FROM outbox").fetchall()
    assert outbox == [("PENDING",)]


def test_multi_fact_transaction_chains_consecutive_seqs(store) -> None:
    conn, _realm, _ = store

    def run(tx) -> dict:
        ids = [
            tx.append_fact(
                FactAppendRequest(
                    entity_type="runtime",
                    entity_id="realm://main",
                    event_type="runtime_initialized",
                    schema_version=1,
                    payload={"n": n},
                    occurred_at_us=1,
                    actor_id=ACTOR,
                )
            )
            for n in range(3)
        ]
        return {"ids": ids}

    result = execute_command(conn, _envelope(), run, deadline=DEADLINE)
    assert result.first_seq == 1 and result.last_seq == 3
    rows = conn.execute(
        "SELECT seq, prev_fact_hash, fact_hash FROM facts ORDER BY seq"
    ).fetchall()
    prev = fact_chain.GENESIS_FACT_HEAD
    for index, (seq, actual_prev, fact_hash) in enumerate(rows, start=1):
        assert seq == index
        assert actual_prev == prev
        prev = fact_hash
    assert len({h for _, _, h in rows}) == 3


def test_idempotent_replay_returns_identical_result(store) -> None:
    conn, _realm, _ = store
    env = _envelope()
    first = execute_command(conn, env, _mutator(), deadline=DEADLINE)
    second = execute_command(conn, env, _mutator(), deadline=DEADLINE)
    assert first == second
    assert conn.execute("SELECT COUNT(*) FROM facts").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0] == 1


def test_same_command_different_payload_conflicts(store) -> None:
    conn, _realm, _ = store
    env = _envelope()
    execute_command(conn, env, _mutator(), deadline=DEADLINE)
    conflict = _envelope(
        command_id=env.command_id, payload={"realm_id": "realm://other"}
    )
    with pytest.raises(StableError) as exc:
        execute_command(conn, conflict, _mutator(), deadline=DEADLINE)
    assert exc.value.code == ErrorCode.IDEMPOTENCY_CONFLICT


def test_different_actor_same_command_conflicts(store) -> None:
    conn, _realm, _ = store
    env = _envelope()
    execute_command(conn, env, _mutator(), deadline=DEADLINE)
    conflict = _envelope(
        command_id=env.command_id,
        actor_id="principal://operator-root/01900000-0000-7000-8000-000000000001",
    )
    with pytest.raises(StableError) as exc:
        execute_command(conn, conflict, _mutator(), deadline=DEADLINE)
    assert exc.value.code == ErrorCode.IDEMPOTENCY_CONFLICT


def test_rejection_records_stable_error_and_replays(store) -> None:
    conn, _realm, _ = store
    env = _envelope()

    def failing(tx):
        raise StableError(code=ErrorCode.REVISION_CONFLICT, message="stale revision")

    rejected = execute_command(conn, env, failing, deadline=DEADLINE)
    assert isinstance(rejected, RejectedResult)
    assert rejected.error.code == ErrorCode.REVISION_CONFLICT
    assert rejected.meta_revision == 0
    assert conn.execute("SELECT COUNT(*) FROM facts").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == 0
    assert conn.execute("SELECT current_meta_revision FROM realms").fetchone()[0] == 0
    replay = execute_command(conn, env, failing, deadline=DEADLINE)
    assert replay == rejected


def test_rollback_does_not_consume_seq(store) -> None:
    conn, _realm, _ = store
    env = _envelope()

    def failing(tx):
        tx.append_fact(
            FactAppendRequest(
                entity_type="runtime",
                entity_id="realm://main",
                event_type="runtime_initialized",
                schema_version=1,
                payload={"n": 1},
                occurred_at_us=1,
                actor_id=ACTOR,
            )
        )
        raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="nope")

    execute_command(conn, env, failing, deadline=DEADLINE)
    ok = execute_command(conn, _envelope(), _mutator(), deadline=DEADLINE)
    assert ok.first_seq == 1  # rolled-back fact did not consume seq 1


def test_meta_revisions_consecutive_across_commands(store) -> None:
    conn, realm, _ = store
    for expected in (1, 2, 3):
        result = execute_command(
            conn, _envelope(payload={"n": expected}), _mutator(), deadline=DEADLINE
        )
        assert result.meta_revision == expected
    revisions = conn.execute(
        "SELECT revision FROM meta_revisions WHERE realm_id = ? ORDER BY revision",
        (realm,),
    ).fetchall()
    assert [r[0] for r in revisions] == [1, 2, 3]


def test_outbox_dedupe_key_unique(store) -> None:
    conn, _realm, _ = store

    def run(tx) -> dict:
        tx.enqueue_outbox(
            OutboxRequest(kind="k", dedupe_key="same", payload={}, available_at_us=1)
        )
        return {}

    execute_command(conn, _envelope(), run, deadline=DEADLINE)
    with pytest.raises(sqlite3.IntegrityError):
        execute_command(conn, _envelope(), run, deadline=DEADLINE)


def test_auth_nonce_replay_rejected(store) -> None:
    conn, _realm, _ = store
    first = _envelope(auth_nonce="nonce-1", auth_issued_at_us=1, auth_signature=b"\x01")
    second = _envelope(auth_nonce="nonce-1", auth_issued_at_us=2, auth_signature=b"\x02")
    execute_command(conn, first, _mutator(), deadline=DEADLINE)
    with pytest.raises(sqlite3.IntegrityError):
        execute_command(conn, second, _mutator(), deadline=DEADLINE)


def test_busy_writer_times_out_as_resource_exhausted(store) -> None:
    conn, _realm, tmp_path = store
    conn.execute("BEGIN IMMEDIATE")  # hold the single-writer lock
    try:
        rival = connect_store(tmp_path / "meta.db", busy_timeout_ms=1)
        try:
            with pytest.raises(StableError) as exc:
                execute_command(
                    rival,
                    _envelope(),
                    _mutator(),
                    deadline=Deadline.after(30_000),
                )
        finally:
            rival.close()
        assert exc.value.code == ErrorCode.RESOURCE_EXHAUSTED
    finally:
        conn.rollback()
