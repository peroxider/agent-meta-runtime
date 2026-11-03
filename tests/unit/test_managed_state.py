"""Step 03 managed-state tests: immutable revisions, MVCC CAS ref, unbound
migration targets, all-or-nothing cutover (§41.31, §41.59.3, FR-MSTATE)."""

from __future__ import annotations

import pytest

from agent_meta_runtime.adapters.store import (
    StateCreateRequest,
    StateMigrationCutoverRequest,
    StateRevisionRegistration,
    StateWriteRequest,
    create_state,
    migrate_state_cutover,
    register_migration_target,
    write_state_revision,
)
from agent_meta_runtime.domain.errors import ErrorCode, StableError

from conftest import ACTOR, artifact_id, execute_command_result, run_command, _seed_artifact

REALM = "realm://main"


def _create(conn, owner=ACTOR):
    artifact = artifact_id("state-1")
    _seed_artifact(conn, artifact)
    return run_command(
        conn,
        create_state(
            StateCreateRequest(owner_id=owner, schema_id="schema://s1", artifact_id=artifact)
        ),
    )


def test_create_then_cas_write(store):
    conn, _realm, _tmp = store
    created = _create(conn)
    state_id = created["state_id"]
    revision_1 = created["state_revision_id"]
    assert created["cas_revision"] == 1
    artifact_2 = artifact_id("state-2")
    _seed_artifact(conn, artifact_2)
    written = run_command(
        conn,
        write_state_revision(
            StateWriteRequest(
                state_id=state_id,
                expected_revision_id=revision_1,
                expected_cas_revision=1,
                schema_id="schema://s1",
                artifact_id=artifact_2,
                writer_id=ACTOR,
            )
        ),
    )
    assert written["cas_revision"] == 2
    revision_2 = written["state_revision_id"]
    row = conn.execute(
        "SELECT current_revision_id, cas_revision, status FROM managed_states"
        " WHERE state_id = ?",
        (state_id,),
    ).fetchone()
    assert row[0] == revision_2
    assert row[1] == 2
    assert row[2] == "ACTIVE"
    # Revisions are immutable rows with a parent chain; ref history tracks moves.
    revisions = conn.execute(
        "SELECT state_revision_id, parent_revision_id FROM state_revisions"
        " WHERE state_id = ? ORDER BY created_at_us",
        (state_id,),
    ).fetchall()
    assert revisions[0][1] is None
    assert revisions[1][1] == revision_1
    history = conn.execute(
        "SELECT state_revision_id FROM state_ref_history WHERE state_id = ?"
        " ORDER BY meta_revision",
        (state_id,),
    ).fetchall()
    assert [r[0] for r in history] == [revision_1, revision_2]
    events = {
        r[0]
        for r in conn.execute(
            "SELECT event_type FROM facts WHERE entity_id = ? AND"
            " event_type = 'state_revision_created'",
            (state_id,),
        ).fetchall()
    }
    assert events == {"state_revision_created"}


def test_stale_writer_never_overwrites(store):
    conn, _realm, _tmp = store
    created = _create(conn)
    state_id = created["state_id"]
    revision_1 = created["state_revision_id"]
    artifact_2 = artifact_id("state-2")
    _seed_artifact(conn, artifact_2)
    # Wrong expected revision.
    stale_revision = execute_command_result(
        conn,
        write_state_revision(
            StateWriteRequest(
                state_id=state_id,
                expected_revision_id="state-revision://missing",
                expected_cas_revision=1,
                schema_id="schema://s1",
                artifact_id=artifact_2,
                writer_id=ACTOR,
            )
        ),
    )
    assert stale_revision.error is not None
    assert stale_revision.error.code == "REVISION_CONFLICT"
    # Wrong expected cas.
    stale_cas = execute_command_result(
        conn,
        write_state_revision(
            StateWriteRequest(
                state_id=state_id,
                expected_revision_id=revision_1,
                expected_cas_revision=7,
                schema_id="schema://s1",
                artifact_id=artifact_2,
                writer_id=ACTOR,
            )
        ),
    )
    assert stale_cas.error is not None
    assert stale_cas.error.code == "REVISION_CONFLICT"
    # The ref never moved and no new revision row was written.
    row = conn.execute(
        "SELECT current_revision_id, cas_revision FROM managed_states WHERE state_id = ?",
        (state_id,),
    ).fetchone()
    assert tuple(row) == (revision_1, 1)
    count = conn.execute(
        "SELECT COUNT(*) FROM state_revisions WHERE state_id = ?", (state_id,)
    ).fetchone()[0]
    assert count == 1


def test_migration_register_then_cutover(store):
    conn, _realm, _tmp = store
    created = _create(conn)
    state_id = created["state_id"]
    source = created["state_revision_id"]
    target_artifact = artifact_id("state-migrated")
    _seed_artifact(conn, target_artifact)
    binding = StateRevisionRegistration(
        state_id=state_id,
        source_revision_id=source,
        schema_id="schema://s2",
        artifact_id=target_artifact,
    )
    registered = run_command(conn, register_migration_target(binding))
    target = registered["state_revision_id"]
    assert registered["bound"] is False
    # The unbound target exists as an auditable revision, but the ref is untouched.
    row = conn.execute(
        "SELECT current_revision_id, cas_revision, status FROM managed_states"
        " WHERE state_id = ?",
        (state_id,),
    ).fetchone()
    assert tuple(row) == (source, 1, "ACTIVE")
    assert conn.execute(
        "SELECT schema_id FROM state_revisions WHERE state_revision_id = ?", (target,)
    ).fetchone()[0] == "schema://s2"
    # The unbound target supersedes its source in the causal graph.
    edge = conn.execute(
        "SELECT to_id FROM causal_edges WHERE from_id = ? AND edge_type = 'supersedes'",
        (target,),
    ).fetchone()
    assert edge[0] == source
    # Cutover binds the target: CAS moves the ref and records the migration.
    bound = run_command(
        conn,
        migrate_state_cutover(
            StateMigrationCutoverRequest(
                bindings=[
                    StateRevisionRegistration(
                        state_id=state_id,
                        source_revision_id=source,
                        schema_id="schema://s2",
                        artifact_id=target_artifact,
                        state_revision_id=target,
                    )
                ],
                reason_code="test_cutover",
            )
        ),
    )
    assert bound == {"bound": [{"state_id": state_id, "state_revision_id": target}]}
    row = conn.execute(
        "SELECT current_revision_id, cas_revision FROM managed_states WHERE state_id = ?",
        (state_id,),
    ).fetchone()
    assert tuple(row) == (target, 2)
    fact = conn.execute(
        "SELECT payload_json FROM facts WHERE event_type = 'migration_completed'"
    ).fetchone()
    assert fact is not None
    assert b"test_cutover" in bytes(fact[0])
    history = conn.execute(
        "SELECT state_revision_id FROM state_ref_history WHERE state_id = ?"
        " ORDER BY meta_revision",
        (state_id,),
    ).fetchall()
    assert [r[0] for r in history] == [source, target]


def test_cutover_rolls_back_entirely_on_any_conflict(store):
    conn, _realm, _tmp = store
    created = _create(conn)
    state_id = created["state_id"]
    source = created["state_revision_id"]
    target_artifact = artifact_id("state-migrated")
    _seed_artifact(conn, target_artifact)
    registered = run_command(
        conn,
        register_migration_target(
            StateRevisionRegistration(
                state_id=state_id,
                source_revision_id=source,
                schema_id="schema://s2",
                artifact_id=target_artifact,
            )
        ),
    )
    target = registered["state_revision_id"]
    # A concurrent writer advances the state after the target was registered.
    artifact_2 = artifact_id("state-2")
    _seed_artifact(conn, artifact_2)
    run_command(
        conn,
        write_state_revision(
            StateWriteRequest(
                state_id=state_id,
                expected_revision_id=source,
                expected_cas_revision=1,
                schema_id="schema://s1",
                artifact_id=artifact_2,
                writer_id=ACTOR,
            )
        ),
    )
    # Cutover against the stale source must roll back as a whole.
    result = execute_command_result(
        conn,
        migrate_state_cutover(
            StateMigrationCutoverRequest(
                bindings=[
                    StateRevisionRegistration(
                        state_id=state_id,
                        source_revision_id=source,
                        schema_id="schema://s2",
                        artifact_id=target_artifact,
                        state_revision_id=target,
                    )
                ]
            )
        ),
    )
    assert result.error is not None
    assert result.error.code == "REVISION_CONFLICT"
    # Nothing was bound: ref still at the concurrent writer's revision, no
    # migration fact, and the unbound target survives as a registered revision.
    row = conn.execute(
        "SELECT current_revision_id, cas_revision FROM managed_states WHERE state_id = ?",
        (state_id,),
    ).fetchone()
    assert row[1] == 2
    assert row[0] != target
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM facts WHERE event_type = 'migration_completed'"
        ).fetchone()[0]
        == 0
    )
    assert conn.execute(
        "SELECT COUNT(*) FROM state_revisions WHERE state_revision_id = ?", (target,)
    ).fetchone()[0] == 1


def test_cutover_validates_bindings(store):
    conn, _realm, _tmp = store
    with pytest.raises(StableError):
        migrate_state_cutover(StateMigrationCutoverRequest(bindings=[]))
    with pytest.raises(StableError):
        migrate_state_cutover(
            StateMigrationCutoverRequest(
                bindings=[
                    StateRevisionRegistration(
                        state_id="state://x",
                        source_revision_id="state-revision://y",
                        schema_id="schema://s",
                        artifact_id=artifact_id("x"),
                    )
                ]
            )
        )
