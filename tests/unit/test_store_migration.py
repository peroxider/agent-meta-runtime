"""Step 01 gate: authoritative DDL migration, PRAGMA profile, triggers (§41.34)."""

from __future__ import annotations

import sqlite3

import pytest

from agent_meta_runtime.adapters.store import (
    APPLICATION_ID,
    USER_VERSION,
    connect_store,
    initialize_store,
    verify_store_identity,
)
from agent_meta_runtime.domain.errors import StableError

EXPECTED_TABLES = {
    "realms", "epochs", "principals", "root_recovery", "root_recovery_history",
    "meta_revisions", "transactions", "commands", "artifacts", "artifact_blobs",
    "artifact_encryption", "capabilities", "capability_instances",
    "capability_surfaces", "compositions", "harness_installations",
    "harness_installation_history", "composition_refs", "composition_ref_history",
    "state_revisions", "managed_states", "state_ref_history", "authority_grants",
    "authority_grant_history", "authority_uses", "tasks", "task_budget_adjustments",
    "actions", "effect_intents", "invocations", "facts", "causal_edges", "outbox",
    "operations", "workspaces", "execution_bindings", "checkpoints",
    "context_projections", "scratch_sessions", "scratch_bindings", "worlds",
    "evolution_objects", "experiments", "evidence", "evaluations",
    "schema_migrations",
}


def test_migration_applies_full_schema(tmp_path) -> None:
    conn = initialize_store(tmp_path / "meta.db")
    try:
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert EXPECTED_TABLES <= tables
        indexes = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
        }
        # Named indexes from the §41.34.3 index list; facts(realm_id, seq) and
        # outbox(dedupe_key) uniqueness comes from inline UNIQUE constraints.
        for expected in (
            "uq_artifact_encryption_active",
            "uq_artifact_plain_blob",
            "uq_epoch_active",
            "uq_command_auth_nonce",
            "ix_fact_entity",
            "ix_fact_action",
            "ix_fact_transaction",
            "ix_outbox_dispatch",
            "ix_edge_to",
        ):
            assert expected in indexes, expected
    finally:
        conn.close()


def test_all_tables_are_strict(tmp_path) -> None:
    conn = initialize_store(tmp_path / "meta.db")
    try:
        for name in EXPECTED_TABLES:
            sql = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                (name,),
            ).fetchone()[0]
            assert "STRICT" in sql, name
    finally:
        conn.close()


def test_store_identity_and_pragma_profile(tmp_path) -> None:
    conn = initialize_store(tmp_path / "meta.db")
    try:
        assert conn.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
        assert conn.execute("PRAGMA user_version").fetchone()[0] == USER_VERSION
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert conn.execute("PRAGMA synchronous").fetchone()[0] == 2  # FULL
        assert conn.execute("PRAGMA trusted_schema").fetchone()[0] == 0
        assert conn.execute("PRAGMA recursive_triggers").fetchone()[0] == 1
        verify_store_identity(conn)
    finally:
        conn.close()


def test_migration_recorded_with_checksum(tmp_path) -> None:
    conn = initialize_store(tmp_path / "meta.db")
    try:
        row = conn.execute(
            "SELECT version, name, checksum FROM schema_migrations"
        ).fetchone()
        assert row[0] == 1 and row[1] == "v0_1_authoritative_ddl"
        from agent_meta_runtime.adapters.store import MIGRATION_CHECKSUM

        assert row[2] == MIGRATION_CHECKSUM
    finally:
        conn.close()


def test_identity_mismatch_rejected(tmp_path) -> None:
    conn = initialize_store(tmp_path / "meta.db")
    conn.execute("PRAGMA user_version = 2")
    with pytest.raises(StableError):
        verify_store_identity(conn)
    conn.close()


def test_tampered_checksum_rejected(tmp_path) -> None:
    conn = initialize_store(tmp_path / "meta.db")
    conn.execute("UPDATE schema_migrations SET checksum = ?", ("0" * 64,))
    with pytest.raises(StableError):
        verify_store_identity(conn)
    conn.close()


def test_facts_are_append_only(store) -> None:
    conn, realm, _ = store
    conn.execute(
        "INSERT INTO facts(fact_id, realm_id, seq, occurred_at_us, recorded_at_us,"
        " actor_id, action_id, transaction_id, entity_type, entity_id, event_type,"
        " schema_version, payload_json, payload_hash, prev_fact_hash, fact_hash)"
        " VALUES (?, ?, 1, 1, 1, ?, NULL, NULL, 'runtime', ?,"
        " 'runtime_initialized', 1, ?, ?, ?, ?)",
        (
            "fact://01900000-0000-7000-8000-00000000000f",
            realm,
            "principal://operator-root/01900000-0000-7000-8000-000000000000",
            realm,
            b"{}",
            "a" * 64,
            "0" * 64,
            "b" * 64,
        ),
    )
    with pytest.raises(sqlite3.IntegrityError, match="FACT_APPEND_ONLY"):
        conn.execute("UPDATE facts SET payload_hash = ? WHERE seq = 1", ("c" * 64,))
    with pytest.raises(sqlite3.IntegrityError, match="FACT_APPEND_ONLY"):
        conn.execute("DELETE FROM facts WHERE seq = 1")


def test_compositions_immutable_triggers(store) -> None:
    conn, realm, _ = store
    conn.execute(
        "INSERT INTO compositions(composition_id, realm_id, revision, parent_id,"
        " body_json, body_hash, created_by, created_at_us)"
        " VALUES (?, ?, 1, NULL, ?, ?, ?, 1)",
        (
            "composition://01900000-0000-7000-8000-000000000001",
            realm,
            b"{}",
            "a" * 64,
            "principal://operator-root/01900000-0000-7000-8000-000000000000",
        ),
    )
    with pytest.raises(sqlite3.IntegrityError, match="COMPOSITION_IMMUTABLE"):
        conn.execute("UPDATE compositions SET body_hash = ?", ("b" * 64,))
    with pytest.raises(sqlite3.IntegrityError, match="COMPOSITION_IMMUTABLE"):
        conn.execute("DELETE FROM compositions")


def test_artifacts_identity_and_no_delete(store) -> None:
    conn, realm, _ = store
    artifact_id = "artifact://sha256/" + "a" * 64
    conn.execute(
        "INSERT INTO artifacts(artifact_id, kind, media_type, size_bytes,"
        " schema_version, created_by, created_at_us, parents_json, manifest_json,"
        " integrity_status) VALUES (?, 'test', 'application/json', 1, 1, ?, 1,"
        " ?, ?, 'VALID')",
        (
            artifact_id,
            "principal://operator-root/01900000-0000-7000-8000-000000000000",
            b"[]",
            b"{}",
        ),
    )
    with pytest.raises(sqlite3.IntegrityError, match="ARTIFACT_IDENTITY_IMMUTABLE"):
        conn.execute(
            "UPDATE artifacts SET media_type = 'text/plain' WHERE artifact_id = ?",
            (artifact_id,),
        )
    with pytest.raises(sqlite3.IntegrityError, match="ARTIFACT_MANIFEST_IMMUTABLE"):
        conn.execute("DELETE FROM artifacts")


def test_foreign_keys_enforced(store) -> None:
    conn, _realm, _ = store
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO facts(fact_id, realm_id, seq, occurred_at_us, recorded_at_us,"
            " actor_id, action_id, transaction_id, entity_type, entity_id, event_type,"
            " schema_version, payload_json, payload_hash, prev_fact_hash, fact_hash)"
            " VALUES (?, 'realm://nope', 1, 1, 1, ?, NULL, NULL, 'runtime', 'x',"
            " 'runtime_initialized', 1, ?, ?, ?, ?)",
            (
                "fact://01900000-0000-7000-8000-00000000000e",
                "principal://operator-root/01900000-0000-7000-8000-000000000000",
                b"{}",
                "a" * 64,
                "0" * 64,
                "b" * 64,
            ),
        )


def test_reconnect_applies_profile(tmp_path) -> None:
    initialize_store(tmp_path / "meta.db").close()
    conn = connect_store(tmp_path / "meta.db")
    try:
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    finally:
        conn.close()
