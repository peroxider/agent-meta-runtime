"""Shared Step 01/02 store fixtures."""

from __future__ import annotations

import hashlib

import pytest

from agent_meta_runtime.adapters.store import bootstrap_realm, initialize_store
from agent_meta_runtime.domain.deadline import Deadline
from agent_meta_runtime.domain.envelope import CommandEnvelope
from agent_meta_runtime.domain.ids import new_uuid7

ACTOR = "principal://operator-root/01900000-0000-7000-8000-000000000000"
DEADLINE = Deadline.after(5_000_000)


def artifact_id(tag: str) -> str:
    return "artifact://sha256/" + hashlib.sha256(tag.encode("utf-8")).hexdigest()


def _seed_artifact(conn, artifact: str) -> None:
    conn.execute(
        "INSERT INTO artifacts(artifact_id, kind, media_type, size_bytes,"
        " schema_version, created_by, created_at_us, parents_json, manifest_json,"
        " integrity_status)"
        " VALUES (?, 'code', 'application/json', 0, 1, ?, 1, ?, ?, 'VALID')",
        (artifact, ACTOR, b"{}", b"{}"),
    )


@pytest.fixture()
def store(tmp_path):
    conn = initialize_store(tmp_path / "meta.db")
    realm = "realm://main"
    bootstrap_realm(conn, realm, "epoch://" + new_uuid7())
    try:
        yield conn, realm, tmp_path
    finally:
        conn.close()


@pytest.fixture()
def semantic_env(store):
    """Realm with seeded artifact/composition/capability-surface FK rows."""

    conn, realm, tmp_path = store
    composition = "composition://" + new_uuid7()
    surface_artifact = artifact_id("surface")
    for tag in ("input", "surface", "output"):
        _seed_artifact(conn, artifact_id(tag))
    conn.execute(
        "INSERT INTO compositions(composition_id, realm_id, revision, parent_id,"
        " body_json, body_hash, created_by, created_at_us)"
        " VALUES (?, ?, 1, NULL, ?, 'h', ?, 1)",
        (composition, realm, b"{}", ACTOR),
    )
    conn.execute(
        "INSERT INTO capability_surfaces(realm_id, surface_revision, composition_id,"
        " artifact_id, authority_fingerprint, backend_profile_hash, created_at_us)"
        " VALUES (?, 1, ?, ?, 'afp', 'bph', 1)",
        (realm, composition, surface_artifact),
    )
    conn.commit()
    return conn, realm, composition, artifact_id("input"), surface_artifact


def make_command(realm: str, **overrides) -> CommandEnvelope:
    base = dict(
        command_id="task://" + new_uuid7(),
        realm_id=realm,
        actor_id=ACTOR,
        authority_grant_id=None,
        expected_meta_revision=None,
        causal_parent_action_id=None,
        payload_type="task.submit/v1",
        payload_schema_version=1,
        payload={},
        auth_nonce=None,
        auth_issued_at_us=None,
        auth_signature=None,
    )
    base.update(overrides)
    return CommandEnvelope(**base)


def run_command(conn, mutator):
    """Execute one command; assert commitment and return the receipt."""

    result = execute_command_result(conn, mutator)
    assert not hasattr(result, "error"), result.error
    return dict(result.receipt)


def execute_command_result(conn, mutator):
    from agent_meta_runtime.adapters.store import execute_command

    return execute_command(
        conn, make_command("realm://main"), mutator, deadline=DEADLINE
    )
