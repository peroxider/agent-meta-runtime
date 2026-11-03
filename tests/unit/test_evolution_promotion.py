"""Step 08.5 gate: Promotion & Rollback store use cases (§41.43, §41.59.3)."""

from __future__ import annotations

import pytest

from agent_meta_runtime.adapters.store.composition import (
    SetServingRequest,
    set_serving,
)
from agent_meta_runtime.adapters.store.evolution import (
    ArchiveCandidateRequest,
    archive_candidate,
)
from agent_meta_runtime.adapters.store.experiment_runner import run_experiment
from agent_meta_runtime.adapters.store.promotion import (
    PromoteCandidateRequest,
    RollbackCompositionRequest,
    promote_candidate,
    rollback_composition,
)
from agent_meta_runtime.domain.canonical import canonical_json, sha256_hex
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.ids import new_uuid7
from conftest import ACTOR, DEADLINE, make_command
from test_evolution_runner import (
    REALM,
    _build_env,
    _make_candidate,
    _make_experiment,
    _make_world,
    _runner_request,
)
from test_evolution_store import _run, _run_err


def _run_experiment(conn, baseline: str, **runner_overrides) -> dict:
    candidate = _make_candidate(conn, baseline)
    world_id = _make_world(conn)
    experiment_id = _make_experiment(
        conn, candidate["candidate_id"], baseline, world_id
    )
    run_receipt = run_experiment(
        conn,
        make_command(REALM),
        _runner_request(experiment_id, **runner_overrides),
        DEADLINE,
    )
    return {
        "candidate": candidate,
        "experiment_id": experiment_id,
        "run": run_receipt,
    }


def test_promote_commits_desired_only_after_accept(tmp_path):
    conn, baseline = _build_env(tmp_path, "promote")
    outcome = _run_experiment(conn, baseline)
    assert outcome["run"]["decision"] == "ACCEPT"
    candidate = outcome["candidate"]
    receipt = _run(
        conn,
        promote_candidate(
            PromoteCandidateRequest(
                realm_id=REALM,
                candidate_id=candidate["candidate_id"],
                evaluation_id=outcome["run"]["evaluation_id"],
                expected_serving_revision=0,
            )
        ),
    )
    assert receipt["desired_revision"] == candidate["revision"]
    assert receipt["reconcile_status"] == "PENDING"
    refs = conn.execute(
        "SELECT desired_revision, serving_revision FROM composition_refs"
        " WHERE realm_id = ?",
        (REALM,),
    ).fetchone()
    assert refs[0] == candidate["revision"]
    assert refs[1] in (0, None)  # serving untouched: Reconciler cuts over
    facts = conn.execute(
        "SELECT event_type FROM facts WHERE entity_id = ?",
        (candidate["candidate_id"],),
    ).fetchall()
    types = [f[0] for f in facts]
    assert "promotion_requested" in types
    assert "candidate_promoted" in types


def test_promote_refuses_rejected_evaluation(tmp_path):
    conn, baseline = _build_env(tmp_path, "reject")
    outcome = _run_experiment(
        conn,
        baseline,
        fixtures=(
            {"slot": "echo", "expected_capability": "capability://echo"},
            {"slot": "extra", "expected_capability": "capability://wrong"},
        ),
    )
    assert outcome["run"]["decision"] == "REJECT"
    error = _run_err(
        conn,
        promote_candidate(
            PromoteCandidateRequest(
                realm_id=REALM,
                candidate_id=outcome["candidate"]["candidate_id"],
                evaluation_id=outcome["run"]["evaluation_id"],
                expected_serving_revision=0,
            )
        ),
    )
    assert error.code == ErrorCode.FAILED_PRECONDITION
    assert conn.execute(
        "SELECT COUNT(*) FROM composition_refs WHERE realm_id = ?", (REALM,)
    ).fetchone()[0] == 0


def test_promote_refuses_foreign_evaluation(tmp_path):
    conn, baseline = _build_env(tmp_path, "foreign")
    outcome = _run_experiment(conn, baseline)
    other = _run_experiment(conn, baseline)
    error = _run_err(
        conn,
        promote_candidate(
            PromoteCandidateRequest(
                realm_id=REALM,
                candidate_id=outcome["candidate"]["candidate_id"],
                evaluation_id=other["run"]["evaluation_id"],
                expected_serving_revision=0,
            )
        ),
    )
    assert error.code == ErrorCode.FAILED_PRECONDITION


def test_completed_experiment_rerun_refused(tmp_path):
    conn, baseline = _build_env(tmp_path, "rerun")
    outcome = _run_experiment(conn, baseline)
    assert outcome["run"]["status"] == "COMPLETED"
    with pytest.raises(StableError) as excinfo:
        run_experiment(
            conn,
            make_command(REALM),
            _runner_request(outcome["experiment_id"]),
            DEADLINE,
        )
    assert excinfo.value.code == ErrorCode.FAILED_PRECONDITION


def test_promote_refuses_archived_candidate_and_serving_conflict(tmp_path):
    conn, baseline = _build_env(tmp_path, "archive")
    outcome = _run_experiment(conn, baseline)
    candidate_id = outcome["candidate"]["candidate_id"]
    _run(
        conn,
        archive_candidate(
            ArchiveCandidateRequest(realm_id=REALM, candidate_id=candidate_id)
        ),
    )
    error = _run_err(
        conn,
        promote_candidate(
            PromoteCandidateRequest(
                realm_id=REALM,
                candidate_id=candidate_id,
                evaluation_id=outcome["run"]["evaluation_id"],
                expected_serving_revision=0,
            )
        ),
    )
    assert error.code == ErrorCode.FAILED_PRECONDITION

    # Fresh accepted candidate: serving-observation conflict is rejected.
    conn2, baseline2 = _build_env(tmp_path, "conflict")
    outcome2 = _run_experiment(conn2, baseline2)
    conflict = _run_err(
        conn2,
        promote_candidate(
            PromoteCandidateRequest(
                realm_id=REALM,
                candidate_id=outcome2["candidate"]["candidate_id"],
                evaluation_id=outcome2["run"]["evaluation_id"],
                expected_serving_revision=5,
            )
        ),
    )
    assert conflict.code == ErrorCode.REVISION_CONFLICT


def test_promote_unknown_effect_gate_fails(tmp_path):
    conn, _clean = _build_env(tmp_path, "unknown")
    # Baseline with an unrecognized top-level declaration; the candidate
    # inherits it and promotion must fail closed.
    next_revision = int(
        conn.execute(
            "SELECT COALESCE(MAX(revision), 0) + 1 FROM compositions"
            " WHERE realm_id = ?",
            (REALM,),
        ).fetchone()[0]
    )
    body = {
        "schema": "composition/v1",
        "realm_id": REALM,
        "slots": {"echo": {"capability": "capability://echo"}},
        "magic_side_channel": {"enabled": True},
    }
    body_json = canonical_json(body)
    baseline = "composition://" + new_uuid7()
    conn.execute(
        "INSERT INTO compositions(composition_id, realm_id, revision, parent_id,"
        " body_json, body_hash, created_by, created_at_us)"
        " VALUES (?, ?, ?, NULL, ?, ?, ?, 1)",
        (baseline, REALM, next_revision, body_json, sha256_hex(body_json), ACTOR),
    )
    conn.commit()
    outcome = _run_experiment(conn, baseline)
    assert outcome["run"]["decision"] == "ACCEPT"  # runner accepted it
    error = _run_err(
        conn,
        promote_candidate(
            PromoteCandidateRequest(
                realm_id=REALM,
                candidate_id=outcome["candidate"]["candidate_id"],
                evaluation_id=outcome["run"]["evaluation_id"],
                expected_serving_revision=0,
            )
        ),
    )
    assert error.code == ErrorCode.FAILED_PRECONDITION
    assert "magic_side_channel" in str(error.details)


def test_rollback_creates_new_transition_and_keeps_revisions(tmp_path):
    conn, baseline = _build_env(tmp_path, "rollback")
    outcome = _run_experiment(conn, baseline)
    candidate = outcome["candidate"]
    _run(
        conn,
        promote_candidate(
            PromoteCandidateRequest(
                realm_id=REALM,
                candidate_id=candidate["candidate_id"],
                evaluation_id=outcome["run"]["evaluation_id"],
                expected_serving_revision=0,
            )
        ),
    )
    # Simulate the Reconciler cutover to the promoted revision.
    serving_cas = int(
        conn.execute(
            "SELECT serving_cas FROM composition_refs WHERE realm_id = ?",
            (REALM,),
        ).fetchone()[0]
    )
    _run(
        conn,
        set_serving(
            SetServingRequest(
                realm_id=REALM,
                revision=candidate["revision"],
                expected_cas=serving_cas,
            )
        ),
    )
    receipt = _run(
        conn,
        rollback_composition(
            RollbackCompositionRequest(
                realm_id=REALM,
                target_parent_id=baseline,
                expected_serving_revision=candidate["revision"],
                state_strategy="KEEP_COMPATIBLE",
                reason_code="operator_rollback",
            )
        ),
    )
    assert receipt["desired_revision"] == 1  # back to the baseline revision
    assert receipt["state_strategy"] == "KEEP_COMPATIBLE"
    # The promoted revision still exists and serving still shows it.
    assert conn.execute(
        "SELECT COUNT(*) FROM compositions WHERE revision = ?",
        (candidate["revision"],),
    ).fetchone()[0] == 1
    refs = conn.execute(
        "SELECT desired_revision, serving_revision FROM composition_refs"
        " WHERE realm_id = ?",
        (REALM,),
    ).fetchone()
    assert refs[0] == 1 and refs[1] == candidate["revision"]


def test_rollback_state_strategy_gates(tmp_path):
    conn, baseline = _build_env(tmp_path, "states")
    no_revisions = _run_err(
        conn,
        rollback_composition(
            RollbackCompositionRequest(
                realm_id=REALM,
                target_parent_id=baseline,
                expected_serving_revision=0,
                state_strategy="RESTORE_PARENT",
            )
        ),
    )
    assert no_revisions.code == ErrorCode.INVALID_ARGUMENT
    bogus = _run_err(
        conn,
        rollback_composition(
            RollbackCompositionRequest(
                realm_id=REALM,
                target_parent_id=baseline,
                expected_serving_revision=0,
                state_strategy="RESTORE_PARENT",
                expected_state_revisions={
                    "state://ghost": "state-revision://ghost"
                },
            )
        ),
    )
    assert bogus.code == ErrorCode.NOT_FOUND
    bad_strategy = _run_err(
        conn,
        rollback_composition(
            RollbackCompositionRequest(
                realm_id=REALM,
                target_parent_id=baseline,
                expected_serving_revision=0,
                state_strategy="MAGIC",
            )
        ),
    )
    assert bad_strategy.code == ErrorCode.INVALID_ARGUMENT
    # unknown parent composition
    ghost_parent = _run_err(
        conn,
        rollback_composition(
            RollbackCompositionRequest(
                realm_id=REALM,
                target_parent_id="composition://ghost",
                expected_serving_revision=0,
            )
        ),
    )
    assert ghost_parent.code == ErrorCode.NOT_FOUND
