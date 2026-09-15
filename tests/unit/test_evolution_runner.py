"""Step 08.4 gate: deterministic experiment runner (§41.43, AC-M42)."""

from __future__ import annotations

import json

import pytest

from agent_meta_runtime.adapters.store.uow import bootstrap_realm
from agent_meta_runtime.adapters.store.evolution import (
    CreateExperimentRequest,
    CreateWorldRequest,
    RegisterCandidateRequest,
    create_experiment,
    create_world,
    get_experiment_row,
    register_candidate,
)
from agent_meta_runtime.adapters.store.experiment_runner import (
    PLACEMENT_REQUIRED_FEATURES,
    RunExperimentRequest,
    fake_model_run,
    run_experiment,
    unmet_features,
)
from agent_meta_runtime.adapters.store.initializer import initialize_store
from agent_meta_runtime.adapters.store.state import StateCreateRequest, create_state
from agent_meta_runtime.domain.canonical import canonical_json, sha256_hex
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.evolution import CRITERIA_SCHEMA
from agent_meta_runtime.domain.ids import new_uuid7
from agent_meta_runtime.domain.semantics import TaskBudget
from conftest import ACTOR, DEADLINE, _seed_artifact, artifact_id, make_command
from test_evolution_store import _baseline_chain, _run, _seed_baseline

REALM = "realm://main"

PORTABLE_FEATURES = {"process": "SUPPORTED", "workspace": "SUPPORTED"}

CRITERIA = {
    "schema": CRITERIA_SCHEMA,
    "decision_rule": "ALL_REQUIRED_PASS",
    "assertions": [
        {"kind": "artifact_integrity"},
        {"kind": "compatibility_report", "require_activatable": True},
        {
            "kind": "test_suite",
            "suite_artifact_id": "artifact://suite",
            "required_pass_rate_ppm": 999000,
        },
        {"kind": "security_policy", "allow_high_findings": 0},
        {
            "kind": "budget",
            "max_wall_time_us": 300000000,
            "max_cost_microunits": 1000,
        },
    ],
}

FIXTURES = (
    {"slot": "echo", "expected_capability": "capability://echo"},
    {"slot": "extra", "expected_capability": "capability://extra"},
)


def _capabilities(conn, *capability_ids: str) -> None:
    for capability in capability_ids:
        descriptor = artifact_id("cap:" + capability)
        _seed_artifact(conn, descriptor)
        conn.execute(
            "INSERT INTO capabilities(capability_id, descriptor_revision,"
            " artifact_id, descriptor_json, created_at_us)"
            " VALUES (?, 1, ?, ?, 1)",
            (capability, descriptor, b"{}"),
        )


def _build_env(tmp_path, label: str):
    conn = initialize_store(tmp_path / f"meta-{label}.db")
    bootstrap_realm(conn, REALM, "epoch://" + new_uuid7())
    for tag in ("cand", "suite", "eval", "result", "evidence", "state-content"):
        _seed_artifact(conn, artifact_id(tag))
    _capabilities(conn, "capability://echo", "capability://extra")
    baseline = _seed_baseline(conn)
    conn.commit()
    return conn, baseline


def _make_candidate(conn, baseline, trust="trusted_candidate", artifacts=(artifact_id("cand"),)):
    _proposal_id, change_set_id = _baseline_chain(conn, baseline)
    return _run(
        conn,
        register_candidate(
            RegisterCandidateRequest(
                realm_id=REALM,
                change_set_id=change_set_id,
                trust_class=trust,
                artifact_ids=tuple(artifacts),
            )
        ),
    )


def _make_world(conn) -> str:
    return _run(
        conn,
        create_world(
            CreateWorldRequest(
                realm_id=REALM,
                backend_profile_hash="bph",
                fixture_artifact_ids=(artifact_id("suite"),),
                state_snapshot_ids=(),
                environment_allowlist=("python3",),
                workspace_quota={"max_bytes": 1000},
                budget=TaskBudget(max_turns=2, max_steps=4, max_model_calls=2),
                seed=7,
                replay_level="FULL",
            )
        ),
    )["world_id"]


def _make_experiment(conn, candidate_id: str, baseline: str, world_id: str) -> str:
    return _run(
        conn,
        create_experiment(
            CreateExperimentRequest(
                realm_id=REALM,
                candidate_id=candidate_id,
                baseline_id=baseline,
                world_id=world_id,
                criteria_artifact_id=artifact_id("suite"),
                budget=TaskBudget(),
            )
        ),
    )["experiment_id"]


def _runner_request(experiment_id: str, **overrides) -> RunExperimentRequest:
    fields = dict(
        realm_id=REALM,
        experiment_id=experiment_id,
        criteria_document=CRITERIA,
        evaluator_artifact_id=artifact_id("eval"),
        result_artifact_id=artifact_id("result"),
        evidence_artifact_id=artifact_id("evidence"),
        fixtures=FIXTURES,
        backend_features=PORTABLE_FEATURES,
    )
    fields.update(overrides)
    return RunExperimentRequest(**fields)


# --------------------------------------------------------------- pure bits --


def test_unmet_features_and_unknown_trust_class_fail_closed():
    assert unmet_features("trusted_candidate", PORTABLE_FEATURES) == ()
    assert unmet_features("trusted_candidate", {}) == ("process", "workspace")
    assert unmet_features("untrusted_candidate", PORTABLE_FEATURES) == (
        "isolated_realm",
        "network_isolation",
        "credential_isolation",
    )
    assert PLACEMENT_REQUIRED_FEATURES["untrusted_candidate"] == (
        "isolated_realm",
        "network_isolation",
        "credential_isolation",
    )
    with pytest.raises(StableError) as excinfo:
        unmet_features("root_kit", PORTABLE_FEATURES)
    assert excinfo.value.code == ErrorCode.INVALID_ARGUMENT


def test_fake_model_is_deterministic_and_order_insensitive():
    body = {"slots": {"echo": {"capability": "capability://echo"}}}
    one = fake_model_run(body, FIXTURES)
    two = fake_model_run(body, tuple(reversed(FIXTURES)))
    assert one == two
    assert one["pass_count"] == 1 and one["check_count"] == 2
    assert one["pass_rate_ppm"] == 500000


# ------------------------------------------------------------ integration --


def test_run_experiment_happy_path_accepts_and_completes(tmp_path):
    conn, baseline = _build_env(tmp_path, "happy")
    candidate = _make_candidate(conn, baseline)
    world_id = _make_world(conn)
    experiment_id = _make_experiment(
        conn, candidate["candidate_id"], baseline, world_id
    )
    receipt = run_experiment(
        conn, make_command(REALM), _runner_request(experiment_id), DEADLINE
    )
    assert receipt["status"] == "COMPLETED"
    assert receipt["decision"] == "ACCEPT"
    assert get_experiment_row(conn, experiment_id)["status"] == "COMPLETED"
    facts = conn.execute(
        "SELECT event_type FROM facts WHERE entity_id = ?", (experiment_id,)
    ).fetchall()
    assert "experiment_started" in [f[0] for f in facts]
    evidence = conn.execute(
        "SELECT subject_id FROM evidence WHERE experiment_id = ?", (experiment_id,)
    ).fetchall()
    assert len(evidence) == 2
    assert {row[0] for row in evidence} == {baseline, candidate["composition_id"]}
    assert receipt["result_document"]["result_hash"]


def test_run_experiment_rejects_failing_candidate_and_keeps_baseline(tmp_path):
    conn, baseline = _build_env(tmp_path, "reject")
    candidate = _make_candidate(conn, baseline)
    world_id = _make_world(conn)
    experiment_id = _make_experiment(
        conn, candidate["candidate_id"], baseline, world_id
    )
    # Fixtures expect a different wiring for slots.extra than the candidate
    # provides: the candidate suite then fails at 500000 ppm.
    wrong = (
        {"slot": "echo", "expected_capability": "capability://echo"},
        {"slot": "extra", "expected_capability": "capability://wrong"},
    )
    receipt = run_experiment(
        conn,
        make_command(REALM),
        _runner_request(experiment_id, fixtures=wrong),
        DEADLINE,
    )
    assert receipt["status"] == "COMPLETED"
    assert receipt["decision"] == "REJECT"
    statuses = {
        entry["kind"]: entry["status"]
        for entry in receipt["result_document"]["assertion_results"]
    }
    assert statuses["test_suite"] == "FAIL"
    assert statuses["artifact_integrity"] == "PASS"
    # baseline composition row is untouched by the experiment
    body = conn.execute(
        "SELECT body_json FROM compositions WHERE composition_id = ?", (baseline,)
    ).fetchone()[0]
    assert b"capability://echo" in body


def test_run_experiment_invalid_when_features_unsupported(tmp_path):
    conn, baseline = _build_env(tmp_path, "invalid")
    candidate = _make_candidate(conn, baseline)
    world_id = _make_world(conn)
    experiment_id = _make_experiment(
        conn, candidate["candidate_id"], baseline, world_id
    )
    receipt = run_experiment(
        conn,
        make_command(REALM),
        _runner_request(experiment_id, backend_features={}),
        DEADLINE,
    )
    assert receipt["status"] == "INVALID"
    assert receipt["unmet_features"] == ["process", "workspace"]
    assert get_experiment_row(conn, experiment_id)["status"] == "INVALID"
    assert conn.execute(
        "SELECT COUNT(*) FROM evidence WHERE experiment_id = ?", (experiment_id,)
    ).fetchone()[0] == 0


def _seed_state_bound_baseline(conn) -> str:
    next_revision = int(
        conn.execute(
            "SELECT COALESCE(MAX(revision), 0) + 1 FROM compositions WHERE realm_id = ?",
            (REALM,),
        ).fetchone()[0]
    )
    body = {
        "schema": "composition/v1",
        "realm_id": REALM,
        "slots": {"echo": {"capability": "capability://echo"}},
        "states": {"memory": {"state_id": None}},  # replaced below
    }
    return next_revision, body


def test_run_experiment_clones_state_per_run_never_writes_production(tmp_path):
    conn, _unused = _build_env(tmp_path, "clone")
    production = _run(
        conn,
        create_state(
            StateCreateRequest(
                owner_id=ACTOR,
                schema_id="json/v1",
                artifact_id=artifact_id("state-content"),
            )
        ),
    )
    state_id = production["state_id"]
    # Insert a dedicated baseline whose body binds the production state.
    next_revision, body = _seed_state_bound_baseline(conn)
    body["states"]["memory"]["state_id"] = state_id
    body_json = canonical_json(body)
    baseline = "composition://" + new_uuid7()
    conn.execute(
        "INSERT INTO compositions(composition_id, realm_id, revision, parent_id,"
        " body_json, body_hash, created_by, created_at_us)"
        " VALUES (?, ?, ?, NULL, ?, ?, ?, 1)",
        (baseline, REALM, next_revision, body_json, sha256_hex(body_json), ACTOR),
    )
    conn.commit()
    candidate = _make_candidate(conn, baseline)
    world_id = _make_world(conn)
    experiment_id = _make_experiment(
        conn, candidate["candidate_id"], baseline, world_id
    )
    receipt = run_experiment(
        conn, make_command(REALM), _runner_request(experiment_id), DEADLINE
    )
    assert receipt["status"] == "COMPLETED"
    states = conn.execute(
        "SELECT state_id, cas_revision FROM managed_states ORDER BY state_id"
    ).fetchall()
    assert len(states) == 3  # production + one fresh clone per run
    production_row = [row for row in states if row[0] == state_id][0]
    assert production_row[1] == 1  # production never advanced
    clone_ids = {row[0] for row in states} - {state_id}
    assert len(clone_ids) == 2
    # The two runs recorded DIFFERENT clones; neither is the production id.
    rows = conn.execute(
        "SELECT metadata_json FROM evidence WHERE experiment_id = ?"
        " ORDER BY evidence_id",
        (experiment_id,),
    ).fetchall()
    metas = [json.loads(bytes(row[0]).decode("utf-8")) for row in rows]
    recorded_clones = {
        meta["cloned_states"][state_id] for meta in metas
    }
    assert recorded_clones == clone_ids
    assert state_id not in recorded_clones


def test_run_experiment_is_deterministic_across_stores(tmp_path):
    receipts = []
    for label in ("a", "b"):
        conn, baseline = _build_env(tmp_path, label)
        candidate = _make_candidate(conn, baseline)
        world_id = _make_world(conn)
        experiment_id = _make_experiment(
            conn, candidate["candidate_id"], baseline, world_id
        )
        receipts.append(
            run_experiment(
                conn, make_command(REALM), _runner_request(experiment_id), DEADLINE
            )
        )
        conn.close()
    assert receipts[0]["decision"] == receipts[1]["decision"] == "ACCEPT"
    assert (
        receipts[0]["candidate_model_result"]
        == receipts[1]["candidate_model_result"]
    )
    assert receipts[0]["result_document"] == receipts[1]["result_document"]
