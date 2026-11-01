"""Evolution graph references must stay in the command Realm."""
import json

import pytest

from agent_meta_runtime.adapters.store import execute_command
from agent_meta_runtime.adapters.store.composition import CompositionCreateRequest, create_composition
from agent_meta_runtime.adapters.store.evolution import (
    CreateChangeSetRequest, CreateExperimentRequest, CreateWorldRequest,
    SubmitProposalRequest, create_change_set, create_experiment, create_world,
    submit_proposal,
)
from agent_meta_runtime.adapters.store.experiment_runner import start_experiment
from agent_meta_runtime.adapters.store.promotion import (
    PromoteCandidateRequest, RollbackCompositionRequest, promote_candidate,
    rollback_composition,
)
from agent_meta_runtime.adapters.store.uow import bootstrap_realm
from agent_meta_runtime.domain.canonical import canonical_json
from agent_meta_runtime.domain.errors import ErrorCode
from agent_meta_runtime.domain.ids import new_uuid7
from agent_meta_runtime.domain.semantics import TaskBudget
from conftest import ACTOR, DEADLINE, artifact_id, make_command
from test_evolution_runner import REALM, PORTABLE_FEATURES, _build_env, _make_candidate, _make_world
from test_evolution_store import _baseline_chain, _run_err

FOREIGN = "realm://foreign"


@pytest.fixture
def graph(tmp_path):
    conn, baseline = _build_env(tmp_path, "realm-boundaries")
    bootstrap_realm(conn, FOREIGN, "epoch://" + new_uuid7())
    result = execute_command(conn, make_command(FOREIGN), create_composition(
        CompositionCreateRequest(realm_id=FOREIGN, revision=1, created_by=ACTOR,
            body={"schema": "composition/v1", "realm_id": FOREIGN, "slots": {}})), deadline=DEADLINE)
    assert not hasattr(result, "error")
    foreign = result.receipt["composition_id"]
    # Deliberately equal revisions: an unscoped ID lookup can select the
    # local revision even though the caller named a different Composition.
    assert conn.execute("SELECT revision FROM compositions WHERE composition_id=?", (baseline,)).fetchone()[0] == 1
    yield conn, baseline, foreign
    conn.close()


def snapshot(conn):
    tables = ("composition_refs", "compositions", "evolution_objects", "experiments",
        "managed_states", "state_revisions", "actions", "facts")
    return {table: [tuple(row) for row in conn.execute("SELECT * FROM " + table + " ORDER BY rowid")]
        for table in tables}


@pytest.mark.parametrize("operation", ["proposal", "change_set", "experiment", "rollback"])
def test_normal_requests_refuse_foreign_composition_without_ref_or_graph_changes(graph, operation):
    conn, baseline, foreign = graph
    if operation == "proposal":
        mutator = submit_proposal(SubmitProposalRequest(REALM, "audit", (), foreign))
    elif operation == "change_set":
        proposal, _change_set = _baseline_chain(conn, baseline)
        mutator = create_change_set(CreateChangeSetRequest(realm_id=REALM, proposal_id=proposal,
            baseline_id=foreign, expected_serving_revision=0, operations=({"operation": "SET_POLICY",
                "target_path": "policy.audit", "expected_old_value_hash": None, "new_value": True},)))
    elif operation == "experiment":
        candidate = _make_candidate(conn, baseline)
        world = _make_world(conn)
        mutator = create_experiment(CreateExperimentRequest(realm_id=REALM,
            candidate_id=candidate["candidate_id"], baseline_id=foreign, world_id=world,
            criteria_artifact_id=artifact_id("suite"), budget=TaskBudget()))
    else:
        mutator = rollback_composition(RollbackCompositionRequest(REALM, foreign, 0))
    before = snapshot(conn)
    error = _run_err(conn, mutator)
    assert error.code == ErrorCode.NOT_FOUND
    assert snapshot(conn) == before


def candidate_reference(conn, original, foreign, *, realm=REALM):
    """A retained malformed graph from a prior writer must also fail closed."""
    row = conn.execute("SELECT parent_id, body_json FROM evolution_objects WHERE object_id=?",
        (original,)).fetchone()
    body = json.loads(row[1]); body["composition_id"] = foreign
    candidate = "candidate://" + new_uuid7()
    conn.execute("INSERT INTO evolution_objects(object_id,realm_id,object_type,parent_id,body_json,status,created_by,created_at_us) VALUES (?,?,'CANDIDATE',?,?,'ACTIVE',?,1)",
        (candidate, realm, row[0], canonical_json(body), ACTOR))
    conn.commit()
    return candidate


def test_promotion_does_not_alias_foreign_candidate_composition_to_local_revision(graph):
    conn, baseline, foreign = graph
    candidate = _make_candidate(conn, baseline)
    malformed = candidate_reference(conn, candidate["candidate_id"], foreign)
    before = snapshot(conn)
    error = _run_err(conn, promote_candidate(PromoteCandidateRequest(REALM, malformed, "evaluation://unused", 0)))
    assert error.code == ErrorCode.FAILED_PRECONDITION
    assert snapshot(conn) == before


@pytest.mark.parametrize("foreign_link", ["experiment", "candidate", "world", "baseline", "candidate_composition"])
def test_runner_refuses_retained_foreign_graph_before_actions_or_state_clones(graph, foreign_link):
    conn, baseline, foreign = graph
    candidate = _make_candidate(conn, baseline)["candidate_id"]
    world = _make_world(conn)
    realm = FOREIGN if foreign_link == "experiment" else REALM
    if foreign_link in ("candidate", "candidate_composition"):
        candidate = candidate_reference(conn, candidate, foreign,
            realm=FOREIGN if foreign_link == "candidate" else REALM)
    if foreign_link == "world":
        request = CreateWorldRequest(realm_id=FOREIGN, backend_profile_hash="audit",
            fixture_artifact_ids=(), state_snapshot_ids=(), environment_allowlist=(),
            workspace_quota={}, budget=TaskBudget(), seed=1, replay_level="FULL")
        result = execute_command(conn, make_command(FOREIGN), create_world(request), deadline=DEADLINE)
        assert not hasattr(result, "error")
        world = result.receipt["world_id"]
    experiment = "experiment://" + new_uuid7()
    conn.execute("INSERT INTO experiments(experiment_id,realm_id,candidate_id,baseline_id,world_id,criteria_artifact_id,budget_json,status,body_json,created_at_us) VALUES (?,?,?,?,?,?,?,'PENDING',?,1)",
        (experiment, realm, candidate, foreign if foreign_link == "baseline" else baseline,
            world, artifact_id("suite"), b"{}", b"{}"))
    conn.commit()
    before = snapshot(conn)
    error = _run_err(conn, start_experiment(experiment, PORTABLE_FEATURES))
    assert error.code == ErrorCode.NOT_FOUND
    assert snapshot(conn) == before
