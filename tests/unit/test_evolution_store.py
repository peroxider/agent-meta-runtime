"""Step 08.2 gate: Evolution store use cases (§41.43)."""

from __future__ import annotations

import pytest

from agent_meta_runtime.adapters.store import execute_command
from agent_meta_runtime.adapters.store.evolution import (
    ArchiveCandidateRequest,
    CreateChangeSetRequest,
    CreateExperimentRequest,
    CreateWorldRequest,
    RecordEvaluationRequest,
    RecordEvidenceRequest,
    RegisterCandidateRequest,
    SubmitProposalRequest,
    archive_candidate,
    create_change_set,
    create_experiment,
    create_world,
    get_evolution_object,
    list_evolution_objects,
    record_evaluation,
    record_evidence,
    register_candidate,
    submit_proposal,
)
from agent_meta_runtime.domain.canonical import canonical_json, sha256_hex
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.ids import new_uuid7
from agent_meta_runtime.domain.semantics import TaskBudget
from conftest import ACTOR, DEADLINE, _seed_artifact, artifact_id, make_command

REALM = "realm://main"


def _run(conn, mutator):
    result = execute_command(
        conn,
        make_command(REALM),
        mutator,
        deadline=DEADLINE,
    )
    assert not hasattr(result, "error"), result.error
    return dict(result.receipt)


def _run_err(conn, mutator) -> StableError:
    """Errors raised inside a mutator surface as RejectedResult.error."""
    result = execute_command(conn, make_command(REALM), mutator, deadline=DEADLINE)
    assert hasattr(result, "error"), result
    return result.error


def _seed_action(conn, action_id: str, composition: str) -> None:
    conn.execute(
        "INSERT INTO actions(action_id, task_id, actor_id, intent, composition_id,"
        " grant_id, causal_parent_action_id, status, budget_json,"
        " consumed_budget_json, created_at_us)"
        " VALUES (?, NULL, ?, 'test', ?, NULL, NULL, 'SUCCEEDED', ?, ?, 1)",
        (action_id, ACTOR, composition, b"{}", b"{}"),
    )


def _seed_baseline(conn) -> str:
    """The semantic_env composition body is {}; seed a real composition/v1."""

    next_revision = int(
        conn.execute(
            "SELECT COALESCE(MAX(revision), 0) + 1 FROM compositions WHERE realm_id = ?",
            (REALM,),
        ).fetchone()[0]
    )
    composition_id = "composition://" + new_uuid7()
    body = canonical_json(
        {
            "schema": "composition/v1",
            "realm_id": REALM,
            "slots": {"echo": {"capability": "capability://echo"}},
        }
    )
    conn.execute(
        "INSERT INTO compositions(composition_id, realm_id, revision, parent_id,"
        " body_json, body_hash, created_by, created_at_us)"
        " VALUES (?, ?, ?, NULL, ?, ?, ?, 1)",
        (composition_id, REALM, next_revision, body, sha256_hex(body), ACTOR),
    )
    conn.commit()
    return composition_id


def _baseline_chain(conn, composition: str):
    """Submit proposal + change set against the seeded baseline composition."""
    proposal = _run(
        conn,
        submit_proposal(
            SubmitProposalRequest(
                realm_id=REALM,
                hypothesis="swap echo artifact",
                source_evidence_ids=(),
                target_composition_id=composition,
            )
        ),
    )
    change_set = _run(
        conn,
        create_change_set(
            CreateChangeSetRequest(
                realm_id=REALM,
                proposal_id=proposal["proposal_id"],
                baseline_id=composition,
                operations=(
                    {
                        "operation": "ADD_SLOT",
                        "target_path": "slots.extra",
                        "expected_old_value_hash": None,
                        "new_value": {"capability": "capability://extra"},
                    },
                ),
                expected_serving_revision=1,
            )
        ),
    )
    return proposal["proposal_id"], change_set["change_set_id"]


def test_proposal_and_change_set_persist_with_facts(semantic_env):
    conn, realm, composition, _input, _surface = semantic_env
    baseline = _seed_baseline(conn)
    proposal_id, change_set_id = _baseline_chain(conn, baseline)
    proposal = get_evolution_object(conn, proposal_id)
    assert proposal["object_type"] == "PROPOSAL"
    assert proposal["body"]["target_composition_id"] == baseline
    change_set = get_evolution_object(conn, change_set_id)
    assert change_set["object_type"] == "CHANGE_SET"
    assert change_set["parent_id"] == proposal_id
    assert change_set["body"]["operations"][0]["target_path"] == "slots.extra"
    facts = conn.execute(
        "SELECT event_type FROM facts WHERE entity_id = ?", (proposal_id,)
    ).fetchall()
    assert [f[0] for f in facts] == ["proposal_created"]


def test_create_change_set_rejects_malformed_operations(semantic_env):
    conn, realm, composition, _input, _surface = semantic_env
    proposal = _run(
        conn,
        submit_proposal(
            SubmitProposalRequest(
                realm_id=REALM,
                hypothesis="h",
                source_evidence_ids=(),
                target_composition_id=composition,
            )
        ),
    )
    with pytest.raises(StableError) as excinfo:
        _run(
            conn,
            create_change_set(
                CreateChangeSetRequest(
                    realm_id=REALM,
                    proposal_id=proposal["proposal_id"],
                    baseline_id=composition,
                    operations=(
                        {"operation": "SET_POLICY", "target_path": "policy.a",
                         "expected_old_value_hash": None, "new_value": 1},
                        {"operation": "SET_POLICY", "target_path": "policy.a",
                         "expected_old_value_hash": None, "new_value": 2},
                    ),
                    expected_serving_revision=1,
                )
            ),
        )
    assert excinfo.value.code == ErrorCode.INVALID_ARGUMENT


def test_register_candidate_clones_new_composition_and_keeps_baseline(semantic_env):
    conn, realm, composition, _input, _surface = semantic_env
    baseline = _seed_baseline(conn)
    baseline_body = bytes(
        conn.execute(
            "SELECT body_json FROM compositions WHERE composition_id = ?",
            (baseline,),
        ).fetchone()[0]
    )
    _proposal_id, change_set_id = _baseline_chain(conn, baseline)
    receipt = _run(
        conn,
        register_candidate(
            RegisterCandidateRequest(
                realm_id=REALM,
                change_set_id=change_set_id,
                trust_class="trusted_candidate",
                artifact_ids=(artifact_id("cand"),),
            )
        ),
    )
    # fixture composition is revision 1, seeded baseline revision 2
    assert receipt["revision"] == 3
    candidate_body = bytes(
        conn.execute(
            "SELECT body_json FROM compositions WHERE composition_id = ?",
            (receipt["composition_id"],),
        ).fetchone()[0]
    )
    assert b"extra" in candidate_body
    # baseline row is byte-identical (ChangeSet never modifies it)
    assert bytes(
        conn.execute(
            "SELECT body_json FROM compositions WHERE composition_id = ?",
            (baseline,),
        ).fetchone()[0]
    ) == baseline_body
    candidate = get_evolution_object(conn, receipt["candidate_id"])
    assert candidate["status"] == "ACTIVE"
    assert candidate["body"]["composition_id"] == receipt["composition_id"]
    facts = conn.execute(
        "SELECT event_type FROM facts WHERE entity_id = ?",
        (receipt["candidate_id"],),
    ).fetchall()
    assert [f[0] for f in facts] == ["candidate_created"]


def test_register_candidate_refuses_unknown_trust_class(semantic_env):
    conn, realm, composition, _input, _surface = semantic_env
    _proposal_id, change_set_id = _baseline_chain(conn, _seed_baseline(conn))
    with pytest.raises(StableError) as excinfo:
        _run(
            conn,
            register_candidate(
                RegisterCandidateRequest(
                    realm_id=REALM,
                    change_set_id=change_set_id,
                    trust_class="root_kit",
                    artifact_ids=(),
                )
            ),
        )
    assert excinfo.value.code == ErrorCode.INVALID_ARGUMENT


def test_world_is_frozen_v1_with_deny_network(semantic_env):
    conn, realm, composition, _input, _surface = semantic_env
    receipt = _run(
        conn,
        create_world(
            CreateWorldRequest(
                realm_id=REALM,
                backend_profile_hash="bph",
                fixture_artifact_ids=(artifact_id("fixture"),),
                state_snapshot_ids=(),
                environment_allowlist=("python3",),
                workspace_quota={"max_bytes": 1000},
                budget=TaskBudget(max_turns=2, max_steps=4, max_model_calls=2),
                seed=7,
                replay_level="FULL",
            )
        ),
    )
    worlds = conn.execute(
        "SELECT body_json FROM worlds WHERE world_id = ?", (receipt["world_id"],)
    ).fetchall()
    assert len(worlds) == 1
    body = worlds[0][0]
    assert b'"network_policy":"DENY"' in body or b'"DENY"' in body
    assert b'"credential_handles":[]' in body or b'"credential_handles": []' in body


def test_experiment_requires_candidate_world_and_criteria(semantic_env):
    conn, realm, composition, _input, _surface = semantic_env
    _proposal_id, change_set_id = _baseline_chain(conn, _seed_baseline(conn))
    candidate = _run(
        conn,
        register_candidate(
            RegisterCandidateRequest(
                realm_id=REALM,
                change_set_id=change_set_id,
                trust_class="trusted_candidate",
                artifact_ids=(),
            )
        ),
    )
    world = _run(
        conn,
        create_world(
            CreateWorldRequest(
                realm_id=REALM,
                backend_profile_hash="bph",
                fixture_artifact_ids=(),
                state_snapshot_ids=(),
                environment_allowlist=(),
                workspace_quota={},
                budget=TaskBudget(),
                seed=1,
                replay_level="FULL",
            )
        ),
    )
    criteria_art = artifact_id("criteria")
    _seed_artifact(conn, criteria_art)
    conn.commit()
    experiment = _run(
        conn,
        create_experiment(
            CreateExperimentRequest(
                realm_id=REALM,
                candidate_id=candidate["candidate_id"],
                baseline_id=composition,
                world_id=world["world_id"],
                criteria_artifact_id=criteria_art,
                budget=TaskBudget(),
            )
        ),
    )
    row = conn.execute(
        "SELECT status FROM experiments WHERE experiment_id = ?",
        (experiment["experiment_id"],),
    ).fetchone()
    assert row[0] == "PENDING"
    error = _run_err(
        conn,
        create_experiment(
            CreateExperimentRequest(
                realm_id=REALM,
                candidate_id="candidate://ghost",
                baseline_id=composition,
                world_id=world["world_id"],
                criteria_artifact_id=criteria_art,
                budget=TaskBudget(),
            )
        ),
    )
    assert error.code == ErrorCode.NOT_FOUND


def test_evidence_is_append_only_and_validated(semantic_env):
    conn, realm, composition, _input, _surface = semantic_env
    action_id = "action://" + "evidence-producer"
    _seed_action(conn, action_id, composition)
    evidence_art = artifact_id("evidence")
    _seed_artifact(conn, evidence_art)
    conn.commit()
    receipt = _run(
        conn,
        record_evidence(
            RecordEvidenceRequest(
                realm_id=REALM,
                experiment_id=None,
                producer_action_id=action_id,
                kind="test_run",
                subject_id=composition,
                artifact_id=evidence_art,
                metadata={"pass_rate_ppm": 1000000},
            )
        ),
    )
    with pytest.raises(Exception) as excinfo:
        conn.execute(
            "UPDATE evidence SET kind = 'tampered' WHERE evidence_id = ?",
            (receipt["evidence_id"],),
        )
        conn.commit()
    assert "EVIDENCE_IMMUTABLE" in str(excinfo.value)
    error = _run_err(
        conn,
        record_evidence(
            RecordEvidenceRequest(
                realm_id=REALM,
                experiment_id=None,
                producer_action_id="action://ghost",
                kind="test_run",
                subject_id=composition,
                artifact_id=evidence_art,
                metadata={},
            )
        ),
    )
    assert error.code == ErrorCode.NOT_FOUND


def test_evaluation_stores_failed_as_reject_and_emits_candidate_rejected(
    semantic_env,
):
    conn, realm, composition, _input, _surface = semantic_env
    _proposal_id, change_set_id = _baseline_chain(conn, _seed_baseline(conn))
    candidate = _run(
        conn,
        register_candidate(
            RegisterCandidateRequest(
                realm_id=REALM,
                change_set_id=change_set_id,
                trust_class="trusted_candidate",
                artifact_ids=(),
            )
        ),
    )
    world = _run(
        conn,
        create_world(
            CreateWorldRequest(
                realm_id=REALM,
                backend_profile_hash="bph",
                fixture_artifact_ids=(),
                state_snapshot_ids=(),
                environment_allowlist=(),
                workspace_quota={},
                budget=TaskBudget(),
                seed=1,
                replay_level="FULL",
            )
        ),
    )
    criteria_art = artifact_id("criteria")
    evaluator_art = artifact_id("evaluator")
    result_art = artifact_id("result")
    evidence_art = artifact_id("evidence")
    for art in (criteria_art, evaluator_art, result_art, evidence_art):
        _seed_artifact(conn, art)
    _seed_action(conn, "action://" + "eval-producer", composition)
    conn.commit()
    experiment = _run(
        conn,
        create_experiment(
            CreateExperimentRequest(
                realm_id=REALM,
                candidate_id=candidate["candidate_id"],
                baseline_id=composition,
                world_id=world["world_id"],
                criteria_artifact_id=criteria_art,
                budget=TaskBudget(),
            )
        ),
    )
    evidence = _run(
        conn,
        record_evidence(
            RecordEvidenceRequest(
                realm_id=REALM,
                experiment_id=experiment["experiment_id"],
                producer_action_id="action://" + "eval-producer",
                kind="test_run",
                subject_id=composition,
                artifact_id=evidence_art,
                metadata={},
            )
        ),
    )
    receipt = _run(
        conn,
        record_evaluation(
            RecordEvaluationRequest(
                realm_id=REALM,
                experiment_id=experiment["experiment_id"],
                evaluator_artifact_id=evaluator_art,
                evidence_ids=(evidence["evidence_id"],),
                assertion_results=({"kind": "artifact_integrity", "status": "PASS"},),
                decision="FAILED",
                result_artifact_id=result_art,
            )
        ),
    )
    assert receipt["decision"] == "REJECT"  # FAILED never stored as ACCEPT
    row = conn.execute(
        "SELECT decision FROM evaluations WHERE evaluation_id = ?",
        (receipt["evaluation_id"],),
    ).fetchone()
    assert row[0] == "REJECT"
    candidate_facts = conn.execute(
        "SELECT event_type FROM facts WHERE entity_id = ?",
        (candidate["candidate_id"],),
    ).fetchall()
    assert "candidate_rejected" in [f[0] for f in candidate_facts]
    error = _run_err(
        conn,
        record_evaluation(
            RecordEvaluationRequest(
                realm_id=REALM,
                experiment_id=experiment["experiment_id"],
                evaluator_artifact_id=evaluator_art,
                evidence_ids=("evidence://ghost",),
                assertion_results=(),
                decision="ACCEPT",
                result_artifact_id=result_art,
            )
        ),
    )
    assert error.code == ErrorCode.NOT_FOUND


def test_archive_candidate_is_a_status_change(semantic_env):
    conn, realm, composition, _input, _surface = semantic_env
    _proposal_id, change_set_id = _baseline_chain(conn, _seed_baseline(conn))
    candidate = _run(
        conn,
        register_candidate(
            RegisterCandidateRequest(
                realm_id=REALM,
                change_set_id=change_set_id,
                trust_class="untrusted_candidate",
                artifact_ids=(),
            )
        ),
    )
    first = _run(
        conn, archive_candidate(ArchiveCandidateRequest(realm_id=REALM,
                                                        candidate_id=candidate["candidate_id"]))
    )
    assert first["status"] == "ARCHIVED"
    again = _run(
        conn, archive_candidate(ArchiveCandidateRequest(realm_id=REALM,
                                                        candidate_id=candidate["candidate_id"]))
    )
    assert again["status"] == "ARCHIVED"  # idempotent
    row = conn.execute(
        "SELECT status FROM evolution_objects WHERE object_id = ?",
        (candidate["candidate_id"],),
    ).fetchone()
    assert row[0] == "ARCHIVED"
    # nothing was deleted
    assert list_evolution_objects(conn, REALM, "CANDIDATE")
