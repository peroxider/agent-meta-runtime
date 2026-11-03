"""Step 02 gate: revision-consistent RuntimeView (§41.44.2, FR-MVIEW-001)."""

from __future__ import annotations

import pytest

from agent_meta_runtime.adapters.store import (
    TaskAcceptRequest,
    TaskTerminalRequest,
    accept_task,
    complete_task,
    get_current_view,
    get_historical_view,
    load_task,
    start_task,
    StateCreateRequest,
    create_state,
)
from agent_meta_runtime.domain.errors import StableError
from agent_meta_runtime.domain.semantics import TaskBudget, TaskStatus
from conftest import ACTOR, artifact_id, execute_command_result, run_command


def _marker_fact_mutator():
    from agent_meta_runtime.ports.repositories import FactAppendRequest

    def mutator(txn):
        fact_id = txn.append_fact(
            FactAppendRequest(
                entity_type="runtime",
                entity_id="realm://main",
                event_type="runtime_initialized",
                schema_version=1,
                payload={},
                occurred_at_us=1,
                actor_id=ACTOR,
            )
        )
        return {"fact_id": fact_id}

    return mutator


def _accept(conn, composition, input_artifact, surface_artifact):
    return run_command(
        conn,
        accept_task(
            TaskAcceptRequest(
                task_id=None,
                actor_id=ACTOR,
                input_artifact_id=input_artifact,
                serving_composition_id=composition,
                serving_revision=1,
                capability_surface_revision=1,
                capability_surface_artifact_id=surface_artifact,
                budget=TaskBudget(),
            )
        ),
    )


def test_empty_realm_view(semantic_env):
    conn, realm, composition, input_artifact, surface_artifact = semantic_env
    view = get_current_view(conn, realm)
    assert view.realm_id == realm
    assert view.meta_revision == 0
    assert view.fact_boundary_seq == 0
    assert view.capability_surface_revision == 1
    assert view.capability_surface_artifact_id == surface_artifact
    assert view.serving_ready is False
    assert view.serving_reasons == ("RECONCILE_UNKNOWN",)
    assert view.historical is False
    assert view.state_revision_bindings == {}


def test_view_reflects_committed_revision(semantic_env):
    conn, realm, composition, input_artifact, surface_artifact = semantic_env
    _accept(conn, composition, input_artifact, surface_artifact)
    view = get_current_view(conn, realm)
    assert view.meta_revision == 1
    assert view.fact_boundary_seq > 0
    assert view.capability_surface_revision == 1
    assert view.capability_surface_artifact_id == surface_artifact
    assert view.backend_profile_hash == "bph"
    assert view.authority_summary == {}

    # Historical view at the same revision is consistent and frozen.
    historical = get_historical_view(conn, realm, view.meta_revision)
    assert historical.meta_revision == view.meta_revision
    assert historical.fact_boundary_seq == view.fact_boundary_seq
    assert historical.historical is True
    assert historical.capability_surface_artifact_id == surface_artifact


def test_historical_view_never_approximates(semantic_env):
    conn, realm, *_ = semantic_env
    with pytest.raises(StableError) as excinfo:
        get_historical_view(conn, realm, 42)
    assert excinfo.value.code == "NOT_FOUND"


def test_historical_state_bindings_bound_by_revision(semantic_env):
    conn, realm, composition, input_artifact, surface_artifact = semantic_env
    # Revision 1 has no State. Revision 2 creates a real State birth Fact and
    # its history boundary, rather than borrowing an unrelated Task Fact.
    result = execute_command_result(conn, _marker_fact_mutator())
    assert result.meta_revision == 1
    created = execute_command_result(conn, create_state(StateCreateRequest(
        owner_id=ACTOR, schema_id='schema://x', artifact_id=input_artifact, state_id='state://s1')))
    assert created.meta_revision == 2
    expected = {'state://s1': created.receipt['state_revision_id']}
    current = get_current_view(conn, realm)
    assert current.state_revision_bindings == expected
    historical = get_historical_view(conn, realm, 2)
    assert historical.state_revision_bindings == expected
    # Revision 1 predates the binding: it must not leak forward.
    earlier = get_historical_view(conn, realm, 1)
    assert earlier.state_revision_bindings == {}


def test_view_after_terminal_task(semantic_env):
    conn, realm, composition, input_artifact, surface_artifact = semantic_env
    receipt = _accept(conn, composition, input_artifact, surface_artifact)
    task_id = receipt["task_id"]
    run_command(conn, start_task(task_id))
    run_command(
        conn,
        complete_task(
            task_id,
            TaskTerminalRequest(
                status=TaskStatus.SUCCEEDED, result_artifact_id=artifact_id("output")
            ),
        ),
    )
    record = load_task(conn, task_id)
    assert record.status == TaskStatus.SUCCEEDED
    view = get_current_view(conn, realm)
    assert view.meta_revision >= 3
    historical = get_historical_view(conn, realm, 1)
    assert historical.meta_revision == 1
