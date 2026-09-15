"""Step 02 gate: Fact catalog registry and why/lineage traversal (§41.35)."""

from __future__ import annotations

import pytest

from agent_meta_runtime.adapters.store import SqliteEdgeSource
from agent_meta_runtime.domain.causal_query import lineage, why
from agent_meta_runtime.domain.errors import StableError
from agent_meta_runtime.domain.fact_catalog import (
    CAUSAL_EDGE_TYPES,
    WHY_EDGE_TYPES,
    validate_causal_edge,
    validate_fact_event,
)
from conftest import ACTOR, artifact_id, run_command


def test_event_registry_validation():
    validate_fact_event("task", "task_accepted", 1, {"k": "v"})
    with pytest.raises(StableError):
        validate_fact_event("nonexistent", "x", 1, {})
    with pytest.raises(StableError):
        validate_fact_event("task", "not_an_event", 1, {})
    with pytest.raises(StableError):
        validate_fact_event("task", "task_accepted", 2, {})
    # Transition events require reason_code + old/new status.
    with pytest.raises(StableError):
        validate_fact_event("task", "task_started", 1, {})
    validate_fact_event(
        "task",
        "task_started",
        1,
        {"reason_code": "r", "old_status": "ACCEPTED", "new_status": "RUNNING"},
    )
    # Non-transition reason-code events require only reason_code.
    with pytest.raises(StableError):
        validate_fact_event("task", "task_cancel_requested", 1, {})
    validate_fact_event("task", "task_cancel_requested", 1, {"reason_code": "r"})


def test_edge_direction_registry():
    assert len(CAUSAL_EDGE_TYPES) == 10
    assert "produced" not in WHY_EDGE_TYPES
    validate_causal_edge("produced", "invocation://x", "artifact://sha256/" + "a" * 64)
    with pytest.raises(StableError):
        validate_causal_edge("produced", "artifact://sha256/" + "a" * 64, "invocation://x")
    with pytest.raises(StableError):
        validate_causal_edge("nonexistent_edge", "action://x", "task://y")


def test_why_walks_reverse_to_causes(semantic_env):
    conn, realm, composition, input_artifact, surface_artifact = semantic_env
    from agent_meta_runtime.adapters.store import (
        InvocationCreateRequest,
        InvocationFinishRequest,
        TaskAcceptRequest,
        TaskTerminalRequest,
        accept_task,
        advance_invocation,
        complete_task,
        create_invocation,
        finish_invocation,
        start_task,
    )
    from agent_meta_runtime.domain.semantics import InvocationStatus, TaskBudget, TaskStatus

    output = artifact_id("output")
    receipt = run_command(
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
    task_id, root = receipt["task_id"], receipt["root_action_id"]
    run_command(conn, start_task(task_id))
    run_command(
        conn,
        complete_task(
            task_id,
            TaskTerminalRequest(status=TaskStatus.SUCCEEDED, result_artifact_id=output),
        ),
    )
    inv = run_command(
        conn,
        create_invocation(
            InvocationCreateRequest(
                invocation_id=None,
                action_id=root,
                kind="model",
                target="model://primary",
                input_artifact_id=input_artifact,
            )
        ),
    )["invocation_id"]
    run_command(conn, advance_invocation(inv, InvocationStatus.DISPATCHED))
    run_command(conn, advance_invocation(inv, InvocationStatus.RUNNING))
    run_command(
        conn,
        finish_invocation(
            InvocationFinishRequest(invocation_id=inv, output_artifact_id=output)
        ),
    )
    source = SqliteEdgeSource(conn)
    explanation = why(source, realm, task_id)
    # Reverse walk from the task: root action (part_of) and its causes.
    assert root in explanation.nodes
    assert all(e[3] for e in explanation.edges), "every edge cites source_fact_id"
    assert explanation.direction == "why"
    lineage_exp = lineage(source, realm, inv)
    edge_targets = {e[2] for e in lineage_exp.edges}
    assert output in edge_targets
    assert lineage_exp.direction == "lineage"


def _append_marker_fact(conn):
    """Create one real fact on the realm chain via a command transaction."""
    from agent_meta_runtime.ports.repositories import FactAppendRequest
    from conftest import execute_command_result

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

    return run_command(conn, mutator)["fact_id"]


def test_projection_completeness_follows_checkpoint(semantic_env):
    conn, realm, *_ = semantic_env
    _append_marker_fact(conn)
    source = SqliteEdgeSource(conn)
    explanation = why(source, realm, "realm://main")
    if explanation.current_fact_seq > explanation.projection_seq:
        assert not explanation.complete
    conn.execute(
        "INSERT OR REPLACE INTO checkpoints(realm_id, projection, seq, updated_at_us)"
        " VALUES (?, 'causal_edges', (SELECT MAX(seq) FROM facts WHERE realm_id = ?), 1)",
        (realm, realm),
    )
    conn.commit()
    assert why(source, realm, "realm://main").complete


def _chain_store(semantic_env):
    """Insert a derived_from chain of artifacts over one real fact."""
    conn, realm, *_ = semantic_env
    fact_id = _append_marker_fact(conn)
    arts = ["artifact://sha256/" + format(i, "064x") for i in range(1, 6)]
    for a, b in zip(arts, arts[1:]):
        conn.execute(
            "INSERT INTO causal_edges(realm_id, from_id, edge_type, to_id,"
            " source_fact_id) VALUES (?, ?, 'derived_from', ?, ?)",
            (realm, b, a, fact_id),
        )
    conn.commit()
    return conn, realm, arts


def test_truncation_and_cursor_resume(semantic_env):
    conn, realm, arts = _chain_store(semantic_env)
    source = SqliteEdgeSource(conn)
    # One edge costs len(from)+len(type)+len(to)+len(fact)+4 bytes; a tiny
    # byte budget must truncate with a resumable cursor.
    cost = len(arts[1]) + len("derived_from") + len(arts[0]) + 44 + 4
    first = lineage(
        source, realm, arts[-1], max_depth=8, max_nodes=500, max_bytes=cost + 1
    )
    assert first.truncated
    assert first.continuation_cursor is not None
    # Exactly one edge fit; its deeper endpoint is un-processed in the cursor.
    assert len(first.edges) == 1
    assert first.edges[0][2] == arts[-2]
    resumed = lineage(
        source,
        realm,
        arts[-1],
        max_depth=8,
        max_nodes=500,
        max_bytes=1 << 20,
        cursor=first.continuation_cursor,
    )
    assert not resumed.truncated
    assert arts[-3] in resumed.nodes and arts[0] in resumed.nodes
    # The full walk reaches the chain head in one call.
    full = lineage(source, realm, arts[-1])
    assert not full.truncated
    assert full.nodes[0] == arts[-1]
    assert arts[0] in full.nodes


def test_unknown_realm_rejected(semantic_env):
    conn, *_ = semantic_env
    source = SqliteEdgeSource(conn)
    from agent_meta_runtime.domain.ids import new_uuid7

    with pytest.raises(StableError):
        why(source, "realm://missing", "task://" + new_uuid7())
