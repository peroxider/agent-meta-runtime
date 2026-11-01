"""Bounded read-only operator projection of durable Task execution records."""

import json

from ...domain.canonical import canonical_json
from ...domain.errors import ErrorCode, StableError


def task_execution(conn, *, realm_id, task_id):
    row = conn.execute("SELECT root_action_id,status,input_artifact_id,serving_composition_id,serving_revision,"
        "capability_surface_artifact_id,state_snapshot_json,budget_json,consumed_budget_json,accepted_at_us,started_at_us,"
        "deadline_at_us,completed_at_us,result_artifact_id,error_json FROM tasks WHERE task_id=? AND realm_id=?",
        (task_id, realm_id)).fetchone()
    if row is None:
        raise StableError(code=ErrorCode.NOT_FOUND, message="unknown Task in this realm")
    keys = ("root_action_id", "status", "input_artifact_id", "serving_composition_id", "serving_revision",
        "capability_surface_artifact_id", "state_snapshot", "budget", "consumed_budget", "accepted_at_us", "started_at_us",
        "deadline_at_us", "completed_at_us", "result_artifact_id", "error")
    result = dict(zip(keys, row))
    for key in ("state_snapshot", "budget", "consumed_budget", "error"):
        result[key] = json.loads(result[key]) if result[key] is not None else None
    accepted = conn.execute("SELECT f.payload_json,f.seq,t.meta_revision FROM facts f LEFT JOIN transactions t ON t.transaction_id=f.transaction_id "
        "WHERE f.realm_id=? AND f.entity_id=? AND f.event_type='task_accepted' ORDER BY f.seq LIMIT 1",
        (realm_id, task_id)).fetchone()
    result["acceptance_view_artifact_id"] = json.loads(accepted[0]).get("acceptance_view_artifact_id") if accepted else None
    result["accepted_meta_revision"] = accepted[2] if accepted else None
    result["accepted_fact_seq"] = accepted[1] if accepted else None
    result["snapshot_revision"] = conn.execute("SELECT current_meta_revision FROM realms WHERE realm_id=?", (realm_id,)).fetchone()[0]
    invocations = conn.execute("SELECT i.invocation_id,i.action_id,i.kind,i.target,i.attempt,i.input_artifact_id,"
        "i.context_projection_id,i.status,i.started_at_us,i.completed_at_us,i.output_artifact_id,i.error_json,i.usage_json,i.latency_us,i.backend_ref_json "
        "FROM invocations i JOIN actions a ON a.action_id=i.action_id WHERE a.task_id=? "
        "ORDER BY i.started_at_us,i.invocation_id LIMIT 1001", (task_id,)).fetchall()
    projections = conn.execute("SELECT projection_id,action_id,manifest_json,rendered_artifact_id,created_at_us "
        "FROM context_projections WHERE task_id=? ORDER BY created_at_us,projection_id LIMIT 65", (task_id,)).fetchall()
    if len(invocations) > 1000 or len(projections) > 64:
        raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="Task execution inspection exceeds its record ceiling")
    invocation_keys = ("invocation_id", "action_id", "kind", "target", "attempt", "input_artifact_id", "context_projection_id",
        "status", "started_at_us", "completed_at_us", "output_artifact_id", "error", "usage", "latency_us")
    result["invocations"] = []
    for invocation in invocations:
        item = dict(zip(invocation_keys, invocation[:-1]))
        for key in ("error", "usage"):
            item[key] = json.loads(item[key]) if item[key] is not None else None
        journal = json.loads(invocation[-1]) if invocation[-1] else {}
        if journal.get("schema") == "host-invocation-journal/v1" and "backend" in journal:
            binding = journal["backend"]
            public_fields = ("backend_id", "request_id", "payload_hash", "handle_hash", "incarnation", "instance_id",
                "token_id", "token_payload_hash", "service_public_key_id", "certificate_artifact_id", "terminal_status",
                "result_hash", "result_artifact_id", "error_code", "ack_state")
            item["execution_binding"] = {key: binding[key] for key in public_fields if key in binding}
        result["invocations"].append(item)
    result["projections"] = [{"projection_id": p[0], "action_id": p[1], "manifest": json.loads(p[2]),
        "rendered_artifact_id": p[3], "created_at_us": p[4]} for p in projections]
    result.update(task_id=task_id, realm_id=realm_id, resource_type="task-execution/v1", schema_version=1)
    encoded = canonical_json(result)
    if len(encoded) > 1024 * 1024:
        raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="Task execution inspection exceeds its byte ceiling")
    return encoded
