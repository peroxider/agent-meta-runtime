"""Read-only bounded Task history, never a projection of raw Fact payloads."""

import json

from ...domain.canonical import canonical_json
from ...domain.errors import ErrorCode, StableError


def _limit(message):
    raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message=message)


def _read_trace(conn, *, realm_id, task_id):
    task = conn.execute("SELECT root_action_id,status FROM tasks WHERE task_id=? AND realm_id=?", (task_id, realm_id)).fetchone()
    if task is None:
        raise StableError(code=ErrorCode.NOT_FOUND, message="unknown Task in this realm")
    revision, boundary = conn.execute("SELECT current_meta_revision,next_seq-1 FROM realms WHERE realm_id=?", (realm_id,)).fetchone()
    action_sizes = conn.execute("SELECT length(CAST(action_id AS BLOB))+length(CAST(actor_id AS BLOB))+"
        "length(CAST(intent AS BLOB))+length(CAST(composition_id AS BLOB))+coalesce(length(CAST(grant_id AS BLOB)),0)+"
        "coalesce(length(CAST(causal_parent_action_id AS BLOB)),0)+length(CAST(status AS BLOB))+"
        "length(CAST(budget_json AS BLOB))+length(CAST(consumed_budget_json AS BLOB))+coalesce(length(CAST(error_json AS BLOB)),0) "
        "FROM actions WHERE task_id=? LIMIT 1001", (task_id,)).fetchall()
    if len(action_sizes) > 1000:
        _limit("Task trace exceeds its Action ceiling")
    if sum(row[0] for row in action_sizes) > 4 * 1024 * 1024:
        _limit("Task trace exceeds its Action byte ceiling")
    actions = conn.execute("SELECT action_id,actor_id,intent,composition_id,grant_id,causal_parent_action_id,status,"
        "budget_json,consumed_budget_json,created_at_us,started_at_us,completed_at_us,error_json "
        "FROM actions WHERE task_id=? ORDER BY created_at_us,action_id LIMIT 1001", (task_id,)).fetchall()
    if len(actions) > 1000:
        _limit("Task trace exceeds its Action ceiling")
    predicate = "f.realm_id=? AND f.seq<=? AND (f.entity_id=? OR f.action_id IN (SELECT action_id FROM actions WHERE task_id=?))"
    params = (realm_id, boundary, task_id, task_id)
    facts = conn.execute("SELECT f.fact_id,f.seq,f.entity_type,f.entity_id,f.event_type,f.schema_version,"
        "f.action_id,f.recorded_at_us,length(CAST(f.payload_json AS BLOB)) FROM facts f WHERE " + predicate + " ORDER BY f.seq LIMIT 4001", params).fetchall()
    if len(facts) > 4000:
        _limit("Task trace exceeds its Fact ceiling")
    if sum(row[8] for row in facts) > 8 * 1024 * 1024:
        _limit("Task trace exceeds its source Fact byte ceiling")
    payloads = conn.execute("SELECT f.payload_json FROM facts f WHERE " + predicate + " ORDER BY f.seq LIMIT 4000", params).fetchall()
    edges = conn.execute("SELECT e.edge_type,e.from_id,e.to_id,e.source_fact_id FROM causal_edges e "
        "JOIN facts f ON f.fact_id=e.source_fact_id WHERE e.realm_id=? AND " + predicate +
        " ORDER BY f.seq,e.edge_type,e.from_id,e.to_id LIMIT 4097", (realm_id, *params)).fetchall()
    if len(edges) > 4096:
        _limit("Task trace exceeds its edge ceiling")
    action_keys = ("action_id", "actor_id", "intent", "composition_id", "grant_id", "causal_parent_action_id", "status",
        "budget", "consumed_budget", "created_at_us", "started_at_us", "completed_at_us", "error")
    action_values = []
    for row in actions:
        value = dict(zip(action_keys, row))
        for field in ("budget", "consumed_budget", "error"):
            value[field] = json.loads(value[field]) if value[field] is not None else None
        action_values.append(value)
    event_keys = ("fact_id", "seq", "entity_type", "entity_id", "event_type", "schema_version", "action_id", "recorded_at_us")
    events = []
    for row, payload_row in zip(facts, payloads):
        value = dict(zip(event_keys, row[:8]))
        payload = json.loads(payload_row[0])
        if not isinstance(payload, dict):
            raise ValueError("Fact payload must be an object")
        for field in ("old_status", "new_status", "reason_code"):
            item = payload.get(field)
            if item is not None and not isinstance(item, str):
                raise ValueError("Fact status metadata must be a string")
            value[field] = item
        events.append(value)
    value = {"resource_type": "task-trace/v1", "schema_version": 1, "task_id": task_id, "realm_id": realm_id,
        "root_action_id": task[0], "status": task[1], "snapshot_revision": revision, "fact_boundary_seq": boundary,
        "actions": action_values, "events": events,
        "edges": [dict(zip(("edge_type", "from_id", "to_id", "source_fact_id"), row)) for row in edges]}
    encoded = canonical_json(value)
    if len(encoded) > 4 * 1024 * 1024:
        _limit("Task trace exceeds its response byte ceiling")
    return encoded


def task_trace(conn, *, realm_id, task_id):
    owns_snapshot = not conn.in_transaction
    if owns_snapshot:
        conn.execute("BEGIN")
    try:
        return _read_trace(conn, realm_id=realm_id, task_id=task_id)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="Task trace metadata is invalid") from exc
    finally:
        if owns_snapshot:
            conn.rollback()
