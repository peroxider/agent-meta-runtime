"""Bounded, read-only Context source capture in the Task admission snapshot."""

import json

from ...domain.authority import authorize
from ...domain.canonical import canonical_json
from ...domain.errors import ErrorCode, StableError
from .authority import _GRANT_COLUMNS, _grant_from_row


def _can_reflect(conn, realm_id, actor_id, epoch_id, now_us, pending_use):
    for row in conn.execute(f"SELECT {_GRANT_COLUMNS} FROM authority_grants WHERE subject_id=?", (actor_id,)):
        grant = _grant_from_row(row)
        uses = conn.execute("SELECT COUNT(*) FROM authority_uses WHERE grant_id=?", (grant.grant_id,)).fetchone()[0]
        if pending_use is not None and pending_use[0] == grant.grant_id and not conn.execute("SELECT 1 FROM authority_uses WHERE grant_id=? AND action_id=? AND use_kind='command'", pending_use).fetchone():
            uses += 1
        if authorize(grant, subject_id=actor_id, permission="runtime.reflect", resource_realm=realm_id,
            resource_target=None, epoch_id=epoch_id, now_us=now_us, uses_count=uses) is None:
            return True
    return False


def capture_context_sources(conn, *, realm_id, actor_id, epoch_id, composition_id, serving_revision,
                            states, now_us, causal_parent_action_id=None, pending_use=None):
    epoch = conn.execute("SELECT constitution_artifact_id FROM epochs WHERE epoch_id=? AND realm_id=?", (epoch_id, realm_id)).fetchone()
    if epoch is None or not epoch[0]:
        raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="Context constitution is unavailable")
    boundary = conn.execute("SELECT next_seq-1 FROM realms WHERE realm_id=?", (realm_id,)).fetchone()[0]
    allowed = _can_reflect(conn, realm_id, actor_id, epoch_id, now_us, pending_use)
    seeds = {composition_id, *states, *states.values()}
    if causal_parent_action_id is not None:
        parent = conn.execute("SELECT a.actor_id FROM actions a JOIN compositions c ON c.composition_id=a.composition_id WHERE a.action_id=? AND c.realm_id=?", (causal_parent_action_id, realm_id)).fetchone()
        if parent is None or parent[0] != actor_id and not allowed:
            raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="Task causal parent is outside the caller's Context scope")
        seeds.add(causal_parent_action_id)
    facts = []
    if allowed:
        if len(seeds) > 512:
            raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="Context roots exceed their source ceiling")
        distances = {entity: 0 for entity in seeds}
        frontier = set(seeds)
        for depth in range(4):
            following = set()
            for entity in sorted(frontier):
                rows = conn.execute("SELECT e.from_id,e.to_id FROM causal_edges e JOIN facts f ON f.fact_id=e.source_fact_id WHERE e.realm_id=? AND f.seq<=? AND (e.from_id=? OR e.to_id=?) LIMIT 513", (realm_id, boundary, entity, entity)).fetchall()
                if len(rows) > 512:
                    raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="Context causal graph exceeds its source ceiling")
                for left, right in rows:
                    other = right if left == entity else left
                    if other not in distances:
                        distances[other] = depth + 1
                        following.add(other)
            if len(distances) > 512:
                raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="Context causal graph exceeds its source ceiling")
            frontier = following
            if not frontier:
                break
        source_bytes = 0
        for entity, distance in sorted(distances.items()):
            rows = conn.execute("SELECT fact_id,seq,event_type,payload_json FROM facts WHERE realm_id=? AND entity_id=? AND seq<=? ORDER BY seq DESC LIMIT 513", (realm_id, entity, boundary))
            for fact_id, seq, event_type, payload in rows:
                source_bytes += len(payload)
                if source_bytes > 4 * 1024 * 1024:
                    raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="Context Fact bytes exceed their source ceiling")
                facts.append({"schema": "context-fact/v1", "fact_id": fact_id, "seq": seq, "causal_distance": distance,
                    "entity_id": entity, "event_type": event_type, "payload": json.loads(payload)})
            if len(facts) > 512:
                raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="Context Facts exceed their source ceiling")
        facts.sort(key=lambda fact: (fact["causal_distance"], -fact["seq"], fact["fact_id"]))
    result = {"schema": "context-source-snapshot/v1", "constitution_artifact_id": epoch[0], "fact_boundary_seq": boundary,
        "facts_available": allowed, "facts": facts, "runtime": {"schema": "context-runtime-summary/v1",
            "serving_revision": serving_revision, "composition_id": composition_id, "state_bindings": dict(sorted(states.items()))}}
    if len(canonical_json(result)) > 4 * 1024 * 1024:
        raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="Context source bytes exceed their ceiling")
    return result
