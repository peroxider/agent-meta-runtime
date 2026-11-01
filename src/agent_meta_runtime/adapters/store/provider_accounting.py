"""Provider reservations live in the same SQLite transaction as Invocation.

Journal data is anchored by immutable Facts. No worker frame, credential,
response body, or native handle belongs in this accounting record. This is
internal Host accounting; EffectIntent dispatch/profile admission remain a
separate integration prerequisite.
"""

import json

from ...domain.canonical import canonical_json
from ...domain.errors import ErrorCode, StableError
from ...domain.fact_catalog import validate_fact_event
from ...domain.provider_accounting import ProviderReservation, amount, settlement
from ...ports.repositories import FactAppendRequest


def read_provider(conn, invocation_id, journal):
    """Validate the mutable projection against its immutable accounting Facts."""
    reserved = conn.execute("SELECT payload_json FROM facts WHERE entity_id=? AND event_type='provider_cost_reserved'", (invocation_id,)).fetchall()
    settled = conn.execute("SELECT payload_json FROM facts WHERE entity_id=? AND event_type='provider_cost_settled'", (invocation_id,)).fetchall()
    dispatched = conn.execute("SELECT payload_json FROM facts WHERE entity_id=? AND event_type='provider_dispatch_authorized'", (invocation_id,)).fetchall()
    if type(journal) is not dict:
        raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="Provider Invocation journal is invalid")
    provider = journal.get("provider")
    if provider is None and not reserved and not settled and not dispatched:
        return None
    try:
        if type(provider) is not dict or set(provider) != {"reservation", "settlement"}:
            raise ValueError("invalid accounting fields")
        document = provider["reservation"]
        value = ProviderReservation(**{key: value for key, value in document.items() if key != "schema"})
        if value.document() != document or len(reserved) != 1 or json.loads(reserved[0][0]) != document:
            raise ValueError("reservation Fact mismatch")
        dispatch = journal.get("provider_dispatch")
        if dispatch is None:
            if dispatched:
                raise ValueError("dispatch Fact without projection")
        elif (not isinstance(dispatch, dict) or dispatch.get("schema") != "provider-dispatch/v1"
                or dispatch.get("request_id") != journal["request_id"]
                or dispatch.get("request_scope_hash") != document["request_hash"]
                or len(dispatched) != 1 or json.loads(dispatched[0][0]) != dispatch):
            raise ValueError("dispatch Fact mismatch")
        terminal = provider["settlement"]
        if terminal is None:
            if settled:
                raise ValueError("settlement Fact without projection")
        else:
            if (settlement(document, terminal["outcome"], terminal["usage"]) != terminal
                    or len(settled) != 1 or json.loads(settled[0][0]) != terminal):
                raise ValueError("settlement Fact mismatch")
            row = conn.execute("SELECT usage_json FROM invocations WHERE invocation_id=?", (invocation_id,)).fetchone()
            if row is None or json.loads(row[0]) != terminal["usage"]:
                raise ValueError("usage projection mismatch")
    except (AttributeError, KeyError, TypeError, ValueError, StableError) as exc:
        raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="Provider accounting projection differs from its Facts") from exc
    return provider


def cost_liability(conn, task_id):
    total = 0
    for invocation_id, raw, raw_usage in conn.execute("SELECT i.invocation_id,i.backend_ref_json,i.usage_json FROM invocations i JOIN actions a ON a.action_id=i.action_id WHERE a.task_id=? AND i.kind='MODEL'", (task_id,)):
        provider = read_provider(conn, invocation_id, json.loads(raw or b"{}"))
        if provider is None:
            cost = json.loads(raw_usage).get("cost_microunits")
            if not amount(cost):
                raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="prior model cost is unknown without a reservation")
            total += cost
        else:
            terminal = provider["settlement"]
            if terminal and (terminal["outcome"] == "UNKNOWN" or terminal["overrun"]):
                raise StableError(code=ErrorCode.EXTERNAL_EFFECT_UNKNOWN if terminal["outcome"] == "UNKNOWN" else ErrorCode.RESOURCE_EXHAUSTED,
                    message="prior Provider outcome or usage prevents further calls")
            total += terminal["liability_microunits"] if terminal else provider["reservation"]["maximum_cost_microunits"]
    return total


def update_cost_totals(txn, task_id):
    task = txn._conn.execute("SELECT root_action_id,consumed_budget_json FROM tasks WHERE task_id=?", (task_id,)).fetchone()
    costs = []
    for invocation_id, raw, raw_usage in txn._conn.execute("SELECT i.invocation_id,i.backend_ref_json,i.usage_json FROM invocations i JOIN actions a ON a.action_id=i.action_id WHERE a.task_id=? AND i.kind='MODEL'", (task_id,)):
        provider = read_provider(txn._conn, invocation_id, json.loads(raw or b"{}"))
        terminal = provider["settlement"] if provider else None
        cost = json.loads(raw_usage).get("cost_microunits")
        # Partial reported cost is not a confirmed total for an UNKNOWN call.
        costs.append(None if provider and (terminal is None or terminal["outcome"] == "UNKNOWN") else cost)
    consumed = json.loads(task[1])
    consumed["cost_microunits"] = None if any(cost is None for cost in costs) else sum(costs)
    txn._conn.execute("UPDATE tasks SET consumed_budget_json=? WHERE task_id=?", (canonical_json(consumed), task_id))
    txn._conn.execute("UPDATE actions SET consumed_budget_json=? WHERE action_id=?", (canonical_json(consumed), task[0]))


def accounting_fact(txn, invocation_id, event, payload):
    validate_fact_event("invocation", event, 1, payload)
    action_id, actor_id = txn._conn.execute("SELECT i.action_id,a.actor_id FROM invocations i JOIN actions a ON a.action_id=i.action_id WHERE i.invocation_id=?", (invocation_id,)).fetchone()
    txn.append_fact(FactAppendRequest(entity_type="invocation", entity_id=invocation_id, event_type=event,
        schema_version=1, payload=payload, actor_id=actor_id, action_id=action_id, occurred_at_us=txn.recorded_at_us))


def settle(txn, invocation_id, *, outcome, usage, output_artifact_id, error):
    row = txn._conn.execute("SELECT backend_ref_json,status,output_artifact_id,error_json,usage_json FROM invocations WHERE invocation_id=?", (invocation_id,)).fetchone()
    if row is None:
        raise StableError(code=ErrorCode.NOT_FOUND, message="Provider Invocation is unavailable")
    journal = json.loads(row[0] or b"{}")
    provider = read_provider(txn._conn, invocation_id, journal)
    if provider is None:
        if outcome is not None:
            raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="Provider accounting requires a durable reservation")
        return usage, False
    outcome = outcome or "UNKNOWN"
    if ((output_artifact_id is None) == (error is None)
            or outcome == "UNKNOWN" and error != ErrorCode.EXTERNAL_EFFECT_UNKNOWN
            or outcome == "NOT_SENT" and output_artifact_id is not None):
        raise StableError(code=ErrorCode.INVALID_RESULT, message="Provider outcome contradicts Invocation terminal")
    terminal = settlement(provider["reservation"], outcome, usage)
    if row[1] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELLED"):
        if provider["settlement"] != terminal or row[2] != output_artifact_id or (json.loads(row[3]) if row[3] else None) != error or json.loads(row[4]) != terminal["usage"]:
            raise StableError(code=ErrorCode.IDEMPOTENCY_CONFLICT, message="Provider terminal replay differs")
        return terminal["usage"], True
    if provider["settlement"] is not None:
        raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="Provider settlement precedes terminal")
    provider["settlement"] = terminal
    txn._conn.execute("UPDATE invocations SET backend_ref_json=? WHERE invocation_id=?", (canonical_json(journal), invocation_id))
    accounting_fact(txn, invocation_id, "provider_cost_settled", terminal)
    return terminal["usage"], False
