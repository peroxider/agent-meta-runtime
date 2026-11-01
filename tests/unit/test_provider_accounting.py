"""Real SQLite Host admission/settlement, synthetic price/tokenizer evidence.

These fixtures do not claim live profile validation, EffectIntent dispatch or
public Provider integration. Authorization and transaction rollback are real.
"""

from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from agent_meta_runtime.adapters.cas import FilesystemCas
from agent_meta_runtime.adapters.store import CreateGrantRequest, create_grant, load_task
from agent_meta_runtime.adapters.store.connection import connect_store
from agent_meta_runtime.adapters.store.host_execution import HostExecutionStore
from agent_meta_runtime.adapters.store.provider_accounting import cost_liability
from agent_meta_runtime.domain.authority import GrantConstraints, Scope, ScopeTarget
from agent_meta_runtime.domain.canonical import canonical_json, sha256_hex
from agent_meta_runtime.domain.deadline import Deadline
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.provider_accounting import ProviderReservation
from agent_meta_runtime.domain.semantics import TaskBudget
from agent_meta_runtime.ports.repositories import FactAppendRequest

from conftest import ACTOR, artifact_id, make_command
from test_authority import _bootstrap
from test_semantic_tasks import _accept

SERVICE = "principal://service/provider-accounting-fixture"
CAPABILITY = "capability://fixture.model"
OPERATION = {"operation_id": "fixture.model", "effects": ["model.invoke"], "required_permissions": ["model.invoke", "state.read"]}


def command(conn, mutator):
    from agent_meta_runtime.adapters.store import execute_command
    result = execute_command(conn, make_command("realm://main"), mutator, deadline=Deadline.after(5_000_000))
    if hasattr(result, "error"):
        raise result.error
    return dict(result.receipt)


def reservation(cost=60):
    return ProviderReservation(artifact_id("synthetic-profile"), artifact_id("synthetic-pricing"),
        artifact_id("synthetic-exact-tokenizer"), sha256_hex(b"synthetic-wire-request"), 10, 20, cost)


@pytest.fixture
def accounting(semantic_env, tmp_path, request):
    conn, realm, composition, input_ref, surface_ref = semantic_env
    root = _bootstrap(conn)
    conn.execute("INSERT INTO principals VALUES (?,?, 'SERVICE',?, 'ACTIVE',1)", (SERVICE, realm, b"{}"))
    conn.commit()
    constraints = GrantConstraints(**getattr(request, "param", {"max_uses": 10}))
    grant = command(conn, create_grant(CreateGrantRequest(root, SERVICE,
        frozenset({"model.invoke", "state.read"}), Scope(realm, [ScopeTarget("CAPABILITY", CAPABILITY)]),
        constraints=constraints)))["grant_id"]
    def activate(txn):
        txn.append_fact(FactAppendRequest(entity_type="harness", entity_id="harness://fixture",
            event_type="harness_activated", schema_version=1, payload={"phase": "requested", "composition_id": composition,
            "grant_ids": [grant]}, actor_id=ACTOR, occurred_at_us=txn.recorded_at_us))
        return {}
    command(conn, activate)
    budget = getattr(request.node, "callspec", SimpleNamespace(params={})).params.get("budget", 100)
    accepted = _accept(conn, realm, composition, input_ref, surface_ref, budget=TaskBudget(max_cost_microunits=budget))
    task = SimpleNamespace(**{name: getattr(load_task(conn, accepted["task_id"]), name)
        for name in ("task_id", "root_action_id", "actor_id", "serving_composition_id")}, loop_policy_content=b"{}")
    def host(connection=conn):
        return HostExecutionStore(connection, catalog=SimpleNamespace(cas=FilesystemCas(tmp_path)),
            run_command=lambda fn: command(connection, fn), realm_id=realm, service_id=SERVICE)
    return conn, task, host, tmp_path


def admit(host, task, ordinal=0, provider=None):
    return host.reserve(task, ordinal=ordinal, kind="MODEL", capability_id=CAPABILITY,
        operation=OPERATION, content=canonical_json({"request": ordinal}), provider=provider)


def journal(conn, invocation):
    return json.loads(conn.execute("SELECT backend_ref_json FROM invocations WHERE invocation_id=?", (invocation,)).fetchone()[0])["provider"]


def test_reservation_grant_uses_and_unknown_cost_commit_together(accounting):
    conn, task, factory, _ = accounting
    before = conn.execute("SELECT COUNT(*) FROM authority_uses").fetchone()[0]
    first = admit(factory(), task, provider=reservation())
    # Two permissions covered by each grant consume one use, not two.
    assert conn.execute("SELECT COUNT(*) FROM authority_uses").fetchone()[0] == before + 2
    assert journal(conn, first["invocation_id"]) == {"reservation": reservation().document(), "settlement": None}
    assert cost_liability(conn, task.task_id) == 60
    assert json.loads(conn.execute("SELECT consumed_budget_json FROM tasks WHERE task_id=?", (task.task_id,)).fetchone()[0])["cost_microunits"] is None
    fact = conn.execute("SELECT payload_json,transaction_id FROM facts WHERE entity_id=? AND event_type='provider_cost_reserved'", (first["invocation_id"],)).fetchone()
    assert json.loads(fact[0]) == reservation().document()
    assert conn.execute("SELECT DISTINCT transaction_id FROM facts WHERE entity_id=?", (first["invocation_id"],)).fetchall() == [(fact[1],)]


def test_budget_denial_rolls_back_every_reservation(accounting):
    conn, task, factory, _ = accounting
    host = factory()
    admit(host, task, provider=reservation())
    before = tuple(conn.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] for table in ("authority_uses", "invocations", "facts"))
    with pytest.raises(StableError, match="Task budget") as caught:
        admit(host, task, 1, reservation())
    assert caught.value.code == ErrorCode.RESOURCE_EXHAUSTED
    assert tuple(conn.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] for table in ("authority_uses", "invocations", "facts")) == before
    assert cost_liability(conn, task.task_id) == 60


def test_confirmed_cost_releases_only_unused_hold_and_terminal_replays(accounting):
    conn, task, factory, _ = accounting
    host = factory()
    invocation = admit(host, task, provider=reservation())["invocation_id"]
    kwargs = dict(content=b'{"normalized":true}', usage=dict(input_tokens=10, output_tokens=5, cost_microunits=25), provider_outcome="CONFIRMED")
    host.finish_invocation(invocation, **kwargs)
    assert cost_liability(conn, task.task_id) == 25
    facts = conn.execute("SELECT COUNT(*) FROM facts WHERE entity_id=?", (invocation,)).fetchone()[0]
    host.finish_invocation(invocation, **kwargs)
    assert conn.execute("SELECT COUNT(*) FROM facts WHERE entity_id=?", (invocation,)).fetchone()[0] == facts
    replay = admit(host, task, provider=reservation())
    assert replay["replay"] and replay["invocation_id"] == invocation
    admit(host, task, 1, reservation(75))
    assert cost_liability(conn, task.task_id) == 100
    with pytest.raises(StableError) as caught:
        host.finish_invocation(invocation, **{**kwargs, "usage": dict(input_tokens=10, output_tokens=5, cost_microunits=0)})
    assert caught.value.code == ErrorCode.IDEMPOTENCY_CONFLICT
    assert journal(conn, invocation)["settlement"]["usage"]["cost_microunits"] == 25


def test_actual_database_reopen_preserves_hold_and_prohibits_resend(accounting):
    conn, task, factory, root = accounting
    invocation = admit(factory(), task, provider=reservation())["invocation_id"]
    # Fresh SQLite connection and fresh Host, no Python request cache.
    reopened = connect_store(root / "meta.db")
    try:
        assert cost_liability(reopened, task.task_id) == 60
        with pytest.raises(StableError) as caught:
            admit(factory(reopened), task, provider=reservation())
        assert caught.value.code == ErrorCode.EXTERNAL_EFFECT_UNKNOWN
        assert conn.execute("SELECT COUNT(*) FROM invocations").fetchone()[0] == 1
        factory(reopened).finish_task(task.task_id, "FAILED_RECOVERY", error=ErrorCode.EXTERNAL_EFFECT_UNKNOWN)
        assert journal(reopened, invocation)["settlement"]["outcome"] == "UNKNOWN"
        assert journal(reopened, invocation)["settlement"]["liability_microunits"] == 60
        assert json.loads(reopened.execute("SELECT usage_json FROM invocations WHERE invocation_id=?", (invocation,)).fetchone()[0])["cost_microunits"] is None
    finally:
        reopened.close()


@pytest.mark.parametrize("outcome,usage,expected", [
    ("NOT_SENT", None, 0), ("CONFIRMED", None, 60),
    ("CONFIRMED", {"cost_microunits": 0}, 0), ("CONFIRMED", {"cost_microunits": 100}, 100),
    ("UNKNOWN", {"cost_microunits": 5}, 60), ("UNKNOWN", {"cost_microunits": 100}, 100)])
def test_settlement_conservatively_preserves_uncertain_cost(accounting, outcome, usage, expected):
    conn, task, factory, _ = accounting
    host = factory()
    invocation = admit(host, task, provider=reservation())["invocation_id"]
    host.finish_invocation(invocation, error=ErrorCode.EXTERNAL_EFFECT_UNKNOWN if outcome == "UNKNOWN" else ErrorCode.INTERNAL,
        usage=usage, provider_outcome=outcome)
    terminal = journal(conn, invocation)["settlement"]
    assert terminal["liability_microunits"] == expected
    if outcome == "UNKNOWN":
        assert json.loads(conn.execute("SELECT consumed_budget_json FROM tasks WHERE task_id=?", (task.task_id,)).fetchone()[0])["cost_microunits"] is None
    if outcome == "UNKNOWN" or terminal["overrun"]:
        with pytest.raises(StableError):
            admit(host, task, 1, reservation(0))
    else:
        assert cost_liability(conn, task.task_id) == expected


@pytest.mark.parametrize("usage", [{"cost_microunits": True}, {"input_tokens": -1}, {"output_tokens": 1.5}, {"secret": "forbidden"}, False, [], "invalid"])
def test_invalid_usage_rolls_back_terminal(accounting, usage):
    conn, task, factory, _ = accounting
    host = factory()
    invocation = admit(host, task, provider=reservation())["invocation_id"]
    with pytest.raises(StableError) as caught:
        host.finish_invocation(invocation, content=b"{}", usage=usage, provider_outcome="CONFIRMED")
    assert caught.value.code == ErrorCode.INVALID_RESULT
    assert journal(conn, invocation)["settlement"] is None
    assert conn.execute("SELECT status,usage_json FROM invocations WHERE invocation_id=?", (invocation,)).fetchone() == ("RUNNING", b"{}")


def test_changed_profile_and_missing_prior_cost_fail_closed(accounting):
    conn, task, factory, _ = accounting
    host = factory()
    invocation = admit(host, task, provider=reservation())["invocation_id"]
    host.finish_invocation(invocation, error=ErrorCode.INTERNAL, provider_outcome="NOT_SENT")
    with pytest.raises(StableError) as caught:
        admit(host, task, provider=replace(reservation(), pricing_artifact_id=artifact_id("changed-price")))
    assert caught.value.code == ErrorCode.IDEMPOTENCY_CONFLICT
    # An older unreserved model with unknown cost cannot become free budget.
    old = admit(host, task, 1)["invocation_id"]
    host.finish_invocation(old, error=ErrorCode.INTERNAL)
    with pytest.raises(StableError) as caught:
        admit(host, task, 2, reservation())
    assert caught.value.code == ErrorCode.FAILED_PRECONDITION


def test_failed_commit_leaves_neither_use_nor_reservation(accounting):
    conn, task, factory, _ = accounting
    host = factory()
    before = tuple(conn.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] for table in ("authority_uses", "invocations", "facts"))
    def failing(fn):
        def mutate(txn):
            fn(txn)
            raise StableError(code=ErrorCode.INTERNAL, message="injected commit failure")
        return command(conn, mutate)
    host.run_command = failing
    with pytest.raises(StableError, match="injected"):
        admit(host, task, provider=reservation())
    assert tuple(conn.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] for table in ("authority_uses", "invocations", "facts")) == before
    assert cost_liability(conn, task.task_id) == 0
    host = factory()
    invocation = admit(host, task, provider=reservation())["invocation_id"]
    host.run_command = failing
    kwargs = dict(content=b"{}", usage={"cost_microunits": 25}, provider_outcome="CONFIRMED")
    with pytest.raises(StableError, match="injected"):
        host.finish_invocation(invocation, **kwargs)
    assert journal(conn, invocation)["settlement"] is None
    assert cost_liability(conn, task.task_id) == 60
    factory().finish_invocation(invocation, **kwargs)
    assert cost_liability(conn, task.task_id) == 25


@pytest.mark.parametrize("tamper", ["remove", "reservation", "settlement", "usage"])
def test_mutable_journal_cannot_release_fact_anchored_hold(accounting, tamper):
    conn, task, factory, _ = accounting
    host = factory()
    invocation = admit(host, task, provider=reservation())["invocation_id"]
    raw = json.loads(conn.execute("SELECT backend_ref_json FROM invocations WHERE invocation_id=?", (invocation,)).fetchone()[0])
    if tamper == "remove":
        del raw["provider"]
    elif tamper == "reservation":
        raw["provider"]["reservation"]["maximum_cost_microunits"] = 0
    else:
        host.finish_invocation(invocation, content=b"{}", usage={"cost_microunits": 50}, provider_outcome="CONFIRMED")
        raw = json.loads(conn.execute("SELECT backend_ref_json FROM invocations WHERE invocation_id=?", (invocation,)).fetchone()[0])
        if tamper == "settlement":
            raw["provider"]["settlement"]["liability_microunits"] = 0
        else:
            conn.execute("UPDATE invocations SET usage_json=? WHERE invocation_id=?", (canonical_json({"cost_microunits": 0}), invocation))
    conn.execute("UPDATE invocations SET backend_ref_json=? WHERE invocation_id=?", (canonical_json(raw), invocation))
    conn.commit()
    with pytest.raises(StableError) as caught:
        admit(host, task, 1, reservation())
    assert caught.value.code == ErrorCode.INTEGRITY_ERROR


@pytest.mark.parametrize("accounting", [{"max_uses": 1}, {"resource_ceiling": {"cost_microunits": 100}}], indirect=True)
def test_grant_constraints_are_not_ignored(accounting, request):
    conn, task, factory, _ = accounting
    host = factory()
    if "max_uses" in request.node.callspec.params["accounting"]:
        invocation = admit(host, task, provider=reservation())["invocation_id"]
        host.finish_invocation(invocation, error=ErrorCode.INTERNAL, provider_outcome="NOT_SENT")
        ordinal = 1
    else:
        ordinal = 0
    with pytest.raises(StableError) as caught:
        admit(host, task, ordinal, reservation())
    assert caught.value.code == ErrorCode.AUTHORITY_DENIED


@pytest.mark.parametrize("usage", [{"input_tokens": 11, "cost_microunits": 0}, {"output_tokens": 21, "cost_microunits": 0}])
def test_token_overrun_is_preserved_and_stops_future_calls(accounting, usage):
    conn, task, factory, _ = accounting
    host = factory()
    invocation = admit(host, task, provider=reservation())["invocation_id"]
    host.finish_invocation(invocation, content=b"{}", usage=usage, provider_outcome="CONFIRMED")
    assert journal(conn, invocation)["settlement"]["overrun"]
    with pytest.raises(StableError) as caught:
        admit(host, task, 1, reservation(0))
    assert caught.value.code == ErrorCode.RESOURCE_EXHAUSTED
    with pytest.raises(StableError) as caught:
        admit(host, task, provider=reservation())
    assert caught.value.code == ErrorCode.RESOURCE_EXHAUSTED


@pytest.mark.parametrize("budget,policy", [(0, {}), (100, {"max_cost_microunits": 59})])
def test_task_and_loop_cost_ceilings_are_both_enforced(accounting, budget, policy):
    conn, task, factory, _ = accounting
    task.loop_policy_content = canonical_json(policy)
    with pytest.raises(StableError) as caught:
        admit(factory(), task, provider=reservation())
    assert caught.value.code == ErrorCode.RESOURCE_EXHAUSTED


def test_unclassified_failure_keeps_unknown_and_cannot_downgrade_to_fake(accounting):
    conn, task, factory, _ = accounting
    host = factory()
    invocation = admit(host, task, provider=reservation())["invocation_id"]
    host.finish_invocation(invocation, error=ErrorCode.INTERNAL)
    terminal = journal(conn, invocation)["settlement"]
    assert terminal["outcome"] == "UNKNOWN" and terminal["liability_microunits"] == 60
    assert json.loads(conn.execute("SELECT error_json FROM invocations WHERE invocation_id=?", (invocation,)).fetchone()[0]) == ErrorCode.EXTERNAL_EFFECT_UNKNOWN
    with pytest.raises(StableError) as caught:
        admit(host, task, 1)
    assert caught.value.code == ErrorCode.EXTERNAL_EFFECT_UNKNOWN


@pytest.mark.parametrize("kwargs", [
    {"content": b"{}", "provider_outcome": "NOT_SENT"},
    {"content": b"{}", "provider_outcome": "UNKNOWN"},
    {"error": ErrorCode.INTERNAL, "provider_outcome": "UNKNOWN"},
    {"error": ErrorCode.INTERNAL, "provider_outcome": "NOT_SENT", "usage": {"cost_microunits": 1}},
    {"provider_outcome": "CONFIRMED"}])
def test_contradictory_outcome_does_not_release_a_reservation(accounting, kwargs):
    conn, task, factory, _ = accounting
    host = factory()
    invocation = admit(host, task, provider=reservation())["invocation_id"]
    with pytest.raises(StableError) as caught:
        host.finish_invocation(invocation, **kwargs)
    assert caught.value.code == ErrorCode.INVALID_RESULT
    assert cost_liability(conn, task.task_id) == 60
    assert journal(conn, invocation)["settlement"] is None


def test_unreserved_invocation_cannot_be_relabelled_as_provider(accounting):
    conn, task, factory, _ = accounting
    host = factory()
    invocation = admit(host, task)["invocation_id"]
    with pytest.raises(StableError) as caught:
        host.finish_invocation(invocation, content=b"{}", provider_outcome="CONFIRMED", usage={"cost_microunits": 0})
    assert caught.value.code == ErrorCode.FAILED_PRECONDITION
    assert conn.execute("SELECT COUNT(*) FROM facts WHERE event_type LIKE 'provider_cost_%'").fetchone()[0] == 0
