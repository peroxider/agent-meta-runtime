"""Shared A–H program: async suspension, CAS supersession and cancellation.

These Runtime service tests inject external transports; they do not establish
an installed package/Backend/Task Host consumer proof.
"""

from agent_meta_runtime.adapters.store.reconciliation import SqliteReconcilePersistence
import asyncio
import json

import pytest

from agent_meta_runtime.application.probes import ProbeRunner
from agent_meta_runtime.application.reconciler import Reconciler
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.probe import HealthProbeDescriptor
from agent_meta_runtime.domain.ids import new_uuid7
from test_reconciler import _seed_desired, _refs


def test_async_round_yields_without_open_transactions_and_serializes_owner(store):
    conn, realm, _ = store
    _seed_desired(conn)
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        calls = []
        async def instantiate(request):
            assert not conn.in_transaction
            calls.append(("instantiate", request["slot"]))
            await asyncio.sleep(0)
            return {"instance_id": "instance://" + new_uuid7()}
        async def probe(request):
            assert not conn.in_transaction
            calls.append(("probe", request["slot"]))
            entered.set()
            await release.wait()
            return {"status": "READY", "reason_code": "OK"}
        async def drain(request):
            assert not conn.in_transaction
            calls.append(("drain", request["new_serving_revision"]))
            await asyncio.sleep(0)
        reconciler = Reconciler(conn, persistence=SqliteReconcilePersistence(), realm_id=realm, slot_executor=instantiate,
            drain_executor=drain, probe_runner=ProbeRunner(transport=probe))
        round_task = asyncio.create_task(reconciler.run_reconcile_async())
        await asyncio.wait_for(entered.wait(), 1)
        assert not conn.in_transaction and _refs(conn)[1] == 0
        with pytest.raises(StableError) as concurrent:
            reconciler.run_reconcile()
        assert concurrent.value.code == ErrorCode.ALREADY_RUNNING
        release.set()
        outcome = await asyncio.wait_for(round_task, 2)
        assert outcome.status == "CONVERGED"
        assert _refs(conn) == (1, 1, 1, "READY")
        assert calls == [("instantiate", "model"), ("probe", "model"),
                         ("instantiate", "cache"), ("probe", "cache"), ("drain", 1)]
    asyncio.run(scenario())


@pytest.mark.parametrize("phase", ["instantiate", "drain"])
def test_superseded_async_round_cannot_cut_over_or_close_new_cycle(store, phase):
    conn, realm, _ = store
    _seed_desired(conn)
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        async def pause():
            entered.set()
            await release.wait()
        async def instantiate(request):
            if phase == "instantiate":
                await pause()
            return {"instance_id": "instance://" + new_uuid7()}
        async def drain(request):
            if phase == "drain":
                await pause()
        reconciler = Reconciler(conn, persistence=SqliteReconcilePersistence(), realm_id=realm, slot_executor=instantiate,
            drain_executor=drain,
            probe_runner=ProbeRunner(transport=lambda request: {"status": "READY", "reason_code": "OK"}))
        round_task = asyncio.create_task(reconciler.run_reconcile_async())
        await asyncio.wait_for(entered.wait(), 1)
        _seed_desired(conn, revision=2)
        release.set()
        outcome = await asyncio.wait_for(round_task, 2)
        assert outcome.status == "SUPERSEDED"
        expected_serving = 0 if phase == "instantiate" else 1
        assert _refs(conn) == (2, expected_serving, 0, "PENDING")
        assert not conn.in_transaction
    asyncio.run(scenario())


def test_cancellation_leaves_resumable_applying_state_without_false_terminal(store):
    conn, realm, _ = store
    _seed_desired(conn)
    async def scenario():
        entered = asyncio.Event()
        async def instantiate(request):
            entered.set()
            await asyncio.Event().wait()
        reconciler = Reconciler(conn, persistence=SqliteReconcilePersistence(), realm_id=realm, slot_executor=instantiate,
            probe_runner=ProbeRunner(transport=lambda request: {"status": "READY", "reason_code": "OK"}))
        round_task = asyncio.create_task(reconciler.run_reconcile_async())
        await asyncio.wait_for(entered.wait(), 1)
        round_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await round_task
        assert not conn.in_transaction
        assert _refs(conn) == (1, 0, 0, "APPLYING")
    asyncio.run(scenario())


def test_async_probe_retry_and_late_ready_are_fail_closed():
    async def scenario():
        calls, sleeps = [], []
        async def probe(request):
            calls.append(request["request_id"])
            if len(calls) < 3:
                raise TimeoutError("not retained")
            return {"status": "READY", "reason_code": "OK"}
        report = await ProbeRunner(transport=probe, async_sleep=sleeps.append).run_async(
            HealthProbeDescriptor("probe.model", max_attempts=3), slot="model", criticality="REQUIRED", reconcile_id="cycle")
        assert report.passed and sleeps == [1, 2] and len(set(calls)) == 1
        async def late(request):
            try:
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                return {"status": "READY", "reason_code": "OK"}
        late_report = await ProbeRunner(transport=late).run_async(
            HealthProbeDescriptor("probe.model", timeout_ms=1), slot="model", criticality="REQUIRED", reconcile_id="late")
        assert not late_report.passed
        assert late_report.result.reason_code == "PROBE_TIMEOUT"
    asyncio.run(scenario())


def test_external_error_text_never_enters_reconcile_facts(store):
    conn, realm, _ = store
    _seed_desired(conn)
    async def broken(request):
        raise RuntimeError("provider-secret-canary-DO-NOT-RETAIN")
    result = asyncio.run(Reconciler(conn, persistence=SqliteReconcilePersistence(), realm_id=realm, slot_executor=broken,
        probe_runner=ProbeRunner(transport=lambda request: {"status": "READY", "reason_code": "OK"})).run_reconcile_async())
    assert result.status == "FAILED"
    persisted = " ".join(str(json.loads(row[0])) for row in conn.execute("SELECT payload_json FROM facts"))
    assert "provider-secret-canary" not in persisted


def test_zero_revision_drain_cannot_mark_new_activation_ready(store):
    from agent_meta_runtime.adapters.store.composition import (
        CompositionCreateRequest, SetDesiredRequest, _cas_update, create_composition, set_desired,
    )
    from conftest import ACTOR, run_command
    from test_reconciler import _body
    conn, realm, _ = store
    _seed_desired(conn)
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        async def instantiate(request):
            return {"instance_id": "instance://" + new_uuid7()}
        async def drain(request):
            if request["new_serving_revision"] == 0:
                entered.set()
                await release.wait()
        reconciler = Reconciler(conn, persistence=SqliteReconcilePersistence(), realm_id=realm, slot_executor=instantiate, drain_executor=drain,
            probe_runner=ProbeRunner(transport=lambda request: {"status": "READY", "reason_code": "OK"}))
        assert (await reconciler.run_reconcile_async()).status == "CONVERGED"
        def deactivate(txn):
            _cas_update(txn, column="desired_revision", cas_column="desired_cas", revision=0,
                        expected_cas=1, new_status="PENDING")
            return {}
        run_command(conn, deactivate)
        draining = asyncio.create_task(reconciler.run_reconcile_async())
        await asyncio.wait_for(entered.wait(), 1)
        run_command(conn, create_composition(CompositionCreateRequest(realm_id=realm, body=_body("v2"), created_by=ACTOR, revision=2)))
        run_command(conn, set_desired(SetDesiredRequest(realm_id=realm, revision=2, expected_cas=2)))
        release.set()
        assert (await draining).status == "SUPERSEDED"
        assert _refs(conn) == (2, 0, 1, "PENDING")
    asyncio.run(scenario())
