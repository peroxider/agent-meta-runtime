"""Private Root assembly with real grants, SQLite, signatures and owned kernels.

This fixture does not pass public package/Host or Seed consumer gates.
"""

import asyncio
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from agent_meta_runtime.adapters.cas import FilesystemCas
from agent_meta_runtime.adapters.crypto import Ed25519KeyPair
from agent_meta_runtime.adapters.scratch_host import ScratchHostCalls
from agent_meta_runtime.adapters.scratch_worker import ScratchWorker
from agent_meta_runtime.adapters.store import (
    RootBootstrapRequest,
    bootstrap_root,
    CreateGrantRequest,
    create_grant,
    RevokeGrantRequest,
    revoke_grant,
    TaskAcceptRequest,
    accept_task,
    start_task,
    load_task,
    InvocationCreateRequest,
    create_invocation,
    advance_invocation,
)
from agent_meta_runtime.adapters.store import scratch_journal
from agent_meta_runtime.adapters.store.host_execution import HostExecutionStore
from agent_meta_runtime.adapters.store.service_certificates import (
    load_service_execution_trust,
)
from agent_meta_runtime.adapters.store.task_snapshot import register_staged_artifact
from agent_meta_runtime.domain.authority import Scope, ScopeTarget, GrantConstraints
from agent_meta_runtime.domain.canonical import canonical_json, now_us, sha256_hex
from agent_meta_runtime.domain.errors import StableError, ErrorCode
from agent_meta_runtime.domain.execution_tokens import issue_service_certificate
from agent_meta_runtime.domain.ids import new_uuid7
from agent_meta_runtime.domain.scratch_execution import ScratchExecution
from agent_meta_runtime.domain.semantics import TaskBudget
from agent_meta_runtime.ports.repositories import FactAppendRequest
from conftest import ACTOR, artifact_id, run_command as command, execute_command_result
from test_execution_tokens import SERVICE

CAP = "capability://fixture.scratch"
OPERATION = {
    "operation_id": "fixture.scratch.execute",
    "resource_contract": "scratch.execute/v1",
    "effects": ["external.irreversible"],
    "required_permissions": ["scratch.execute"],
    "idempotency": "KEYED",
    "retry_semantics": "NEVER",
    "input_schema_artifact_id": artifact_id("input"),
    "output_schema_artifact_id": artifact_id("output"),
}


@pytest.fixture()
def scratch_case(semantic_env, tmp_path, request):
    pytest.importorskip("ipykernel")
    source_text = getattr(request, "param", "print(6*7)")
    conn, realm, _, input_ref, _ = semantic_env
    root, service = Ed25519KeyPair.generate(), Ed25519KeyPair.generate()
    epoch = conn.execute("SELECT epoch_id FROM realms").fetchone()[0]
    root_grant = command(
        conn,
        bootstrap_root(
            RootBootstrapRequest(realm, epoch, ACTOR, root.public_bytes_raw(), "a" * 64)
        ),
    )["grant_id"]
    conn.execute(
        "INSERT INTO principals VALUES (?,?,'SERVICE',?,'ACTIVE',1)",
        (
            SERVICE,
            realm,
            canonical_json(
                {
                    "algorithm": "Ed25519",
                    "public_key_hex": service.public_bytes_raw().hex(),
                }
            ),
        ),
    )
    conn.commit()
    grant = command(
        conn,
        create_grant(
            CreateGrantRequest(
                root_grant,
                SERVICE,
                frozenset({"capability.invoke", "scratch.execute"}),
                Scope(
                    realm,
                    [
                        ScopeTarget("CAPABILITY", CAP),
                        ScopeTarget("ARTIFACT_KIND", "source"),
                    ],
                ),
                constraints=GrantConstraints(max_uses=1),
            )
        ),
    )["grant_id"]
    cas = FilesystemCas(tmp_path / "cas")

    def read(ref):
        size, manifest = conn.execute(
            "SELECT size_bytes,manifest_json FROM artifacts WHERE artifact_id=?", (ref,)
        ).fetchone()
        return cas.open_blob(
            json.loads(manifest)["storage_relpath"], ref.rsplit("/", 1)[1], size
        )

    def runtime_command(fn):
        result = execute_command_result(conn, fn)
        if hasattr(result, "error"):
            raise result.error
        return dict(result.receipt)

    store = HostExecutionStore(
        conn,
        catalog=SimpleNamespace(cas=cas, read_artifact=read),
        run_command=runtime_command,
        realm_id=realm,
        service_id=SERVICE,
    )
    source_stage = store.stage(source_text.encode("utf-8"))
    surface = {
        "operations": [
            {
                "operation_id": OPERATION["operation_id"],
                "resource_contract": "scratch.execute/v1",
                "effects": OPERATION["effects"],
                "required_permissions": OPERATION["required_permissions"],
                "idempotency": "KEYED",
                "input_schema_hash": input_ref.rsplit("/", 1)[1],
                "output_schema_hash": artifact_id("output").rsplit("/", 1)[1],
            }
        ]
    }
    surface_stage = store.stage(canonical_json(surface))
    certificate = issue_service_certificate(
        {
            "service_principal_id": SERVICE,
            "public_key": service.public_bytes_raw().hex(),
            "realm_id": realm,
            "epoch_id": epoch,
            "permissions": ["capability.invoke", "scratch.execute"],
            "not_after": now_us() + 86_400_000_000,
        },
        root_principal_id=ACTOR,
        signer=root.sign,
    )
    certificate_stage = store.stage(certificate)
    composition = "composition://" + new_uuid7()
    body = {
        "slots": {
            "scratch": {
                "capability_id": CAP,
                "descriptor_revision": 1,
                "artifact_id": source_stage["artifact_id"],
            }
        }
    }

    def initialize(txn):
        txn.execute(
            "INSERT INTO artifacts VALUES (?,'source','text/x-python',?,1,?,?,?,?,'VALID')",
            (
                source_stage["artifact_id"],
                len(source_stage["content"]),
                ACTOR,
                txn.recorded_at_us,
                b"[]",
                canonical_json(source_stage["manifest"]),
            ),
        )
        register_staged_artifact(txn, surface_stage, kind="capability_surface")
        register_staged_artifact(txn, certificate_stage, kind="authority_certificate")
        txn.execute(
            "INSERT INTO capabilities VALUES (?,1,?,?,?)",
            (
                CAP,
                source_stage["artifact_id"],
                canonical_json({"operations": [OPERATION]}),
                txn.recorded_at_us,
            ),
        )
        txn.execute(
            "INSERT INTO compositions VALUES (?,?,2,NULL,?,?,?,?)",
            (
                composition,
                realm,
                canonical_json(body),
                sha256_hex(canonical_json(body)),
                ACTOR,
                txn.recorded_at_us,
            ),
        )
        txn.execute(
            "INSERT INTO capability_surfaces VALUES (?,2,?,?,'scratch-afp','scratch-profile',?)",
            (realm, composition, surface_stage["artifact_id"], txn.recorded_at_us),
        )
        for entity, identity, event, payload in (
            (
                "runtime",
                realm,
                "runtime_initialized",
                {
                    "service_principal_id": SERVICE,
                    "service_certificate_artifact_id": certificate_stage["artifact_id"],
                },
            ),
            (
                "harness",
                "harness://fixture",
                "harness_activated",
                {
                    "phase": "requested",
                    "composition_id": composition,
                    "grant_ids": [grant],
                },
            ),
        ):
            txn.append_fact(
                FactAppendRequest(
                    entity_type=entity,
                    entity_id=identity,
                    event_type=event,
                    schema_version=1,
                    payload=payload,
                    actor_id=ACTOR,
                    occurred_at_us=txn.recorded_at_us,
                )
            )
        return {}

    command(conn, initialize)
    accepted = command(
        conn,
        accept_task(
            TaskAcceptRequest(
                None,
                ACTOR,
                input_ref,
                composition,
                2,
                TaskBudget(),
                deadline_at_us=now_us() + 60_000_000,
                capability_surface_revision=2,
                capability_surface_artifact_id=surface_stage["artifact_id"],
            )
        ),
    )
    accepted_revision = conn.execute(
        "SELECT current_meta_revision FROM realms"
    ).fetchone()[0]
    command(conn, start_task(accepted["task_id"]))
    record = load_task(conn, accepted["task_id"])
    task = SimpleNamespace(
        **{
            name: getattr(record, name)
            for name in (
                "task_id",
                "root_action_id",
                "realm_id",
                "actor_id",
                "serving_composition_id",
                "deadline_at_us",
            )
        },
        accepted_meta_revision=accepted_revision,
        acceptance_view_content=canonical_json({"epoch_id": epoch}),
        loop_policy_content=b"{}",
    )
    create_inv = command(
        conn,
        create_invocation(
            InvocationCreateRequest(
                None,
                task.root_action_id,
                "CAPABILITY",
                CAP + "#fixture.create",
                input_ref,
            )
        ),
    )["invocation_id"]
    command(conn, advance_invocation(create_inv, "DISPATCHED"))
    command(conn, advance_invocation(create_inv, "RUNNING"))
    workspace = "workspace://" + new_uuid7()

    def reserve_owner(txn):
        txn.execute(
            "INSERT INTO workspaces VALUES (?,?,?,'kernel',1048576,'ACTIVE',?,NULL,NULL)",
            (workspace, realm, task.root_action_id, txn.recorded_at_us),
        )
        return scratch_journal.reserve_session(
            create_inv, workspace_id=workspace, backend_request_id=create_inv
        )(txn)

    session = command(conn, reserve_owner)["session_id"]
    trust = load_service_execution_trust(conn, cas, realm_id=realm, now_us=now_us())
    calls = ScratchHostCalls(store, trust=trust, epoch_id=epoch, signer=service.sign)
    return SimpleNamespace(
        conn=conn,
        store=store,
        task=task,
        session=session,
        calls=calls,
        grant=grant,
        source=source_stage["artifact_id"],
        source_text=source_text,
        root=tmp_path,
    )


async def owned(case):
    worker = await ScratchWorker(
        workspace_root=case.root, workspace=case.root / "kernel"
    ).start()
    case.calls.bind_new_worker(case.session, worker)
    return worker


def reserve(case, *, deadline=None):
    request = ScratchExecution(
        case.session,
        case.source,
        (
            deadline
            if deadline is not None
            else min(case.task.deadline_at_us, now_us() + 30_000_000)
        ),
    )
    invocation = case.calls.reserve(
        case.task,
        ordinal=0,
        capability_id=CAP,
        operation=OPERATION,
        content=canonical_json({"source_artifact_id": case.source}),
        request=request,
    )["invocation_id"]
    return request, invocation


def observed(case, invocation):
    return [
        json.loads(row[0])
        for row in case.conn.execute(
            "SELECT payload_json FROM facts WHERE entity_id=? AND event_type='scratch_cell_observed'",
            (case.session,),
        )
        if json.loads(row[0])["invocation_id"] == invocation
    ]


def test_actual_kernel_requires_committed_certified_dispatch_and_grouped_uses(
    scratch_case,
):
    case = scratch_case

    async def run():
        worker = await owned(case)
        try:
            request, invocation = reserve(case)
            result = await case.calls.execute(
                task=case.task, invocation_id=invocation, request=request
            )
            assert result.stdout.strip() == "42" and worker.ordinal == 1
            uses = case.conn.execute(
                "SELECT amount_json FROM authority_uses WHERE grant_id=?", (case.grant,)
            ).fetchall()
            assert len(uses) == 1 and len(json.loads(uses[0][0])["claims"]) == 3
            assert observed(case, invocation)[0]["status"] == "SUCCEEDED"
            payload = case.conn.execute(
                "SELECT payload_json FROM facts WHERE entity_id=? AND event_type='scratch_dispatch_authorized'",
                (invocation,),
            ).fetchone()
            dispatch = json.loads(payload[0])
            assert dispatch["source_sha256"] == case.source.rsplit("/", 1)[1]
            assert dispatch["action_id"] != case.task.root_action_id
            assert not case.conn.in_transaction
            # Output normalization failure cannot rewrite the native effect.
            case.store.finish_invocation(invocation, error=ErrorCode.INVALID_RESULT)
            assert observed(case, invocation)[0]["status"] == "SUCCEEDED"
        finally:
            await case.calls.close()

    asyncio.run(run())


def test_revocation_after_reservation_sends_no_cell_and_keeps_heap(scratch_case):
    case = scratch_case

    async def run():
        worker = await owned(case)
        try:
            request, invocation = reserve(case)
            command(case.conn, revoke_grant(RevokeGrantRequest(case.grant)))
            with pytest.raises(StableError) as rejected:
                await case.calls.execute(
                    task=case.task, invocation_id=invocation, request=request
                )
            assert rejected.value.code == ErrorCode.AUTHORITY_DENIED
            assert worker.ordinal == 0 and worker.state == "ACTIVE"
            assert observed(case, invocation)[0]["status"] == "NOT_DISPATCHED"
        finally:
            await case.calls.close()

    asyncio.run(run())


@pytest.mark.parametrize("change", ["revoke", "deadline", "malformed"])
def test_waiting_on_owner_lock_rechecks_authority_deadline_and_preserves_first_call(
    scratch_case, change
):
    case = scratch_case

    async def run():
        worker = await owned(case)
        held = False
        pending = None
        try:
            request, invocation = reserve(
                case, deadline=now_us() + 500_000 if change == "deadline" else None
            )
            signed = asyncio.Event()
            signer = case.calls.signer

            def sign(raw):
                signed.set()
                return signer(raw)

            case.calls.signer = sign
            await worker._lock.acquire()
            held = True
            pending = asyncio.create_task(
                case.calls.execute(
                    task=case.task, invocation_id=invocation, request=request
                )
            )
            await asyncio.wait_for(signed.wait(), 3)
            if change == "revoke":
                command(case.conn, revoke_grant(RevokeGrantRequest(case.grant)))
            elif change == "deadline":
                await asyncio.sleep(
                    max(0, (request.deadline_at_us - now_us()) / 1e6) + 0.05
                )
            else:
                with pytest.raises(StableError) as rejected:
                    await case.calls.execute(
                        task=case.task,
                        invocation_id=invocation,
                        request=replace(request, timeout_us=1_000_000),
                    )
                assert rejected.value.code == ErrorCode.AUTHORITY_DENIED
                assert not observed(case, invocation)
            worker._lock.release()
            held = False
            if change == "malformed":
                assert (await pending).stdout.strip() == "42" and worker.ordinal == 1
            else:
                with pytest.raises(StableError) as rejected:
                    await pending
                assert rejected.value.code == (
                    ErrorCode.AUTHORITY_DENIED
                    if change == "revoke"
                    else ErrorCode.DEADLINE_EXCEEDED
                )
                assert (
                    worker.ordinal == 0
                    and observed(case, invocation)[0]["status"] == "NOT_DISPATCHED"
                )
        finally:
            if held:
                worker._lock.release()
            if pending is not None:
                await asyncio.gather(pending, return_exceptions=True)
            await case.calls.close()

    asyncio.run(run())


def test_immutable_dispatch_fact_blocks_resubmit_after_projection_marker_deletion(
    scratch_case,
):
    case = scratch_case

    async def run():
        worker = await owned(case)
        try:
            request, invocation = reserve(case)
            await case.calls.execute(
                task=case.task, invocation_id=invocation, request=request
            )

            def remove_marker(txn):
                journal, _ = case.store._journal(txn._conn, invocation)
                del journal["scratch_dispatch"]
                txn.execute(
                    "UPDATE invocations SET backend_ref_json=? WHERE invocation_id=?",
                    (canonical_json(journal), invocation),
                )
                return {}

            command(case.conn, remove_marker)
            with pytest.raises(StableError) as rejected:
                await case.calls.execute(
                    task=case.task, invocation_id=invocation, request=request
                )
            assert rejected.value.code == ErrorCode.EXTERNAL_EFFECT_UNKNOWN
            assert worker.ordinal == 1 and len(observed(case, invocation)) == 1
        finally:
            await case.calls.close()

    asyncio.run(run())


@pytest.mark.parametrize(
    "scratch_case,outcome,error",
    [
        ("raise ValueError('SCRATCH_NATIVE_EXCEPTION_SECRET')", "FAILED", "ValueError"),
        ("import os\nos._exit(17)", "UNKNOWN", None),
    ],
    indirect=["scratch_case"],
)
def test_native_failure_or_actual_process_loss_has_durable_outcome(
    scratch_case, outcome, error
):
    case = scratch_case

    async def run():
        worker = await owned(case)
        try:
            request, invocation = reserve(case)
            if outcome == "UNKNOWN":
                with pytest.raises(StableError) as rejected:
                    await case.calls.execute(
                        task=case.task, invocation_id=invocation, request=request
                    )
                assert rejected.value.code == ErrorCode.EXTERNAL_EFFECT_UNKNOWN
                assert worker.state == "LOST"
            else:
                result = await case.calls.execute(
                    task=case.task, invocation_id=invocation, request=request
                )
                assert (
                    result.error_type == error
                    and "SECRET" not in result.stdout + result.stderr
                )
            assert observed(case, invocation)[0]["status"] == outcome
            assert "SCRATCH_NATIVE_EXCEPTION_SECRET" not in str(
                case.conn.execute("SELECT payload_json FROM facts").fetchall()
            )
        finally:
            await case.calls.close()

    asyncio.run(run())


@pytest.mark.parametrize(
    "change", ["surface", "effects", "source_kind", "source_integrity", "capability"]
)
def test_admission_is_atomic_and_derived_from_actual_frozen_inputs(
    scratch_case, change
):
    case = scratch_case

    async def run():
        worker = await owned(case)
        try:
            operation = dict(OPERATION)
            if change == "surface":
                operation["operation_id"] = "fixture.absent"
            elif change == "effects":
                operation["effects"] = ["none"]
            elif change == "source_kind":
                # A supported but ungranted source kind. Artifact identities
                # stay immutable: this is a new actual catalog entry.
                staged = case.store.stage(b"print(7*6)")

                def source(txn):
                    txn.execute(
                        "INSERT INTO artifacts VALUES (?,'other_source','text/x-python',?,1,?,?,?,?,'VALID')",
                        (
                            staged["artifact_id"],
                            len(staged["content"]),
                            ACTOR,
                            txn.recorded_at_us,
                            b"[]",
                            canonical_json(staged["manifest"]),
                        ),
                    )
                    return {}

                command(case.conn, source)
                case.source = staged["artifact_id"]
            elif change == "source_integrity":

                def corrupt(txn):
                    txn.execute(
                        "UPDATE artifacts SET integrity_status='CORRUPT' WHERE artifact_id=?",
                        (case.source,),
                    )
                    return {}

                command(case.conn, corrupt)
            before = (
                case.conn.execute("SELECT COUNT(*) FROM invocations").fetchone()[0],
                case.conn.execute(
                    "SELECT consumed_budget_json FROM tasks WHERE task_id=?",
                    (case.task.task_id,),
                ).fetchone()[0],
                case.conn.execute(
                    "SELECT COUNT(*) FROM authority_uses WHERE grant_id=?",
                    (case.grant,),
                ).fetchone()[0],
            )
            request = ScratchExecution(case.session, case.source, now_us() + 30_000_000)
            with pytest.raises(StableError):
                case.calls.reserve(
                    case.task,
                    ordinal=0,
                    capability_id=(
                        "capability://other" if change == "capability" else CAP
                    ),
                    operation=operation,
                    content=b"{}",
                    request=request,
                )
            after = (
                case.conn.execute("SELECT COUNT(*) FROM invocations").fetchone()[0],
                case.conn.execute(
                    "SELECT consumed_budget_json FROM tasks WHERE task_id=?",
                    (case.task.task_id,),
                ).fetchone()[0],
                case.conn.execute(
                    "SELECT COUNT(*) FROM authority_uses WHERE grant_id=?",
                    (case.grant,),
                ).fetchone()[0],
            )
            assert before == after and worker.ordinal == 0
        finally:
            await case.calls.close()

    asyncio.run(run())


def test_invalid_service_signature_is_rejected_before_native_acceptance(scratch_case):
    case = scratch_case

    async def run():
        worker = await owned(case)
        try:
            request, invocation = reserve(case)
            case.calls.signer = lambda _: b"\0" * 64
            with pytest.raises(StableError) as rejected:
                await case.calls.execute(
                    task=case.task, invocation_id=invocation, request=request
                )
            assert rejected.value.code == ErrorCode.AUTHORITY_DENIED
            assert (
                worker.ordinal == 0
                and observed(case, invocation)[0]["status"] == "NOT_DISPATCHED"
            )
            assert not case.conn.execute(
                "SELECT 1 FROM facts WHERE entity_id=? AND event_type='scratch_dispatch_authorized'",
                (invocation,),
            ).fetchone()
        finally:
            await case.calls.close()

    asyncio.run(run())


def test_new_host_cannot_adopt_an_active_heap_or_submit_without_owner(scratch_case):
    case = scratch_case

    async def run():
        worker = await owned(case)
        try:
            request, invocation = reserve(case)
            fresh = ScratchHostCalls(
                case.store,
                trust=case.calls.trust,
                epoch_id=case.calls.epoch_id,
                signer=case.calls.signer,
            )
            with pytest.raises(StableError) as expired:
                fresh.bind_new_worker(case.session, worker)
            assert expired.value.code == ErrorCode.HANDLE_EXPIRED
            with pytest.raises(StableError) as expired:
                await fresh.execute(
                    task=case.task, invocation_id=invocation, request=request
                )
            assert (
                expired.value.code == ErrorCode.HANDLE_EXPIRED and worker.ordinal == 0
            )
        finally:
            await case.calls.close()

    asyncio.run(run())


def test_zero_absolute_deadline_is_expired_not_unset(scratch_case):
    case = scratch_case

    async def run():
        worker = await owned(case)
        try:
            with pytest.raises(StableError) as rejected:
                reserve(case, deadline=0)
            assert (
                rejected.value.code == ErrorCode.DEADLINE_EXCEEDED
                and worker.ordinal == 0
            )
        finally:
            await case.calls.close()

    asyncio.run(run())


def test_expired_execution_certificate_is_not_a_native_execution(scratch_case):
    case = scratch_case

    async def run():
        worker = await owned(case)
        try:
            request, invocation = reserve(case)
            case.calls.trust = replace(case.calls.trust, expires_at_us=now_us() - 1)
            with pytest.raises(StableError) as rejected:
                await case.calls.execute(
                    task=case.task, invocation_id=invocation, request=request
                )
            assert (
                rejected.value.code == ErrorCode.KEY_UNAVAILABLE and worker.ordinal == 0
            )
            assert observed(case, invocation)[0]["status"] == "NOT_DISPATCHED"
        finally:
            await case.calls.close()

    asyncio.run(run())


@pytest.mark.parametrize(
    "scratch_case",
    ["from pathlib import Path\nPath('entered').write_text('ready')\nwhile True: pass"],
    indirect=True,
)
def test_cancel_retains_confirmed_interrupt_and_does_not_invent_unknown(scratch_case):
    case = scratch_case

    async def run():
        worker = await owned(case)
        pending = None
        try:
            request, invocation = reserve(case)
            pending = asyncio.create_task(
                case.calls.execute(
                    task=case.task, invocation_id=invocation, request=request
                )
            )
            async with asyncio.timeout(10):
                while not (worker.workspace / "entered").exists():
                    await asyncio.sleep(0.01)
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
            assert observed(case, invocation)[0]["status"] == "INTERRUPTED"
            assert (
                worker.state == "ACTIVE"
                and worker.confirmed_result.error_type == "KeyboardInterrupt"
            )
        finally:
            if pending is not None and not pending.done():
                pending.cancel()
                await asyncio.gather(pending, return_exceptions=True)
            await case.calls.close()

    asyncio.run(run())
