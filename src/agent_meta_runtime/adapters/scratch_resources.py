"""Runtime-owned asynchronous Scratch resources for the package Host boundary."""

import asyncio
import json
from pathlib import Path
import secrets
import shutil

from ..domain.canonical import canonical_json, now_us, sha256_hex
from ..domain.errors import ErrorCode, StableError
from ..domain.execution_tokens import (
    ExecutionTokenBinding,
    issue_execution_token,
    MAX_TOKEN_TTL_US,
)
from ..domain.ids import new_uuid7
from ..domain.resource_contract import ResourceReceipt
from ..domain.scratch_execution import (
    ScratchCreate,
    ScratchExecution,
    ScratchRelease,
    ScratchBindings,
    ScratchInspect,
    ScratchExportCandidate,
)
from ..ports.repositories import FactAppendRequest
from .credentials import service_signing_authority
from .scratch_host import ScratchHostCalls
from .scratch_worker import ScratchWorker
from .store import scratch_journal
from .store import scratch_bindings
from .store.host_resources import read_reservation, reauthorize, fact
from .store.scratch_admission import dispatch_lifecycle
from .store.semantic import _append_edge
from .store.service_certificates import load_service_execution_trust
from .store.task_snapshot import register_staged_artifact


def _fail(code, message):
    raise StableError(code=code, message=message)


class OwnedScratchResources:
    def __init__(self, store, *, data_dir, instance_id, allow_insecure=False):
        self.store, self.data_dir = store, Path(data_dir)
        self.instance_id, self.allow_insecure = instance_id, allow_insecure
        self.root = self.data_dir / "workspaces"
        self.root.mkdir(mode=0o700, exist_ok=True)
        if self.root.is_symlink() or self.root.is_junction():
            _fail(ErrorCode.INTEGRITY_ERROR, "Scratch workspace root cannot be a link")
        self._calls = None
        self._locks = {}
        self._creation = asyncio.Lock()
        self._recovered = set()

    def recover(self):
        """Called only after the daemon acquired its exclusive native owner lock.

        Previous kernels are parent-owned (Job/PDEATH supervisor). No native
        owner or heap is adopted; explicit release still owns directory cleanup.
        """
        sessions = self.store.conn.execute(
            "SELECT session_id FROM scratch_sessions WHERE realm_id=? AND status!='RELEASED'",
            (self.store.realm_id,),
        ).fetchall()
        for (session,) in sessions:
            self.store.run_command(scratch_journal.lose_session(session))
            self._recovered.add(session)

    def _controller(self):
        if self._calls is None:
            trust = load_service_execution_trust(
                self.store.conn,
                self.store.catalog.cas,
                realm_id=self.store.realm_id,
                now_us=now_us(),
            )
            signer = service_signing_authority(
                self.data_dir,
                expected_public_key=trust.service_public_key,
                allow_insecure=self.allow_insecure,
            )
            epoch = self.store.conn.execute(
                "SELECT epoch_id FROM realms WHERE realm_id=?", (self.store.realm_id,)
            ).fetchone()[0]
            self._calls = ScratchHostCalls(
                self.store, trust=trust, epoch_id=epoch, signer=signer
            )
        return self._calls

    def _authorize(self, task, invocation_id, request, session_id):
        calls = self._controller()
        row = self.store.conn.execute(
            "SELECT workspace_id,backend_request_id FROM scratch_sessions WHERE session_id=?",
            (session_id,),
        ).fetchone()
        reservation = read_reservation(self.store, invocation_id)
        action = self.store._journal(self.store.conn, invocation_id)[1]
        scope = {
            "request": request.document(),
            "session_id": session_id,
            "workspace_id": row[0],
        }
        permissions = frozenset(
            claim["permission"]
            for claims in reservation["grants"].values()
            for claim in claims
        )
        binding = ExecutionTokenBinding(
            row[1],
            task.realm_id,
            calls.epoch_id,
            task.actor_id,
            action,
            (
                "process.spawn"
                if type(request) is ScratchCreate
                else (
                    "none"
                    if type(request) in (ScratchBindings, ScratchInspect)
                    else "external.irreversible"
                )
            ),
            sha256_hex(canonical_json(scope)),
            {"calls": 1},
            permissions,
            task.deadline_at_us,
        )
        current = now_us()
        if calls.trust.expires_at_us <= current:
            _fail(ErrorCode.KEY_UNAVAILABLE, "Scratch Service certificate expired")
        expires = min(
            current + MAX_TOKEN_TTL_US,
            calls.trust.expires_at_us,
            (
                task.deadline_at_us
                if task.deadline_at_us is not None
                else current + MAX_TOKEN_TTL_US
            ),
        )
        if expires <= current:
            _fail(ErrorCode.DEADLINE_EXCEEDED, "Scratch lifecycle deadline expired")
        token = issue_execution_token(
            {
                "token_version": 1,
                "token_id": new_uuid7(),
                "backend_session_id": row[1],
                "realm_id": task.realm_id,
                "actor_id": task.actor_id,
                "action_id": action,
                "effect_kind": binding.effect_kind,
                "target_scope_hash": binding.target_scope_hash,
                "resource_ceiling": {"calls": 1},
                "issued_at_us": current,
                "expires_at_us": expires,
                "nonce": secrets.token_hex(16),
            },
            service_principal_id=calls.trust.service_principal_id,
            signer=calls.signer,
        )
        return lambda txn: dispatch_lifecycle(
            self.store,
            txn,
            task,
            invocation_id,
            request,
            session_id=session_id,
            binding=binding,
            authorization=token,
        )

    def _receipt(self, request, value):
        raw = canonical_json(value)
        staged = self.store.stage(raw)
        return (
            ResourceReceipt(
                request.document()["schema"],
                staged["artifact_id"],
                "application/json",
                raw,
            ),
            staged,
        )

    async def prepare(self, *, task, invocation_id, request):
        reservation = read_reservation(self.store, invocation_id)
        if reservation["request"] != request.document():
            _fail(ErrorCode.AUTHORITY_DENIED, "Scratch request differs from admission")
        self.store.run_command(
            lambda txn: (
                reauthorize(self.store, txn, task, invocation_id, reservation) or {}
            )
        )
        if type(request) is ScratchCreate:
            async with self._creation:
                return await self._create(task, invocation_id, request)
        async with self._locks.setdefault(request.session_id, asyncio.Lock()):
            if type(request) is ScratchExportCandidate:
                from .store.scratch_export import prepare as export_prepare

                return await export_prepare(self.store, task, invocation_id, request)
            if type(request) is ScratchExecution:
                return await self._execute(task, invocation_id, request)
            if type(request) is ScratchRelease:
                return await self._release(task, invocation_id, request)
            if type(request) in (ScratchBindings, ScratchInspect):
                return await self._observe(task, invocation_id, request)
        _fail(ErrorCode.INVALID_ARGUMENT, "unsupported Scratch intent")

    async def _create(self, task, invocation_id, request):
        calls = self._controller()
        workspace_id, relative = "workspace://" + new_uuid7(), new_uuid7()
        reservation = read_reservation(self.store, invocation_id)

        def reserve(txn):
            reauthorize(self.store, txn, task, invocation_id, reservation)
            action = self.store._journal(txn._conn, invocation_id)[1]
            # No hard disk quota is advertised by this trusted profile.
            txn.execute(
                "INSERT INTO workspaces VALUES (?,?,?,?,0,'ACTIVE',?,?,NULL)",
                (
                    workspace_id,
                    task.realm_id,
                    action,
                    relative,
                    txn.recorded_at_us,
                    txn.recorded_at_us + request.wall_ttl_us,
                ),
            )
            return scratch_journal.reserve_session(
                invocation_id,
                workspace_id=workspace_id,
                backend_request_id=invocation_id,
                idle_ttl_us=request.idle_ttl_us,
                wall_ttl_us=request.wall_ttl_us,
            )(txn)

        session_id = self.store.run_command(reserve)["session_id"]
        worker = ScratchWorker(
            workspace_root=self.root,
            workspace=self.root / relative,
            idle_ttl_s=request.idle_ttl_us / 1e6,
            wall_ttl_s=request.wall_ttl_us / 1e6,
        )
        try:
            authorize = self._authorize(task, invocation_id, request, session_id)

            def before_start():
                self.store.run_token(authorize)

            await worker.start(before_start=before_start)
            expires = self.store.conn.execute(
                "SELECT idle_expires_at_us,wall_expires_at_us FROM scratch_sessions WHERE session_id=?",
                (session_id,),
            ).fetchone()
            worker.idle_ttl_s = min(
                worker.idle_ttl_s, max(0.000001, (expires[0] - now_us()) / 1e6)
            )
            worker.wall_ttl_s = min(
                worker.wall_ttl_s, max(0.000001, (expires[1] - now_us()) / 1e6)
            )
            calls.bind_new_worker(session_id, worker)
        except BaseException:
            await worker.close(force=True)
            self.store.run_command(scratch_journal.lose_session(session_id))
            self._recovered.add(session_id)
            await self._cleanup(session_id, worker=worker)
            raise
        return self._receipt(
            request,
            {
                "schema": "scratch-session-receipt/v1",
                "session_id": session_id,
                "status": "ACTIVE",
                "idle_ttl_us": request.idle_ttl_us,
                "wall_ttl_us": request.wall_ttl_us,
            },
        )

    def _bounded_stream(self, task, request, ordinal, channel, value, truncated):
        text = self.store.resource_value(task, value)

        def encode(length):
            return canonical_json(
                {
                    "schema": "scratch-stream/v1",
                    "session_id": request.session_id,
                    "cell_ordinal": ordinal,
                    "channel": channel,
                    "text": text[:length],
                }
            )

        raw = encode(len(text))
        if len(raw) > 1024 * 1024:
            lower, upper = 0, len(text)
            while lower < upper:
                middle = (lower + upper + 1) // 2
                if len(encode(middle)) <= 1024 * 1024:
                    lower = middle
                else:
                    upper = middle - 1
            raw, truncated = encode(lower), True
        return self.store.stage(raw), truncated

    async def _execute(self, task, invocation_id, request):
        calls = self._controller()
        owner = calls._owners.get(request.session_id)
        if owner is None:
            _fail(ErrorCode.HANDLE_EXPIRED, "Scratch owner cannot be restored")
        worker = owner[1]
        if worker.state != "ACTIVE":
            self.store.run_command(scratch_journal.lose_session(request.session_id))
            _fail(ErrorCode.HANDLE_EXPIRED, "Scratch owner expired")
        before = json.loads(await worker.bindings())
        result = await calls.execute(
            task=task, invocation_id=invocation_id, request=request
        )
        after = json.loads(await worker.bindings())
        cell = self.store.run_command(
            scratch_journal.reserve_cell(
                request.session_id,
                invocation_id,
                source_artifact_id=request.source_artifact_id,
                timeout_us=request.timeout_us,
            )
        )
        ordinal = cell["ordinal"]
        stdout, out_cut = self._bounded_stream(
            task, request, ordinal, "stdout", result.stdout, result.stdout_truncated
        )
        stderr, err_cut = self._bounded_stream(
            task, request, ordinal, "stderr", result.stderr, result.stderr_truncated
        )
        displays, remaining, display_cut = [], 1024 * 1024, result.display_truncated
        for raw in result.displays:
            content = canonical_json(
                {
                    "schema": "scratch-display/v1",
                    "session_id": request.session_id,
                    "cell_ordinal": ordinal,
                    "bundle": self.store.resource_value(task, json.loads(raw)),
                }
            )
            if len(content) > remaining:
                display_cut = True
                break
            displays.append(self.store.stage(content))
            remaining -= len(content)
        bindings = scratch_bindings.inventory(
            self.store, task, request.session_id, after
        )
        value = {
            "schema": "scratch-execution-receipt/v1",
            "session_id": request.session_id,
            "cell_ordinal": ordinal,
            "execution_count": result.ordinal,
            "source_artifact_id": request.source_artifact_id,
            "stdout_artifact_id": stdout["artifact_id"],
            "stderr_artifact_id": stderr["artifact_id"],
            "display_artifact_ids": [item["artifact_id"] for item in displays],
            "error_type": result.error_type,
            "stdout_truncated": out_cut,
            "stderr_truncated": err_cut,
            "display_truncated": display_cut,
            "declared_binding_names": sorted(
                item["name"]
                for item in bindings["bindings"]
                if item["created_cell"] == ordinal
            ),
            "changed_binding_names": sorted(
                item["name"]
                for item in bindings["bindings"]
                if item["last_changed_cell"] == ordinal
                and item["created_cell"] != ordinal
            ),
            "binding_change_precision": (
                "CELL_MAIN_THREAD_NAME_WRITES"
                if bindings["binding_write_tracking_complete"]
                else "PARTIAL"
            ),
            "binding_inventory_truncated": before["truncated"] or after["truncated"],
        }
        receipt, staged = self._receipt(request, value)

        def publish(txn):
            reservation = read_reservation(self.store, invocation_id)
            reauthorize(self.store, txn, task, invocation_id, reservation)
            scratch_bindings.persist_snapshot(
                self.store, txn, task, invocation_id, bindings
            )
            artifacts = [stdout, stderr, *displays, staged]
            for item in artifacts:
                register_staged_artifact(
                    txn,
                    item,
                    kind="scratch_output",
                    parents=(request.source_artifact_id,),
                )
            source = fact(
                txn,
                invocation_id,
                "scratch_output_published",
                {
                    "schema": "scratch-output-publication/v1",
                    "request": request.document(),
                    "receipt_artifact_id": receipt.artifact_id,
                    "output_artifact_ids": [item["artifact_id"] for item in artifacts],
                    "redaction_profile_artifact_id": task.context.profile_artifact_id,
                },
            )
            for item in artifacts:
                _append_edge(
                    txn,
                    fact_id=source,
                    edge_type="produced",
                    from_id=invocation_id,
                    to_id=item["artifact_id"],
                )
            return {}

        self.store.run_command(publish)
        return receipt, staged

    def _redact_node(self, task, node, label=None):
        # ReflectNode child-edge labels carry object/dict key semantics.
        key = label
        if type(label) is str and label.startswith('"'):
            try:
                decoded = json.loads(label)
                if type(decoded) is str:
                    key = decoded
            except ValueError:
                pass
        if (
            type(key) is str
            and self.store.resource_value(task, {key: "POLICY_PROBE"})[key]
            == "[REDACTED]"
        ):
            return {
                "kind": "redacted",
                "value": "[REDACTED]",
                "children": [],
                "truncated": False,
            }
        result = {
            name: value
            for name, value in node.items()
            if name not in ("children", "token")
        }
        # An observed weak handle is not a credential token. Use a distinct
        # public field; the frozen policy must keep redacting real token keys.
        result["handle"] = node.get("token")
        result["children"] = [
            [
                self.store.resource_value(task, name),
                self._redact_node(task, child, name),
            ]
            for name, child in node.get("children", [])
        ]
        return self.store.resource_value(task, result)

    async def _observe(self, task, invocation_id, request):
        calls = self._controller()
        owner = calls._owners.get(request.session_id)
        if owner is None or owner[1].state != "ACTIVE":
            self.store.run_command(scratch_journal.lose_session(request.session_id))
            _fail(ErrorCode.HANDLE_EXPIRED, "Scratch observation owner is unavailable")
        worker = owner[1]
        authorize = self._authorize(task, invocation_id, request, request.session_id)
        self.store.run_token(authorize)
        snapshot = json.loads(await worker.bindings())
        bindings = scratch_bindings.inventory(
            self.store, task, request.session_id, snapshot
        )
        reservation = read_reservation(self.store, invocation_id)

        def record(txn):
            reauthorize(self.store, txn, task, invocation_id, reservation)
            scratch_bindings.persist_snapshot(
                self.store, txn, task, invocation_id, bindings
            )
            return {}

        self.store.run_command(record)
        if type(request) is ScratchBindings:
            receipt, staged = self._receipt(request, bindings)
        else:
            origin = scratch_bindings.target(self.store, request.session_id, request)
            from dataclasses import replace

            budget = request.budget()
            budget = replace(
                budget, max_bytes=min(budget.max_bytes, 1024 * 1024 - 16384)
            )
            try:
                native = json.loads(
                    await worker.safe_inspect(
                        name=request.name, handle=request.handle, budget=budget
                    )
                )
            except StableError as error:
                if (
                    error.code == ErrorCode.HANDLE_EXPIRED
                    and request.handle is not None
                ):
                    digest = sha256_hex(request.handle.encode())

                    def expired(txn):
                        txn.execute(
                            "UPDATE scratch_bindings SET status='EXPIRED' WHERE session_id=? AND observed_handle_hash=?",
                            (request.session_id, digest),
                        )
                        fact(
                            txn,
                            invocation_id,
                            "scratch_handle_expired",
                            {"session_id": request.session_id, "handle_hash": digest},
                        )
                        return {}

                    self.store.run_command(expired)
                raise
            if native["cell_ordinal"] != snapshot["cell_ordinal"]:
                _fail(
                    ErrorCode.REVISION_CONFLICT,
                    "Scratch namespace changed during observation",
                )
            node = self._redact_node(task, native["node"], origin["name"])
            value = {
                "schema": "scratch-inspection-receipt/v1",
                "session_id": request.session_id,
                "cell_ordinal": bindings["cell_ordinal"],
                "binding_origin": origin,
                "node": node,
                "value_mutation_impact": "UNKNOWN_RISK",
                "observed_by_action_id": self.store._journal(
                    self.store.conn, invocation_id
                )[1],
            }
            if len(canonical_json(value)) > 1024 * 1024:
                value["node"] = {
                    "kind": "opaque",
                    "children": [],
                    "truncated": True,
                    "reason": "POLICY_ENVELOPE_LIMIT",
                }
            receipt, staged = self._receipt(request, value)

        def publish(txn):
            reauthorize(self.store, txn, task, invocation_id, reservation)
            register_staged_artifact(txn, staged, kind="scratch_observation")
            if type(request) is ScratchInspect:
                issued = scratch_bindings.issued_handles(value["node"])
                scratch_bindings.persist_handles(
                    txn, request.session_id, origin, issued
                )
                source = fact(
                    txn,
                    invocation_id,
                    "scratch_inspection_published",
                    {
                        "schema": "scratch-inspection-publication/v1",
                        "session_id": request.session_id,
                        "receipt_artifact_id": receipt.artifact_id,
                        "binding_origin": origin,
                        "issued_handle_hashes": issued,
                        "redaction_profile_artifact_id": task.context.profile_artifact_id,
                    },
                )
                _append_edge(
                    txn,
                    fact_id=source,
                    edge_type="produced",
                    from_id=invocation_id,
                    to_id=receipt.artifact_id,
                )
            row, initial = scratch_journal._session(txn, request.session_id)
            scratch_journal._active(txn, row)
            txn.execute(
                "UPDATE scratch_sessions SET last_activity_at_us=?,idle_expires_at_us=?,updated_at_us=? WHERE session_id=?",
                (
                    txn.recorded_at_us,
                    min(txn.recorded_at_us + initial["idle_ttl_us"], row[6]),
                    txn.recorded_at_us,
                    request.session_id,
                ),
            )
            return {}

        self.store.run_command(publish)
        return receipt, staged

    def _cleanup_plan(self, txn, session_id, invocation_id=None, lifecycle_cause=None):
        row, origin = scratch_journal._session(txn, session_id)
        workspace = txn._conn.execute(
            "SELECT root_relpath,status FROM workspaces WHERE workspace_id=?", (row[3],)
        ).fetchone()
        relative = Path(workspace[0])
        if (
            relative.is_absolute()
            or len(relative.parts) != 1
            or relative.name in (".", "..")
        ):
            _fail(
                ErrorCode.INTEGRITY_ERROR,
                "Scratch cleanup path is not its allocated child",
            )
        scratch_journal.begin_release(session_id, invocation_id=invocation_id)(txn)
        txn.execute(
            "UPDATE workspaces SET status='RELEASING' WHERE workspace_id=? AND status!='RELEASED'",
            (row[3],),
        )
        context = scratch_journal._context(
            txn, invocation_id or origin["invocation_id"]
        )
        plan = {
            "schema": "scratch-workspace-cleanup/v1",
            "session_id": session_id,
            "workspace_id": row[3],
            "root_relpath": workspace[0],
            "owner_instance_id": self.instance_id,
            **(
                {"lifecycle_cause": lifecycle_cause}
                if lifecycle_cause is not None
                else {}
            ),
        }
        txn.append_fact(
            FactAppendRequest(
                entity_type="execution",
                entity_id=row[3],
                event_type="workspace_cleanup_planned",
                schema_version=1,
                payload=plan,
                occurred_at_us=txn.recorded_at_us,
                actor_id=context.actor_id,
                action_id=context.action_id,
            )
        )
        return plan

    async def _cleanup(
        self,
        session_id,
        *,
        worker=None,
        authorize=None,
        invocation_id=None,
        lifecycle_cause=None,
    ):
        def planned(txn):
            if authorize is not None:
                authorize(txn)
            return self._cleanup_plan(txn, session_id, invocation_id, lifecycle_cause)

        plan = (
            self.store.run_token(planned)
            if authorize is not None
            else self.store.run_command(planned)
        )
        if worker is not None:
            await worker.close()
        elif session_id not in self._recovered:
            _fail(
                ErrorCode.FAILED_PRECONDITION,
                "Scratch native owner exit is not established",
            )
        self.store.run_command(scratch_journal.lose_session(session_id))
        self.store.run_command(
            scratch_journal.begin_release(session_id, invocation_id=invocation_id)
        )
        target = self.root / plan["root_relpath"]
        # No computed deletion until the resolved absolute child is verified.
        if (
            self.root.is_symlink()
            or self.root.is_junction()
            or target.is_symlink()
            or target.is_junction()
            or target.resolve().parent != self.root.resolve()
            or target.resolve() == self.root.resolve()
        ):
            _fail(ErrorCode.INTEGRITY_ERROR, "Scratch cleanup target changed")
        if target.exists():
            await asyncio.to_thread(shutil.rmtree, target)

        def completed(txn):
            row, origin = scratch_journal._session(txn, session_id)
            txn.execute(
                "UPDATE workspaces SET status='RELEASED',released_at_us=? WHERE workspace_id=?",
                (txn.recorded_at_us, row[3]),
            )
            context = scratch_journal._context(
                txn, invocation_id or origin["invocation_id"]
            )
            txn.append_fact(
                FactAppendRequest(
                    entity_type="execution",
                    entity_id=row[3],
                    event_type="workspace_cleanup_completed",
                    schema_version=1,
                    payload=plan,
                    occurred_at_us=txn.recorded_at_us,
                    actor_id=context.actor_id,
                    action_id=context.action_id,
                )
            )
            return scratch_journal.confirm_release(session_id)(txn)

        self.store.run_command(completed)
        self._recovered.discard(session_id)

    async def _release(self, task, invocation_id, request):
        status = self.store.conn.execute(
            "SELECT status FROM scratch_sessions WHERE session_id=?",
            (request.session_id,),
        ).fetchone()[0]
        if status != "RELEASED":
            calls = self._controller()
            owner = calls._owners.get(request.session_id)
            authorize = self._authorize(
                task, invocation_id, request, request.session_id
            )
            cleanup = asyncio.create_task(
                self._cleanup(
                    request.session_id,
                    worker=owner[1] if owner else None,
                    authorize=authorize,
                    invocation_id=invocation_id,
                )
            )
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                await asyncio.gather(cleanup, return_exceptions=True)
                if not cleanup.cancelled() and cleanup.exception() is None:
                    calls._owners.pop(request.session_id, None)
                raise
            calls._owners.pop(request.session_id, None)
        return self._receipt(
            request,
            {
                "schema": "scratch-release-receipt/v1",
                "session_id": request.session_id,
                "status": "RELEASED",
            },
        )

    async def failed(self, *, task, invocation_id, request):
        if type(request) is ScratchCreate:
            row = self.store.conn.execute(
                "SELECT entity_id FROM facts WHERE event_type='scratch_session_reserved' "
                "AND json_extract(payload_json,'$.invocation_id')=?",
                (invocation_id,),
            ).fetchone()
            if row is not None and self._calls is not None:
                owner = self._calls._owners.get(row[0])
                if owner is not None:
                    await self._cleanup(row[0], worker=owner[1])
                    self._calls._owners.pop(row[0], None)

    async def drain(self, composition_id, *, reconcile_id):
        """Root retirement only, after its old Tasks have drained. No package port."""
        rows = self.store.conn.execute(
            "SELECT s.session_id FROM scratch_sessions s JOIN facts f ON f.entity_id=s.session_id "
            "AND f.realm_id=s.realm_id AND f.event_type='scratch_session_reserved' "
            "WHERE s.realm_id=? AND s.status!='RELEASED' AND json_extract(f.payload_json,'$.composition_id')=?",
            (self.store.realm_id, composition_id),
        ).fetchall()
        cause = {
            "reason_code": "COMPOSITION_RETIRED",
            "composition_id": composition_id,
            "reconcile_id": reconcile_id,
            "requesting_service_id": self.store.service_id,
        }
        for (session_id,) in rows:
            async with self._locks.setdefault(session_id, asyncio.Lock()):
                if self.store.conn.execute(
                    "SELECT status FROM scratch_sessions WHERE session_id=?",
                    (session_id,),
                ).fetchone() == ("RELEASED",):
                    continue
                owner = (
                    self._calls._owners.get(session_id)
                    if self._calls is not None
                    else None
                )
                cleanup = asyncio.create_task(
                    self._cleanup(
                        session_id,
                        worker=owner[1] if owner else None,
                        lifecycle_cause=cause,
                    )
                )
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    await cleanup
                    if self._calls is not None:
                        self._calls._owners.pop(session_id, None)
                    raise
                if self._calls is not None:
                    self._calls._owners.pop(session_id, None)

    async def close(self):
        errors = []
        if self._calls is not None:
            for session_id, (_, worker) in tuple(self._calls._owners.items()):
                try:
                    await self._cleanup(session_id, worker=worker)
                except Exception as error:
                    errors.append(error)
                finally:
                    await worker.close(force=True)
                    self._calls._owners.pop(session_id, None)
        if errors:
            _fail(ErrorCode.BACKEND_UNAVAILABLE, "Scratch cleanup was not confirmed")
