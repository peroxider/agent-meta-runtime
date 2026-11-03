"""Private Root assembly: reserved grants -> owned kernel -> native Fact.

This is not mounted on the package facade. Creation authorization, output
publication/normalization, binding inventory and public consumer wiring remain
separate responsibilities. Native results below stay inside the Root boundary.
"""

import asyncio
import json
import os
import secrets

from ..domain.canonical import canonical_json, now_us, sha256_hex
from ..domain.errors import ErrorCode, StableError
from ..domain.execution_tokens import (
    ExecutionTokenBinding,
    issue_execution_token,
    MAX_TOKEN_TTL_US,
)
from ..domain.ids import new_uuid7
from ..domain.scratch_execution import ScratchExecution
from ..domain.scratch_export import ScratchSource
from .scratch_worker import ScratchWorker
from .store import scratch_journal
from .store.artifact_content import read_artifact_content
from .store.host_resources import read_reservation, reauthorize
from .store.scratch_admission import dispatch
from .store.task_snapshot import register_staged_artifact


def _fail(code, message):
    raise StableError(code=code, message=message)


class ScratchHostCalls:
    def __init__(self, store, *, trust, epoch_id, signer):
        self.store, self.trust, self.epoch_id, self.signer = (
            store,
            trust,
            epoch_id,
            signer,
        )
        self._owners = {}

    def bind_new_worker(self, session_id, worker):
        """Root creation assembly only: never adopt an ACTIVE/restarted heap.

        The caller must authorize creation before starting the native owner.
        This method confirms the new owner; it does not grant creation rights.
        """
        if (
            type(worker) is not ScratchWorker
            or worker.state != "ACTIVE"
            or worker.pid in (None, os.getpid())
            or worker.ordinal != 0
        ):
            _fail(
                ErrorCode.FAILED_PRECONDITION,
                "Scratch binding requires a fresh owned kernel",
            )

        def bind(txn):
            row, _ = scratch_journal._session(txn, session_id)
            if row[2] != "STARTING" or session_id in self._owners:
                _fail(
                    ErrorCode.HANDLE_EXPIRED, "Scratch lifetime cannot adopt a kernel"
                )
            workspace = txn._conn.execute(
                "SELECT root_relpath FROM workspaces WHERE workspace_id=?", (row[3],)
            ).fetchone()
            if (
                workspace is None
                or worker.workspace.resolve() != (worker.root / workspace[0]).resolve()
            ):
                _fail(
                    ErrorCode.AUTHORITY_DENIED,
                    "Scratch native workspace differs from its Root reservation",
                )
            return scratch_journal.activate_session(session_id)(txn)

        self.store.run_command(bind)
        self._owners[session_id] = (new_uuid7(), worker)

    def reserve(self, task, *, ordinal, capability_id, operation, content, request):
        return self.store.reserve(
            task,
            ordinal=ordinal,
            kind="CAPABILITY",
            capability_id=capability_id,
            operation=operation,
            content=content,
            scratch_request=request,
        )

    def _native_observation(self, request, invocation_id, result):
        # Persist bounded native evidence before any package normalizer or
        # policy/output publication can fail. No raw streams or objects enter
        # this receipt; Root output publication must retain channel refs later.
        value = {
            "schema": "scratch-native-observation/v1",
            "session_id": request.session_id,
            "source_artifact_id": request.source_artifact_id,
            "worker_ordinal": result.ordinal,
            "execution_count": result.execution_count,
            "error_type": result.error_type,
            "stdout_sha256": sha256_hex(result.stdout.encode("utf-8")),
            "stderr_sha256": sha256_hex(result.stderr.encode("utf-8")),
            "display_sha256": [sha256_hex(raw) for raw in result.displays],
            "stdout_truncated": result.stdout_truncated,
            "stderr_truncated": result.stderr_truncated,
            "display_truncated": result.display_truncated,
        }
        staged = self.store.stage(canonical_json(value))
        outcome = (
            "INTERRUPTED"
            if result.error_type == "KeyboardInterrupt"
            else "FAILED" if result.error_type else "SUCCEEDED"
        )

        def commit(txn):
            register_staged_artifact(
                txn,
                staged,
                kind="scratch_native_observation",
                parents=(request.source_artifact_id,),
            )
            return scratch_journal.observe_cell(
                request.session_id,
                invocation_id,
                outcome=outcome,
                receipt_artifact_id=staged["artifact_id"],
                native_ordinal=result.ordinal,
            )(txn)

        return self.store.run_command(commit)

    async def execute(self, *, task, invocation_id, request):
        if type(request) is not ScratchExecution:
            _fail(
                ErrorCode.INVALID_ARGUMENT,
                "Scratch execution requires its exact intent",
            )
        owner = self._owners.get(request.session_id)
        if owner is None:
            _fail(
                ErrorCode.HANDLE_EXPIRED,
                "Scratch native owner is unavailable; heap adoption is forbidden",
            )
        owner_id, worker = owner
        submitted = False
        owns_reservation = False
        accepted_worker_ordinal = None
        try:
            reservation = read_reservation(self.store, invocation_id)
            if reservation["request"] != request.document():
                _fail(
                    ErrorCode.AUTHORITY_DENIED,
                    "Scratch execution differs from its reserved intent",
                )
            owns_reservation = True
            self.store.run_command(
                lambda txn: (
                    reauthorize(self.store, txn, task, invocation_id, reservation) or {}
                )
            )
            # Authorized immutable read before receiving Source bytes. The
            # second authorization at the owner lock is still mandatory.
            content = json.loads(
                read_artifact_content(
                    self.store.conn, self.store.catalog.cas, request.source_artifact_id
                )
            )
            source = ScratchSource(
                request.source_artifact_id, bytes.fromhex(content["content_hex"])
            )
            action = self.store._journal(self.store.conn, invocation_id)[1]
            permissions = frozenset(
                claim["permission"]
                for claims in reservation["grants"].values()
                for claim in claims
            )
            binding = ExecutionTokenBinding(
                owner_id,
                task.realm_id,
                self.epoch_id,
                task.actor_id,
                action,
                "external.irreversible",
                sha256_hex(canonical_json(request.document())),
                {"calls": 1, "timeout_us": request.timeout_us},
                permissions,
                request.deadline_at_us,
            )
            current = now_us()
            if self.trust.expires_at_us <= current:
                _fail(
                    ErrorCode.KEY_UNAVAILABLE,
                    "Scratch execution Service certificate has expired",
                )
            expires = min(
                current + MAX_TOKEN_TTL_US,
                request.deadline_at_us,
                self.trust.expires_at_us,
            )
            if expires <= current:
                _fail(
                    ErrorCode.DEADLINE_EXCEEDED,
                    "Scratch execution authorization has expired",
                )
            token = issue_execution_token(
                {
                    "token_version": 1,
                    "token_id": new_uuid7(),
                    "backend_session_id": owner_id,
                    "realm_id": task.realm_id,
                    "actor_id": task.actor_id,
                    "action_id": action,
                    "effect_kind": binding.effect_kind,
                    "target_scope_hash": binding.target_scope_hash,
                    "resource_ceiling": dict(binding.resource_ceiling),
                    "issued_at_us": current,
                    "expires_at_us": expires,
                    "nonce": secrets.token_hex(16),
                },
                service_principal_id=self.trust.service_principal_id,
                signer=self.signer,
            )

            def authorize_submission():
                nonlocal submitted, accepted_worker_ordinal
                if self._owners.get(request.session_id) != owner:
                    _fail(
                        ErrorCode.HANDLE_EXPIRED,
                        "Scratch owner generation changed before submission",
                    )
                self.store.run_token(
                    lambda txn: dispatch(
                        self.store,
                        txn,
                        task,
                        invocation_id,
                        request,
                        worker_session_id=owner_id,
                        binding=binding,
                        authorization=token,
                    )
                )
                accepted_worker_ordinal = worker.ordinal + 1
                submitted = True

            # The hook runs after the worker lock/liveness await, then commits
            # before the only native exchange can be scheduled.
            result = await worker.execute(
                source.content.decode("utf-8"),
                timeout_s=request.timeout_us / 1e6,
                deadline_at_us=request.deadline_at_us,
                before_submit=authorize_submission,
            )
            if result.ordinal != accepted_worker_ordinal:
                _fail(
                    ErrorCode.INTEGRITY_ERROR,
                    "Scratch native result belongs to another accepted cell",
                )
            self._native_observation(request, invocation_id, result)
            return result
        except BaseException as exc:
            code = (
                exc.code if isinstance(exc, StableError) else ErrorCode.INVALID_ARGUMENT
            )
            if submitted:
                result = worker.confirmed_result
                if result is not None and result.ordinal == accepted_worker_ordinal:
                    # A confirmed interrupt/error is still a known native
                    # outcome, even when Task cancellation wins the return.
                    self._native_observation(request, invocation_id, result)
                else:
                    await worker.close(force=True)
                    self.store.run_command(
                        scratch_journal.lose_session(request.session_id)
                    )
            elif owns_reservation:
                # Do not let a malformed second caller abort a first caller's
                # accepted effect. Only this still-RESERVED cell may close.
                try:
                    self.store.run_command(
                        scratch_journal.abort_cell_reservation(
                            request.session_id, invocation_id, reason_code=code
                        )
                    )
                except StableError as rejected:
                    if rejected.code not in (
                        ErrorCode.FAILED_PRECONDITION,
                        ErrorCode.NOT_FOUND,
                    ):
                        raise
            raise

    async def close(self):
        owners, self._owners = self._owners, {}
        for session_id, (_, worker) in owners.items():
            try:
                await worker.close()
            finally:
                self.store.run_command(scratch_journal.lose_session(session_id))
