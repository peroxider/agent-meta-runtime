"""Local composition root: one owner, storage, IPC and explicit Host profile."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import json
import os
from pathlib import Path
import signal
import time
import uuid

from ..adapters.cas import FilesystemCas
from ..adapters.daemon_lock import acquire_daemon_lock
from ..adapters.private_paths import secure_private_path
from ..adapters.store.connection import connect_store
from ..adapters.store.doctor import run_integrity_doctor
from ..adapters.store.uow import execute_command
from ..adapters.store.authority import load_grant_row, _reserve_use_row
from ..adapters.host_packages import InstalledHarnessCatalog
from ..adapters.store.host_execution import HostExecutionStore
from ..adapters.store.service_certificates import load_service_execution_trust
from ..adapters.credentials import service_signing_authority
from ..adapters.memory_host import MemoryHostActivities
from ..adapters.configured_provider import ControlledConfiguredProviderHost
from ..adapters.scratch_resources import OwnedScratchResources
from ..adapters.store.reconciliation import SqliteReconcilePersistence
from ..application.config import ConfigError, load_config, write_effective_config
from ..application.readiness import ReadinessEvaluator
from ..application.host_control import HostControl, restore_bound_snapshots
from ..application.task_host import TaskHost
from ..application.outbox import OutboxDispatcher
from ..application.probes import ProbeRunner
from ..application.reconciler import Reconciler
from ..domain.authority import authorize
from ..domain.canonical import now_us
from ..domain.clock import ClockStabilityMonitor
from ..domain.deadline import Deadline
from ..domain.envelope import CommandEnvelope
from ..domain.errors import ErrorCode, StableError
from ..domain.fact_catalog import validate_fact_event
from ..domain.host_profile import (TRUSTED_HOST_BACKEND_FEATURES, TRUSTED_HOST_PROFILE_HASH,
    INMEMORY_HOST_BACKEND_FEATURES, INMEMORY_HOST_PROFILE_HASH, CONTROLLED_PROVIDER_HOST_PROFILE_HASH)
from ..domain.ids import new_uuid7
from ..ports.repositories import FactAppendRequest
from ..sdk.transport import pipe_name_for_data_dir
from .cli.init import _reinit
from .local_api.handlers import PublicApiHandlers
from .local_api.peer import socket_path_for_data_dir
from .local_api.server import LocalApiServer
from .local_api.staging import ChunkedStaging


class RuntimeDaemon:
    def __init__(self, data_dir: Path, *, config_path: Path | None = None,
                 allow_insecure_credentials: bool = False, trusted_publishers=(), execution_backend=None,
                 controlled_provider_test_ca: bytes | None = None, context_tokenizer=None):
        self.data_dir = Path(data_dir).resolve()
        self.instance_id = uuid.uuid4().hex
        self._config_path = config_path
        self._allow_insecure = allow_insecure_credentials
        if execution_backend not in (None, "trusted_in_process", "in_memory"):
            raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="unsupported Host execution backend")
        self._execution_backend = execution_backend
        self._activities = None
        if controlled_provider_test_ca is not None and (type(controlled_provider_test_ca) is not bytes or not 0 < len(controlled_provider_test_ca) <= 65536):
            raise StableError(code=ErrorCode.INVALID_ARGUMENT,message='controlled Provider test anchor is invalid')
        self._provider_test_ca = controlled_provider_test_ca
        self._context_tokenizer = context_tokenizer
        self._providers = None
        self._scratch = None
        if not all(isinstance(item, str) and len(item) == 64 and set(item) <= set("0123456789abcdef") for item in trusted_publishers):
            raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="trusted publisher fingerprints must be lowercase SHA-256")
        self._trusted_publishers = frozenset(trusted_publishers)
        self._lock = None
        self._conn = None
        self._server = None
        self._handlers = None
        self._shutdown = asyncio.Event()
        self._clock = ClockStabilityMonitor()
        self._signals = {}
        self._started = False
        self._ever_started = False
        self._stopping = False
        self._catalog = None
        self._control = None
        self._control_task = None
        self._task_host = None
        self._task_host_task = None

    async def start(self):
        if self._ever_started or self._lock is not None:
            raise StableError(code=ErrorCode.ALREADY_RUNNING, message="daemon owner already started")
        if not (self.data_dir / "meta.db").is_file():
            raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="initialize the data directory before starting the daemon")
        self.endpoint = (pipe_name_for_data_dir(self.data_dir) if os.name == "nt"
                         else str(socket_path_for_data_dir(self.data_dir)))
        self._lock = acquire_daemon_lock(self.data_dir, self.endpoint, self.instance_id)
        try:
            secure_private_path(self.data_dir / "run")
            # Verification/cleanup is covered by this owner's already-held lock.
            _reinit(self.data_dir, self.data_dir / "meta.db", allow_insecure=self._allow_insecure)
            try:
                self.config = load_config(self._config_path, default_data_dir=self.data_dir)
                if self._execution_backend is not None:
                    self.config = replace(self.config, execution_backend=self._execution_backend)
                if self.config.transport_endpoint not in ("", self.endpoint) or self.config.transport_auth_secret:
                    raise ConfigError("daemon supports its data-directory local endpoint and signed commands only")
                if not 0 <= self.config.shutdown_grace_s <= 300 or not 1 <= self.config.store_busy_timeout_ms <= 60_000:
                    raise ConfigError("shutdown grace or store busy timeout exceeds supported bounds")
            except (ConfigError, OSError) as exc:
                raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="daemon configuration invalid") from exc
            self._conn = connect_store(self.data_dir / "meta.db")
            self._conn.execute(f"PRAGMA busy_timeout={self.config.store_busy_timeout_ms}")
            doctor = run_integrity_doctor(self.data_dir / "meta.db", cas_root=self.data_dir)
            if not doctor.ok:
                raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="startup integrity doctor failed", details={"findings": doctor.findings[:10]})
            initialized = self._conn.execute("SELECT payload_json FROM facts WHERE event_type='runtime_initialized' ORDER BY seq LIMIT 1").fetchone()
            identities = json.loads(initialized[0])
            self.realm_id = identities["realm_id"]
            self._service_id = identities["service_principal_id"]
            service = self._conn.execute("SELECT 1 FROM principals WHERE principal_id=? AND realm_id=? AND kind='SERVICE' AND status='ACTIVE'", (self._service_id, self.realm_id)).fetchone()
            if service is None:
                raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="daemon Service identity is unavailable")
            grant = self._conn.execute("SELECT grant_id FROM authority_grants WHERE subject_id=? AND parent_grant_id IS NULL AND status='ACTIVE'", (self._service_id,)).fetchone()
            if grant is None:
                raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="daemon Service grant is unavailable")
            self._service_grant_id = grant[0]
            write_effective_config(self.data_dir, self.config)
            cas = FilesystemCas(self.data_dir)
            memory = self.config.execution_backend == "in_memory"
            if memory and self._provider_test_ca is not None:
                raise StableError(code=ErrorCode.INVALID_ARGUMENT,message='controlled Provider tests require the explicit trusted in-process Host')
            profile_hash = INMEMORY_HOST_PROFILE_HASH if memory else TRUSTED_HOST_PROFILE_HASH
            if self._provider_test_ca is not None:
                profile_hash = CONTROLLED_PROVIDER_HOST_PROFILE_HASH
            features = INMEMORY_HOST_BACKEND_FEATURES if memory else TRUSTED_HOST_BACKEND_FEATURES
            self._readiness = ReadinessEvaluator(self._conn, realm_id=self.realm_id,
                db_path=self.data_dir / "meta.db", clock=self._clock,
                serving_health=lambda revision: self._catalog is not None and self._catalog.serving_healthy(revision))
            self._handlers = PublicApiHandlers(self._conn, data_dir=self.data_dir,
                realm_id=self.realm_id, db_path=self.data_dir / "meta.db", cas=cas,
                staging=ChunkedStaging(cas, now_us=now_us), readiness=self.readiness,
                now_us=now_us, trusted_publishers=self._trusted_publishers,
                daemon_instance_id=self.instance_id, backend_features=features,
                backend_profile_hash=profile_hash,
                context_profile_for=lambda composition_id: self._catalog.binding(composition_id).context_profile_artifact_id)
            self._catalog = InstalledHarnessCatalog(self._conn, cas=cas, realm_id=self.realm_id,
                service_id=self._service_id, run_command=self._run_control, validate_package=self._handlers._validate_package,
                drain_resources=self._drain_scratch)
            probe_runner = ProbeRunner(transport=self._catalog.probe)
            reconciler = Reconciler(self._conn, realm_id=self.realm_id, actor_id=self._service_id,
                persistence=SqliteReconcilePersistence(run_command=self._run_control),
                slot_executor=self._catalog.instantiate, drain_executor=self._catalog.drain,
                probe_runner=probe_runner)
            async def restore():
                await restore_bound_snapshots(self._catalog.restore_plans(), instantiate=self._catalog.instantiate,
                    probe_runner=probe_runner, withdraw_health=self._catalog.withdraw_health,
                    complete_restore=self._catalog.complete_restore)
            self._control = HostControl(reconciler, read_refs=lambda: tuple(self._conn.execute(
                "SELECT desired_revision,reconcile_status FROM composition_refs WHERE realm_id=?", (self.realm_id,)).fetchone()), startup=restore)
            self._catalog.prepare_restart(self.instance_id)
            execution = HostExecutionStore(self._conn, catalog=self._catalog,
                run_command=lambda mutator: self._run_control(mutator, permission="task.execute"),
                realm_id=self.realm_id, service_id=self._service_id, profile_hash=profile_hash,
                run_project=lambda mutator: self._run_control(mutator, permission="runtime.project"),
                run_token=lambda mutator: self._run_control(mutator, permission="runtime.token.issue"),
                context_tokenizer=self._context_tokenizer)
            if memory or self._provider_test_ca is not None:
                trust = load_service_execution_trust(self._conn, cas, realm_id=self.realm_id, now_us=now_us())
                signer = service_signing_authority(self.data_dir, expected_public_key=trust.service_public_key, allow_insecure=self._allow_insecure)
                epoch = self._conn.execute("SELECT epoch_id FROM realms WHERE realm_id=?", (self.realm_id,)).fetchone()[0]
                if memory:
                    self._activities = MemoryHostActivities(execution, trust=trust, epoch_id=epoch, signer=signer)
                    await self._activities.start()
                else:
                    self._providers = ControlledConfiguredProviderHost(execution,data_dir=self.data_dir,trust=trust,epoch_id=epoch,
                        signer=signer,test_ca_pem=self._provider_test_ca,allow_insecure=self._allow_insecure)
            async def acknowledge(item):
                if self._activities is not None:
                    await self._activities.acknowledge(item)
                elif execution.check_ack(item["payload"]) == "PENDING":
                    execution.record_ack(item["payload"], acknowledged=False)
            self._dispatcher = OutboxDispatcher(self._conn, instance_id=self.instance_id, clock=self._clock,
                handlers={"RECONCILE_REQUEST": self._control.deliver, "BACKEND_TERMINAL_ACK": acknowledge})
            self._dispatcher.recover_foreign_leases()
            self._scratch = OwnedScratchResources(execution, data_dir=self.data_dir, instance_id=self.instance_id,
                allow_insecure=self._allow_insecure)
            self._scratch.recover()
            self._task_host = TaskHost(execution, self._catalog, self._activities, self._providers, self._scratch)
            self._server = LocalApiServer(self.data_dir, handlers=self._handlers.handlers(),
                instance_id=self.instance_id, response_sent=self._response_sent)
            await self._server.start()
            self._runtime_fact("runtime_started", {"instance_id": self.instance_id,
                "pid": os.getpid(), "endpoint": self.endpoint})
            self._started = True
            self._ever_started = True
            self._install_signals()
            self._control_task = asyncio.create_task(self._control.run(self._dispatcher))
            self._task_host_task = asyncio.create_task(self._task_host.run())
            return self.status()
        except BaseException:
            await self.close()
            raise

    async def _drain_scratch(self, composition_id, request):
        if self._scratch is None:
            raise StableError(code=ErrorCode.BACKEND_UNAVAILABLE, message="Scratch owner is unavailable for drain")
        await self._scratch.drain(composition_id, reconcile_id=request["reconcile_id"])

    def readiness(self):
        snapshot = self._readiness.evaluate()
        if self._control is not None and self._control.failure is not None:
            snapshot = replace(snapshot, core_ready=False, serving_ready=False,
                               core_reasons=tuple(sorted({*snapshot.core_reasons, "BACKEND_UNAVAILABLE"})))
        if self._task_host is not None and self._task_host.failure is not None:
            snapshot = replace(snapshot, core_ready=False, serving_ready=False,
                core_reasons=tuple(sorted({*snapshot.core_reasons, "BACKEND_UNAVAILABLE"})))
        composition = self._conn.execute("SELECT c.composition_id FROM composition_refs r JOIN compositions c ON c.realm_id=r.realm_id AND c.revision=r.serving_revision WHERE r.realm_id=?", (self.realm_id,)).fetchone()
        if snapshot.serving_ready and (self._task_host is None or composition is None or not self._catalog.healthy_for(composition[0])):
            # Never advertise execution from persisted refs alone. A real bound
            # Host must establish each serving snapshot after restart.
            snapshot = replace(snapshot, serving_ready=False, serving_reasons=("FEATURE_UNAVAILABLE",))
        if self._stopping:
            snapshot = replace(snapshot, serving_ready=False, serving_reasons=("RECONCILE_NOT_READY",))
        return snapshot

    def _run_control(self, mutator, *, permission="runtime.reconcile"):
        if permission == "runtime.token.issue" and self._clock.unstable:
            raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="unstable clock forbids new execution tokens")
        envelope = CommandEnvelope("task://" + new_uuid7(), self.realm_id, self._service_id,
            self._service_grant_id, None, None, "runtime.host-control/v1", 1, {}, None, None, None)
        def guarded(txn):
            grant = load_grant_row(txn._conn, self._service_grant_id)
            epoch = txn._conn.execute("SELECT epoch_id FROM realms WHERE realm_id=?", (self.realm_id,)).fetchone()[0]
            count = txn._conn.execute("SELECT COUNT(*) FROM authority_uses WHERE grant_id=?", (self._service_grant_id,)).fetchone()[0]
            reason = "GRANT_NOT_FOUND" if grant is None else authorize(grant, subject_id=self._service_id,
                permission=permission, resource_realm=self.realm_id, resource_target=None,
                epoch_id=epoch, now_us=txn.recorded_at_us, uses_count=count)
            principal = txn._conn.execute("SELECT status FROM principals WHERE principal_id=? AND realm_id=?", (self._service_id, self.realm_id)).fetchone()
            if principal is None or principal[0] != "ACTIVE":
                reason = "ACTIVE_PRINCIPAL_REQUIRED"
            if reason is not None:
                raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="Host control authority denied", details={"reason_code": reason})
            _reserve_use_row(txn, grant.grant_id, envelope.command_id, "host_control", {})
            return mutator(txn)
        result = execute_command(self._conn, envelope, guarded, deadline=Deadline.after(5_000_000))
        if hasattr(result, "error"):
            raise result.error
        return dict(result.receipt)

    def status(self):
        snapshot = self.readiness()
        return {"state": "RUNNING", "instance_id": self.instance_id, "endpoint": self.endpoint,
                "realm_id": self.realm_id, "core_ready": snapshot.core_ready,
                "execution_backend": self.config.execution_backend,
                "provider_execution": "CONTROLLED_TEST_ONLY" if self._provider_test_ca is not None else "UNAVAILABLE",
                "serving_ready": snapshot.serving_ready, "core_reasons": list(snapshot.core_reasons),
                "serving_reasons": list(snapshot.serving_reasons)}

    def _runtime_fact(self, event, payload):
        validate_fact_event("runtime", event, 1, payload)
        envelope = CommandEnvelope("task://" + new_uuid7(), self.realm_id, self._service_id,
            None, None, None, "runtime.control/v1", 1, {"event": event, **payload}, None, None, None)
        def mutate(txn):
            return {"fact_id": txn.append_fact(FactAppendRequest(entity_type="runtime",
                entity_id=self.realm_id, event_type=event, schema_version=1, payload=payload,
                actor_id=self._service_id, occurred_at_us=txn.recorded_at_us))}
        result = execute_command(self._conn, envelope, mutate, deadline=Deadline.after(5_000_000))
        if hasattr(result, "error"):
            raise result.error

    def _response_sent(self, method, success):
        if success and method == "agent_meta.public.v1.Runtime.Stop" and self._handlers.stop_requested:
            self.request_shutdown()

    def request_shutdown(self):
        self._stopping = True
        self._shutdown.set()

    def _install_signals(self):
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGINT, signal.SIGTERM):
            try:
                previous = signal.getsignal(signum)
                signal.signal(signum, lambda *_: loop.call_soon_threadsafe(self.request_shutdown))
                self._signals[signum] = previous
            except ValueError:
                # An embedded test host may run outside Python's main thread.
                pass

    async def wait(self):
        last_check = time.monotonic()
        while not self._shutdown.is_set():
            try:
                await asyncio.wait_for(self._shutdown.wait(), 1)
            except asyncio.TimeoutError:
                if self._clock.due(last_check):
                    self._clock.check()
                    last_check = time.monotonic()

    async def close(self):
        # Stop admission, cancel/drain bound work, then checkpoint storage.
        self._stopping = True
        try:
            if self._server is not None:
                await self._server.close()
                self._server = None
            if self._control is not None:
                self._control.stopping = True
            if self._task_host is not None:
                self._task_host.stopping = True
            if self._task_host_task is not None:
                self._task_host_task.cancel()
                await asyncio.gather(self._task_host_task, return_exceptions=True)
                self._task_host_task = None
            if self._control_task is not None:
                self._control_task.cancel()
                await asyncio.gather(self._control_task, return_exceptions=True)
                self._control_task = None
            if self._activities is not None:
                await self._activities.close()
                self._activities = None
            if self._providers is not None:
                await self._providers.close()
                self._providers = None
            if self._scratch is not None:
                await self._scratch.close()
                self._scratch = None
            if self._catalog is not None:
                self._catalog.close()
                self._catalog = None
            if self._conn is not None:
                if self._started and not self._handlers.stop_requested:
                    self._runtime_fact("runtime_stopping", {"instance_id": self.instance_id, "reason_code": "local_shutdown"})
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
            for signum, previous in self._signals.items():
                signal.signal(signum, previous)
            self._signals.clear()
            if self._lock is not None:
                self._lock.release()
                self._lock = None
            self._started = False
