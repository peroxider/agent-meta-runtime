"""Durable invocation journal for the trusted in-process Host.

Request input/output are CAS artifacts. No native handles are invented: the
backend reference is a versioned journal key, not an execution binding.
"""

import json

from ...domain.authority import ScopeTarget, authorize
from ...domain.canonical import canonical_json, now_us, sha256_hex
from ...domain.context_projection import ProjectionManifest, Section, render_sections
from ...domain.errors import ErrorCode, StableError
from ...domain.host_contract import ContextProjection, TaskEnvelope
from ...domain.host_profile import TRUSTED_HOST_PROFILE_HASH
from ...domain.context_contract import (ContextSnapshot, FrozenContextSource, build_projection_input,
    context_document, context_profile_references, policy_schema_references)
from ...domain.ids import new_uuid7
from ...domain.provider_accounting import ProviderReservation
from ...ports.repositories import FactAppendRequest, OutboxRequest
from ...domain.semantics import TASK_TERMINAL_STATUSES, TaskBudget
from .authority import _GRANT_COLUMNS, _grant_from_row, _reserve_use_row
from .semantic import (InvocationCreateRequest, InvocationFinishRequest, TaskTerminalRequest,
    advance_invocation, complete_task, create_invocation, finish_invocation, load_task, start_task, _append_edge)
from .task_snapshot import register_staged_artifact
from .provider_accounting import accounting_fact, cost_liability, read_provider, settle, update_cost_totals
from .provider_dispatch import authorize_dispatch
from .provider_admission import authorize_configuration


class HostExecutionStore:
    def __init__(self, conn, *, catalog, run_command, realm_id, service_id, profile_hash=TRUSTED_HOST_PROFILE_HASH, run_project=None, run_token=None):
        self.conn, self.catalog, self.run_command = conn, catalog, run_command
        self.realm_id, self.service_id = realm_id, service_id
        self.profile_hash = profile_hash
        self.run_project = run_project or run_command
        self.run_token = run_token or run_command

    def stage(self, content):
        path = self.catalog.cas.put(content)
        return {"content": content, "artifact_id": "artifact://sha256/" + sha256_hex(content),
                "manifest": {"storage_relpath": path, "size_bytes": len(content)}}

    def read_artifact(self, reference):
        return self.catalog.read_artifact(reference)

    def candidates(self):
        return self.conn.execute("SELECT task_id,serving_composition_id FROM tasks WHERE realm_id=? AND status IN ('ACCEPTED','RUNNING') ORDER BY accepted_at_us", (self.realm_id,)).fetchall()

    def check(self, task_id):
        record = load_task(self.conn, task_id)
        if record is None or record.status in TASK_TERMINAL_STATUSES:
            raise asyncio_cancelled()
        if self.conn.execute("SELECT 1 FROM facts WHERE entity_id=? AND event_type='task_cancel_requested'", (task_id,)).fetchone():
            raise asyncio_cancelled()
        if record.deadline_at_us is not None and now_us() >= record.deadline_at_us:
            raise StableError(code=ErrorCode.DEADLINE_EXCEEDED, message="Task deadline exceeded")
        return record

    def envelope(self, task_id, bound):
        record = self.check(task_id)
        row = self.conn.execute("SELECT payload_json FROM facts WHERE entity_id=? AND event_type='task_accepted' ORDER BY seq LIMIT 1", (task_id,)).fetchone()
        reference = json.loads(row[0]).get("acceptance_view_artifact_id") if row else None
        if reference is None:
            raise StableError(code=ErrorCode.DATA_LOSS, message="Task has no durable acceptance View")
        raw = self.catalog.read_artifact(reference)
        view = json.loads(raw)
        if not isinstance(view, dict) or view.get("schema") != "task-acceptance-view/v1":
            raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="invalid frozen Task acceptance View")
        if view.get("backend_profile_hash") != self.profile_hash:
            raise StableError(code=ErrorCode.CONTRACT_INCOMPATIBLE, message="frozen Task execution profile is unavailable")
        if view["composition_id"] != record.serving_composition_id or view["package_artifact_id"] != bound.manifest["package_artifact_id"] or view["composition"] != bound.composition:
            raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="Task package differs from frozen acceptance View")
        manifest_raw = self.catalog.read_artifact(view["harness_manifest_artifact_id"])
        if json.loads(manifest_raw) != bound.manifest:
            raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="Task manifest differs from bound package")
        surface_content = self.catalog.read_artifact(record.capability_surface_artifact_id)
        context = self._context(view, bound, surface_content)
        return TaskEnvelope(record.task_id, record.realm_id, record.actor_id, record.root_action_id,
            record.input_artifact_id, self.catalog.read_artifact(record.input_artifact_id),
            record.serving_composition_id, record.serving_revision, record.capability_surface_artifact_id,
            surface_content, tuple(sorted(record.state_snapshot.items())),
            record.budget, view["meta_revision"], bound.loop_policy, record.deadline_at_us,
            canonical_json(view["composition"]), reference, raw, manifest_raw, context)

    def _context(self, view, bound, surface_content):
        profile_ref = view.get("context_profile_artifact_id")
        if profile_ref is None or profile_ref != bound.context_profile_artifact_id:
            raise StableError(code=ErrorCode.CONTRACT_INCOMPATIBLE, message="frozen Context profile is unavailable")
        artifacts = {}
        def read(ref):
            if ref not in artifacts:
                artifacts[ref] = self.catalog.read_artifact(ref)
            return artifacts[ref]
        profile, refs = context_profile_references(read(profile_ref))
        for ref in refs:
            read(ref)
        policy, schemas = policy_schema_references(read(profile["policy_artifact_id"]))
        for ref in schemas:
            read(ref)
        for operation in context_document(surface_content)["operations"]:
            if operation["operation_id"] in policy["selected_operation_ids"]:
                for direction in ("input", "output"):
                    read("artifact://sha256/" + operation[direction + "_schema_hash"])
        data = view["context_sources"]
        constitution = data["constitution_artifact_id"]
        sources = [FrozenContextSource("constitution", constitution, self.catalog.read_artifact(constitution)),
            FrozenContextSource("runtime", bound.composition_id, canonical_json(data["runtime"]))]
        sources.extend(FrozenContextSource("fact", item["fact_id"], canonical_json(item)) for item in data["facts"])
        return ContextSnapshot(profile_ref, tuple(sorted(artifacts.items())), tuple(sources), data["facts_available"])

    def start(self, task_id):
        if self.check(task_id).status == "ACCEPTED":
            self.run_command(start_task(task_id))

    def finish_task(self, task_id, status, *, content=None, error=None):
        record = load_task(self.conn, task_id)
        if record is None or record.status in TASK_TERMINAL_STATUSES:
            return
        staged = self.stage(content) if content is not None else None
        def finish(txn):
            if staged is not None:
                register_staged_artifact(txn, staged, kind="task_result")
            pending = txn._conn.execute("SELECT i.invocation_id,i.status FROM invocations i JOIN actions a ON a.action_id=i.action_id WHERE a.task_id=? AND i.status IN ('CREATED','DISPATCHED','RUNNING')", (task_id,)).fetchall()
            for invocation_id, old in pending:
                if old == "CREATED":
                    advance_invocation(invocation_id, "DISPATCHED")(txn)
                usage, _ = settle(txn, invocation_id, outcome=None, usage=None,
                    output_artifact_id=None, error=ErrorCode.EXTERNAL_EFFECT_UNKNOWN)
                if usage is not None:
                    txn._conn.execute("UPDATE invocations SET usage_json=? WHERE invocation_id=?", (canonical_json(usage), invocation_id))
                finish_invocation(InvocationFinishRequest(invocation_id, error=ErrorCode.EXTERNAL_EFFECT_UNKNOWN,
                    reason_code="OUTCOME_UNKNOWN"))(txn)
                self._backend_unknown(txn, invocation_id)
            if pending:
                update_cost_totals(txn, task_id)
            return complete_task(task_id, TaskTerminalRequest(status,
                result_artifact_id=staged["artifact_id"] if staged else None, error=error,
                reason_code=error or "COMPLETED"))(txn)
        self.run_command(finish)

    def _grant(self, txn, subject, permission, capability_id, composition_id):
        epoch = txn._conn.execute("SELECT epoch_id FROM realms WHERE realm_id=?", (self.realm_id,)).fetchone()[0]
        principal = txn._conn.execute("SELECT status FROM principals WHERE principal_id=? AND realm_id=?", (subject, self.realm_id)).fetchone()
        if principal is None or principal[0] != "ACTIVE":
            raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="Host principal is inactive")
        rows = txn._conn.execute(f"SELECT {_GRANT_COLUMNS} FROM authority_grants WHERE subject_id=? ORDER BY grant_id", (subject,)).fetchall()
        service_grants = None
        if subject == self.service_id:
            activation = txn._conn.execute("SELECT payload_json FROM facts WHERE realm_id=? AND event_type='harness_activated' AND json_extract(CAST(payload_json AS TEXT),'$.phase')='requested' AND json_extract(CAST(payload_json AS TEXT),'$.composition_id')=? ORDER BY seq DESC LIMIT 1", (self.realm_id, composition_id)).fetchone()
            service_grants = set(json.loads(activation[0])["grant_ids"]) if activation else set()
        for row in rows:
            grant = _grant_from_row(row)
            if service_grants is not None and grant.grant_id not in service_grants:
                continue
            count = txn._conn.execute("SELECT COUNT(*) FROM authority_uses WHERE grant_id=?", (grant.grant_id,)).fetchone()[0]
            if authorize(grant, subject_id=subject, permission=permission, resource_realm=self.realm_id,
                resource_target=ScopeTarget("CAPABILITY", capability_id), epoch_id=epoch, now_us=txn.recorded_at_us, uses_count=count) is None:
                # Amount ceilings are not yet implemented by this Host. Never
                # silently accept one merely because the permission matches.
                if grant.constraints.resource_ceiling:
                    continue
                return grant.grant_id
        raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="Host invocation authority denied")

    def reserve(self, task, *, ordinal, kind, capability_id, operation, content, projection_id=None, provider=None, provider_request=None):
        if provider is not None and (kind != "MODEL" or type(provider) is not ProviderReservation):
            raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="Provider reservation requires a model invocation")
        staged = self.stage(content)
        request_id = f"{task.task_id}/invocation/{ordinal}"
        def reserve(txn):
            self.check(task.task_id)
            old = txn._conn.execute("SELECT invocation_id,status,input_artifact_id,output_artifact_id,error_json,backend_ref_json FROM invocations WHERE action_id=? AND json_extract(CAST(backend_ref_json AS TEXT),'$.ordinal')=?", (task.root_action_id, ordinal)).fetchone()
            if old is not None:
                journal = json.loads(old[5])
                old_provider = read_provider(txn._conn, old[0], journal)
                core = {key: value for key, value in journal.items() if key not in ("backend", "provider", "provider_dispatch")}
                if core != {"schema": "host-invocation-journal/v1", "ordinal": ordinal, "request_id": request_id, "request_hash": sha256_hex(content)} or old[2] != staged["artifact_id"]:
                    raise StableError(code=ErrorCode.IDEMPOTENCY_CONFLICT, message="replayed Host invocation request differs")
                if (journal.get("provider", {}).get("reservation") != (provider.document() if provider else None)):
                    raise StableError(code=ErrorCode.IDEMPOTENCY_CONFLICT, message="replayed Provider reservation differs")
                if old[1] not in ("SUCCEEDED", "FAILED"):
                    raise StableError(code=ErrorCode.EXTERNAL_EFFECT_UNKNOWN, message="dispatched invocation outcome is unknown")
                if old_provider and old_provider["settlement"] and old_provider["settlement"]["overrun"]:
                    raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="Provider usage exceeded the admitted reservation")
                return {"invocation_id": old[0], "replay": True, "output_artifact_id": old[3], "error": json.loads(old[4]) if old[4] else None,
                    "raise_error": journal.get("backend", {}).get("raise_error", False)}
            if provider is not None and provider.configuration_fact_id is not None:
                if provider_request is None or getattr(provider_request,'request_id',None) != request_id:
                    raise StableError(code=ErrorCode.AUTHORITY_DENIED,message='configured Provider request identity differs')
                authorize_configuration(self,task,capability_id,provider,provider_request)
            invocation_id = "invocation://" + new_uuid7()
            required = set(operation["required_permissions"]) | ({"model.invoke"} if kind == "MODEL" else {"capability.invoke"})
            # Both the initiating principal and the scoped Harness Service need
            # the authority. The daemon's broad bootstrap grant is excluded.
            grants = {}
            for permission in sorted(required):
                for subject in (task.actor_id, self.service_id):
                    grant_id = self._grant(txn, subject, permission, capability_id, task.serving_composition_id)
                    grants.setdefault(grant_id, set()).add(permission)
            for grant_id, permissions in grants.items():
                _reserve_use_row(txn, grant_id, invocation_id, "host_invocation", {"permissions": sorted(permissions)})
            row = txn._conn.execute("SELECT budget_json,consumed_budget_json FROM tasks WHERE task_id=?", (task.task_id,)).fetchone()
            budget, consumed = json.loads(row[0]), json.loads(row[1])
            policy = json.loads(task.loop_policy_content)
            if kind == "MODEL":
                ceiling = min(budget["max_cost_microunits"], policy.get("max_cost_microunits", budget["max_cost_microunits"]))
                maximum = provider.maximum_cost_microunits if provider is not None else 0
                if cost_liability(txn._conn, task.task_id) + maximum > ceiling:
                    raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="Provider cost reservation exceeds Task budget")
            increments = {"steps": 1, "effects": int(set(operation["effects"]) != {"none"})}
            if kind == "MODEL":
                increments.update(turns=1, model_calls=1)
            for key, amount in increments.items():
                limit = min(budget["max_" + key], policy.get("max_" + key, budget["max_" + key]))
                if consumed.get(key, 0) + amount > limit:
                    raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="Task invocation budget exhausted")
                consumed[key] = consumed.get(key, 0) + amount
            if kind == "MODEL":
                # Reservation has no confirmed usage yet. An interrupted call
                # must never leave an apparent zero-cost total behind.
                consumed["cost_microunits"] = None
            register_staged_artifact(txn, staged, kind="invocation_input")
            create_invocation(InvocationCreateRequest(invocation_id, task.root_action_id, kind,
                capability_id + "#" + operation["operation_id"], staged["artifact_id"], context_projection_id=projection_id))(txn)
            journal = {"schema": "host-invocation-journal/v1", "ordinal": ordinal, "request_id": request_id, "request_hash": sha256_hex(content)}
            if provider is not None:
                journal["provider"] = {"reservation": provider.document(), "settlement": None}
            txn._conn.execute("UPDATE invocations SET backend_ref_json=? WHERE invocation_id=?", (canonical_json(journal), invocation_id))
            if provider is not None:
                accounting_fact(txn, invocation_id, "provider_cost_reserved", provider.document())
            txn._conn.execute("UPDATE tasks SET consumed_budget_json=? WHERE task_id=?", (canonical_json(consumed), task.task_id))
            txn._conn.execute("UPDATE actions SET consumed_budget_json=? WHERE action_id=?", (canonical_json(consumed), task.root_action_id))
            advance_invocation(invocation_id, "DISPATCHED")(txn)
            advance_invocation(invocation_id, "RUNNING")(txn)
            return {"invocation_id": invocation_id, "replay": False}
        return self.run_command(reserve)

    def finish_invocation(self, invocation_id, *, content=None, error=None, usage=None, backend_result=None, provider_outcome=None, require_undispatched=False):
        staged = self.stage(content) if content is not None else None
        def finish(txn):
            terminal_error = error
            journal, _ = self._journal(txn._conn, invocation_id)
            if require_undispatched and "provider_dispatch" in journal:
                raise StableError(code=ErrorCode.EXTERNAL_EFFECT_UNKNOWN, message="Provider attempt may already have been submitted")
            if "provider" in journal and provider_outcome is None and content is None:
                terminal_error = ErrorCode.EXTERNAL_EFFECT_UNKNOWN
            final_usage, replay = settle(txn, invocation_id, outcome=provider_outcome, usage=usage,
                output_artifact_id=staged["artifact_id"] if staged else None, error=terminal_error)
            if replay:
                return {"provider_overrun": bool(journal.get("provider", {}).get("settlement", {}).get("overrun"))}
            if backend_result is not None:
                journal, action_id = self._journal(txn._conn, invocation_id)
                binding = journal.get("backend")
                if binding is None:
                    raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="Host Backend binding is absent")
                expected = {**binding, "terminal_status": "FAILED" if error else "SUCCEEDED",
                    "result_artifact_id": staged["artifact_id"] if staged else None, "error_code": error,
                    "raise_error": backend_result.get("raise_error", False), "ack_state": "PENDING"}
                expected["result_hash"] = sha256_hex(canonical_json({"code": error, "raise_error": expected["raise_error"]}) if error else staged["artifact_id"].encode())
                if backend_result != expected or binding.get("ack_state") != "NOT_TERMINAL":
                    raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="Host Backend terminal binding mismatch")
                journal["backend"] = expected
                txn._conn.execute("UPDATE invocations SET backend_ref_json=? WHERE invocation_id=?", (canonical_json(journal), invocation_id))
                txn._conn.execute("UPDATE execution_bindings SET status=?,last_observed_at_us=? WHERE backend_id=? AND semantic_id=? AND incarnation=?",
                    (expected["terminal_status"], txn.recorded_at_us, binding["backend_id"], invocation_id, binding["incarnation"]))
                self._execution_fact(txn, binding["instance_id"], action_id, "execution_status_observed",
                    {"invocation_id": invocation_id, "request_id": binding["request_id"], "status": expected["terminal_status"], "result_hash": expected["result_hash"]})
                txn.enqueue_outbox(OutboxRequest("BACKEND_TERMINAL_ACK", invocation_id + "/terminal-ack", self._ack_payload(invocation_id, expected), txn.recorded_at_us))
            if staged:
                register_staged_artifact(txn, staged, kind="invocation_output")
            if final_usage is not None:
                txn._conn.execute("UPDATE invocations SET usage_json=? WHERE invocation_id=?", (canonical_json(final_usage), invocation_id))
                task_id = txn._conn.execute("SELECT a.task_id FROM actions a JOIN invocations i ON i.action_id=a.action_id WHERE i.invocation_id=?", (invocation_id,)).fetchone()[0]
                update_cost_totals(txn, task_id)
            result = finish_invocation(InvocationFinishRequest(invocation_id,
                output_artifact_id=staged["artifact_id"] if staged else None, error=terminal_error))(txn)
            provider = read_provider(txn._conn, invocation_id, self._journal(txn._conn, invocation_id)[0])
            return {**result, "provider_overrun": bool(provider and provider["settlement"]["overrun"])}
        return self.run_command(finish)

    def authorize_provider(self, task, invocation_id, *, request, binding, authorization):
        return self.run_token(lambda txn: authorize_dispatch(self, txn, task, invocation_id, request, binding, authorization))

    @staticmethod
    def _journal(conn, invocation_id):
        row = conn.execute("SELECT backend_ref_json,action_id FROM invocations WHERE invocation_id=?", (invocation_id,)).fetchone()
        if row is None:
            raise StableError(code=ErrorCode.NOT_FOUND, message="Host Invocation is unavailable")
        return json.loads(row[0]), row[1]

    def _execution_fact(self, txn, instance_id, action_id, event, payload):
        return txn.append_fact(FactAppendRequest(entity_type="execution", entity_id=instance_id, event_type=event,
            schema_version=1, payload=payload, actor_id=self.service_id, action_id=action_id, occurred_at_us=txn.recorded_at_us))

    def authorize_backend(self, task, invocation_id, capability_id, audit):
        """Persist only verified public token audit, guarded by token.issue."""
        def record(txn):
            journal, action_id = self._journal(txn._conn, invocation_id)
            if action_id != task.root_action_id or audit.request_id != invocation_id or "backend" in journal:
                raise StableError(code=ErrorCode.IDEMPOTENCY_CONFLICT, message="Host execution authorization identity conflicts")
            rows = txn._conn.execute("SELECT instance_id FROM capability_instances WHERE realm_id=? AND composition_id=? AND capability_id=? AND status IN ('ACTIVE','DRAINING')",
                (self.realm_id, task.serving_composition_id, capability_id)).fetchall()
            if len(rows) != 1:
                raise StableError(code=ErrorCode.BACKEND_UNAVAILABLE, message="Host Capability instance is unavailable or ambiguous")
            result = {"instance_id": rows[0][0], "token_id": audit.token_id, "token_payload_hash": audit.payload_hash,
                "service_public_key_id": audit.service_public_key_id, "certificate_artifact_id": audit.certificate_artifact_id}
            self._execution_fact(txn, rows[0][0], action_id, "execution_submitted", {"invocation_id": invocation_id, "request_id": audit.request_id, **result})
            return result
        return self.run_token(record)

    def bind_backend(self, invocation_id, *, handle, payload_hash, audit):
        def bind(txn):
            journal, action_id = self._journal(txn._conn, invocation_id)
            if journal["request_hash"] != payload_hash or handle.request_id != invocation_id or not handle.opaque_handle or "backend" in journal:
                raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="Backend returned an invalid Host binding")
            binding = {**audit, "backend_id": handle.backend_id, "session_id": handle.session_id, "request_id": handle.request_id,
                "payload_hash": payload_hash, "handle_hash": sha256_hex(bytes(handle.opaque_handle)), "incarnation": handle.incarnation, "ack_state": "NOT_TERMINAL"}
            txn._conn.execute("INSERT INTO execution_bindings(backend_id,semantic_id,incarnation,request_id,payload_hash,handle_bytes,session_id,status,expires_at_us,last_observed_at_us) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (handle.backend_id, invocation_id, handle.incarnation, handle.request_id, payload_hash, bytes(handle.opaque_handle), handle.session_id, "RUNNING", handle.expires_at_us, txn.recorded_at_us))
            journal["backend"] = binding
            txn._conn.execute("UPDATE invocations SET backend_ref_json=? WHERE invocation_id=?", (canonical_json(journal), invocation_id))
            fact = self._execution_fact(txn, audit["instance_id"], action_id, "execution_bound", {"invocation_id": invocation_id, **binding})
            _append_edge(txn, fact_id=fact, edge_type="executed_as", from_id=invocation_id, to_id=audit["instance_id"])
            return binding
        return self.run_command(bind)

    @staticmethod
    def _ack_payload(invocation_id, binding):
        return {"invocation_id": invocation_id, **{key: binding[key] for key in ("backend_id", "session_id", "request_id", "result_hash")}}

    def check_ack(self, payload):
        journal, _ = self._journal(self.conn, payload["invocation_id"])
        binding = journal.get("backend", {})
        if self._ack_payload(payload["invocation_id"], binding) != payload or binding["ack_state"] not in ("PENDING", "ACKNOWLEDGED", "UNAVAILABLE_SESSION_LOST"):
            raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="Backend acknowledgement intent differs from committed terminal")
        return binding["ack_state"]

    def record_ack(self, payload, *, acknowledged):
        def record(txn):
            state = self.check_ack(payload)
            if state != "PENDING":
                return {}
            journal, action_id = self._journal(txn._conn, payload["invocation_id"])
            binding = journal["backend"]
            binding["ack_state"] = "ACKNOWLEDGED" if acknowledged else "UNAVAILABLE_SESSION_LOST"
            txn._conn.execute("UPDATE invocations SET backend_ref_json=? WHERE invocation_id=?", (canonical_json(journal), payload["invocation_id"]))
            self._execution_fact(txn, binding["instance_id"], action_id,
                "terminal_acknowledged" if acknowledged else "execution_status_observed",
                {**payload, "ack_state": binding["ack_state"]})
            return {}
        self.run_command(record)

    def backend_unknown(self, invocation_id):
        def record(txn):
            self._backend_unknown(txn, invocation_id)
            return {}
        self.run_command(record)

    def _backend_unknown(self, txn, invocation_id):
        journal, action_id = self._journal(txn._conn, invocation_id)
        binding = journal.get("backend")
        if binding is not None and binding["ack_state"] == "NOT_TERMINAL":
            txn._conn.execute("UPDATE execution_bindings SET status='UNKNOWN',last_observed_at_us=? WHERE backend_id=? AND semantic_id=?", (txn.recorded_at_us, binding["backend_id"], invocation_id))
            binding.update(terminal_status="UNKNOWN", ack_state="NOT_APPLICABLE")
            txn._conn.execute("UPDATE invocations SET backend_ref_json=? WHERE invocation_id=?", (canonical_json(journal), invocation_id))
            self._execution_fact(txn, binding["instance_id"], action_id, "external_effect_unknown", {"invocation_id": invocation_id, "request_id": binding["request_id"], "reason_code": "OUTCOME_UNKNOWN"})

    def interrupted(self, task_id):
        return self.conn.execute("SELECT 1 FROM invocations i JOIN actions a ON a.action_id=i.action_id WHERE a.task_id=? AND i.status IN ('CREATED','DISPATCHED','RUNNING')", (task_id,)).fetchone() is not None

    def save_projection(self, task, request):
        self.check(task.task_id)
        expected = build_projection_input(task)
        if request != expected:
            raise StableError(code=ErrorCode.INVALID_RESULT, message="Context projection differs from its frozen policy and source snapshot")
        if request.tokenizer_id != "utf8-bytes/v1" or request.budget_tokens > 1024 * 1024:
            raise StableError(code=ErrorCode.FEATURE_UNAVAILABLE, message="unsupported Host tokenizer or context ceiling")
        # The complete ordered refs were independently reconstructed above;
        # a package cannot submit new live sources or invent their provenance.
        # Policies/renderers are immutable registered artifacts. They are
        # provenance, never arbitrary code evaluated by this storage adapter.
        for reference in {request.policy_artifact_id, request.redaction_policy_artifact_id, *(s.renderer_artifact_id for s in request.sections)}:
            self.catalog.read_artifact(reference)
        sections = []
        stages = []
        for section in request.sections:
            section.content.decode("utf-8", errors="strict")
            if section.token_count != len(section.content):
                raise StableError(code=ErrorCode.INVALID_RESULT, message="projection token accounting differs from selected tokenizer")
            staged = self.stage(section.content)
            stages.append(staged)
            sections.append(Section(section.section_id, section.renderer_artifact_id, staged["artifact_id"], section.token_count))
        rendered = render_sections([section.content for section in request.sections])
        total = len(rendered)  # includes delimiters, independently counted
        identity = {"task_id": task.task_id, "policy": request.policy_artifact_id, "sources": [dict(kind=r.kind, ref=r.ref, content_hash=r.content_hash) for r in request.source_refs],
            "sections": [dict(section_id=s.section_id, renderer_artifact_id=s.renderer_artifact_id, output_artifact_id=s.output_artifact_id, token_count=s.token_count) for s in sections],
            "redaction": request.redaction_policy_artifact_id, "tokenizer": request.tokenizer_id, "budget": request.budget_tokens}
        request_hash = sha256_hex(canonical_json(identity))
        previous = self.conn.execute("SELECT projection_id FROM context_projections WHERE task_id=? AND json_extract(CAST(manifest_json AS TEXT),'$.x_request_hash')=?", (task.task_id, request_hash)).fetchone()
        projection_id = previous[0] if previous else "context://projection/" + new_uuid7()
        manifest = ProjectionManifest(projection_id, request.policy_artifact_id, task.serving_composition_id,
            task.accepted_meta_revision, request.source_refs, tuple(sections), request.redaction_policy_artifact_id,
            request.tokenizer_id, total, request.budget_tokens)
        manifest_value = {**manifest.required_fields(), "x_task_id": task.task_id,
            "x_identity_hash": manifest.identity_hash(), "x_request_hash": request_hash}
        rendered_stage, manifest_stage = self.stage(rendered), self.stage(canonical_json(manifest_value))
        def save(txn):
            self.check(task.task_id)
            for staged in [*stages, rendered_stage, manifest_stage]:
                register_staged_artifact(txn, staged, kind="context_projection")
            inserted = txn._conn.execute("INSERT OR IGNORE INTO context_projections(projection_id,task_id,action_id,policy_artifact_id,composition_id,meta_revision,manifest_json,rendered_artifact_id,created_at_us) VALUES (?,?,?,?,?,?,?,?,?)",
                (projection_id, task.task_id, task.root_action_id, request.policy_artifact_id, task.serving_composition_id, task.accepted_meta_revision, manifest_stage["content"], rendered_stage["artifact_id"], txn.recorded_at_us))
            if inserted.rowcount:
                txn.append_fact(FactAppendRequest(entity_type="artifact", entity_id=manifest_stage["artifact_id"], event_type="artifact_registered",
                    schema_version=1, payload={"kind": "context_projection", "artifact_id": manifest_stage["artifact_id"],
                        "projection_id": projection_id, "task_id": task.task_id}, actor_id=self.service_id, action_id=task.root_action_id,
                    occurred_at_us=txn.recorded_at_us))
            return {}
        self.run_project(save)
        return ContextProjection(manifest, rendered_stage["artifact_id"], rendered)


def asyncio_cancelled():
    # Keep cancellation a control signal; no new stable public error code.
    from asyncio import CancelledError
    return CancelledError()
