"""Installed AMPAK instances for the explicitly trusted in-process profile.

This owns actual Python adapter lifetimes and durable Capability instances. It
never manufactures a Backend handle or treats a registration row as health.
"""

import asyncio
from dataclasses import dataclass
import json

from ..domain.canonical import canonical_json, now_us
from ..domain.authority import authorize
from ..domain.errors import ErrorCode, StableError
from ..domain.fact_catalog import validate_fact_event
from ..domain.host_contract import HealthProbeInvocation, HealthStatus
from ..domain.ids import new_uuid7
from ..ports.repositories import FactAppendRequest, OutboxRequest
from .harness_loader import HarnessPackageLoader
from .store.authority import load_grant_row


@dataclass
class BoundHarness:
    harness_id: str
    composition_id: str
    manifest: dict
    composition: dict
    descriptors: dict
    adapter: object
    loop_policy: bytes
    context_profile_artifact_id: str | None = None


class InstalledHarnessCatalog:
    def __init__(self, conn, *, cas, realm_id, service_id, run_command, validate_package):
        self.conn, self.cas, self.realm_id = conn, cas, realm_id
        self.service_id, self.run_command = service_id, run_command
        self.validate_package = validate_package
        self.bindings, self.loaders, self.instances = {}, {}, {}
        self.healthy = set()
        self.restore_outcomes = {}

    def read_artifact(self, artifact_id):
        row = self.conn.execute("SELECT manifest_json,integrity_status FROM artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
        if row is None or row[1] != "VALID":
            raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="Host artifact is missing or invalid")
        manifest = json.loads(row[0])
        if "storage_relpath" not in manifest or "size_bytes" not in manifest:
            raise StableError(code=ErrorCode.DATA_LOSS, message="Host artifact has no stored content")
        return self.cas.open_blob(manifest["storage_relpath"], artifact_id.rsplit("/", 1)[1], manifest["size_bytes"])

    def _fact(self, txn, capability_id, instance_id, old, new, *, request_id, composition_id, slot, reason_code="HOST_INSTANCE"):
        payload = {"reason_code": reason_code, "old_status": old, "new_status": new,
                   "instance_id": instance_id, "request_id": request_id, "composition_id": composition_id, "slot": slot}
        validate_fact_event("capability", "instance_transitioned", 1, payload)
        return txn.append_fact(FactAppendRequest(entity_type="capability", entity_id=capability_id,
            event_type="instance_transitioned", schema_version=1, payload=payload,
            actor_id=self.service_id, occurred_at_us=txn.recorded_at_us))

    def binding(self, composition_id):
        if composition_id in self.bindings:
            return self.bindings[composition_id]
        row = self.conn.execute(
            "SELECT DISTINCT h.harness_id,h.manifest_artifact_id,h.package_artifact_id,c.body_json FROM harness_installations h "
            "JOIN harness_installation_history x ON x.harness_id=h.harness_id JOIN compositions c ON c.composition_id=x.composition_id "
            "WHERE x.composition_id=? AND h.realm_id=? AND h.status!='UNINSTALLED'",
            (composition_id, self.realm_id),
        ).fetchall()
        if len(row) != 1:
            raise StableError(code=ErrorCode.CONTRACT_INCOMPATIBLE, message="composition has no unique installed Harness owner")
        harness_id, manifest_id, package_id, raw_body = row[0]
        report = self.validate_package(manifest_id)
        if not report["valid"] or report["trust_class"] != "builtin_or_signed":
            raise StableError(code=ErrorCode.FEATURE_UNAVAILABLE, message="Host requires an explicitly trusted verified publisher")
        manifest = json.loads(self.read_artifact(manifest_id))
        composition = json.loads(raw_body)
        descriptors = {}
        for reference in manifest["capability_descriptor_artifact_ids"]:
            descriptor = json.loads(self.read_artifact(reference))
            descriptors[(descriptor["capability_id"], descriptor["descriptor_revision"])] = descriptor
        for slot in composition["slots"].values():
            descriptor = descriptors.get((slot["capability_id"], slot["descriptor_revision"]))
            if descriptor is None or descriptor["placement"] != "in_process" or slot.get("placement") != "in_process" or descriptor["artifact_id"] != package_id or slot["artifact_id"] != package_id:
                raise StableError(code=ErrorCode.FEATURE_UNAVAILABLE, message="Host has no compatible in-process placement for this slot")
        if package_id not in self.loaders:
            self.loaders[package_id] = HarnessPackageLoader(package_id, self.read_artifact(package_id))
        bound = BoundHarness(harness_id, composition_id, manifest, composition, descriptors, None,
                             self.read_artifact(manifest["loop_policy_artifact_id"]),
                             self.loaders[package_id].manifest.package.runtime_constraints.get("context_profile_artifact_id"))
        self.bindings[composition_id] = bound
        return bound

    async def instantiate(self, request):
        bound = self.binding(request["composition_id"])
        key = (request["composition_id"], request["slot"])
        if key in self.instances:
            return {"instance_id": self.instances[key]}
        def register(txn):
            previous = txn._conn.execute(
                "SELECT i.instance_id,i.status,i.binding_incarnation FROM capability_instances i JOIN facts f "
                "ON json_extract(CAST(f.payload_json AS TEXT),'$.instance_id')=i.instance_id "
                "WHERE f.realm_id=? AND f.event_type='instance_transitioned' "
                "AND json_extract(CAST(f.payload_json AS TEXT),'$.request_id')=? ORDER BY f.seq DESC LIMIT 1",
                (self.realm_id, request["request_id"]),
            ).fetchone()
            if previous is None:
                instance_id, old, incarnation = "instance://" + new_uuid7(), "DEFINED", 1
                txn._conn.execute("INSERT INTO capability_instances(instance_id,realm_id,capability_id,descriptor_revision,composition_id,placement,trust_class,status,binding_incarnation,created_at_us,updated_at_us) VALUES (?,?,?,?,?,'in_process','builtin_or_signed','INSTANTIATING',?,?,?)",
                    (instance_id, self.realm_id, request["capability_id"], request["descriptor_revision"], request["composition_id"], incarnation, txn.recorded_at_us, txn.recorded_at_us))
            else:
                instance_id, old, incarnation = previous[0], previous[1], (previous[2] or 0) + 1
                txn._conn.execute("UPDATE capability_instances SET status='INSTANTIATING',binding_incarnation=?,updated_at_us=? WHERE instance_id=?",
                                 (incarnation, txn.recorded_at_us, instance_id))
            self._fact(txn, request["capability_id"], instance_id, old, "INSTANTIATING",
                       request_id=request["request_id"], composition_id=bound.composition_id, slot=request["slot"])
            return {"instance_id": instance_id}
        receipt = self.run_command(register)
        self.instances[key] = receipt["instance_id"]
        if bound.adapter is None:
            try:
                bound.adapter = self.loaders[bound.manifest["package_artifact_id"]].instantiate(trust_class="builtin_or_signed", placement="in_process")
            except BaseException:
                def failed(txn):
                    txn._conn.execute("UPDATE capability_instances SET status='FAILED',updated_at_us=? WHERE instance_id=?", (txn.recorded_at_us, receipt["instance_id"]))
                    self._fact(txn, request["capability_id"], receipt["instance_id"], "INSTANTIATING", "FAILED",
                               request_id=request["request_id"], composition_id=bound.composition_id, slot=request["slot"])
                    return {}
                self.run_command(failed)
                raise
        return receipt

    async def probe(self, request):
        bound = self.bindings.get(request["composition_id"])
        if bound is None:
            raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="probe has no live adapter")
        slot = bound.composition["slots"][request["slot"]]
        descriptor = bound.descriptors[(slot["capability_id"], slot["descriptor_revision"])]
        operation = next((item for item in descriptor["operations"] if item["operation_id"] == request["operation_id"]), None)
        if operation is None or set(operation["effects"]) - {"none"} or operation["idempotency"] != "PURE":
            raise StableError(code=ErrorCode.CONTRACT_INCOMPATIBLE, message="health operation must be declared PURE without external effects")
        result = await bound.adapter.probe(HealthProbeInvocation(request["request_id"], request["slot"],
            descriptor["capability_id"], descriptor["descriptor_revision"], request["operation_id"], now_us() + request["timeout_ms"] * 1000))
        if not isinstance(result, HealthStatus):
            raise StableError(code=ErrorCode.INVALID_RESULT, message="health callback returned an invalid value")
        key = (bound.composition_id, request["slot"])
        instance_id = self.instances[key]
        status = {"READY": "ACTIVE", "DEGRADED": "DEGRADED", "UNHEALTHY": "FAILED"}[result.status]
        def observe(txn):
            old = txn._conn.execute("SELECT status FROM capability_instances WHERE instance_id=?", (instance_id,)).fetchone()[0]
            txn._conn.execute("UPDATE capability_instances SET status=?,updated_at_us=? WHERE instance_id=?", (status, txn.recorded_at_us, instance_id))
            self._fact(txn, descriptor["capability_id"], instance_id, old, status,
                       request_id=request["request_id"], composition_id=bound.composition_id, slot=request["slot"])
            return {}
        self.run_command(observe)
        if result.status == "READY" or result.status == "DEGRADED" and slot["criticality"] == "OPTIONAL":
            self.healthy.add(key)
        else:
            self.healthy.discard(key)
        return {"status": result.status, "reason_code": result.reason_code}

    def healthy_for(self, composition_id):
        bound = self.bindings.get(composition_id)
        return bound is not None and bound.context_profile_artifact_id is not None and bool(bound.composition["slots"]) and all((composition_id, slot) in self.healthy for slot in bound.composition["slots"])

    def serving_healthy(self, revision):
        principal = self.conn.execute("SELECT status FROM principals WHERE principal_id=? AND realm_id=?", (self.service_id, self.realm_id)).fetchone()
        if principal is None or principal[0] != "ACTIVE":
            return False
        epoch = self.conn.execute("SELECT epoch_id FROM realms WHERE realm_id=?", (self.realm_id,)).fetchone()[0]
        control_available = False
        for (grant_id,) in self.conn.execute("SELECT grant_id FROM authority_grants WHERE subject_id=? AND parent_grant_id IS NULL", (self.service_id,)):
            grant = load_grant_row(self.conn, grant_id)
            uses = self.conn.execute("SELECT COUNT(*) FROM authority_uses WHERE grant_id=?", (grant_id,)).fetchone()[0]
            if authorize(grant, subject_id=self.service_id, permission="runtime.reconcile", resource_realm=self.realm_id,
                resource_target=None, epoch_id=epoch, now_us=now_us(), uses_count=uses) is None:
                control_available = True
                break
        if not control_available:
            return False
        row = self.conn.execute("SELECT composition_id FROM compositions WHERE realm_id=? AND revision=?", (self.realm_id, revision)).fetchone()
        return row is not None and self.healthy_for(row[0])

    def restore_plans(self):
        """Serving and frozen live Tasks, independent of the desired candidate."""
        rows = self.conn.execute(
            "SELECT c.composition_id,c.revision,c.body_hash,c.body_json FROM compositions c WHERE c.realm_id=? AND "
            "(c.revision=(SELECT serving_revision FROM composition_refs WHERE realm_id=?) OR "
            "c.composition_id IN (SELECT serving_composition_id FROM tasks WHERE realm_id=? AND status IN ('ACCEPTED','RUNNING'))) ORDER BY c.revision",
            (self.realm_id, self.realm_id, self.realm_id)).fetchall()
        return [{"realm_id": self.realm_id, "composition_id": row[0], "revision": row[1], "body_hash": row[2], "body": json.loads(row[3])} for row in rows]

    def withdraw_health(self, composition_id, slot):
        self.healthy.discard((composition_id, slot))

    def complete_restore(self, composition_id, passed):
        self.restore_outcomes[composition_id] = passed
        if not passed:
            def unavailable(txn):
                rows = txn._conn.execute("SELECT instance_id,capability_id,status FROM capability_instances WHERE realm_id=? AND composition_id=? AND status!='RELEASED'", (self.realm_id, composition_id)).fetchall()
                for instance_id, capability_id, old in rows:
                    txn._conn.execute("UPDATE capability_instances SET status='FAILED',updated_at_us=? WHERE instance_id=?", (txn.recorded_at_us, instance_id))
                    self._fact(txn, capability_id, instance_id, old, "FAILED", request_id="host-rebind:" + composition_id,
                        composition_id=composition_id, slot="recovery", reason_code="HOST_REBIND_UNAVAILABLE")
                return {}
            self.run_command(unavailable)

    def recovery_failed(self, composition_id):
        return self.restore_outcomes.get(composition_id) is False

    async def drain(self, request):
        old = request["old_serving_revision"]
        if old == 0 or old == request["new_serving_revision"]:
            return {}
        row = self.conn.execute("SELECT composition_id FROM compositions WHERE realm_id=? AND revision=?", (self.realm_id, old)).fetchone()
        if row is None:
            return {}
        composition_id = row[0]
        deadline = asyncio.get_running_loop().time() + 30
        while self.conn.execute("SELECT 1 FROM tasks WHERE serving_composition_id=? AND status IN ('ACCEPTED','RUNNING') LIMIT 1", (composition_id,)).fetchone():
            if asyncio.get_running_loop().time() >= deadline:
                raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="old Harness still has live Tasks")
            await asyncio.sleep(.02)
        def release(txn):
            txn._conn.execute("UPDATE capability_instances SET status='RELEASED',updated_at_us=? WHERE composition_id=? AND realm_id=?", (txn.recorded_at_us, composition_id, self.realm_id))
            return {}
        self.run_command(release)
        self.healthy = {key for key in self.healthy if key[0] != composition_id}
        self.bindings.pop(composition_id, None)
        return {}

    def prepare_restart(self, instance_id):
        refs = self.conn.execute("SELECT desired_revision,reconcile_status,serving_revision,realized_revision FROM composition_refs WHERE realm_id=?", (self.realm_id,)).fetchone()
        if refs is None or refs[0] == 0 or refs[1] not in ("READY", "APPLYING", "RETRYING", "DEGRADED") or refs[1] == "READY" and refs[0] == refs[2] == refs[3]:
            return
        def retry(txn):
            txn._conn.execute("UPDATE composition_refs SET reconcile_status='RETRYING' WHERE realm_id=?", (self.realm_id,))
            txn.enqueue_outbox(OutboxRequest(kind="RECONCILE_REQUEST", dedupe_key=f"host-rebind:{instance_id}",
                payload={"revision": refs[0]}, available_at_us=txn.recorded_at_us))
            return {}
        self.run_command(retry)

    def close(self):
        for loader in self.loaders.values():
            loader.close()
        self.loaders.clear()
        self.bindings.clear()
        self.healthy.clear()
