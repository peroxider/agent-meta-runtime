"""Reconciler state machine (§41.38, §41.59.2/3/4).

One reconcile cycle is the fixed single round: a short read of the three
composition refs (A), a pure DAG plan over the desired slots (B), a short
transaction flipping the cycle to ``APPLYING`` and enqueuing a
``RECONCILE_REQUEST`` outbox item (C), external slot work strictly outside
any store transaction (D), a per-slot short transaction committing each
observation as Facts (E), the serving cutover short transaction that binds
planned state revisions and CASes ``serving`` in one terminal transaction
(F), the external drain (G), and the final short transaction CASing
``realized`` to the desired revision (H).

``reconcile_id`` is derived from realm, desired revision and body hash, so
every external request id is stable across crash-resumed retries: work may
replay but only one cycle ever settles. The serving cutover CAS makes a
superseded cycle lose cleanly without touching progress; a failed gate
never moves serving (the old composition keeps serving). State migration
targets are registered externally and bound only inside the terminal
transaction — a failed cutover leaves them unbound and auditable.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from ..adapters.store import (
    SetRealizedRequest,
    SetServingRequest,
    StateMigrationCutoverRequest,
    StateRevisionRegistration,
    execute_command,
    migrate_state_cutover,
    set_realized,
    set_serving,
)
from ..adapters.store.harness import settle_harness_for_cutover
from ..domain.deadline import Deadline
from ..domain.envelope import CommandEnvelope
from ..domain.errors import ErrorCode, StableError
from ..domain.ids import new_uuid7
from ..domain.outbox import outbox_dedupe_key
from ..domain.probe import HealthProbeDescriptor
from ..ports.repositories import FactAppendRequest, OutboxRequest
from .probes import ProbeRunner

__all__ = [
    "UnknownOutcomeError",
    "ReconcileObservation",
    "SlotOutcome",
    "ReconcileOutcome",
    "Reconciler",
    "reconcile_id",
    "slot_request_id",
    "topological_slots",
]

SlotExecutor = Callable[[Mapping[str, Any]], Mapping[str, Any]]
DrainExecutor = Callable[[Mapping[str, Any]], Mapping[str, Any]]

#: Executor contract: the returned mapping may carry ``instance_id`` and
#: ``state_bindings`` (list of StateRevisionRegistration-shaped dicts with
#: state_id / source_revision_id / schema_id / artifact_id /
#: state_revision_id). A raise means the slot failed;
#: :class:`UnknownOutcomeError` means the external effect may or may not
#: have happened (§41.31 UNKNOWN handling).


class UnknownOutcomeError(Exception):
    """External call ended in an UNKNOWN outcome (§41.31, §41.38)."""


def reconcile_id(realm_id: str, desired_revision: int, body_hash: str) -> str:
    """Stable cycle id: identical for every retry of the same desired state."""

    preimage = b"\x00".join(
        part.encode("utf-8")
        for part in ("reconcile", realm_id, str(desired_revision), body_hash)
    )
    return hashlib.sha256(preimage).hexdigest()


def slot_request_id(reconcile: str, slot: str, operation: str) -> str:
    """Stable external request id for one slot operation in one cycle."""

    preimage = b"\x00".join(
        part.encode("utf-8")
        for part in ("slot", reconcile, slot, operation)
    )
    return hashlib.sha256(preimage).hexdigest()


def topological_slots(body: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    """Slots in wiring DAG order (Kahn, deterministic by name); cycle → error."""

    slots = body.get("slots")
    if not isinstance(slots, dict) or not slots:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="composition body must declare a slots mapping",
        )
    edges: dict[str, set[str]] = {name: set() for name in slots}  # slot → providers
    indegree = {name: 0 for name in slots}
    wiring = body.get("wiring", []) or []
    if not isinstance(wiring, list):
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT, message="wiring must be a list"
        )
    for entry in wiring:
        consumer, provider = entry.get("consumer_slot"), entry.get("provider_slot")
        if consumer in slots and provider in slots and provider not in edges[consumer]:
            edges[consumer].add(provider)
            indegree[consumer] += 1
    ready = sorted(name for name, degree in indegree.items() if degree == 0)
    order: list[str] = []
    while ready:
        name = ready.pop(0)
        order.append(name)
        for consumer, providers in edges.items():
            if name in providers:
                providers.discard(name)
                indegree[consumer] -= 1
                if indegree[consumer] == 0:
                    ready.append(consumer)
        ready.sort()
    if len(order) != len(slots):
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="composition wiring contains a cycle",
        )
    return tuple(
        {
            "slot": name,
            "criticality": slots[name].get("criticality", "REQUIRED"),
            "degradation_policy": slots[name].get("degradation_policy", "REJECT_TASK"),
            "health_probe": slots[name].get("health_probe"),
            "capability_id": slots[name].get("capability_id", ""),
            "descriptor_revision": slots[name].get("descriptor_revision", 0),
        }
        for name in order
    )


@dataclass(frozen=True, slots=True)
class ReconcileObservation:
    """Short-read snapshot of one realm's refs and desired body (A)."""

    desired_revision: int
    serving_revision: int
    realized_revision: int
    desired_cas: int
    serving_cas: int
    realized_cas: int
    reconcile_status: str
    composition_id: str
    body: Mapping[str, Any]
    body_hash: str


@dataclass(frozen=True, slots=True)
class SlotOutcome:
    """One slot's external + probe result with its gate decision (D/E)."""

    slot: str
    passed: bool
    status: str
    reason_code: str
    instance_id: str
    state_bindings: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    attempts: int = 1
    fact_ids: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class ReconcileOutcome:
    """Cycle verdict over the frozen status vocabulary."""

    status: str  # CONVERGED | ALREADY_CONVERGED | FAILED | UNKNOWN | DEGRADED | SUPERSEDED
    reconcile_id: str
    desired_revision: int
    serving_revision: int
    realized_revision: int
    slots: tuple[SlotOutcome, ...] = field(default_factory=tuple)
    reason_code: str = ""
    detail: str = ""


class Reconciler:
    """Orchestrates the A–H round; all external calls run outside txns."""

    def __init__(
        self,
        conn: Any,
        *,
        realm_id: str,
        slot_executor: SlotExecutor,
        drain_executor: DrainExecutor | None = None,
        probe_runner: ProbeRunner | None = None,
        actor_id: str | None = None,
        command_deadline_us: int = 5_000_000,
    ) -> None:
        self._conn = conn
        self._realm_id = realm_id
        self._slot_executor = slot_executor
        self._drain_executor = drain_executor
        self._probe_runner = probe_runner
        self._actor_id = actor_id or f"principal://service/{new_uuid7()}"
        self._command_deadline_us = command_deadline_us

    # -- short read (A) --------------------------------------------------------
    def read_state(self) -> ReconcileObservation:
        row = self._conn.execute(
            "SELECT desired_revision, serving_revision, realized_revision,"
            " desired_cas, serving_cas, realized_cas, reconcile_status"
            " FROM composition_refs WHERE realm_id = ?",
            (self._realm_id,),
        ).fetchone()
        if row is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message=f"no composition refs for realm: {self._realm_id}",
            )
        desired = int(row[0])
        if desired == 0:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="no desired revision set; nothing to reconcile",
            )
        comp = self._conn.execute(
            "SELECT composition_id, body_json, body_hash FROM compositions"
            " WHERE realm_id = ? AND revision = ?",
            (self._realm_id, desired),
        ).fetchone()
        if comp is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message="desired composition revision row missing",
                details={"revision": str(desired)},
            )
        body = json.loads(bytes(comp[1]).decode("utf-8"))
        return ReconcileObservation(
            desired_revision=desired,
            serving_revision=int(row[1]),
            realized_revision=int(row[2]),
            desired_cas=int(row[3]),
            serving_cas=int(row[4]),
            realized_cas=int(row[5]),
            reconcile_status=str(row[6]),
            composition_id=str(comp[0]),
            body=body,
            body_hash=str(comp[2]),
        )

    # -- command plumbing ----------------------------------------------------------
    def _envelope(self) -> CommandEnvelope:
        return CommandEnvelope(
            command_id="action://" + new_uuid7(),
            realm_id=self._realm_id,
            actor_id=self._actor_id,
            authority_grant_id=None,
            expected_meta_revision=None,
            causal_parent_action_id=None,
            payload_type="reconcile.control/v1",
            payload_schema_version=1,
            payload={},
            auth_nonce=None,
            auth_issued_at_us=None,
            auth_signature=None,
        )

    def _run_command(self, mutator: Callable[[Any], dict[str, Any]]) -> dict[str, Any]:
        result = execute_command(
            self._conn,
            self._envelope(),
            mutator,
            deadline=Deadline.after(self._command_deadline_us),
        )
        if getattr(result, "error", None) is not None:
            raise result.error
        return dict(result.receipt)

    def _append_fact(
        self,
        txn: Any,
        *,
        entity_type: str,
        entity_id: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> str:
        return txn.append_fact(
            FactAppendRequest(
                entity_type=entity_type,
                entity_id=entity_id,
                event_type=event_type,
                schema_version=1,
                payload=payload,
                occurred_at_us=txn.recorded_at_us,
                actor_id=self._actor_id,
            )
        )

    # -- cycle begin (C) --------------------------------------------------------
    def _begin_apply(self, obs: ReconcileObservation, rid: str) -> None:
        def mutator(txn: Any) -> dict[str, Any]:
            cursor = txn._conn.execute(
                "UPDATE composition_refs SET reconcile_status='APPLYING'"
                " WHERE realm_id = ? AND reconcile_status IN"
                " ('PENDING','APPLYING','RETRYING','DEGRADED')",
                (self._realm_id,),
            )
            if cursor.rowcount != 1:
                raise StableError(
                    code=ErrorCode.FAILED_PRECONDITION,
                    message="reconcile cycle not in a resumable state",
                    details={"status": obs.reconcile_status},
                )
            try:
                txn.enqueue_outbox(
                    OutboxRequest(
                        kind="RECONCILE_REQUEST",
                        dedupe_key=outbox_dedupe_key(
                            "RECONCILE_REQUEST",
                            self._realm_id,
                            "composition",
                            str(obs.desired_revision),
                            obs.body_hash,
                        ),
                        payload={
                            "reconcile_id": rid,
                            "desired_revision": str(obs.desired_revision),
                        },
                        available_at_us=0,
                    )
                )
            except sqlite3.IntegrityError:
                pass  # one semantic transition keeps exactly one outbox item
            return {"reconcile_id": rid}

        self._run_command(mutator)

    # -- per-result short txn (E) ---------------------------------------------------
    def _record(
        self, events: list[tuple[str, str, str, dict[str, Any]]]
    ) -> tuple[str, ...]:
        def mutator(txn: Any) -> dict[str, Any]:
            fact_ids = [
                self._append_fact(
                    txn, entity_type=et, entity_id=eid, event_type=ev, payload=pl
                )
                for et, eid, ev, pl in events
            ]
            return {"fact_ids": fact_ids}

        result = self._run_command(mutator)
        return tuple(result["fact_ids"])

    # -- slot round (D + E) -------------------------------------------------------
    def _run_slot(
        self, step: Mapping[str, Any], obs: ReconcileObservation, rid: str
    ) -> SlotOutcome:
        slot = str(step["slot"])
        criticality = str(step["criticality"])
        request_id = slot_request_id(rid, slot, "instantiate")
        instance_id = ""
        state_bindings: tuple[Mapping[str, Any], ...] = ()
        try:
            result = self._slot_executor(
                {
                    "request_id": request_id,
                    "reconcile_id": rid,
                    "composition_id": obs.composition_id,
                    "realm_id": self._realm_id,
                    "desired_revision": obs.desired_revision,
                    "slot": slot,
                    "capability_id": step.get("capability_id", ""),
                    "descriptor_revision": step.get("descriptor_revision", 0),
                    "criticality": criticality,
                    "degradation_policy": step.get("degradation_policy", ""),
                }
            )
            if isinstance(result, Mapping):
                instance_id = str(result.get("instance_id", ""))
                state_bindings = tuple(result.get("state_bindings", ()) or ())
        except UnknownOutcomeError as exc:
            fact_ids = self._record(
                [
                    (
                        "execution",
                        f"execution://{new_uuid7()}",
                        "external_effect_unknown",
                        {
                            "reason_code": ErrorCode.EXTERNAL_EFFECT_UNKNOWN,
                            "reconcile_id": rid,
                            "slot": slot,
                            "detail": str(exc)[:500],
                        },
                    )
                ]
            )
            return SlotOutcome(
                slot=slot,
                passed=False,
                status="UNKNOWN",
                reason_code=ErrorCode.EXTERNAL_EFFECT_UNKNOWN,
                instance_id="",
                fact_ids=fact_ids,
            )
        except StableError as exc:
            fact_ids = self._record(
                [
                    (
                        "capability",
                        f"capability://{slot}",
                        "instance_degraded",
                        {
                            "reason_code": str(exc.code),
                            "old_status": "PENDING",
                            "new_status": "UNHEALTHY",
                            "reconcile_id": rid,
                            "slot": slot,
                            "detail": str(exc)[:500],
                        },
                    )
                ]
            )
            return SlotOutcome(
                slot=slot,
                passed=False,
                status="FAILED",
                reason_code=str(exc.code),
                instance_id="",
                fact_ids=fact_ids,
            )
        except Exception as exc:  # noqa: BLE001 - external boundary
            fact_ids = self._record(
                [
                    (
                        "capability",
                        f"capability://{slot}",
                        "instance_degraded",
                        {
                            "reason_code": "SLOT_EXECUTOR_ERROR",
                            "old_status": "PENDING",
                            "new_status": "UNHEALTHY",
                            "reconcile_id": rid,
                            "slot": slot,
                            "detail": str(exc)[:500],
                        },
                    )
                ]
            )
            return SlotOutcome(
                slot=slot,
                passed=False,
                status="FAILED",
                reason_code="SLOT_EXECUTOR_ERROR",
                instance_id="",
                fact_ids=fact_ids,
            )

        descriptor = step.get("health_probe")
        if descriptor is None:
            if criticality == "REQUIRED":
                fact_ids = self._record(
                    [
                        (
                            "capability",
                            f"capability://{slot}",
                            "instance_degraded",
                            {
                                "reason_code": "PROBE_DESCRIPTOR_MISSING",
                                "old_status": "PENDING",
                                "new_status": "UNHEALTHY",
                                "reconcile_id": rid,
                                "slot": slot,
                                "detail": "required slot must declare a health_probe",
                            },
                        )
                    ]
                )
                return SlotOutcome(
                    slot=slot,
                    passed=False,
                    status="FAILED",
                    reason_code="PROBE_DESCRIPTOR_MISSING",
                    instance_id=instance_id,
                    state_bindings=state_bindings,
                    fact_ids=fact_ids,
                )
            fact_ids = self._record(
                [
                    (
                        "capability",
                        instance_id or f"capability://{slot}",
                        "instance_transitioned",
                        {
                            "reason_code": "NO_PROBE_DECLARED",
                            "old_status": "PENDING",
                            "new_status": "READY",
                            "reconcile_id": rid,
                            "slot": slot,
                        },
                    )
                ]
            )
            return SlotOutcome(
                slot=slot,
                passed=True,
                status="READY",
                reason_code="NO_PROBE_DECLARED",
                instance_id=instance_id,
                state_bindings=state_bindings,
                fact_ids=fact_ids,
            )

        assert self._probe_runner is not None, (
            "probe_runner required when slots declare health_probe"
        )
        report = self._probe_runner.run(
            HealthProbeDescriptor.from_descriptor(descriptor),
            slot=slot,
            criticality=criticality,
            reconcile_id=rid,
            composition_id=obs.composition_id,
            instance_id=instance_id,
            descriptor_revision=int(step.get("descriptor_revision", 0) or 0),
        )
        event_type = (
            "instance_transitioned"
            if report.result.status == "READY"
            else "instance_degraded"
        )
        fact_ids = self._record(
            [
                (
                    "capability",
                    instance_id or f"capability://{slot}",
                    event_type,
                    {
                        "reason_code": report.result.reason_code,
                        "old_status": "PENDING",
                        "new_status": report.result.status,
                        "reconcile_id": rid,
                        "slot": slot,
                        "request_id": report.result.request_id,
                    },
                )
            ]
        )
        return SlotOutcome(
            slot=slot,
            passed=report.passed,
            status=report.result.status,
            reason_code=report.result.reason_code,
            instance_id=instance_id,
            state_bindings=state_bindings,
            attempts=report.attempts,
            fact_ids=fact_ids,
        )

    # -- cutover (F) ----------------------------------------------------------------
    def _cutover(
        self,
        obs: ReconcileObservation,
        rid: str,
        state_bindings: list[Mapping[str, Any]],
    ) -> None:
        def mutator(txn: Any) -> dict[str, Any]:
            if state_bindings:
                migrate_state_cutover(
                    StateMigrationCutoverRequest(
                        bindings=[
                            StateRevisionRegistration(
                                state_id=b["state_id"],
                                source_revision_id=b["source_revision_id"],
                                schema_id=b.get("schema_id", ""),
                                artifact_id=b.get("artifact_id", ""),
                                state_revision_id=b["state_revision_id"],
                            )
                            for b in state_bindings
                        ]
                    )
                )(txn)
            set_serving(
                SetServingRequest(
                    realm_id=self._realm_id,
                    revision=obs.desired_revision,
                    expected_cas=obs.serving_cas,
                )
            )(txn)
            # Harness activation settles in the same terminal transaction
            # that moves serving (§41.60.4).
            settle_harness_for_cutover(self._realm_id, obs.composition_id)(txn)
            return {"serving_revision": obs.desired_revision}

        self._run_command(mutator)

    # -- terminal commit (H) ------------------------------------------------------
    def _complete(self, obs: ReconcileObservation) -> None:
        row = self._conn.execute(
            "SELECT realized_cas FROM composition_refs WHERE realm_id = ?",
            (self._realm_id,),
        ).fetchone()
        self._run_command(
            set_realized(
                SetRealizedRequest(
                    realm_id=self._realm_id,
                    revision=obs.desired_revision,
                    expected_cas=int(row[0]),
                )
            )
        )

    # -- failure terminal states ----------------------------------------------------
    def _mark(self, status: str, reason_code: str, detail: str) -> None:
        def mutator(txn: Any) -> dict[str, Any]:
            cursor = txn._conn.execute(
                "UPDATE composition_refs SET reconcile_status=?"
                " WHERE realm_id = ? AND reconcile_status IN"
                " ('APPLYING','PENDING','RETRYING')",
                (status, self._realm_id),
            )
            fact_id = self._append_fact(
                txn,
                entity_type="composition",
                entity_id="composition://plan",
                event_type="reconcile_failed",
                payload={"reason_code": reason_code, "detail": detail[:500]},
            )
            return {"fact_id": fact_id, "updated": cursor.rowcount}

        self._run_command(mutator)

    # -- main round --------------------------------------------------------------
    # -- drain cycle: desired revision 0 (harness deactivation, §41.60.4) -----------
    def _drain_cycle(self, serving_revision: int, realized_revision: int) -> ReconcileOutcome:
        row = self._conn.execute(
            "SELECT serving_cas, realized_cas FROM composition_refs WHERE realm_id = ?",
            (self._realm_id,),
        ).fetchone()
        serving_cas, realized_cas = (int(row[0]), int(row[1])) if row else (0, 0)
        rid = reconcile_id(self._realm_id, 0, "")

        if serving_revision != 0:
            def mutator(txn: Any) -> dict[str, Any]:
                set_serving(
                    SetServingRequest(
                        realm_id=self._realm_id, revision=0, expected_cas=serving_cas
                    )
                )(txn)
                # settle the drained harness in the same terminal transaction
                settle_harness_for_cutover(self._realm_id, None)(txn)
                return {"serving_revision": 0}

            try:
                self._run_command(mutator)
            except StableError as exc:
                if exc.code == ErrorCode.REVISION_CONFLICT:
                    return ReconcileOutcome(
                        status="SUPERSEDED",
                        reconcile_id=rid,
                        desired_revision=0,
                        serving_revision=serving_revision,
                        realized_revision=realized_revision,
                        reason_code="SERVING_CAS_CONFLICT",
                    )
                raise

        if self._drain_executor is not None:
            try:
                self._drain_executor(
                    {
                        "reconcile_id": rid,
                        "realm_id": self._realm_id,
                        "old_serving_revision": serving_revision,
                        "new_serving_revision": 0,
                    }
                )
            except Exception as exc:  # noqa: BLE001 - drain failure degrades
                self._mark("DEGRADED", "DRAIN_FAILED", str(exc))
                return ReconcileOutcome(
                    status="DEGRADED",
                    reconcile_id=rid,
                    desired_revision=0,
                    serving_revision=0,
                    realized_revision=realized_revision,
                    reason_code="DRAIN_FAILED",
                )

        # closes the cycle to READY even when the values are already at 0
        self._run_command(
            set_realized(
                SetRealizedRequest(
                    realm_id=self._realm_id, revision=0, expected_cas=realized_cas
                )
            )
        )
        return ReconcileOutcome(
            status="DRAINED",
            reconcile_id=rid,
            desired_revision=0,
            serving_revision=0,
            realized_revision=0,
            reason_code="HARNESS_DEACTIVATED" if serving_revision else "ALREADY_DRAINED",
        )

    def run_reconcile(self) -> ReconcileOutcome:
        refs = self._conn.execute(
            "SELECT desired_revision, serving_revision, realized_revision"
            " FROM composition_refs WHERE realm_id = ?",
            (self._realm_id,),
        ).fetchone()
        if refs is not None and int(refs[0]) == 0:
            return self._drain_cycle(int(refs[1]), int(refs[2]))
        obs = self.read_state()
        rid = reconcile_id(self._realm_id, obs.desired_revision, obs.body_hash)
        if (
            obs.reconcile_status == "READY"
            and obs.desired_revision == obs.realized_revision
        ):
            return ReconcileOutcome(
                status="ALREADY_CONVERGED",
                reconcile_id=rid,
                desired_revision=obs.desired_revision,
                serving_revision=obs.serving_revision,
                realized_revision=obs.realized_revision,
            )
        steps = topological_slots(obs.body)
        self._begin_apply(obs, rid)

        outcomes: list[SlotOutcome] = []
        state_bindings: list[Mapping[str, Any]] = []
        gate_passed = True
        for step in steps:
            outcome = self._run_slot(step, obs, rid)
            outcomes.append(outcome)
            if outcome.status == "UNKNOWN":
                self._mark("UNKNOWN", outcome.reason_code, f"slot {outcome.slot} unknown")
                return ReconcileOutcome(
                    status="UNKNOWN",
                    reconcile_id=rid,
                    desired_revision=obs.desired_revision,
                    serving_revision=obs.serving_revision,
                    realized_revision=obs.realized_revision,
                    slots=tuple(outcomes),
                    reason_code=outcome.reason_code,
                )
            if not outcome.passed:
                gate_passed = False
                break
            state_bindings.extend(outcome.state_bindings)

        if not gate_passed:
            failed = next(o for o in outcomes if not o.passed)
            self._mark("FAILED", failed.reason_code, f"slot {failed.slot} failed gate")
            return ReconcileOutcome(
                status="FAILED",
                reconcile_id=rid,
                desired_revision=obs.desired_revision,
                serving_revision=obs.serving_revision,
                realized_revision=obs.realized_revision,
                slots=tuple(outcomes),
                reason_code=failed.reason_code,
            )

        # (F) single terminal transaction: state bindings + serving CAS.
        if obs.serving_revision != obs.desired_revision:
            try:
                self._cutover(obs, rid, state_bindings)
            except StableError as exc:
                if exc.code == ErrorCode.REVISION_CONFLICT:
                    return ReconcileOutcome(
                        status="SUPERSEDED",
                        reconcile_id=rid,
                        desired_revision=obs.desired_revision,
                        serving_revision=obs.serving_revision,
                        realized_revision=obs.realized_revision,
                        slots=tuple(outcomes),
                        reason_code="SERVING_CAS_CONFLICT",
                    )
                raise

        # (G) external drain of the previous serving generation.
        if self._drain_executor is not None:
            try:
                self._drain_executor(
                    {
                        "reconcile_id": rid,
                        "realm_id": self._realm_id,
                        "old_serving_revision": obs.serving_revision,
                        "new_serving_revision": obs.desired_revision,
                    }
                )
            except Exception as exc:  # noqa: BLE001 - drain failure degrades
                self._mark("DEGRADED", "DRAIN_FAILED", str(exc))
                return ReconcileOutcome(
                    status="DEGRADED",
                    reconcile_id=rid,
                    desired_revision=obs.desired_revision,
                    serving_revision=obs.desired_revision,
                    realized_revision=obs.realized_revision,
                    slots=tuple(outcomes),
                    reason_code="DRAIN_FAILED",
                    detail=str(exc)[:500],
                )

        # (H) realized CAS + READY checkpoint.
        self._complete(obs)
        return ReconcileOutcome(
            status="CONVERGED",
            reconcile_id=rid,
            desired_revision=obs.desired_revision,
            serving_revision=obs.desired_revision,
            realized_revision=obs.desired_revision,
            slots=tuple(outcomes),
        )
