"""Daemon restart recovery and orphan quarantine (§41.31, §41.38, §41.59.4).

Recovery runs once after the daemon lock is held and the outbox dispatcher
has reset foreign leases. It inspects the reconcile cycle left behind and
re-drives it deterministically: ``PENDING``/``APPLYING``/``RETRYING``/
``DEGRADED`` cycles re-enter :meth:`Reconciler.run_reconcile` (external work
is idempotent under stable request ids); ``UNKNOWN`` cycles are inspected
through an executor callback — a confirmed applied or not-applied outcome
resets the cycle to ``RETRYING`` and re-drives it, while an undeterminable
outcome stays quarantined as ``UNKNOWN`` and blocks core readiness.
``RUNNING``/``ACCEPTED`` operations cannot have an owner across the lock
boundary and are quarantined to ``FAILED_RECOVERY`` with a
``task_recovery_failed`` fact; execution bindings stale beyond the
threshold get an ``execution_orphan_quarantined`` fact.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from ..domain.ids import new_uuid7
from ..ports.repositories import FactAppendRequest
from .reconciler import ReconcileOutcome, Reconciler

__all__ = ["RecoveryReport", "RecoveryCoordinator"]

InspectExecutor = Callable[[Mapping[str, Any]], str]
"""inspect(context) → "APPLIED" | "NOT_APPLIED" | "UNDETERMINED"."""

_RESUMABLE = ("PENDING", "APPLYING", "RETRYING", "DEGRADED")


@dataclass(frozen=True, slots=True)
class RecoveryReport:
    """What the restart inspection found and did."""

    recovered_leases: int
    cycle_status_before: str
    reconcile_outcome: ReconcileOutcome | None = None
    unknown_inspection: str = ""
    unknown_outstanding: bool = False
    operations_quarantined: int = 0
    bindings_quarantined: int = 0
    notes: tuple[str, ...] = field(default_factory=tuple)


class RecoveryCoordinator:
    """Single-owner restart inspection, reconcile re-drive, quarantine."""

    def __init__(
        self,
        conn: Any,
        *,
        realm_id: str,
        reconciler: Reconciler,
        outbox_dispatcher: Any,
        inspect_executor: InspectExecutor | None = None,
        actor_id: str | None = None,
        binding_staleness_us: int = 24 * 60 * 60 * 1_000_000,
        now_us: Callable[[], int] | None = None,
    ) -> None:
        self._conn = conn
        self._realm_id = realm_id
        self._reconciler = reconciler
        self._outbox = outbox_dispatcher
        self._inspect_executor = inspect_executor
        self._actor_id = actor_id or f"principal://service/{new_uuid7()}"
        self._binding_staleness_us = binding_staleness_us
        self._now_us = now_us or (lambda: 0)

    # -- facts ----------------------------------------------------------------
    def _append_fact(self, events: list[tuple[str, str, str, dict[str, Any]]]) -> None:
        def mutator(txn: Any) -> dict[str, Any]:
            fact_ids = [
                txn.append_fact(
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
                for entity_type, entity_id, event_type, payload in events
            ]
            return {"fact_ids": fact_ids}

        self._reconciler._run_command(mutator)

    # -- quarantine -------------------------------------------------------------
    def _quarantine_operations(self) -> int:
        """RUNNING/ACCEPTED operations cannot survive the lock boundary."""

        rows = self._conn.execute(
            "SELECT operation_id, status FROM operations"
            " WHERE realm_id = ? AND status IN ('ACCEPTED','RUNNING')",
            (self._realm_id,),
        ).fetchall()
        if not rows:
            return 0
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            for operation_id, _ in rows:
                self._conn.execute(
                    "UPDATE operations SET status='FAILED_RECOVERY',"
                    " error_json=? WHERE operation_id=? AND status IN"
                    " ('ACCEPTED','RUNNING')",
                    (
                        b'{"reason_code":"DAEMON_RESTART_QUARANTINE"}',
                        operation_id,
                    ),
                )
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._append_fact(
            [
                (
                    "task",
                    str(operation_id),
                    "task_recovery_failed",
                    {
                        "reason_code": "DAEMON_RESTART_QUARANTINE",
                        "old_status": str(status),
                        "new_status": "FAILED_RECOVERY",
                    },
                )
                for operation_id, status in rows
            ]
        )
        return len(rows)

    def _quarantine_stale_bindings(self) -> int:
        """Bindings not observed within the threshold are declared orphans."""

        if self._now_us is None:
            return 0
        cutoff = int(self._now_us()) - self._binding_staleness_us
        rows = self._conn.execute(
            "SELECT backend_id, request_id, status FROM execution_bindings"
            " WHERE last_observed_at_us < ? AND status NOT IN"
            " ('SUCCEEDED','FAILED','CANCELLED','TIMED_OUT','QUARANTINED')",
            (cutoff,),
        ).fetchall()
        if not rows:
            return 0
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            for backend_id, request_id, _ in rows:
                self._conn.execute(
                    "UPDATE execution_bindings SET status='QUARANTINED'"
                    " WHERE backend_id=? AND request_id=?",
                    (backend_id, request_id),
                )
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._append_fact(
            [
                (
                    "execution",
                    f"execution://{new_uuid7()}",
                    "execution_orphan_quarantined",
                    {
                        "reason_code": "BINDING_STALE",
                        "backend_id": backend_id,
                        "request_id": request_id,
                        "old_status": str(status),
                        "new_status": "QUARANTINED",
                    },
                )
                for backend_id, request_id, status in rows
            ]
        )
        return len(rows)

    # -- cycle inspection ---------------------------------------------------------
    def _cycle_status(self) -> str:
        row = self._conn.execute(
            "SELECT reconcile_status FROM composition_refs WHERE realm_id = ?",
            (self._realm_id,),
        ).fetchone()
        return str(row[0]) if row else "PENDING"

    def _set_cycle_status(self, status: str) -> None:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "UPDATE composition_refs SET reconcile_status=? WHERE realm_id = ?",
                (status, self._realm_id),
            )
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise

    # -- main entry ---------------------------------------------------------------
    def recover(self) -> RecoveryReport:
        notes: list[str] = []
        recovered_leases = self._outbox.recover_foreign_leases()
        cycle_before = self._cycle_status()

        outcome: ReconcileOutcome | None = None
        inspection = ""
        unknown_outstanding = False
        if cycle_before in _RESUMABLE:
            outcome = self._reconciler.run_reconcile()
            if outcome.status == "UNKNOWN":
                unknown_outstanding = True
        elif cycle_before == "UNKNOWN":
            if self._inspect_executor is None:
                unknown_outstanding = True
                notes.append("no inspect_executor; UNKNOWN cycle quarantined")
            else:
                refs = self._conn.execute(
                    "SELECT desired_revision FROM composition_refs"
                    " WHERE realm_id = ?",
                    (self._realm_id,),
                ).fetchone()
                inspection = str(
                    self._inspect_executor(
                        {
                            "realm_id": self._realm_id,
                            "desired_revision": int(refs[0]) if refs else 0,
                        }
                    )
                )
                if inspection in ("APPLIED", "NOT_APPLIED"):
                    self._set_cycle_status("RETRYING")
                    outcome = self._reconciler.run_reconcile()
                    if outcome.status == "UNKNOWN":
                        unknown_outstanding = True
                else:
                    unknown_outstanding = True
                    notes.append("inspection UNDETERMINED; cycle stays UNKNOWN")
        elif cycle_before == "FAILED":
            notes.append("cycle FAILED; awaiting operator recovery decision")

        operations_quarantined = self._quarantine_operations()
        bindings_quarantined = self._quarantine_stale_bindings()

        return RecoveryReport(
            recovered_leases=recovered_leases,
            cycle_status_before=cycle_before,
            reconcile_outcome=outcome,
            unknown_inspection=inspection,
            unknown_outstanding=unknown_outstanding,
            operations_quarantined=operations_quarantined,
            bindings_quarantined=bindings_quarantined,
            notes=tuple(notes),
        )
