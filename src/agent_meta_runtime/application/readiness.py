"""Core/serving readiness evaluation (§41.51, §41.59.4).

``core_ready`` gates control-plane progress: an openable store with the
frozen schema, no critical outbox dead-letters, no ``UNKNOWN`` reconcile
cycle, an available Root authority grant, a stable clock and disk space of
at least max(512 MiB, 5% of the volume). ``serving_ready`` additionally
requires a serving revision and explained live serving health (or a ``READY``
cycle for a standalone evaluator without a bound health port), and drops to
false while any backpressure signal exceeds its ceiling (pending tasks,
pending outbox items, projection lag, WAL bytes). Reason codes form a
frozen registry; every boolean downgrade maps to at least one code.
"""

from __future__ import annotations

import shutil
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from ..domain.meta_schema import META_SCHEMA_VERSION
from ..domain.canonical import now_us
from ..domain.clock import CLOCK_UNSTABLE_REASON

__all__ = [
    "READINESS_REASONS",
    "BackpressureLimits",
    "ReadinessSnapshot",
    "ReadinessEvaluator",
]

READINESS_REASONS: frozenset[str] = frozenset(
    {
        "STORE_UNAVAILABLE",
        "SCHEMA_INCOMPATIBLE",
        "ARTIFACT_MISSING",
        "ARTIFACT_CORRUPT",
        "KEY_UNAVAILABLE",
        "BACKEND_UNAVAILABLE",
        "FEATURE_UNAVAILABLE",
        "RECONCILE_UNKNOWN",
        "CRITICAL_DEAD_LETTER",
        "DISK_LOW",
        "ROOT_AUTH_UNAVAILABLE",
        "CLOCK_UNSTABLE",
        "NO_SERVING_COMPOSITION",
        "RECONCILE_NOT_READY",
        "BACKPRESSURE_TASKS",
        "BACKPRESSURE_OUTBOX",
        "BACKPRESSURE_PROJECTION",
        "BACKPRESSURE_WAL",
    }
)

_DISK_FLOOR_BYTES = 512 * 1024 * 1024
_DISK_FLOOR_RATIO = 0.05
_WAL_CEILING_BYTES = 1 << 30  # 1 GiB

_CRITICAL_KINDS = (
    "EXECUTION_SUBMIT",
    "OPERATION_RUN",
    "RECONCILE_REQUEST",
    "TERMINAL_ACK",
)


@dataclass(frozen=True, slots=True)
class BackpressureLimits:
    """Fixed v0.1 backpressure ceilings (§41.51)."""

    pending_tasks: int = 1000
    pending_outbox: int = 10_000
    projection_lag: int = 100_000
    wal_bytes: int = _WAL_CEILING_BYTES


@dataclass(frozen=True, slots=True)
class ReadinessSnapshot:
    """One evaluation result; reason codes are a subset of the registry."""

    core_ready: bool
    serving_ready: bool
    core_reasons: tuple[str, ...] = ()
    serving_reasons: tuple[str, ...] = ()
    backpressure: Mapping[str, int] = field(default_factory=dict)
    observed_at_us: int = 0

    def to_fact_payload(
        self, previous: "ReadinessSnapshot | None" = None
    ) -> dict[str, Any]:
        old = "true" if previous is not None and previous.core_ready else "false"
        return {
            "reason_code": ",".join(self.core_reasons) or "READY",
            "old_status": old,
            "new_status": "true" if self.core_ready else "false",
            "serving_ready": "true" if self.serving_ready else "false",
            "serving_reasons": ",".join(self.serving_reasons),
        }

    def changed_since(self, previous: "ReadinessSnapshot | None") -> bool:
        if previous is None:
            return True
        return (
            previous.core_ready != self.core_ready
            or previous.serving_ready != self.serving_ready
            or set(previous.core_reasons) != set(self.core_reasons)
            or set(previous.serving_reasons) != set(self.serving_reasons)
        )


class ReadinessEvaluator:
    """Computes the §41.51 readiness booleans and reason codes."""

    def __init__(
        self,
        conn: Any,
        *,
        realm_id: str,
        db_path: Path | str,
        clock: Any = None,
        limits: BackpressureLimits = BackpressureLimits(),
        disk_floor_bytes: int = _DISK_FLOOR_BYTES,
        serving_health=None,
    ) -> None:
        self._conn = conn
        self._realm_id = realm_id
        self._db_path = Path(db_path)
        self._clock = clock
        self._limits = limits
        self._disk_floor_bytes = disk_floor_bytes
        self._serving_health = serving_health

    # -- individual signals ---------------------------------------------------
    def _store_and_schema(self, reasons: set[str]) -> bool:
        try:
            row = self._conn.execute("PRAGMA user_version").fetchone()
            quick = self._conn.execute("SELECT 1 FROM realms LIMIT 1").fetchone()
        except sqlite3.Error:
            reasons.add("STORE_UNAVAILABLE")
            return False
        if int(row[0]) != META_SCHEMA_VERSION:
            reasons.add("SCHEMA_INCOMPATIBLE")
            return False
        return quick is not None

    def _critical_dead_letters(self) -> bool:
        placeholders = ",".join("?" for _ in _CRITICAL_KINDS)
        row = self._conn.execute(
            "SELECT 1 FROM outbox WHERE state='DEAD_LETTER'"
            f" AND kind IN ({placeholders}) LIMIT 1",
            _CRITICAL_KINDS,
        ).fetchone()
        return row is not None

    def _reconcile_unknown(self) -> bool:
        row = self._conn.execute(
            "SELECT reconcile_status FROM composition_refs WHERE realm_id = ?",
            (self._realm_id,),
        ).fetchone()
        return row is not None and str(row[0]) == "UNKNOWN"

    def _disk_low(self) -> bool:
        usage = shutil.disk_usage(self._db_path.parent)
        floor = max(self._disk_floor_bytes, int(usage.total * _DISK_FLOOR_RATIO))
        return usage.free < floor

    def _root_auth_available(self, now: int) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM authority_grants g JOIN realms r ON g.epoch_id = r.epoch_id"
            " JOIN epochs e ON e.epoch_id=r.epoch_id AND e.authority_root_principal_id=g.subject_id"
            " JOIN principals p ON p.principal_id=g.subject_id AND p.realm_id=r.realm_id"
            " WHERE r.realm_id = ? AND g.status='ACTIVE' AND g.parent_grant_id IS NULL"
            " AND p.kind='OPERATOR_ROOT' AND p.status='ACTIVE'"
            " AND (g.expires_at_us IS NULL OR g.expires_at_us > ?)"
            " LIMIT 1",
            (self._realm_id, now),
        ).fetchone()
        return row is not None

    def _backpressure(self) -> tuple[dict[str, int], tuple[str, ...]]:
        counts: dict[str, int] = {}
        reasons: list[str] = []
        counts["pending_tasks"] = int(
            self._conn.execute(
                "SELECT COUNT(*) FROM tasks WHERE realm_id = ?"
                " AND status IN ('ACCEPTED','RUNNING')",
                (self._realm_id,),
            ).fetchone()[0]
        )
        counts["pending_outbox"] = int(
            self._conn.execute(
                "SELECT COUNT(*) FROM outbox WHERE state IN ('PENDING','LEASED')"
            ).fetchone()[0]
        )
        counts["wal_bytes"] = 0
        wal = self._db_path.parent / (self._db_path.name + "-wal")
        if wal.exists():
            counts["wal_bytes"] = int(wal.stat().st_size)
        head = int(
            self._conn.execute(
                "SELECT next_seq FROM realms WHERE realm_id = ?", (self._realm_id,)
            ).fetchone()[0]
        )
        lag = 0
        for (seq,) in self._conn.execute(
            "SELECT seq FROM checkpoints WHERE realm_id = ?", (self._realm_id,)
        ).fetchall():
            lag = max(lag, head - int(seq) - 1)
        counts["projection_lag"] = lag
        if counts["pending_tasks"] > self._limits.pending_tasks:
            reasons.append("BACKPRESSURE_TASKS")
        if counts["pending_outbox"] > self._limits.pending_outbox:
            reasons.append("BACKPRESSURE_OUTBOX")
        if counts["projection_lag"] > self._limits.projection_lag:
            reasons.append("BACKPRESSURE_PROJECTION")
        if counts["wal_bytes"] > self._limits.wal_bytes:
            reasons.append("BACKPRESSURE_WAL")
        return counts, tuple(reasons)

    # -- main entry ------------------------------------------------------------
    def evaluate(self) -> ReadinessSnapshot:
        reasons: set[str] = set()
        core = self._store_and_schema(reasons)
        if core:
            if self._critical_dead_letters():
                reasons.add("CRITICAL_DEAD_LETTER")
            if self._reconcile_unknown():
                reasons.add("RECONCILE_UNKNOWN")
            if self._disk_low():
                reasons.add("DISK_LOW")
            if not self._root_auth_available(now_us()):
                reasons.add("ROOT_AUTH_UNAVAILABLE")
            if self._clock is not None and self._clock.unstable:
                reasons.add(CLOCK_UNSTABLE_REASON)
            core = not reasons

        backpressure: dict[str, int] = {}
        serving_reasons: tuple[str, ...] = ()
        serving = False
        if core:
            backpressure, bp_reasons = self._backpressure()
            refs = self._conn.execute(
                "SELECT serving_revision, reconcile_status FROM composition_refs"
                " WHERE realm_id = ?",
                (self._realm_id,),
            ).fetchone()
            serving_revision = int(refs[0]) if refs else 0
            reconcile_status = str(refs[1]) if refs else "PENDING"
            healthy = reconcile_status == "READY"
            if self._serving_health is not None and serving_revision > 0:
                # Desired reconciliation and serving health are independent:
                # a failing candidate must not stop the healthy old version.
                healthy = bool(self._serving_health(serving_revision))
            serving = (
                serving_revision > 0
                and healthy
                and not bp_reasons
            )
            if serving_revision == 0:
                serving_reasons = ("NO_SERVING_COMPOSITION",)
            elif not healthy:
                serving_reasons = ("RECONCILE_NOT_READY",)
            elif bp_reasons:
                serving_reasons = bp_reasons

        return ReadinessSnapshot(
            core_ready=core,
            serving_ready=serving,
            core_reasons=tuple(sorted(reasons)),
            serving_reasons=serving_reasons,
            backpressure=backpressure,
        )
