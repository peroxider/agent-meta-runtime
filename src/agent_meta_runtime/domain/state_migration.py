"""Managed State migration contract (§41.31, §41.59.3).

Migration runs against the planned ``source_revision_id`` and produces an
unbound immutable ``target_revision_id``. Binding happens only in the serving
cutover transaction, which CAS-checks every state and rolls back entirely on
any conflict. Rollback strategies are the two fixed v0.1 options.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .errors import ErrorCode, StableError

__all__ = [
    "MIGRATION_MANIFEST_FIELDS",
    "DETERMINISM_LEVELS",
    "ROLLBACK_STRATEGIES",
    "MigrationManifest",
    "StateRollbackRequest",
    "parse_migration_manifest",
]

MIGRATION_MANIFEST_FIELDS: tuple[str, ...] = (
    "source_schema_id",
    "target_schema_id",
    "entrypoint",
    "runtime_constraint",
    "resource_budget",
    "determinism_level",
    "expected_output_schema",
)

DETERMINISM_LEVELS: frozenset[str] = frozenset({"DETERMINISTIC", "NON_DETERMINISTIC"})

ROLLBACK_STRATEGIES: frozenset[str] = frozenset({"KEEP_COMPATIBLE", "RESTORE_PARENT"})


@dataclass(frozen=True, slots=True)
class MigrationManifest:
    """Validated State Migration Artifact manifest (§41.31)."""

    source_schema_id: str
    target_schema_id: str
    entrypoint: str
    runtime_constraint: Mapping[str, Any]
    resource_budget: Mapping[str, Any]
    determinism_level: str
    expected_output_schema: Mapping[str, Any]
    artifact_id: str

    @property
    def retryable(self) -> bool:
        """Non-deterministic migrations must never be auto-retried."""

        return self.determinism_level == "DETERMINISTIC"

    def to_json(self) -> dict[str, Any]:
        return {
            "source_schema_id": self.source_schema_id,
            "target_schema_id": self.target_schema_id,
            "entrypoint": self.entrypoint,
            "runtime_constraint": dict(self.runtime_constraint),
            "resource_budget": dict(self.resource_budget),
            "determinism_level": self.determinism_level,
            "expected_output_schema": dict(self.expected_output_schema),
            "artifact_id": self.artifact_id,
        }


def parse_migration_manifest(
    payload: Mapping[str, Any], artifact_id: str
) -> MigrationManifest:
    """Validate a migration manifest; missing fields fail closed (§41.31)."""

    missing = [field for field in MIGRATION_MANIFEST_FIELDS if field not in payload]
    if missing:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="migration manifest missing required fields",
            details={"missing": missing},
        )
    if payload["determinism_level"] not in DETERMINISM_LEVELS:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="unknown determinism_level",
            details={"determinism_level": str(payload["determinism_level"])},
        )
    if payload["source_schema_id"] == payload["target_schema_id"]:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="migration source and target schema must differ",
        )
    return MigrationManifest(
        source_schema_id=str(payload["source_schema_id"]),
        target_schema_id=str(payload["target_schema_id"]),
        entrypoint=str(payload["entrypoint"]),
        runtime_constraint=dict(payload["runtime_constraint"]),
        resource_budget=dict(payload["resource_budget"]),
        determinism_level=str(payload["determinism_level"]),
        expected_output_schema=dict(payload["expected_output_schema"]),
        artifact_id=artifact_id,
    )


@dataclass(frozen=True, slots=True)
class StateRollbackRequest:
    """A rollback command body (§41.59.3): exactly one fixed strategy."""

    strategy: str
    parent_composition_id: str
    expected_state_revisions: Mapping[str, str]
    reason_code: str = "operator_rollback"

    def __post_init__(self) -> None:
        if self.strategy not in ROLLBACK_STRATEGIES:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="rollback strategy must be KEEP_COMPATIBLE or RESTORE_PARENT",
                details={"strategy": self.strategy},
            )
