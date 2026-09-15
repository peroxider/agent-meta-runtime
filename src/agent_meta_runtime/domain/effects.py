"""EffectIntent v1 (§41.45): the fixed-shape DTO for every external effect.

The field set is frozen for v1. Reversibility classes: ``REVERSIBLE`` must
restore via a stable inverse request in the same backend; ``COMPENSATABLE``
promises business compensation and must carry a compensation artifact;
``IRREVERSIBLE``/``UNKNOWN`` demand an explicit ``effect.execute.irreversible``
grant, a Managed backend, and an operator-visible intent preview. Portable
v0.1 rejects high-risk irreversible effects.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_json
from .compatibility import EFFECT_REGISTRY
from .errors import ErrorCode, StableError

__all__ = [
    "REVERSIBILITY_CLASSES",
    "IDEMPOTENCY_CLASSES",
    "HIGH_RISK_REVERSIBILITY",
    "EffectIntent",
    "effect_intent_hash",
]

REVERSIBILITY_CLASSES = ("REVERSIBLE", "COMPENSATABLE", "IRREVERSIBLE", "UNKNOWN")
IDEMPOTENCY_CLASSES = ("PURE", "KEYED", "NONE")
HIGH_RISK_REVERSIBILITY = frozenset({"IRREVERSIBLE", "UNKNOWN"})


@dataclass(frozen=True, slots=True)
class EffectIntent:
    """Fixed v1 field set (§41.45); __post_init__ enforces every dimension."""

    effect_intent_id: str  # effect-intent://<uuidv7>
    action_id: str  # action://...
    kind: str  # EFFECT_REGISTRY name (e.g. filesystem.write)
    target_scope: dict[str, Any]  # e.g. {"workspace_id": "workspace://..."}
    payload_artifact_id: str
    idempotency_class: str  # PURE|KEYED|NONE
    reversibility: str  # REVERSIBLE|COMPENSATABLE|IRREVERSIBLE|UNKNOWN
    required_permissions: tuple[str, ...] = ()
    required_backend_features: tuple[str, ...] = ()
    budget_effects: int = 1
    budget_cost_microunits: int = 0
    compensation_artifact_id: str | None = None

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if not self.effect_intent_id.startswith("effect-intent://"):
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="effect_intent_id must use the effect-intent:// scheme",
            )
        if not self.action_id.startswith("action://"):
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="action_id must use the action:// scheme",
            )
        if self.kind not in EFFECT_REGISTRY:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message=f"unknown effect kind: {self.kind}",
                details={"kind": self.kind},
            )
        if self.idempotency_class not in IDEMPOTENCY_CLASSES:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message=f"invalid idempotency_class: {self.idempotency_class}",
            )
        if self.reversibility not in REVERSIBILITY_CLASSES:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message=f"invalid reversibility: {self.reversibility}",
            )
        if not self.target_scope:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="canonical target scope is required",
            )
        if not self.payload_artifact_id:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="payload_artifact_id is required",
            )
        if self.reversibility == "COMPENSATABLE" and not self.compensation_artifact_id:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="COMPENSATABLE effects must provide a compensation artifact",
            )
        if self.budget_effects < 0 or self.budget_cost_microunits < 0:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="budget cost must be non-negative",
            )

    def to_json(self) -> dict[str, Any]:
        return {
            "effect_intent_id": self.effect_intent_id,
            "action_id": self.action_id,
            "kind": self.kind,
            "target_scope": self.target_scope,
            "payload_artifact_id": self.payload_artifact_id,
            "idempotency_class": self.idempotency_class,
            "reversibility": self.reversibility,
            "required_permissions": sorted(self.required_permissions),
            "required_backend_features": sorted(self.required_backend_features),
            "budget_cost": {
                "effects": self.budget_effects,
                "cost_microunits": self.budget_cost_microunits,
            },
            "compensation_artifact_id": self.compensation_artifact_id,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_json())


def effect_intent_hash(intent: EffectIntent) -> str:
    """Deterministic intent hash used for submission dedupe."""

    return hashlib.sha256(intent.canonical_bytes()).hexdigest()
