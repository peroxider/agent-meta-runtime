"""Effect submission pipeline (§41.45): reservation, dedupe, settlement.

The submission order is fixed: validate schema → resolve canonical target →
Authority → budget reservation → Backend features → commit → execute outside
the transaction → settle the reservation. Validation/Authority failures
never consume budget. A successful reservation counts the effect; replaying
the same request id returns the original receipt without counting again, and
a different intent under the same request id is an ``IDEMPOTENCY_CONFLICT``.
Actual cost above the reservation is recorded as an overrun and blocks
further effects — consumed values are never written back down. Irreversible
and unknown-reversibility effects fail closed: they require a Managed backend
profile (plus the ``effect.execute.irreversible`` grant, enforced through the
Authority check).
"""

from __future__ import annotations

from typing import Any, Callable

from ..domain.effects import HIGH_RISK_REVERSIBILITY, EffectIntent, effect_intent_hash
from ..domain.errors import ErrorCode, StableError

__all__ = ["EffectCoordinator", "EffectReservationLedger"]

AuthorityCheck = Callable[[EffectIntent], None]
"""Raises AUTHORITY_DENIED when the principal lacks the required grant."""


class EffectReservationLedger:
    """Durable reservation records with restart simulation support."""

    def __init__(self) -> None:
        self._by_request: dict[str, dict[str, Any]] = {}
        self._by_intent: dict[str, str] = {}

    # -- restart surface ---------------------------------------------------------
    def to_bytes(self) -> bytes:
        import pickle

        return pickle.dumps(
            {"by_request": self._by_request, "by_intent": self._by_intent}
        )

    def restore_bytes(self, raw: bytes) -> None:
        import pickle

        data = pickle.loads(raw)
        self._by_request = data["by_request"]
        self._by_intent = data["by_intent"]

    # -- record access --------------------------------------------------------------
    def get(self, request_id: str) -> dict[str, Any] | None:
        return self._by_request.get(request_id)

    def put(self, request_id: str, record: dict[str, Any]) -> None:
        self._by_request[request_id] = record
        self._by_intent[record["intent_hash"]] = request_id

    def by_intent(self, intent_hash: str) -> str | None:
        return self._by_intent.get(intent_hash)


class EffectCoordinator:
    """Enforces the fixed EffectIntent submission order (§41.45)."""

    def __init__(
        self,
        *,
        max_effects: int,
        max_cost_microunits: int = 0,
        backend_profile: str = "PORTABLE",
        backend_features: dict[str, Any] | None = None,
        authority_check: AuthorityCheck | None = None,
        ledger: EffectReservationLedger | None = None,
    ) -> None:
        self._max_effects = max_effects
        self._max_cost = max_cost_microunits
        self._backend_profile = backend_profile
        self._features = backend_features or {}
        self._authority_check = authority_check
        self.ledger = ledger or EffectReservationLedger()
        self.effects_consumed = 0
        self.cost_consumed = 0
        self.overrun = False

    # -- helpers ------------------------------------------------------------------------
    def _budget_available(self, intent: EffectIntent) -> bool:
        if self.effects_consumed + intent.budget_effects > self._max_effects:
            return False
        if self._max_cost and self.cost_consumed + intent.budget_cost_microunits > self._max_cost:
            return False
        return True

    def _refund(self, intent: EffectIntent) -> None:
        """Undo a fresh reservation consumed by a post-reservation failure.

        Only uncommitted reservations are refunded; settled consumption is
        never written back down (§41.45).
        """

        self.effects_consumed = max(self.effects_consumed - intent.budget_effects, 0)
        self.cost_consumed = max(self.cost_consumed - intent.budget_cost_microunits, 0)

    # -- submission -----------------------------------------------------------------------
    def submit(self, request_id: str, intent: EffectIntent) -> dict[str, Any]:
        """Run the fixed order up to commit; returns the reservation receipt."""

        # 1. validate schema (EffectIntent.__post_init__ already ran validate()).
        # 2. resolve canonical target.
        if "workspace_id" not in intent.target_scope and "realm_id" not in intent.target_scope:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="canonical target must carry workspace_id or realm_id",
            )
        # 3. Authority — failure consumes no budget.
        if self._authority_check is not None:
            self._authority_check(intent)
        # Replay / conflict check before counting (dedupe by request id).
        existing = self.ledger.get(request_id)
        intent_hash = effect_intent_hash(intent)
        if existing is not None:
            if existing["intent_hash"] != intent_hash:
                raise StableError(
                    code=ErrorCode.IDEMPOTENCY_CONFLICT,
                    message="same request id with a different effect intent",
                    details={"request_id": request_id},
                )
            return dict(existing["receipt"])  # idempotent replay, no double count
        # High-risk reversibility fails closed before any reservation.
        if intent.reversibility in HIGH_RISK_REVERSIBILITY:
            if self._backend_profile != "MANAGED":
                raise StableError(
                    code=ErrorCode.FEATURE_UNAVAILABLE,
                    message="irreversible effects require a Managed backend",
                    details={"reversibility": intent.reversibility},
                )
        # 4. budget reservation.
        if self.overrun:
            raise StableError(
                code=ErrorCode.RESOURCE_EXHAUSTED,
                message="earlier effect overrun blocks subsequent effects",
            )
        if not self._budget_available(intent):
            raise StableError(
                code=ErrorCode.RESOURCE_EXHAUSTED,
                message="effect budget exhausted",
            )
        self.effects_consumed += intent.budget_effects
        self.cost_consumed += intent.budget_cost_microunits
        # 5. Backend features — failure refunds the fresh reservation.
        for feature in intent.required_backend_features:
            if self._features.get(feature) != "SUPPORTED":
                self._refund(intent)
                raise StableError(
                    code=ErrorCode.FEATURE_UNAVAILABLE,
                    message=f"required backend feature unavailable: {feature}",
                    details={"feature": feature},
                )
        # 6. commit the reservation.
        receipt = {
            "request_id": request_id,
            "intent_hash": intent_hash,
            "reserved_effects": intent.budget_effects,
            "reserved_cost_microunits": intent.budget_cost_microunits,
        }
        self.ledger.put(request_id, {"intent_hash": intent_hash, "receipt": receipt})
        return dict(receipt)

    # -- settlement ---------------------------------------------------------------------------
    def settle(
        self, request_id: str, actual_effects: int = -1, actual_cost: int = -1
    ) -> dict[str, Any]:
        """Commit result/Fact then settle; overruns block later effects."""

        record = self.ledger.get(request_id)
        if record is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND, message=f"unknown reservation {request_id}"
            )
        if record.get("settled"):
            return dict(record["settlement"])  # replay-safe
        receipt = record["receipt"]
        reserved_effects = receipt["reserved_effects"]
        reserved_cost = receipt["reserved_cost_microunits"]
        used_effects = reserved_effects if actual_effects < 0 else actual_effects
        used_cost = reserved_cost if actual_cost < 0 else actual_cost
        settlement = {
            "overrun_effects": max(used_effects - reserved_effects, 0),
            "overrun_cost_microunits": max(used_cost - reserved_cost, 0),
        }
        if settlement["overrun_effects"] or settlement["overrun_cost_microunits"]:
            self.overrun = True  # consumed values are never written back down
        record["settled"] = True
        record["settlement"] = settlement
        return dict(settlement)
