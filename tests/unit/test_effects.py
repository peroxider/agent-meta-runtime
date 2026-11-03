"""Step 04 tests: EffectIntent v1 and the reservation pipeline (§41.45)."""

from __future__ import annotations

import pytest

from agent_meta_runtime.application.effects import (
    EffectCoordinator,
    EffectReservationLedger,
)
from agent_meta_runtime.domain.effects import (
    EffectIntent,
    effect_intent_hash,
)
from agent_meta_runtime.domain.errors import ErrorCode, StableError


def make_intent(**overrides) -> EffectIntent:
    base = dict(
        effect_intent_id="effect-intent://01900000-0000-7000-8000-000000000001",
        action_id="action://01900000-0000-7000-8000-000000000002",
        kind="filesystem.write",
        target_scope={"workspace_id": "workspace://w1"},
        payload_artifact_id="artifact://sha256/" + "a" * 64,
        idempotency_class="KEYED",
        reversibility="REVERSIBLE",
        budget_effects=1,
        budget_cost_microunits=10,
    )
    base.update(overrides)
    return EffectIntent(**base)


def test_effect_intent_validation_rules() -> None:
    with pytest.raises(StableError) as exc:
        make_intent(effect_intent_id="urn:wrong")
    assert exc.value.code == ErrorCode.INVALID_ARGUMENT
    with pytest.raises(StableError):
        make_intent(action_id="https://wrong")
    with pytest.raises(StableError):
        make_intent(kind="not.a.kind")
    with pytest.raises(StableError):
        make_intent(reversibility="MAYBE")
    with pytest.raises(StableError):
        make_intent(idempotency_class="SOMETIMES")
    with pytest.raises(StableError):
        make_intent(target_scope={})
    with pytest.raises(StableError):
        make_intent(payload_artifact_id="")
    # COMPENSATABLE demands a compensation artifact
    with pytest.raises(StableError):
        make_intent(reversibility="COMPENSATABLE")
    ok = make_intent(reversibility="COMPENSATABLE", compensation_artifact_id="artifact://c")
    assert ok.compensation_artifact_id == "artifact://c"
    with pytest.raises(StableError):
        make_intent(budget_effects=-1)
    with pytest.raises(StableError):
        make_intent(budget_cost_microunits=-5)


def test_intent_hash_is_deterministic() -> None:
    a, b = make_intent(), make_intent()
    assert effect_intent_hash(a) == effect_intent_hash(b)
    assert effect_intent_hash(a) != effect_intent_hash(
        make_intent(budget_cost_microunits=11)
    )


def test_submission_order_authority_failure_consumes_no_budget() -> None:
    def denied(intent: EffectIntent) -> None:
        raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="no grant")

    coordinator = EffectCoordinator(max_effects=10, authority_check=denied)
    with pytest.raises(StableError) as exc:
        coordinator.submit("req-1", make_intent())
    assert exc.value.code == ErrorCode.AUTHORITY_DENIED
    assert coordinator.effects_consumed == 0
    assert coordinator.cost_consumed == 0


def test_canonical_target_required() -> None:
    coordinator = EffectCoordinator(max_effects=10)
    with pytest.raises(StableError) as exc:
        coordinator.submit("req-1", make_intent(target_scope={"other": "x"}))
    assert exc.value.code == ErrorCode.INVALID_ARGUMENT
    assert coordinator.effects_consumed == 0


def test_replay_idempotent_and_conflict_detected() -> None:
    coordinator = EffectCoordinator(max_effects=10)
    receipt = coordinator.submit("req-1", make_intent())
    again = coordinator.submit("req-1", make_intent())
    assert again == receipt
    assert coordinator.effects_consumed == 1  # no double count
    with pytest.raises(StableError) as exc:
        coordinator.submit("req-1", make_intent(budget_cost_microunits=99))
    assert exc.value.code == ErrorCode.IDEMPOTENCY_CONFLICT


def test_feature_failure_refunds_fresh_reservation() -> None:
    coordinator = EffectCoordinator(
        max_effects=10, backend_features={"fs.atomic_write": "SUPPORTED"}
    )
    with pytest.raises(StableError) as exc:
        coordinator.submit(
            "req-1",
            make_intent(required_backend_features=("fs.atomic_write", "net.deny")),
        )
    assert exc.value.code == ErrorCode.FEATURE_UNAVAILABLE
    assert coordinator.effects_consumed == 0  # refunded
    assert coordinator.cost_consumed == 0


def test_budget_exhaustion_and_overrun_blocking() -> None:
    coordinator = EffectCoordinator(max_effects=2)
    coordinator.submit("req-1", make_intent())
    coordinator.submit("req-2", make_intent())
    with pytest.raises(StableError) as exc:
        coordinator.submit("req-3", make_intent())
    assert exc.value.code == ErrorCode.RESOURCE_EXHAUSTED


def test_settlement_overrun_blocks_further_effects() -> None:
    coordinator = EffectCoordinator(max_effects=10)
    coordinator.submit("req-1", make_intent(budget_cost_microunits=10))
    settlement = coordinator.settle("req-1", actual_cost=50)
    assert settlement["overrun_cost_microunits"] == 40
    assert coordinator.overrun is True
    # consumed values are never written back down
    assert coordinator.cost_consumed == 10
    with pytest.raises(StableError) as exc:
        coordinator.submit("req-2", make_intent())
    assert exc.value.code == ErrorCode.RESOURCE_EXHAUSTED
    # settle replay is safe and stable
    assert coordinator.settle("req-1") == settlement


def test_high_risk_reversibility_fails_closed() -> None:
    portable = EffectCoordinator(max_effects=10, backend_profile="PORTABLE")
    for rev in ("IRREVERSIBLE", "UNKNOWN"):
        with pytest.raises(StableError) as exc:
            portable.submit(f"req-{rev}", make_intent(reversibility=rev))
        assert exc.value.code == ErrorCode.FEATURE_UNAVAILABLE
        assert portable.effects_consumed == 0
    # Managed profile accepts (grant enforcement is the authority check's job)
    managed = EffectCoordinator(max_effects=10, backend_profile="MANAGED")
    receipt = managed.submit("req-irr", make_intent(reversibility="IRREVERSIBLE"))
    assert receipt["reserved_effects"] == 1


def test_reservation_ledger_restart_round_trip() -> None:
    ledger = EffectReservationLedger()
    coordinator = EffectCoordinator(max_effects=10, ledger=ledger)
    receipt = coordinator.submit("req-1", make_intent())
    restored = EffectReservationLedger()
    restored.restore_bytes(ledger.to_bytes())
    replay_coordinator = EffectCoordinator(max_effects=10, ledger=restored)
    assert replay_coordinator.submit("req-1", make_intent()) == receipt
    with pytest.raises(StableError) as exc:
        replay_coordinator.submit("req-1", make_intent(budget_cost_microunits=1))
    assert exc.value.code == ErrorCode.IDEMPOTENCY_CONFLICT
