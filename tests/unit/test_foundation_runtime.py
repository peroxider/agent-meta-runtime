"""Step 00 gate: stable error registry, deadline/cancellation, envelopes."""

from __future__ import annotations

import json

import pytest

from agent_meta_runtime.domain import deadline, envelope, errors, ids

REALM = "realm://main"
ACTOR = "principal://operator-root/01900000-0000-7000-8000-000000000000"
GRANT = "capability://my-cap.v2"
COMMAND = "task://01900000-0000-7000-8000-000000000000"


# ------------------------------------------------------------------ errors ---
def test_error_registry_covers_all_codes_with_retryability() -> None:
    assert len(errors.ErrorCode.ALL) == len(errors.RETRYABLE_CODES)
    for code in errors.ErrorCode.ALL:
        assert errors.RETRYABLE_CODES[code] in (True, False, None)


def test_retryability_is_fixed_per_spec() -> None:
    assert errors.RETRYABLE_CODES[errors.ErrorCode.AUTHORITY_DENIED] is False
    assert errors.RETRYABLE_CODES[errors.ErrorCode.SERVING_NOT_READY] is True
    assert errors.RETRYABLE_CODES[errors.ErrorCode.REVISION_CONFLICT] is None
    assert errors.RETRYABLE_CODES[errors.ErrorCode.EXTERNAL_EFFECT_UNKNOWN] is None


def test_stable_error_round_trip() -> None:
    err = errors.StableError(
        code=errors.ErrorCode.AUTHORITY_DENIED,
        message="no grant",
        details={"capability": GRANT},
    )
    assert err.retryable is False
    body = err.to_json()
    assert body == {
        "code": "AUTHORITY_DENIED",
        "retryable": False,
        "message": "no grant",
        "details": {"capability": GRANT},
    }
    assert json.loads(json.dumps(body)) == body
    restored = errors.error_from_json(body)
    assert restored.code == err.code
    assert restored.details == err.details


def test_stable_error_rejects_unknown_code() -> None:
    with pytest.raises(ValueError):
        errors.StableError(code="TOTALLY_BOGUS", message="x")
    with pytest.raises(ValueError):
        errors.error_from_json({"code": "TOTALLY_BOGUS"})


# ---------------------------------------------------------------- deadline ---
def test_deadline_never_and_after() -> None:
    assert not deadline.Deadline.never().expired
    soon = deadline.Deadline.after(50_000)
    assert not soon.expired
    assert 0 < soon.remaining_us <= 50_000


def test_deadline_check_raises_when_elapsed() -> None:
    d = deadline.Deadline.after(0)
    with pytest.raises(deadline.DeadlineExceeded):
        d.check()


async def test_deadline_sleep_bounded() -> None:
    d = deadline.Deadline.after(2_000_000)
    await d.sleep(1_000)  # short sleep well within budget
    assert not d.expired


def test_deadline_after_rejects_bad_duration() -> None:
    with pytest.raises(ValueError):
        deadline.Deadline.after(-1)
    with pytest.raises(ValueError):
        deadline.Deadline.after(1.5)  # type: ignore[arg-type]


def test_cancellation_cascades_to_children() -> None:
    parent = deadline.CancellationToken()
    child = parent.child()
    grandchild = child.child()
    assert not parent.cancelled
    parent.cancel("shutdown")
    assert child.cancelled and grandchild.cancelled
    with pytest.raises(deadline.CancellationError):
        child.check()
    assert grandchild.reason == "shutdown"
    parent.cancel("again")  # idempotent


def test_child_of_cancelled_parent_starts_cancelled() -> None:
    parent = deadline.CancellationToken()
    parent.cancel()
    assert parent.child().cancelled


# --------------------------------------------------------------- envelopes ---
def _command(**overrides) -> envelope.CommandEnvelope:
    base = dict(
        command_id=COMMAND,
        realm_id=REALM,
        actor_id=ACTOR,
        authority_grant_id=GRANT,
        expected_meta_revision=7,
        causal_parent_action_id=None,
        payload_type="task.create/v1",
        payload_schema_version=1,
        payload={"title": "t"},
        auth_nonce=None,
        auth_issued_at_us=None,
        auth_signature=None,
    )
    base.update(overrides)
    return envelope.CommandEnvelope(**base)


def test_command_envelope_accepts_valid() -> None:
    cmd = _command()
    assert cmd.payload == {"title": "t"}


def test_command_envelope_accepts_unspecified_meta_revision() -> None:
    cmd = _command(expected_meta_revision=None)
    assert cmd.expected_meta_revision is None


@pytest.mark.parametrize(
    "field, value",
    [
        ("command_id", "bogus://x"),
        ("realm_id", "realm://Main"),
        ("actor_id", "principal://superuser/01900000-0000-7000-8000-000000000000"),
        ("authority_grant_id", "not-an-id"),
        ("causal_parent_action_id", "task://zzz"),
    ],
)
def test_command_envelope_validates_ids(field: str, value: str) -> None:
    with pytest.raises(ids.IdError):
        _command(**{field: value})


@pytest.mark.parametrize(
    "field, value",
    [
        ("expected_meta_revision", -1),
        ("expected_meta_revision", "3"),
        ("payload_schema_version", 0),
        ("payload_type", ""),
        ("payload_type", "Task.Submit/v1"),
        ("payload_type", "task.submit/v1;drop"),
    ],
)
def test_command_envelope_validates_fields(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        _command(**{field: value})


def test_command_envelope_rejects_non_json_payload() -> None:
    with pytest.raises(ValueError):
        _command(payload={"x": object()})


def test_command_envelope_auth_pairing() -> None:
    with pytest.raises(ValueError):
        _command(auth_nonce="n1")
    with pytest.raises(ValueError):
        _command(auth_signature=b"\x00")
    paired = _command(
        auth_nonce="n1", auth_issued_at_us=1_700_000_000_000_000, auth_signature=b"\x01"
    )
    assert paired.auth_signature == b"\x01"


def test_command_envelope_is_frozen() -> None:
    cmd = _command()
    with pytest.raises(Exception):
        cmd.payload_type = "other"  # type: ignore[misc]


def test_authorization_hash_stability_and_sensitivity() -> None:
    a = _command()
    b = _command()
    assert envelope.command_authorization_hash(a) == envelope.command_authorization_hash(b)
    other_payload = _command(payload={"title": "different"})
    other_revision = _command(expected_meta_revision=8)
    other_actor = _command(
        actor_id="principal://operator-root/01900000-0000-7000-8000-000000000001"
    )
    h = envelope.command_authorization_hash(a)
    assert h != envelope.command_authorization_hash(other_payload)
    assert h != envelope.command_authorization_hash(other_revision)
    assert h != envelope.command_authorization_hash(other_actor)


def test_fact_envelope_accepts_valid_chain_fields() -> None:
    fact = envelope.FactEnvelope(
        fact_id=ids.build_uri("fact", ids.new_uuid7()),
        realm_id=REALM,
        seq=1,
        occurred_at_us=1_700_000_000_000_000,
        recorded_at_us=1_700_000_000_000_001,
        actor_id=ACTOR,
        action_id=None,
        transaction_id=None,
        entity_type="task",
        entity_id="task://01900000-0000-7000-8000-000000000002",
        event_type="task.created",
        schema_version=1,
        payload={},
        payload_hash="0" * 64,
        prev_fact_hash="0" * 64,
        fact_hash="0" * 64,
    )
    assert fact.seq == 1


def test_fact_envelope_rejects_zero_seq_and_missing_types() -> None:
    kwargs = dict(
        fact_id=ids.build_uri("fact", ids.new_uuid7()),
        realm_id=REALM,
        seq=0,
        occurred_at_us=1,
        recorded_at_us=1,
        actor_id=ACTOR,
        action_id=None,
        transaction_id=None,
        entity_type="task",
        entity_id="task://01900000-0000-7000-8000-000000000002",
        event_type="task.created",
        schema_version=1,
        payload={},
        payload_hash="0" * 64,
        prev_fact_hash="0" * 64,
        fact_hash="0" * 64,
    )
    with pytest.raises(ValueError):
        envelope.FactEnvelope(**kwargs)
    with pytest.raises(ValueError):
        envelope.FactEnvelope(**{**kwargs, "seq": 1, "entity_type": ""})
    with pytest.raises(ValueError):
        envelope.FactEnvelope(**{**kwargs, "seq": 1, "schema_version": 0})
