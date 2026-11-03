"""Public command and fact envelopes (§41.4.3).

``CommandEnvelope`` is the single write-path entry shape; ``FactEnvelope`` is
the canonical ledger record shape. Both are frozen; payload content is a
verifiable JSON value — large content lives in the Artifact Store and only
hash/size/media-type references appear in Facts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Union

from .canonical import canonical_json, sha256_hex
from .ids import validate_id

__all__ = [
    "CommandEnvelope",
    "FactEnvelope",
    "JsonValue",
    "command_authorization_hash",
    "command_payload_hash",
]

JsonValue = Union[None, bool, int, float, str, list["JsonValue"], dict[str, "JsonValue"]]

_PAYLOAD_TYPE_RE = re.compile(r"[a-z][a-z0-9._-]*(?:/[a-z0-9._-]+)*\Z")


@dataclass(frozen=True, slots=True)
class CommandEnvelope:
    command_id: str
    realm_id: str
    actor_id: str
    authority_grant_id: str | None
    expected_meta_revision: int | None
    causal_parent_action_id: str | None
    payload_type: str
    payload_schema_version: int
    payload: Mapping[str, JsonValue]
    auth_nonce: str | None
    auth_issued_at_us: int | None
    auth_signature: bytes | None

    def __post_init__(self) -> None:
        validate_id(self.command_id)
        validate_id(self.realm_id)
        validate_id(self.actor_id)
        if self.authority_grant_id is not None:
            validate_id(self.authority_grant_id)
        if self.causal_parent_action_id is not None:
            validate_id(self.causal_parent_action_id)
        if self.expected_meta_revision is not None and (
            type(self.expected_meta_revision) is not int
            or self.expected_meta_revision < 0
        ):
            raise ValueError(
                "expected_meta_revision must be None or a non-negative integer"
            )
        if (
            not self.payload_type
            or len(self.payload_type) > 128
            or not _PAYLOAD_TYPE_RE.match(self.payload_type)
        ):
            raise ValueError("payload_type must be a registry token, e.g. task.submit/v1")
        if type(self.payload_schema_version) is not int or self.payload_schema_version < 1:
            raise ValueError("payload_schema_version must be >= 1")
        object.__setattr__(self, "payload", _freeze_json(self.payload))
        auth_triple = (self.auth_nonce, self.auth_issued_at_us, self.auth_signature)
        if any(x is not None for x in auth_triple) and not all(
            x is not None for x in auth_triple
        ):
            raise ValueError(
                "auth_nonce, auth_issued_at_us and auth_signature must be provided together"
            )
        if self.auth_signature is not None and not isinstance(self.auth_signature, bytes):
            raise ValueError("auth_signature must be bytes")


@dataclass(frozen=True, slots=True)
class FactEnvelope:
    fact_id: str
    realm_id: str
    seq: int
    occurred_at_us: int
    recorded_at_us: int
    actor_id: str
    action_id: str | None
    transaction_id: str | None
    entity_type: str
    entity_id: str
    event_type: str
    schema_version: int
    payload: Mapping[str, JsonValue]
    payload_hash: str
    prev_fact_hash: str
    fact_hash: str

    def __post_init__(self) -> None:
        validate_id(self.fact_id)
        validate_id(self.realm_id)
        if self.seq < 1:
            raise ValueError("fact seq starts at 1")
        validate_id(self.actor_id)
        if self.action_id is not None:
            validate_id(self.action_id)
        if self.transaction_id is not None:
            validate_id(self.transaction_id)
        if not self.entity_type or not self.event_type:
            raise ValueError("entity_type and event_type are required")
        if self.schema_version < 1:
            raise ValueError("schema_version must be >= 1")
        object.__setattr__(self, "payload", _freeze_json(self.payload))


def _freeze_json(value: Any) -> Any:
    """Recursively convert mappings to plain dicts and validate JSON-ness."""

    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("non-finite floats are not JSON values")
        return value
    if isinstance(value, (list, tuple)):
        return [_freeze_json(item) for item in value]
    if isinstance(value, Mapping):
        return {str(k): _freeze_json(v) for k, v in value.items()}
    raise ValueError(f"type {type(value).__name__} is not a JSON value")


def command_payload_hash(
    payload_type: str, payload_schema_version: int, payload: Mapping[str, JsonValue]
) -> str:
    """``sha256(payload_type NUL schema_version NUL JCS(payload))`` (§41.46)."""

    material = b"\x00".join(
        (
            payload_type.encode("utf-8"),
            str(payload_schema_version).encode("utf-8"),
            canonical_json(dict(payload)),
        )
    )
    return sha256_hex(material)


def _or_empty(value: str | int | None) -> str:
    return "" if value is None else str(value)


def command_authorization_hash(envelope: CommandEnvelope) -> str:
    """SHA-256 over the NUL-joined idempotency-relevant fields (§41.46).

    ``authorization_hash = sha256(command_id NUL realm_id NUL actor_id NUL
    authority_grant_id-or-empty NUL expected_meta_revision-or-empty NUL
    causal_parent_action_id-or-empty NUL payload_hash)``. A different
    authorization under the same command_id yields ``IDEMPOTENCY_CONFLICT``.
    """

    payload_hash = command_payload_hash(
        envelope.payload_type, envelope.payload_schema_version, envelope.payload
    )
    material = b"\x00".join(
        field.encode("utf-8")
        for field in (
            envelope.command_id,
            envelope.realm_id,
            envelope.actor_id,
            _or_empty(envelope.authority_grant_id),
            _or_empty(envelope.expected_meta_revision),
            _or_empty(envelope.causal_parent_action_id),
            payload_hash,
        )
    )
    return sha256_hex(material)
