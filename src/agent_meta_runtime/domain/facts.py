"""Per-Realm Fact hash chain math (§41.35).

Pure domain logic: the chain prefix, field order and NUL separators are part
of the frozen wire contract. Genesis ``fact_head_hash`` is 64 ASCII ``0``.
"""

from __future__ import annotations

from typing import Any, Mapping

from .canonical import canonical_json, sha256_hex

__all__ = [
    "FACT_HASH_PREFIX",
    "GENESIS_FACT_HEAD",
    "compute_fact_hash",
    "fact_payload_hash",
]

FACT_HASH_PREFIX = b"agent-meta-fact-v1"
GENESIS_FACT_HEAD = "0" * 64


def fact_payload_hash(payload: Mapping[str, JsonValue]) -> str:
    """SHA-256 over the JCS encoding of the fact payload."""

    return sha256_hex(canonical_json(dict(payload)))


def compute_fact_hash(
    prev_fact_hash: str,
    *,
    realm_id: str,
    seq: int,
    occurred_at_us: int,
    recorded_at_us: int,
    actor_id: str,
    action_id: str | None,
    transaction_id: str | None,
    entity_type: str,
    entity_id: str,
    event_type: str,
    schema_version: int,
    payload_hash: str,
) -> str:
    """``sha256("agent-meta-fact-v1" NUL <fields NUL-joined>)`` per §41.35."""

    material = b"\x00".join(
        field.encode("utf-8")
        for field in (
            "agent-meta-fact-v1",
            prev_fact_hash,
            realm_id,
            str(seq),
            str(occurred_at_us),
            str(recorded_at_us),
            actor_id,
            action_id or "",
            transaction_id or "",
            entity_type,
            entity_id,
            event_type,
            str(schema_version),
            payload_hash,
        )
    )
    return sha256_hex(material)
