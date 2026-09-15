"""Outbox fixed vocabulary and delivery policy (§41.38, §41.59.4).

The five delivery kinds are frozen; a semantic transition has exactly one
``dedupe_key``. The key preimage is
``sha256(kind + NUL + realm_id + NUL + semantic_entity_id + NUL +
transition_revision_or_request_id + NUL + payload_hash)``. Critical kinds
dead-lettering hold ``core_ready`` at false; only non-critical telemetry may
degrade readiness while staying true.
"""

from __future__ import annotations

import hashlib

__all__ = [
    "OUTBOX_KINDS",
    "CRITICAL_OUTBOX_KINDS",
    "OUTBOX_STATES",
    "MAX_OUTBOX_ATTEMPTS",
    "DEAD_LETTER_AGE_US",
    "outbox_dedupe_key",
    "outbox_backoff_s",
]

OUTBOX_KINDS = (
    "RECONCILE_REQUEST",
    "EXECUTION_SUBMIT",
    "TERMINAL_ACK",
    "PROJECTION_ADVANCE",
    "OPERATION_RUN",
)

#: Kinds whose dead-lettering fails core readiness (critical reconcile and
#: outbound effects). Non-critical telemetry may stay readiness-true.
CRITICAL_OUTBOX_KINDS = frozenset(
    {"RECONCILE_REQUEST", "EXECUTION_SUBMIT", "TERMINAL_ACK", "OPERATION_RUN"}
)

OUTBOX_STATES = ("PENDING", "LEASED", "DELIVERED", "DEAD_LETTER")

#: More than 20 attempts or 24h in delivery → DEAD_LETTER (§41.38).
MAX_OUTBOX_ATTEMPTS = 20
DEAD_LETTER_AGE_US = 24 * 60 * 60 * 1_000_000


def outbox_dedupe_key(
    kind: str,
    realm_id: str,
    semantic_entity_id: str,
    transition_id: str,
    payload_hash: str,
) -> str:
    """Stable dedupe key for one semantic transition (§41.38)."""

    preimage = b"\x00".join(
        part.encode("utf-8")
        for part in (kind, realm_id, semantic_entity_id, transition_id, payload_hash)
    )
    return hashlib.sha256(preimage).hexdigest()


def outbox_backoff_s(attempts: int) -> float:
    """Retry backoff ladder 1/2/4/8/16s, capped at 16s."""

    return float(min(2 ** max(attempts, 0), 16))
