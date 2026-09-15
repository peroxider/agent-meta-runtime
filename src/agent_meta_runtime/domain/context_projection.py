"""Deterministic context projection v1 (§41.12, §41.44.4, FR-MCTX-004).

Two-stage pipeline: sources are selected and redacted *before* ranking, then
rendered under a fixed budget ladder with per-section provenance. The same
source revisions, policy, tokenizer and budget must produce the identical
redacted projection, so every step here is a pure function of its inputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence

from .canonical import canonical_json, sha256_hex
from .errors import ErrorCode, StableError
from .ids import validate_id

__all__ = [
    "SECTION_DELIMITER",
    "Allocation",
    "BUDGET_LADDER",
    "BudgetLadder",
    "CandidateFact",
    "ProjectionManifest",
    "Section",
    "SourceRef",
    "allocate_budget",
    "projection_identity",
    "render_sections",
    "select_facts",
]

# Fixed UTF-8 delimiter rendered between sections (§41.44.4).
SECTION_DELIMITER = b"\n\x1e\n"

# Budget ladder order and caps as fractions of the total budget (§41.44.4):
# (segment, fraction, required_full). Required-full overflow rejects.
BUDGET_LADDER: tuple[tuple[str, float, bool], ...] = (
    ("system", 0.20, True),
    ("task_input", 0.30, False),
    ("capability_schema", 0.20, True),
    ("state_summary", 0.15, False),
    ("facts", 0.15, False),
)


@dataclass(frozen=True, slots=True)
class BudgetLadder:
    """Per-segment token needs; ``None`` means the segment is absent."""

    needs: Mapping[str, int | None]

    def __post_init__(self) -> None:
        unknown = set(self.needs) - {name for name, _, _ in BUDGET_LADDER}
        if unknown:
            raise ValueError(f"unknown ladder segments: {sorted(unknown)}")


@dataclass(frozen=True, slots=True)
class Allocation:
    total_budget: int
    granted: Mapping[str, int]
    rejected: str | None = None  # segment that overflowed a required cap


@dataclass(frozen=True, slots=True)
class CandidateFact:
    """A fact candidate for context selection; payload already redacted."""

    fact_id: str
    seq: int
    causal_distance: int
    entity_id: str
    payload: Mapping[str, object]


def allocate_budget(budget_tokens: int, ladder: BudgetLadder) -> Allocation:
    """Ladder allocation with unused quota rolling to later segments.

    A required-full segment that exceeds its cap yields ``rejected=<segment>``
    — the caller must fail with ``FAILED_PRECONDITION`` rather than silently
    over-budgeting (§41.44.4).
    """

    granted: dict[str, int] = {}
    remaining = budget_tokens
    for name, fraction, required_full in BUDGET_LADDER:
        need = ladder.needs.get(name)
        if need is None:
            granted[name] = 0
            continue
        if need < 0:
            raise ValueError(f"segment {name} need must be non-negative")
        cap = int(budget_tokens * fraction)
        if required_full and need > cap:
            return Allocation(
                total_budget=budget_tokens, granted=dict(granted), rejected=name
            )
        take = min(need, cap, remaining)
        granted[name] = take
        remaining -= take
    # Roll any unused quota into the last segment (facts).
    if remaining > 0:
        granted["facts"] = granted.get("facts", 0) + remaining
    return Allocation(total_budget=budget_tokens, granted=granted)


def select_facts(
    candidates: Sequence[CandidateFact],
    *,
    budget_tokens: int,
    tokens_per_fact: int,
) -> tuple[CandidateFact, ...]:
    """Deterministic fact selection: distance asc, seq desc, fact id asc.

    Deduplicates fact ids, sorts by the fixed key and truncates to the
    remaining budget. Callers redact *before* building candidates
    (redact-before-rank, §41.44.4).
    """

    if tokens_per_fact <= 0:
        raise ValueError("tokens_per_fact must be positive")
    if budget_tokens < 0:
        raise ValueError("budget_tokens must be non-negative")
    seen: set[str] = set()
    unique = []
    for fact in candidates:
        if fact.fact_id not in seen:
            seen.add(fact.fact_id)
            unique.append(fact)
    unique.sort(key=lambda f: (f.causal_distance, -f.seq, f.fact_id))
    max_facts = budget_tokens // tokens_per_fact
    return tuple(unique[:max_facts])


@dataclass(frozen=True, slots=True)
class SourceRef:
    kind: str
    ref: str
    content_hash: str


@dataclass(frozen=True, slots=True)
class Section:
    section_id: str
    renderer_artifact_id: str
    output_artifact_id: str
    token_count: int


@dataclass(frozen=True, slots=True)
class ProjectionManifest:
    """ProjectionManifest v1 — required fields only (§41.12).

    ``x_``-prefixed extension fields may be attached by callers but never
    participate in the projection identity.
    """

    projection_id: str
    policy_artifact_id: str
    composition_id: str
    meta_revision: int
    source_refs: tuple[SourceRef, ...]
    sections: tuple[Section, ...]
    redaction_policy_artifact_id: str
    tokenizer_id: str
    total_tokens: int
    budget_tokens: int
    extensions: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        validate_id(self.projection_id)
        if not str(self.projection_id).startswith("context://projection/"):
            raise ValueError("projection_id must be a context://projection/ id")
        validate_id(self.policy_artifact_id)
        validate_id(self.composition_id)
        if self.meta_revision < 0:
            raise ValueError("meta_revision must be non-negative")
        if not self.source_refs:
            raise ValueError("manifest requires at least one source ref")
        if not self.sections:
            raise ValueError("manifest requires at least one section")
        for ref in self.source_refs:
            if not ref.kind or not ref.ref or not ref.content_hash:
                raise ValueError("source refs require kind, ref and content_hash")
        for section in self.sections:
            validate_id(section.renderer_artifact_id)
            validate_id(section.output_artifact_id)
            if section.token_count < 0:
                raise ValueError("section token_count must be non-negative")
        if self.total_tokens > self.budget_tokens:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="projection exceeds token budget",
                details={
                    "total_tokens": str(self.total_tokens),
                    "budget_tokens": str(self.budget_tokens),
                },
            )
        for key in self.extensions:
            if not key.startswith("x_"):
                raise ValueError("extension fields must start with x_")

    def identity_hash(self) -> str:
        """Hash over required fields only; extensions never included."""

        body = {
            "budget_tokens": self.budget_tokens,
            "composition_id": self.composition_id,
            "meta_revision": self.meta_revision,
            "policy_artifact_id": self.policy_artifact_id,
            "projection_id": self.projection_id,
            "redaction_policy_artifact_id": self.redaction_policy_artifact_id,
            "sections": [
                {
                    "output_artifact_id": s.output_artifact_id,
                    "renderer_artifact_id": s.renderer_artifact_id,
                    "section_id": s.section_id,
                    "token_count": s.token_count,
                }
                for s in self.sections
            ],
            "source_refs": [
                {"content_hash": r.content_hash, "kind": r.kind, "ref": r.ref}
                for r in self.source_refs
            ],
            "tokenizer_id": self.tokenizer_id,
            "total_tokens": self.total_tokens,
        }
        return sha256_hex(canonical_json(body))


def render_sections(bodies: Sequence[bytes]) -> bytes:
    """Join section bodies with the fixed UTF-8 delimiter (§41.44.4)."""

    return SECTION_DELIMITER.join(bodies)


def projection_identity(manifest: ProjectionManifest) -> str:
    return manifest.identity_hash()
