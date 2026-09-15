"""Explicit Authority model (§41.16, §41.28).

Pure domain invariants: the frozen ``<resource>.<verb>`` permission registry,
typed scope unions, constraint v1 semantics, delegation containment and the
fixed authorization order (status/epoch → subject → permission → scope →
constraints/expiry → revocation). Storage and counters live in adapters; this
module never touches I/O. Unknown permissions/scopes fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .canonical import canonical_json
from .errors import ErrorCode, StableError

__all__ = [
    "PERMISSIONS",
    "SCOPE_TARGET_TYPES",
    "SCOPE_REALM_ALL",
    "ScopeTarget",
    "Scope",
    "GrantConstraints",
    "Grant",
    "AUTHORIZATION_DENIED_REASONS",
    "authorize",
    "validate_delegation",
    "command_signature_preimage",
    "execution_token_payload_hash",
]

# §41.28 v0.1 registry — the complete frozen set. Anything else is unknown and
# fails closed; additions require a schema minor plus ADR.
PERMISSIONS: frozenset[str] = frozenset(
    {
        "task.submit",
        "task.execute",
        "task.cancel",
        "task.budget.extend",
        "model.invoke",
        "artifact.put",
        "artifact.read.restricted",
        "artifact.verify",
        "composition.validate",
        "composition.commit",
        "composition.promote",
        "composition.rollback",
        "capability.invoke",
        "capability.inspect",
        "harness.install",
        "harness.activate",
        "harness.deactivate",
        "harness.uninstall",
        "state.read",
        "state.write",
        "state.migrate",
        "authority.inspect",
        "authority.grant",
        "authority.delegate",
        "authority.revoke",
        "experiment.run",
        "evaluation.record",
        "runtime.reflect",
        "runtime.diagnostics",
        "runtime.reconcile",
        "runtime.project",
        "runtime.token.issue",
        "runtime.admin.stop",
        "scratch.create",
        "scratch.execute",
        "scratch.inspect",
        "scratch.export",
        "scratch.release",
        "operations.backup",
        "operations.gc",
        "operations.repair",
        "effect.execute.irreversible",
    }
)

SCOPE_TARGET_TYPES: frozenset[str] = frozenset(
    {
        "REALM_ALL",
        "CAPABILITY",
        "HARNESS",
        "ARTIFACT_KIND",
        "TASK",
        "EXPERIMENT",
        "EFFECT_KIND",
    }
)
SCOPE_REALM_ALL = "REALM_ALL"


@dataclass(frozen=True, slots=True)
class ScopeTarget:
    """One typed scope target; ``REALM_ALL`` ignores ``id``."""

    type: str
    id: str = ""

    def __post_init__(self) -> None:
        if self.type not in SCOPE_TARGET_TYPES:
            raise ValueError(f"unknown scope target type: {self.type!r}")
        if self.type == SCOPE_REALM_ALL:
            if self.id not in ("", "*"):
                raise ValueError("REALM_ALL target takes no concrete id")
            object.__setattr__(self, "id", "*")
        elif not self.id:
            raise ValueError(f"scope target {self.type} requires an exact id")


@dataclass(frozen=True, slots=True)
class Scope:
    """Scope v1 ``{realm_id, targets:[{type,id}]}`` — a typed union, never a
    free-form string. Multiple targets are OR; there is no glob/prefix/regex."""

    realm_id: str
    targets: tuple[ScopeTarget, ...] = ()

    def __post_init__(self) -> None:
        if not self.realm_id or "://" not in self.realm_id:
            raise ValueError("scope realm_id must be a realm id")
        seen: set[tuple[str, str]] = set()
        for target in self.targets:
            key = (target.type, target.id)
            if key in seen:
                raise ValueError("duplicate scope target")
            seen.add(key)

    def matches(self, resource_realm: str, target: ScopeTarget | None) -> bool:
        """A check's resource provides its realm plus one concrete target."""

        if self.realm_id != resource_realm:
            return False
        if any(t.type == SCOPE_REALM_ALL for t in self.targets):
            return True
        if target is None:
            return False
        return any(t.type == target.type and t.id == target.id for t in self.targets)

    def contains(self, child: "Scope") -> bool:
        """Delegation containment: every child target must be covered."""

        if child.realm_id != self.realm_id:
            return False
        if any(t.type == SCOPE_REALM_ALL for t in self.targets):
            return True
        if any(t.type == SCOPE_REALM_ALL for t in child.targets):
            return False
        return all(t in self.targets for t in child.targets)

    def to_json(self) -> dict[str, Any]:
        return {
            "realm_id": self.realm_id,
            "targets": [{"type": t.type, "id": t.id} for t in self.targets],
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_json())

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> "Scope":
        try:
            targets = tuple(ScopeTarget(**t) for t in data.get("targets", []))
            return cls(realm_id=data["realm_id"], targets=targets)
        except (KeyError, TypeError) as exc:
            raise ValueError(f"malformed scope: {exc}") from exc


@dataclass(frozen=True, slots=True)
class GrantConstraints:
    """Constraint v1: the six fixed dimensions AND together. A missing numeric
    ceiling does NOT mean unlimited expansion — only the Root Grant may declare
    ``unbounded``."""

    epoch_id: str | None = None
    not_before_us: int | None = None
    expires_at_us: int | None = None
    max_uses: int | None = None
    resource_ceiling: Mapping[str, int] | None = None
    delegation_depth_remaining: int | None = None
    unbounded: bool = False

    def to_json(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        if self.epoch_id is not None:
            data["epoch_id"] = self.epoch_id
        if self.not_before_us is not None:
            data["not_before_us"] = self.not_before_us
        if self.expires_at_us is not None:
            data["expires_at_us"] = self.expires_at_us
        if self.max_uses is not None:
            data["max_uses"] = self.max_uses
        if self.resource_ceiling is not None:
            data["resource_ceiling"] = dict(self.resource_ceiling)
        if self.delegation_depth_remaining is not None:
            data["delegation_depth_remaining"] = self.delegation_depth_remaining
        if self.unbounded:
            data["unbounded"] = True
        return data

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> "GrantConstraints":
        unknown = set(data) - {
            "epoch_id",
            "not_before_us",
            "expires_at_us",
            "max_uses",
            "resource_ceiling",
            "delegation_depth_remaining",
            "unbounded",
        }
        if unknown:
            raise ValueError(f"unknown constraint dimensions: {sorted(unknown)}")
        ceiling = data.get("resource_ceiling")
        return cls(
            epoch_id=data.get("epoch_id"),
            not_before_us=data.get("not_before_us"),
            expires_at_us=data.get("expires_at_us"),
            max_uses=data.get("max_uses"),
            resource_ceiling=dict(ceiling) if ceiling is not None else None,
            delegation_depth_remaining=data.get("delegation_depth_remaining"),
            unbounded=bool(data.get("unbounded", False)),
        )


@dataclass(frozen=True, slots=True)
class Grant:
    """An immutable grant definition plus its current-status reference.

    Definition fields (issuer/subject/permissions/scope/constraints/...) are
    committed-once; ``status`` is the mutable active reference whose every
    change must write ``authority_grant_history`` plus a Fact.
    """

    grant_id: str
    epoch_id: str
    issuer_id: str
    subject_id: str
    permissions: frozenset[str]
    scope: Scope
    constraints: GrantConstraints
    delegable: bool
    delegation_depth: int
    status: str
    issued_at_us: int
    expires_at_us: int | None = None
    revoked_at_us: int | None = None
    parent_grant_id: str | None = None

    def __post_init__(self) -> None:
        if self.status not in ("ACTIVE", "REVOKED", "EXPIRED"):
            raise ValueError(f"invalid grant status: {self.status!r}")
        unknown = self.permissions - PERMISSIONS
        if unknown:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="grant references unknown permissions; failing closed",
                details={"unknown_permissions": sorted(unknown)},
            )


AUTHORIZATION_DENIED_REASONS: tuple[str, ...] = (
    "STATUS",
    "EPOCH",
    "SUBJECT",
    "PERMISSION",
    "SCOPE",
    "CONSTRAINT_TIME",
    "CONSTRAINT_USES",
    "REVOKED",
)


def authorize(
    grant: Grant,
    *,
    subject_id: str,
    permission: str,
    resource_realm: str,
    resource_target: ScopeTarget | None,
    epoch_id: str,
    now_us: int,
    uses_count: int = 0,
) -> str | None:
    """Run the fixed authorization order. Returns ``None`` when allowed or a
    stable denial reason from ``AUTHORIZATION_DENIED_REASONS``.

    Expiry is evaluated from caller-supplied time values (lazy expiry); the
    caller persists the EXPIRED transition after a denial reason of
    ``CONSTRAINT_TIME`` caused by ``expires_at_us`` in the past.
    """

    if permission not in PERMISSIONS:
        return "PERMISSION"  # unknown permission fails closed
    if grant.status != "ACTIVE":
        return "STATUS" if grant.status == "REVOKED" else "REVOKED"
    if grant.subject_id != subject_id:
        return "SUBJECT"
    if permission not in grant.permissions:
        return "PERMISSION"
    if not grant.scope.matches(resource_realm, resource_target):
        return "SCOPE"
    constraints = grant.constraints
    if constraints.epoch_id is not None and constraints.epoch_id != epoch_id:
        return "EPOCH"
    if constraints.not_before_us is not None and now_us < constraints.not_before_us:
        return "CONSTRAINT_TIME"
    if grant.expires_at_us is not None and now_us >= grant.expires_at_us:
        return "CONSTRAINT_TIME"
    if constraints.expires_at_us is not None and now_us >= constraints.expires_at_us:
        return "CONSTRAINT_TIME"
    if constraints.max_uses is not None and uses_count >= constraints.max_uses:
        return "CONSTRAINT_USES"
    return None


def validate_delegation(
    parent: Grant,
    *,
    child_permissions: frozenset[str],
    child_scope: Scope,
    child_constraints: GrantConstraints,
    child_delegable: bool,
) -> int:
    """Delegation must not expand any dimension (§41.28).

    Returns the child's ``delegation_depth`` (parent minus one). Raises
    ``StableError`` (AUTHORITY_DENIED) when containment is violated.
    """

    def deny(reason: str) -> StableError:
        return StableError(
            code=ErrorCode.AUTHORITY_DENIED,
            message=f"delegation expands parent grant: {reason}",
            details={"parent_grant_id": parent.grant_id, "dimension": reason},
        )

    if not parent.delegable:
        raise deny("DELEGABLE")
    if parent.status != "ACTIVE":
        raise deny("STATUS")
    unknown = child_permissions - PERMISSIONS
    if unknown:
        raise deny("UNKNOWN_PERMISSION")
    if not child_permissions <= parent.permissions:
        raise deny("PERMISSIONS")
    if not parent.scope.contains(child_scope):
        raise deny("SCOPE")
    pc = parent.constraints
    cc = child_constraints
    if pc.epoch_id is not None and cc.epoch_id != pc.epoch_id:
        raise deny("EPOCH")
    if pc.not_before_us is not None and (
        cc.not_before_us is None or cc.not_before_us < pc.not_before_us
    ):
        raise deny("NOT_BEFORE")
    if pc.expires_at_us is not None and (
        cc.expires_at_us is None or cc.expires_at_us > pc.expires_at_us
    ):
        raise deny("EXPIRES_AT")
    if cc.unbounded and not pc.unbounded:
        raise deny("UNBOUNDED")
    for dimension, parent_value in (pc.resource_ceiling or {}).items():
        child_value = (cc.resource_ceiling or {}).get(dimension)
        if child_value is None or child_value > parent_value:
            raise deny("RESOURCE_CEILING")
    if pc.max_uses is not None and (cc.max_uses is None or cc.max_uses > pc.max_uses):
        raise deny("MAX_USES")
    if parent.delegation_depth <= 0:
        raise deny("DEPTH_EXHAUSTED")
    if child_delegable and parent.delegation_depth - 1 <= 0:
        # A child that is itself delegable needs one remaining depth to spare.
        raise deny("DEPTH_EXHAUSTED")
    return parent.delegation_depth - 1


def command_signature_preimage(
    authorization_hash: str, nonce: str, issued_at_us: int
) -> bytes:
    """Root-authorized command signature preimage (§41.28).

    ``agent-meta-command-v1\\0`` + 32-byte authorization hash + NUL + nonce
    UTF-8 + NUL + issued time decimal ASCII.
    """

    raw = bytes.fromhex(authorization_hash)
    if len(raw) != 32:
        raise ValueError("authorization hash must be 32 bytes hex")
    return b"\x00".join(
        (
            b"agent-meta-command-v1",
            raw,
            nonce.encode("utf-8"),
            str(issued_at_us).encode("ascii"),
        )
    )


EXECUTION_TOKEN_VERSION = 1


def execution_token_payload_hash(payload: Mapping[str, Any]) -> bytes:
    """Execution token signature preimage (§41.16): domain separator + JCS."""

    required = (
        "token_version",
        "token_id",
        "backend_session_id",
        "realm_id",
        "actor_id",
        "action_id",
        "effect_kind",
        "target_scope_hash",
        "resource_ceiling",
        "issued_at_us",
        "expires_at_us",
        "nonce",
    )
    missing = [key for key in required if key not in payload]
    if missing:
        raise ValueError(f"execution token payload missing fields: {missing}")
    if payload["token_version"] != EXECUTION_TOKEN_VERSION:
        raise ValueError("unsupported execution token version")
    return b"agent-meta-execution-token-v1\x00" + canonical_json(dict(payload))
