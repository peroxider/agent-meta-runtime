"""Deterministic compatibility solver (§41.37, §41.42.1/2).

``validate(base, candidate, catalog, backend_profile)`` is a pure function
over frozen inputs producing a byte-stable ``CompatibilityReport``. The twelve
check codes run in the fixed spec order; identical frozen inputs yield
identical JCS report bytes. Schema comparison uses the conservative syntactic
subset only — anything unprovable is ``COMPATIBILITY_UNKNOWN`` and breaks
activation, never silently ignored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .canonical import canonical_json, sha256_hex

__all__ = [
    "EFFECT_REGISTRY",
    "TRUST_PLACEMENT",
    "PLACEMENTS",
    "CompatibilityIssue",
    "CompatibilityReport",
    "parse_semver_range",
    "semver_satisfies",
    "compare_schema",
    "validate",
]

EFFECT_REGISTRY: frozenset[str] = frozenset(
    {
        "none",
        "model.invoke",
        "artifact.put",
        "filesystem.read",
        "filesystem.write",
        "network.request",
        "process.spawn",
        "credential.use",
        "state.read",
        "state.write",
        "external.reversible",
        "external.irreversible",
    }
)

# §41.32 trust class → minimum acceptable placements (v0.1 Portable truth).
TRUST_PLACEMENT: dict[str, frozenset[str]] = {
    "builtin_or_signed": frozenset({"in_process", "process", "isolated_process", "managed"}),
    "trusted_candidate": frozenset({"isolated_process", "managed"}),
    "untrusted_candidate": frozenset({"managed"}),
    "high_risk_effect_candidate": frozenset({"managed"}),
}
PLACEMENTS: frozenset[str] = frozenset({"in_process", "process", "isolated_process", "managed"})

_SLOT_NAME_RE = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_SEMVER_RE = re.compile(
    r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\Z"
)
_COMPARATOR_RE = re.compile(r"(>=|<=|==|=|>|<)\s*(\S+)")
_UNKNOWN_KEYWORDS = ("oneOf", "anyOf", "allOf", "not", "$ref", "$dynamicRef")


def parse_semver_range(range_expr: str) -> tuple[tuple[str, tuple[int, int, int]], ...]:
    """Parse a comparator conjunction; OR/wildcards are rejected (§41.42.1)."""

    comparators: list[tuple[str, tuple[int, int, int]]] = []
    for token in range_expr.split():
        match = _COMPARATOR_RE.fullmatch(token)
        if match is None:
            raise ValueError(f"unsupported semver comparator: {token!r}")
        op, version = match.group(1), match.group(2)
        if "*" in version or "x" in version:
            raise ValueError(f"wildcard not allowed in semver range: {token!r}")
        m = _SEMVER_RE.match(version)
        if m is None or m.end() != len(version):
            raise ValueError(f"invalid semver: {version!r}")
        if op == "=":
            op = "=="
        comparators.append((op, (int(m.group(1)), int(m.group(2)), int(m.group(3)))))
    if not comparators:
        raise ValueError("empty semver range")
    return tuple(comparators)


def semver_satisfies(
    version: str, comparators: tuple[tuple[str, tuple[int, int, int]], ...]
) -> bool:
    m = _SEMVER_RE.match(version)
    if m is None or m.end() != len(version):
        raise ValueError(f"invalid semver: {version!r}")
    v = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    for op, ref in comparators:
        if op == ">=" and not v >= ref:
            return False
        if op == ">" and not v > ref:
            return False
        if op == "<=" and not v <= ref:
            return False
        if op == "<" and not v < ref:
            return False
        if op == "==" and v != ref:
            return False
    return True


def _hash_of(value: Any) -> str:
    return sha256_hex(canonical_json(value))


def _contains_unknown_keyword(schema: Any) -> bool:
    if isinstance(schema, dict):
        if any(key in schema for key in _UNKNOWN_KEYWORDS):
            return True
        return any(_contains_unknown_keyword(v) for v in schema.values())
    if isinstance(schema, list):
        return any(_contains_unknown_keyword(v) for v in schema)
    return False


def _as_type_set(type_value: Any) -> frozenset[str] | None:
    if type_value is None:
        return None
    if isinstance(type_value, str):
        return frozenset({type_value})
    if isinstance(type_value, list) and all(isinstance(t, str) for t in type_value):
        return frozenset(type_value)
    return None


def _type_accepts(old: Any, new: Any) -> bool:
    """True when every value of type ``old`` is also of type-set ``new``."""

    old_types = _as_type_set(old)
    new_types = _as_type_set(new)
    if old_types is None or new_types is None:
        return True
    return old_types <= new_types


def _bounds_contain(
    old: Mapping[str, Any], new: Mapping[str, Any], keys: tuple[str, ...]
) -> bool:
    """Numeric/length bound pairs: new interval must contain the old one."""

    for lower, upper in zip(keys, keys[1:]):
        old_lo, old_hi = old.get(lower), old.get(upper)
        new_lo, new_hi = new.get(lower), new.get(upper)
        if old_lo is not None and (new_lo is None or new_lo > old_lo):
            return False
        if old_hi is not None and (new_hi is None or new_hi < old_hi):
            return False
    return True


def compare_schema(old: Any, new: Any, *, direction: str) -> str:
    """Conservative JSON-Schema compatibility verdict (§41.37, §41.42.2).

    ``direction='input'``: ``new`` must accept every value ``old`` accepted
    (contravariance). ``direction='output'``: ``new`` outputs must still
    satisfy ``old`` (covariance). Returns ``compatible`` | ``breaking`` |
    ``unknown``.
    """

    if direction not in ("input", "output"):
        raise ValueError("direction must be 'input' or 'output'")
    if _contains_unknown_keyword(old) or _contains_unknown_keyword(new):
        return "compatible" if _hash_of(old) == _hash_of(new) else "unknown"
    if not isinstance(old, dict) or not isinstance(new, dict):
        return "compatible" if _hash_of(old) == _hash_of(new) else "breaking"
    widening = direction == "input"

    if not _type_accepts(old.get("type"), new.get("type")):
        return "breaking"

    old_enum, new_enum = old.get("enum"), new.get("enum")
    old_const, new_const = old.get("const"), new.get("const")
    old_allowed = set(old_enum) if old_enum is not None else (
        {old_const} if old_const is not None else None
    )
    new_allowed = set(new_enum) if new_enum is not None else (
        {new_const} if new_const is not None else None
    )
    if old_allowed is not None and new_allowed is not None:
        if not old_allowed <= new_allowed:
            return "breaking"
    elif old_allowed is not None and new_allowed is None:
        if not widening:
            return "breaking"  # output schema dropped its value constraint

    old_props = old.get("properties", {})
    new_props = new.get("properties", {})
    old_required = set(old.get("required", ()))
    new_required = set(new.get("required", ()))
    if widening:
        if new_required - old_required:
            return "breaking"  # adding an input requirement rejects old payloads
        if old_props and not set(old_props) <= set(new_props):
            # additionalProperties defaults to false: a dropped property
            # rejects previously valid inputs.
            if not old.get("additionalProperties", False) and not new.get(
                "additionalProperties", False
            ):
                return "breaking"
    else:
        if old_required and not old_required <= new_required:
            return "breaking"
        if old_props and not set(old_props) <= set(new_props):
            return "breaking"

    for name in set(old_props) & set(new_props):
        verdict = compare_schema(old_props[name], new_props[name], direction=direction)
        if verdict != "compatible":
            return verdict

    if "items" in old and "items" in new:
        verdict = compare_schema(old["items"], new["items"], direction=direction)
        if verdict != "compatible":
            return verdict

    if not _bounds_contain(old, new, ("minimum", "maximum")) or not _bounds_contain(
        old, new, ("minLength", "maxLength")
    ):
        return "breaking"

    old_additional = old.get("additionalProperties", False)
    new_additional = new.get("additionalProperties", False)
    if old_additional and not new_additional:
        return "breaking"
    return "compatible"


_SEVERITY_RANK = {"ERROR": 0, "WARNING": 1}
_IDEMPOTENCY_RANK = {"NONE": 0, "KEYED": 1, "PURE": 2}
_RETRY_RANK = {"NEVER": 0, "SAME_KEY_TRANSIENT": 1}


@dataclass(frozen=True, slots=True)
class CompatibilityIssue:
    """One stable report issue; ``path`` is RFC 6901 JSON Pointer."""

    code: str
    severity: str
    path: str
    message_template_id: str
    old_value_hash: str | None = None
    new_value_hash: str | None = None
    required_permissions: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "path": self.path,
            "old_value_hash": self.old_value_hash,
            "new_value_hash": self.new_value_hash,
            "required_permissions": list(self.required_permissions),
            "message_template_id": self.message_template_id,
        }


@dataclass(frozen=True, slots=True)
class CompatibilityReport:
    """report_version=1 result; identical frozen inputs are byte-identical."""

    base_composition_id: str
    candidate_composition_id: str
    catalog_revision: int
    backend_profile_hash: str
    validator_artifact_id: str
    validated_at_meta_revision: int
    issues: tuple[CompatibilityIssue, ...] = field(default_factory=tuple)

    @property
    def activatable(self) -> bool:
        return not any(issue.severity == "ERROR" for issue in self.issues)

    def sorted_issues(self) -> tuple[CompatibilityIssue, ...]:
        deduped: dict[tuple, CompatibilityIssue] = {}
        for issue in self.issues:
            key = (
                issue.code,
                issue.path,
                issue.old_value_hash or "",
                issue.new_value_hash or "",
            )
            deduped.setdefault(key, issue)
        return tuple(
            sorted(
                deduped.values(),
                key=lambda i: (
                    _SEVERITY_RANK[i.severity],
                    i.code,
                    i.path,
                    i.old_value_hash or "",
                    i.new_value_hash or "",
                ),
            )
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "report_version": 1,
            "base_composition_id": self.base_composition_id,
            "candidate_composition_id": self.candidate_composition_id,
            "catalog_revision": self.catalog_revision,
            "backend_profile_hash": self.backend_profile_hash,
            "validator_artifact_id": self.validator_artifact_id,
            "validated_at_meta_revision": self.validated_at_meta_revision,
            "issues": [issue.to_json() for issue in self.sorted_issues()],
            "activatable": self.activatable,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_json())


def _slot_map(composition: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    slots = composition.get("slots")
    if not isinstance(slots, dict):
        raise ValueError("composition slots must be a mapping")
    return dict(slots)


def _operation_permissions(contract: Mapping[str, Any]) -> set[str]:
    perms: set[str] = set()
    for operation in contract.get("operations", []):
        perms.update(operation.get("required_permissions", []))
    return perms


def _operation_effects(contract: Mapping[str, Any]) -> set[str]:
    effects: set[str] = set()
    for operation in contract.get("operations", []):
        effects.update(operation.get("effects", []))
    return effects


def _wiring_dag_has_cycle(
    slots: Mapping[str, Mapping[str, Any]], wiring: Iterable[Mapping[str, Any]]
) -> bool:
    edges: dict[str, set[str]] = {name: set() for name in slots}
    for entry in wiring:
        consumer, provider = entry.get("consumer_slot"), entry.get("provider_slot")
        if consumer in edges and provider in edges:
            edges[consumer].add(provider)
    state: dict[str, int] = {}

    def visit(node: str) -> bool:
        if state.get(node) == 1:
            return True
        if state.get(node) == 2:
            return False
        state[node] = 1
        if any(visit(next_node) for next_node in edges[node]):
            return True
        state[node] = 2
        return False

    return any(visit(name) for name in slots)


def validate(
    base: Mapping[str, Any],
    candidate: Mapping[str, Any],
    catalog: Mapping[tuple[str, int], Mapping[str, Any]],
    backend_profile: Mapping[str, Any],
    *,
    artifact_index: Iterable[str] = (),
    migration_paths: Iterable[tuple[str, str]] = (),
    approved_effect_expansions: Iterable[str] = (),
    new_grant_permissions: Iterable[str] = (),
    realm_resource_ceiling: Mapping[str, int] | None = None,
    catalog_revision: int = 0,
    backend_profile_hash: str = "",
    validator_artifact_id: str = "",
    validated_at_meta_revision: int = 0,
) -> CompatibilityReport:
    """Run the twelve fixed checks in order (§41.37)."""

    known_artifacts = frozenset(artifact_index)
    migrations = frozenset(migration_paths)
    approved_effects = frozenset(approved_effect_expansions)
    granted_permissions = frozenset(new_grant_permissions)
    features = set(backend_profile.get("features", ()))
    managed_backend = backend_profile.get("placement") == "managed"

    issues: list[CompatibilityIssue] = []

    def issue(
        code: str,
        path: str,
        template: str,
        *,
        severity: str = "ERROR",
        old: Any = None,
        new: Any = None,
        permissions: Iterable[str] = (),
    ) -> None:
        issues.append(
            CompatibilityIssue(
                code=code,
                severity=severity,
                path=path,
                message_template_id=template,
                old_value_hash=_hash_of(old) if old is not None else None,
                new_value_hash=_hash_of(new) if new is not None else None,
                required_permissions=tuple(sorted(set(permissions))),
            )
        )

    try:
        base_slots = _slot_map(base)
        candidate_slots = _slot_map(candidate)
    except ValueError:
        base_slots, candidate_slots = {}, {}

    # 1. STRUCTURE_INVALID
    if candidate.get("schema") != "composition/v1":
        issue("STRUCTURE_INVALID", "", "structure.schema_tag")
    for name, slot in candidate_slots.items():
        if not _SLOT_NAME_RE.match(name):
            issue("STRUCTURE_INVALID", f"/slots/{name}", "structure.slot_name")
        if slot.get("criticality") not in ("REQUIRED", "OPTIONAL"):
            issue(
                "STRUCTURE_INVALID",
                f"/slots/{name}/criticality",
                "structure.criticality",
            )
        elif slot.get("criticality") == "REQUIRED" and slot.get(
            "degradation_policy"
        ) not in ("REJECT_TASK", "FALLBACK"):
            issue(
                "STRUCTURE_INVALID",
                f"/slots/{name}/degradation_policy",
                "structure.required_degradation",
            )
        elif slot.get("criticality") == "OPTIONAL" and slot.get(
            "degradation_policy"
        ) not in ("REJECT_TASK", "OMIT", "FALLBACK"):
            issue(
                "STRUCTURE_INVALID",
                f"/slots/{name}/degradation_policy",
                "structure.optional_degradation",
            )
        fallback = slot.get("fallback_slot")
        if fallback is not None and fallback not in candidate_slots:
            issue(
                "STRUCTURE_INVALID",
                f"/slots/{name}/fallback_slot",
                "structure.fallback_missing",
            )
        elif fallback == name:
            issue(
                "STRUCTURE_INVALID",
                f"/slots/{name}/fallback_slot",
                "structure.fallback_self",
            )
    candidate_wiring = candidate.get("wiring", [])
    if not isinstance(candidate_wiring, list):
        candidate_wiring = []
        issue("STRUCTURE_INVALID", "/wiring", "structure.wiring_type")
    if _wiring_dag_has_cycle(candidate_slots, candidate_wiring):
        issue("STRUCTURE_INVALID", "/wiring", "structure.wiring_cycle")

    def contract_of(slot: Mapping[str, Any]) -> Mapping[str, Any]:
        return catalog.get((slot.get("capability_id"), slot.get("descriptor_revision")), {})

    # 2. ARTIFACT_INVALID
    for name, slot in candidate_slots.items():
        key = (slot.get("capability_id"), slot.get("descriptor_revision"))
        if key not in catalog:
            issue("ARTIFACT_INVALID", f"/slots/{name}", "artifact.descriptor_missing")
        elif slot.get("artifact_id") not in known_artifacts:
            issue("ARTIFACT_INVALID", f"/slots/{name}/artifact_id", "artifact.missing")

    # 3. INTERFACE_MISSING — every require exactly one compatible provider.
    provider_index: dict[str, list[tuple[str, Mapping[str, Any]]]] = {}
    for name, slot in candidate_slots.items():
        for provided in contract_of(slot).get("provides", []):
            provider_index.setdefault(provided.get("interface_id"), []).append(
                (name, provided)
            )
    wiring_by_consumer: dict[str, list[Mapping[str, Any]]] = {}
    for entry in candidate_wiring:
        wiring_by_consumer.setdefault(entry.get("consumer_slot"), []).append(entry)
    for name, slot in candidate_slots.items():
        for requirement in contract_of(slot).get("requires", []):
            interface_id = requirement.get("interface_id")
            entries = [
                e
                for e in wiring_by_consumer.get(name, [])
                if e.get("requirement_interface") == interface_id
            ]
            if len(entries) != 1:
                issue(
                    "INTERFACE_MISSING",
                    f"/slots/{name}",
                    "interface.requirement_unwired",
                    new=interface_id,
                )
                continue
            provider_slot = entries[0].get("provider_slot")
            if provider_slot not in candidate_slots:
                issue("INTERFACE_MISSING", "/wiring", "interface.provider_unknown", new=interface_id)
                continue
            providers = provider_index.get(interface_id, [])
            if len(providers) != 1 or providers[0][0] != provider_slot:
                issue(
                    "INTERFACE_MISSING",
                    "/wiring",
                    "interface.provider_mismatch",
                    new=interface_id,
                )
                continue
            for provided in contract_of(candidate_slots[provider_slot]).get("provides", []):
                if provided.get("interface_id") != interface_id:
                    continue
                try:
                    comparators = parse_semver_range(requirement.get("version_range", ""))
                    ok = semver_satisfies(provided.get("version", ""), comparators)
                except ValueError:
                    ok = False
                if not ok:
                    issue(
                        "INTERFACE_MISSING",
                        "/wiring",
                        "interface.version_range_unmet",
                        new=interface_id,
                    )

    # 4. SCHEMA_BREAKING / COMPATIBILITY_UNKNOWN — per matched slot pair.
    for name, slot in candidate_slots.items():
        base_slot = base_slots.get(name) if base_slots else None
        if base_slot is None:
            continue
        base_ops = {
            op.get("operation_id"): op
            for op in contract_of(base_slot).get("operations", [])
        }
        for cand_op in contract_of(slot).get("operations", []):
            base_op = base_ops.get(cand_op.get("operation_id"))
            if base_op is None:
                continue
            if base_op.get('resource_contract') != cand_op.get('resource_contract'):
                issue('SCHEMA_BREAKING', f'/slots/{name}', 'resource.contract_changed',
                    old=base_op.get('resource_contract'), new=cand_op.get('resource_contract'))
            for direction in ("input", "output"):
                base_schema = base_op.get(f"_{direction}_schema")
                cand_schema = cand_op.get(f"_{direction}_schema")
                if base_schema is None or cand_schema is None:
                    continue
                verdict = compare_schema(base_schema, cand_schema, direction=direction)
                if verdict == "breaking":
                    issue(
                        "SCHEMA_BREAKING",
                        f"/slots/{name}",
                        "schema.breaking",
                        old=base_schema,
                        new=cand_schema,
                    )
                elif verdict == "unknown":
                    issue(
                        "COMPATIBILITY_UNKNOWN",
                        f"/slots/{name}",
                        "schema.unknown",
                        old=base_schema,
                        new=cand_schema,
                    )

    # 5. EFFECT_EXPANDED — candidate effect set must be a baseline subset.
    for name, slot in candidate_slots.items():
        candidate_effects = _operation_effects(contract_of(slot))
        unknown_effects = candidate_effects - EFFECT_REGISTRY
        if unknown_effects:
            issue(
                "EFFECT_EXPANDED",
                f"/slots/{name}",
                "effect.unknown",
                new=sorted(unknown_effects),
            )
        base_slot = base_slots.get(name) if base_slots else None
        if base_slot is not None:
            base_effects = _operation_effects(contract_of(base_slot))
            expanded = candidate_effects - base_effects - approved_effects
            if expanded:
                issue(
                    "EFFECT_EXPANDED",
                    f"/slots/{name}",
                    "effect.expanded",
                    new=sorted(expanded),
                )

    # 6. AUTHORITY_EXPANDED
    for name, slot in candidate_slots.items():
        candidate_permissions = _operation_permissions(contract_of(slot))
        unknown_permissions = candidate_permissions - granted_permissions
        base_slot = base_slots.get(name) if base_slots else None
        if base_slot is not None:
            unknown_permissions -= _operation_permissions(contract_of(base_slot))
        if unknown_permissions:
            issue(
                "AUTHORITY_EXPANDED",
                f"/slots/{name}",
                "authority.expanded",
                new=sorted(unknown_permissions),
                permissions=unknown_permissions,
            )

    # 7. STATE_MIGRATION_MISSING
    for name, slot in candidate_slots.items():
        target_schema = (contract_of(slot).get("state") or {}).get("schema_artifact_id")
        if target_schema is None:
            continue
        base_slot = base_slots.get(name) if base_slots else None
        if base_slot is None:
            continue
        base_schema = (contract_of(base_slot).get("state") or {}).get("schema_artifact_id")
        if base_schema is not None and base_schema != target_schema:
            if (base_schema, target_schema) not in migrations:
                issue(
                    "STATE_MIGRATION_MISSING",
                    f"/slots/{name}/state",
                    "state.migration_missing",
                    old=base_schema,
                    new=target_schema,
                )

    # 8. RETRY_SEMANTICS_BREAKING
    for name, slot in candidate_slots.items():
        base_slot = base_slots.get(name) if base_slots else None
        if base_slot is None:
            continue
        base_ops = {
            op.get("operation_id"): op
            for op in contract_of(base_slot).get("operations", [])
        }
        for cand_op in contract_of(slot).get("operations", []):
            base_op = base_ops.get(cand_op.get("operation_id"))
            if base_op is None:
                continue
            if _IDEMPOTENCY_RANK.get(cand_op.get("idempotency"), -1) < _IDEMPOTENCY_RANK.get(
                base_op.get("idempotency"), -1
            ):
                issue(
                    "RETRY_SEMANTICS_BREAKING",
                    f"/slots/{name}",
                    "retry.idempotency_weakened",
                    old=base_op.get("idempotency"),
                    new=cand_op.get("idempotency"),
                )
            if _RETRY_RANK.get(cand_op.get("retry_semantics"), -1) > _RETRY_RANK.get(
                base_op.get("retry_semantics"), -1
            ):
                issue(
                    "RETRY_SEMANTICS_BREAKING",
                    f"/slots/{name}",
                    "retry.widened",
                    old=base_op.get("retry_semantics"),
                    new=cand_op.get("retry_semantics"),
                )

    # 9. BACKEND_FEATURE_MISSING
    for name, slot in candidate_slots.items():
        requirements = contract_of(slot).get("execution_requirements") or {}
        for feature in requirements.get("required_features", ()):
            if feature not in features:
                issue(
                    "BACKEND_FEATURE_MISSING",
                    f"/slots/{name}",
                    "backend.required_feature_missing",
                    new=feature,
                )
        for feature in requirements.get("preferred_features", ()):
            if feature not in features:
                issue(
                    "BACKEND_FEATURE_MISSING",
                    f"/slots/{name}",
                    "backend.preferred_feature_missing",
                    severity="WARNING",
                    new=feature,
                )

    # 10. PLACEMENT_UNSAFE — trust class vs placement (§41.32).
    for name, slot in candidate_slots.items():
        trust_class = contract_of(slot).get("runtime_constraints", {}).get(
            "trust_class", "trusted_candidate"
        )
        placement = slot.get("placement", "isolated_process")
        if placement not in PLACEMENTS:
            issue("PLACEMENT_UNSAFE", f"/slots/{name}/placement", "placement.unknown")
        elif not managed_backend and placement not in TRUST_PLACEMENT.get(
            trust_class, frozenset()
        ):
            issue(
                "PLACEMENT_UNSAFE",
                f"/slots/{name}/placement",
                "placement.trust_violation",
                new=placement,
            )

    # 11. BUDGET_INCOMPATIBLE
    for name, slot in candidate_slots.items():
        minimum = contract_of(slot).get("execution_requirements", {}).get(
            "resource_minimum"
        ) or {}
        ceiling = dict(realm_resource_ceiling or {})
        ceiling.update(
            candidate.get("execution_requirements", {}).get("resource_ceiling", {})
        )
        for dimension, required_value in minimum.items():
            limit = ceiling.get(dimension)
            if limit is not None and required_value > limit:
                issue(
                    "BUDGET_INCOMPATIBLE",
                    f"/slots/{name}",
                    "budget.minimum_exceeds_ceiling",
                    new=dimension,
                )

    return CompatibilityReport(
        base_composition_id=str(base.get("composition_id", "")),
        candidate_composition_id=str(candidate.get("composition_id", "")),
        catalog_revision=catalog_revision,
        backend_profile_hash=backend_profile_hash,
        validator_artifact_id=validator_artifact_id,
        validated_at_meta_revision=validated_at_meta_revision,
        issues=tuple(issues),
    )
