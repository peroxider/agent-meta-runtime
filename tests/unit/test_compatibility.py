"""Step 03 compatibility tests: semver ranges, conservative schema compare,
the fixed check set, trust/placement matrix, deterministic reports (§41.37,
§41.42.1/2, FR-MCAP)."""

from __future__ import annotations

import pytest

from agent_meta_runtime.domain.compatibility import (
    EFFECT_REGISTRY,
    PLACEMENTS,
    TRUST_PLACEMENT,
    CompatibilityReport,
    compare_schema,
    parse_semver_range,
    semver_satisfies,
    validate,
)

BACKEND = {"placement": "isolated_process", "features": ["net-io"]}
ARTIFACT = "artifact://sha256/" + "0" * 64
VALIDATOR = "artifact://sha256/" + "1" * 64


def _contract(**overrides):
    contract = {
        "capability_id": "capability://cap-a",
        "contract_version": "1.0.0",
        "provides": [{"interface_id": "iface://x", "version": "1.0.0"}],
        "requires": [],
        "operations": [
            {
                "operation_id": "op1",
                "required_permissions": ["capability.invoke"],
                "effects": ["state.read"],
                "idempotency": "KEYED",
                "retry_semantics": "SAME_KEY_TRANSIENT",
                "_input_schema": {
                    "type": "object",
                    "properties": {"a": {"type": "string"}},
                    "required": ["a"],
                    "additionalProperties": False,
                },
                "_output_schema": {
                    "type": "object",
                    "properties": {"r": {"type": "string"}},
                    "required": ["r"],
                    "additionalProperties": False,
                },
            }
        ],
    }
    contract.update(overrides)
    return contract


def _composition(revision=1, placement="isolated_process"):
    return {
        "schema": "composition/v1",
        "slots": {
            "alpha": {
                "capability_id": "capability://cap-a",
                "descriptor_revision": revision,
                "artifact_id": ARTIFACT,
                "criticality": "REQUIRED",
                "degradation_policy": "REJECT_TASK",
                "placement": placement,
            }
        },
        "wiring": [],
    }


def _catalog(**overrides):
    return {("capability://cap-a", 1): _contract(**overrides)}


def _validate(base, candidate, catalog, backend=BACKEND, *, new_grant_permissions=("capability.invoke",), **kwargs):
    return validate(
        base,
        candidate,
        catalog,
        backend,
        artifact_index=[ARTIFACT],
        new_grant_permissions=new_grant_permissions,
        catalog_revision=7,
        backend_profile_hash="bph",
        validator_artifact_id=VALIDATOR,
        validated_at_meta_revision=42,
        **kwargs,
    )


def test_semver_ranges_are_conjunctions_only():
    range_ = parse_semver_range(">=1.0.0 <2.0.0")
    assert semver_satisfies("1.2.3", range_)
    assert not semver_satisfies("2.0.0", range_)
    assert semver_satisfies("1.0.0", parse_semver_range("=1.0.0"))
    # Wildcards, OR ranges and emptiness are rejected.
    with pytest.raises(ValueError):
        parse_semver_range("1.x")
    with pytest.raises(ValueError):
        parse_semver_range(">=1.0.0 || <2.0.0")
    with pytest.raises(ValueError):
        parse_semver_range("")


def test_compare_schema_input_contravariance():
    old = {
        "type": "object",
        "properties": {"a": {"type": "string"}},
        "required": ["a"],
        "additionalProperties": False,
    }
    # Adding a new required input field rejects previously valid payloads.
    new_required = {
        **old,
        "properties": {**old["properties"], "b": {"type": "string"}},
        "required": ["a", "b"],
    }
    assert compare_schema(old, new_required, direction="input") == "breaking"
    # Adding an optional input field is compatible.
    new_optional = {**old, "properties": {**old["properties"], "b": {"type": "string"}}}
    assert compare_schema(old, new_optional, direction="input") == "compatible"
    # Narrowing the type set rejects old values.
    narrowed = {**old, "properties": {"a": {"type": "integer"}}}
    assert compare_schema(old, narrowed, direction="input") == "breaking"
    # Unknown combinators are conservative unless byte-identical.
    assert compare_schema(old, {"oneOf": [old]}, direction="input") == "unknown"
    assert compare_schema(old, old, direction="input") == "compatible"


def test_compare_schema_output_covariance():
    old = {
        "type": "object",
        "properties": {"r": {"type": "string"}},
        "required": ["r"],
        "additionalProperties": False,
    }
    # Adding output fields is fine.
    added = {**old, "properties": {**old["properties"], "s": {"type": "string"}}}
    assert compare_schema(old, added, direction="output") == "compatible"
    # Dropping a required output breaks the consumer.
    dropped = {**old, "required": []}
    assert compare_schema(old, dropped, direction="output") == "breaking"
    # Removing an output property entirely is breaking too.
    removed = {"type": "object", "properties": {}, "additionalProperties": False}
    assert compare_schema(old, removed, direction="output") == "breaking"


def test_registry_and_trust_matrix_shapes():
    assert len(EFFECT_REGISTRY) == 11
    assert "external.irreversible" in EFFECT_REGISTRY
    assert "state.write" in EFFECT_REGISTRY
    assert TRUST_PLACEMENT["untrusted_candidate"] == frozenset({"managed"})
    assert TRUST_PLACEMENT["high_risk_effect_candidate"] == frozenset({"managed"})
    assert TRUST_PLACEMENT["builtin_or_signed"] == PLACEMENTS
    assert TRUST_PLACEMENT["trusted_candidate"] == frozenset(
        {"isolated_process", "managed"}
    )


def test_identical_compositions_produce_clean_report():
    comp = _composition()
    report = _validate(comp, comp, _catalog())
    assert report.issues == ()
    assert report.activatable
    body = report.to_json()
    assert body["report_version"] == 1
    assert body["catalog_revision"] == 7
    assert body["validated_at_meta_revision"] == 42
    assert body["activatable"] is True


def test_structure_checks():
    bad_schema = dict(_composition(), schema="composition/v2")
    report = _validate(_composition(), bad_schema, _catalog())
    assert any(
        i.code == "STRUCTURE_INVALID" and i.path == "" for i in report.sorted_issues()
    )
    assert not report.activatable
    # Required slots must declare a valid degradation policy.
    bad_policy = {
        **_composition(),
        "slots": {
            "alpha": {**_composition()["slots"]["alpha"], "degradation_policy": "OMIT"}
        },
    }
    report = _validate(_composition(), bad_policy, _catalog())
    assert any(
        i.code == "STRUCTURE_INVALID" and i.path == "/slots/alpha/degradation_policy"
        for i in report.sorted_issues()
    )
    # Wiring cycles are rejected.
    cyclic = {
        **_composition(),
        "slots": {
            **_composition()["slots"],
            "beta": {
                "capability_id": "capability://cap-a",
                "descriptor_revision": 1,
                "artifact_id": ARTIFACT,
                "criticality": "OPTIONAL",
                "degradation_policy": "OMIT",
            },
        },
        "wiring": [
            {"consumer_slot": "alpha", "provider_slot": "beta"},
            {"consumer_slot": "beta", "provider_slot": "alpha"},
        ],
    }
    report = _validate(_composition(), cyclic, _catalog())
    assert any(
        i.code == "STRUCTURE_INVALID" and i.path == "/wiring"
        for i in report.sorted_issues()
    )


def test_artifact_and_interface_checks():
    # Missing descriptor in the catalog.
    report = _validate(
        _composition(),
        _composition(revision=2),
        _catalog(),
    )
    assert any(
        i.code == "ARTIFACT_INVALID" and i.path == "/slots/alpha"
        for i in report.sorted_issues()
    )
    # Unwired requirement.
    requiring = _contract(
        requires=[{"interface_id": "iface://y", "version_range": ">=1.0.0"}]
    )
    report = _validate(
        _composition(), _composition(), {("capability://cap-a", 1): requiring}
    )
    assert any(
        i.code == "INTERFACE_MISSING" and i.path == "/slots/alpha"
        for i in report.sorted_issues()
    )


def test_effect_expansion_needs_approval():
    expanded = _contract(
        operations=[
            {
                "operation_id": "op1",
                "required_permissions": ["capability.invoke"],
                "effects": ["state.read", "state.write"],
                "idempotency": "KEYED",
                "retry_semantics": "SAME_KEY_TRANSIENT",
            }
        ]
    )
    catalog = {("capability://cap-a", 1): _contract(), ("capability://cap-a", 2): expanded}
    candidate = _composition(revision=2)
    # Without approval: ERROR.
    report = _validate(_composition(), candidate, catalog)
    assert any(i.code == "EFFECT_EXPANDED" for i in report.sorted_issues())
    assert not report.activatable
    # With approval: clean.
    report = _validate(
        _composition(),
        candidate,
        catalog,
        approved_effect_expansions=["state.write"],
    )
    assert not any(i.code == "EFFECT_EXPANDED" for i in report.sorted_issues())
    assert report.activatable


def test_authority_expansion_lists_required_permissions():
    expanded = _contract(
        operations=[
            {
                "operation_id": "op1",
                "required_permissions": ["capability.invoke", "state.write"],
                "effects": ["state.read"],
                "idempotency": "KEYED",
                "retry_semantics": "SAME_KEY_TRANSIENT",
            }
        ]
    )
    catalog = {("capability://cap-a", 1): _contract(), ("capability://cap-a", 2): expanded}
    report = _validate(_composition(), _composition(revision=2), catalog)
    issues = [i for i in report.sorted_issues() if i.code == "AUTHORITY_EXPANDED"]
    assert issues
    assert issues[0].required_permissions == ("state.write",)
    # Granting the new permission clears the issue.
    report = _validate(
        _composition(),
        _composition(revision=2),
        catalog,
        new_grant_permissions=["capability.invoke", "state.write"],
    )
    assert not any(i.code == "AUTHORITY_EXPANDED" for i in report.sorted_issues())


def test_retry_semantics_weakening_detected():
    weakened = _contract(
        operations=[
            {
                "operation_id": "op1",
                "required_permissions": ["capability.invoke"],
                "effects": ["state.read"],
                "idempotency": "NONE",
                "retry_semantics": "SAME_KEY_TRANSIENT",
            }
        ]
    )
    catalog = {("capability://cap-a", 1): _contract(), ("capability://cap-a", 2): weakened}
    report = _validate(_composition(), _composition(revision=2), catalog)
    assert any(
        i.code == "RETRY_SEMANTICS_BREAKING" and i.path == "/slots/alpha"
        for i in report.sorted_issues()
    )


def test_schema_breaking_between_descriptor_revisions():
    base_catalog = {("capability://cap-a", 1): _contract()}
    cand_catalog = {
        ("capability://cap-a", 2): _contract(
            operations=[
                {
                    "operation_id": "op1",
                    "required_permissions": ["capability.invoke"],
                    "effects": ["state.read"],
                    "idempotency": "KEYED",
                    "retry_semantics": "SAME_KEY_TRANSIENT",
                    "_input_schema": {
                        "type": "object",
                        "properties": {
                            "a": {"type": "string"},
                            "b": {"type": "string"},
                        },
                        "required": ["a", "b"],
                        "additionalProperties": False,
                    },
                }
            ]
        )
    }
    candidate = _composition(revision=2)
    report = validate(
        _composition(),
        candidate,
        {**base_catalog, **cand_catalog},
        BACKEND,
        artifact_index=[ARTIFACT],
        new_grant_permissions=["capability.invoke"],
    )
    assert any(i.code == "SCHEMA_BREAKING" for i in report.sorted_issues())
    # Adding the field as optional instead is compatible.
    cand_catalog[("capability://cap-a", 2)]["operations"][0]["_input_schema"] = {
        "type": "object",
        "properties": {"a": {"type": "string"}, "b": {"type": "string"}},
        "required": ["a"],
        "additionalProperties": False,
    }
    report = validate(
        _composition(),
        candidate,
        {**base_catalog, **cand_catalog},
        BACKEND,
        artifact_index=[ARTIFACT],
        new_grant_permissions=["capability.invoke"],
    )
    assert not any(
        i.code in ("SCHEMA_BREAKING", "COMPATIBILITY_UNKNOWN")
        for i in report.sorted_issues()
    )


def test_backend_features_and_placement():
    requiring = _contract(
        execution_requirements={
            "required_features": ["net-io"],
            "preferred_features": ["gpu"],
        }
    )
    report = _validate(
        _composition(), _composition(), {("capability://cap-a", 1): requiring}
    )
    codes = {(i.code, i.severity) for i in report.sorted_issues()}
    assert ("BACKEND_FEATURE_MISSING", "WARNING") in codes
    assert ("BACKEND_FEATURE_MISSING", "ERROR") not in codes
    # A missing required feature is an ERROR.
    strict = _contract(
        execution_requirements={"required_features": ["tpu"], "preferred_features": []}
    )
    report = _validate(
        _composition(), _composition(), {("capability://cap-a", 1): strict}
    )
    assert ("BACKEND_FEATURE_MISSING", "ERROR") in {
        (i.code, i.severity) for i in report.sorted_issues()
    }
    # trusted_candidate cannot run in_process (§41.32).
    report = _validate(
        _composition(), _composition(placement="in_process"), _catalog()
    )
    assert any(
        i.code == "PLACEMENT_UNSAFE" and i.path == "/slots/alpha/placement"
        for i in report.sorted_issues()
    )
    # ...but a managed backend bypasses the placement check.
    report = _validate(
        _composition(),
        _composition(placement="in_process"),
        _catalog(),
        backend={"placement": "managed", "features": []},
    )
    assert not any(i.code == "PLACEMENT_UNSAFE" for i in report.sorted_issues())


def test_report_is_deterministic_and_frozen():
    comp = _composition()
    report_a = _validate(comp, comp, _catalog())
    report_b = _validate(comp, comp, _catalog())
    assert report_a.canonical_bytes() == report_b.canonical_bytes()
    assert isinstance(report_a, CompatibilityReport)
