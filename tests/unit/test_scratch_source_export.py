"""Real canonical AMPAK export, compiler scopes and locked dependency bytes."""

import io
import json
import zipfile

import pytest

from agent_meta_runtime.domain.ampak import decode_package
from agent_meta_runtime.domain.canonical import canonical_json
from agent_meta_runtime.domain.errors import StableError
from agent_meta_runtime.domain.scratch_export import (
    ExportArtifact,
    ScratchSource,
    build_scratch_export,
    canonical_scratch_source,
)

REF = "artifact://sha256/" + "a" * 64


def document(value):
    return ExportArtifact.from_bytes(canonical_json(value))


def contract():
    return document(
        {
            "schema": "capability-contract/v1",
            "capability_id": "capability://example",
            "contract_version": "1.0.0",
            "operations": [
                {
                    "operation_id": "apply",
                    "input_schema_artifact_id": REF,
                    "output_schema_artifact_id": REF,
                    "idempotency": "PURE",
                    "retry_semantics": "NEVER",
                    "effects": ["none"],
                    "required_permissions": ["capability.invoke"],
                }
            ],
            "requires": [],
            "provides": [],
            "state": {},
            "execution_requirements": {},
            "runtime_constraints": {},
        }
    )


def lock(*, stdlib=(), wheels=()):
    return document(
        {
            "schema": "scratch-python-dependency-lock/v1",
            "python_abi": "cp312",
            "stdlib_modules": list(stdlib),
            "wheels": list(wheels),
        }
    )


def export(
    source,
    *,
    names=("chosen",),
    sources=None,
    dependency_lock=None,
    dependencies=(),
    **options,
):
    return build_scratch_export(
        sources=sources or (ScratchSource.from_text(source),),
        export_names=names,
        contract=contract(),
        dependency_lock=dependency_lock or lock(),
        entrypoint="scratch_candidate:" + names[-1],
        dependency_artifacts=dependencies,
        **options,
    )


def wheel(
    *,
    module="example",
    distribution="example",
    version="1.0.0",
    metadata=None,
    extra=None,
):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(
            module + "/__init__.py",
            'raise RuntimeError("dependency must never be imported")\n',
        )
        archive.writestr(
            distribution + ".dist-info/METADATA",
            metadata
            or f"Metadata-Version: 2.1\nName: {distribution}\nVersion: {version}\n",
        )
        archive.writestr(
            distribution + ".dist-info/WHEEL",
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr(distribution + ".dist-info/RECORD", "")
        for name, raw in (extra or {}).items():
            archive.writestr(name, raw)
    return ExportArtifact.from_bytes(output.getvalue())


def wheel_lock(artifact, **overrides):
    return lock(
        wheels=(
            {
                "distribution": "example",
                "version": "1.0.0",
                "artifact_id": artifact.artifact_id,
                "modules": ["example"],
                **overrides,
            },
        )
    )


def refusal(source, reason="OPAQUE_DEPENDENCY", **options):
    with pytest.raises(StableError) as failure:
        export(source, **options)
    assert failure.value.details["reason_code"] == reason
    return failure.value


def test_canonical_source_normalizes_line_endings_but_preserves_final_newline():
    assert canonical_scratch_source("x\r\ny\rz") == b"x\ny\nz"
    assert canonical_scratch_source("x") == b"x"
    assert canonical_scratch_source("x\n") == b"x\n"
    with pytest.raises(ValueError):
        ScratchSource.from_bytes(b"x\r\n")
    with pytest.raises(ValueError):
        ScratchSource("artifact://sha256/" + "0" * 64, b"x")


def test_export_builds_deterministic_real_package_and_preserves_source_provenance():
    source = ScratchSource.from_text("def chosen(value):\r\n    return value+1\r\n")
    first = export("", sources=(source,))
    second = export("", sources=(source,))
    assert first == second and first.trust_class == "trusted_candidate"
    manifest, files = decode_package(first.package.content)
    assert manifest.package.artifact_kind == "capability"
    assert manifest.package.entrypoint == "scratch_candidate:chosen"
    assert files["scratch_candidate.py"] == b"def chosen(value):\n    return value+1\n"
    assert manifest.package.build_provenance_artifact_id == first.provenance.artifact_id
    provenance = json.loads(first.provenance.content)
    assert provenance["source_artifact_ids"] == [source.artifact_id]
    assert (
        provenance["selected_definitions"][0]["source_artifact_id"]
        == source.artifact_id
    )
    assert manifest.package.runtime_constraints["trust_class"] == "trusted_candidate"


@pytest.mark.parametrize(
    "source",
    [
        "hidden=object()\ndef chosen(): return hidden",
        "def chosen():\n    def inner(): hidden=42\n    return hidden",
        "class Unselected: pass\ndef chosen(): return Unselected()",
        "def chosen(x=hidden): return x",
        "def chosen(x: Hidden): return x",
        "@hidden\ndef chosen(): return 1",
        "class chosen(Hidden): pass",
        "class chosen:\n    hidden=42\n    def method(self): return hidden",
        "len=42\ndef chosen(value): return len(value)",
        'def chosen(): return eval("hidden")',
        "def chosen(): return lambda value:value",
    ],
)
def test_hidden_or_dynamic_dependencies_are_rejected_by_lexical_scope(source):
    refusal(source)


def test_duplicate_selected_definitions_and_missing_entrypoint_are_refused():
    refusal("def chosen(): return 1\ndef chosen(): return 2", "SELECTION_AMBIGUOUS")
    refusal("chosen=lambda value:value", "SELECTION_MISSING")
    with pytest.raises(StableError) as invalid:
        build_scratch_export(
            sources=(ScratchSource.from_text("def chosen(): return 1"),),
            export_names=("chosen",),
            contract=contract(),
            dependency_lock=lock(),
            entrypoint="other:chosen",
        )
    assert invalid.value.details["reason_code"] == "INVALID_ENTRYPOINT"


def test_nested_closures_comprehensions_class_cells_and_recursion_are_source_closed():
    for source in (
        "def chosen(values):\n    offset=1\n    def inner(value): return value+offset\n    return [inner(value) for value in values]",
        "class chosen:\n    def method(self): return __class__",
        "def chosen(value):\n    return 1 if value==0 else value*chosen(value-1)",
        "values=[len for len in [1]]\ndef chosen(value): return len(value)",
        'def chosen(value):\n    match value:\n        case {"key": local}: return local\n    return None',
        "def chosen(values=[hidden for hidden in [1]]): return values",
        "def chosen(values={hidden:hidden+1 for hidden in [1]}): return values",
    ):
        assert export(source).package.content.startswith(b"AMPAK1\n")


def test_multiple_explicit_sources_require_all_referenced_definitions_to_be_selected():
    sources = (
        ScratchSource.from_text("def helper(value): return value+1"),
        ScratchSource.from_text("def chosen(value): return helper(value)"),
    )
    refusal("", sources=sources)
    result = export("", sources=sources, names=("helper", "chosen"))
    assert json.loads(result.provenance.content)["source_artifact_ids"] == [
        source.artifact_id for source in sources
    ]


def test_decorators_unicode_offsets_and_semicolons_do_not_copy_unselected_effects(
    tmp_path,
):
    marker = tmp_path / "must-not-exist"
    source = (
        "import math; " + f'open({str(marker)!r},"w").write("not exported")\n'
        "def decorator(value): return value\n@decorator\ndef chosen(é): return math.ceil(é)"
    )
    result = export(
        source, names=("decorator", "chosen"), dependency_lock=lock(stdlib=("math",))
    )
    _, files = decode_package(result.package.content)
    generated = files["scratch_candidate.py"].decode()
    assert "@decorator\ndef chosen(é)" in generated
    assert (
        "open(" not in generated
        and str(marker) not in generated
        and not marker.exists()
    )


def test_locked_imports_are_checked_inside_nested_functions_without_importing_dependencies():
    dependency = wheel()
    source = "def chosen(value):\n    import example\n    return example.apply(value)"
    refusal(source)
    result = export(
        source, dependency_lock=wheel_lock(dependency), dependencies=(dependency,)
    )
    assert json.loads(result.provenance.content)["imports"] == ["example"]
    assert dependency in result.inputs


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"modules": ["invented"]}, "DEPENDENCY_MODULE_MISMATCH"),
        ({"version": "9.0.0"}, "DEPENDENCY_METADATA_MISMATCH"),
        ({"distribution": "different"}, "DEPENDENCY_METADATA_MISMATCH"),
    ],
)
def test_wheel_module_and_distribution_declarations_need_actual_byte_evidence(
    change, reason
):
    dependency = wheel()
    refusal(
        "import example\ndef chosen(): return example",
        reason,
        dependency_lock=wheel_lock(dependency, **change),
        dependencies=(dependency,),
    )


@pytest.mark.parametrize("extra", [{"../escape.py": b""}, {"example/link.py": b""}])
def test_malformed_wheel_paths_and_unclaimed_modules_fail_closed(extra):
    if "example/link.py" in extra:
        # A second top-level module cannot be omitted from the declaration.
        extra = {"hidden.py": b""}
        reason = "DEPENDENCY_MODULE_MISMATCH"
    else:
        reason = "INVALID_DEPENDENCY_WHEEL"
    dependency = wheel(extra=extra)
    refusal(
        "import example\ndef chosen(): return example",
        reason,
        dependency_lock=wheel_lock(dependency),
        dependencies=(dependency,),
    )


def test_relative_star_private_runtime_and_dynamic_imports_are_refused():
    for source in (
        "from .outside import value\ndef chosen(): return value",
        "from math import *\ndef chosen(): return sqrt(4)",
        'def chosen(): return __import__("math")',
    ):
        refusal(source, dependency_lock=lock(stdlib=("math",)))


def test_candidate_construction_never_executes_selected_class_bodies_or_decorators(
    tmp_path,
):
    marker = tmp_path / "class-must-not-run"
    result = export(
        "class chosen:\n    " + f'open({str(marker)!r},"w").write("executed")\n'
    )
    assert result.package.content and not marker.exists()


@pytest.mark.parametrize(
    "decorator",
    [
        "@(decorator)",
        "@(\n    decorator\n)",
        "@(\n    # parenthesized decorator\n    decorator\n)",
    ],
)
def test_parenthesized_decorator_source_is_preserved_and_runs_when_explicitly_tested(
    decorator,
):
    source = (
        "def decorator(fn):\n    def wrapper(value): return fn(value)+1\n    return wrapper\n"
        + decorator
        + "\ndef chosen(value): return value*2"
    )
    result = export(source, names=("decorator", "chosen"))
    _, files = decode_package(result.package.content)
    assert decorator in files["scratch_candidate.py"].decode()
    namespace = {}
    # Explicit execution of a test-owned pure fixture after construction.
    exec(
        compile(files["scratch_candidate.py"], "<test-owned-candidate>", "exec"),
        namespace,
    )
    assert namespace["chosen"](20) == 41


@pytest.mark.parametrize(
    "change",
    [
        {"schema": "other-contract/v1"},
        {"requires": [42]},
        {"provides": [{"interface_id": "x", "version": "broken"}]},
        {"operations": []},
        {"state": {"schema_artifact_id": "not-an-artifact"}},
    ],
)
def test_malformed_contracts_do_not_produce_candidate_packages(change):
    value = json.loads(contract().content)
    value.update(change)
    with pytest.raises(StableError) as invalid:
        build_scratch_export(
            sources=(ScratchSource.from_text("def chosen(): return 1"),),
            export_names=("chosen",),
            contract=document(value),
            dependency_lock=lock(),
            entrypoint="scratch_candidate:chosen",
        )
    assert invalid.value.details["reason_code"] == "INVALID_CONTRACT"


def test_source_cannot_elevate_candidate_trust_with_contract_metadata():
    value = json.loads(contract().content)
    value["runtime_constraints"] = {"trust_class": "builtin_or_signed"}
    result = build_scratch_export(
        sources=(ScratchSource.from_text("def chosen(): return 1"),),
        export_names=("chosen",),
        contract=document(value),
        dependency_lock=lock(),
        entrypoint="scratch_candidate:chosen",
    )
    assert result.trust_class == "trusted_candidate"
    assert (
        decode_package(result.package.content)[0].package.runtime_constraints[
            "trust_class"
        ]
        == "trusted_candidate"
    )


def test_only_type_stub_files_do_not_prove_an_importable_wheel_module():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("example.pyi", "def apply(value): ...")
        archive.writestr(
            "example.dist-info/METADATA", "Name: example\nVersion: 1.0.0\n"
        )
        archive.writestr(
            "example.dist-info/WHEEL",
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr("example.dist-info/RECORD", "")
    dependency = ExportArtifact.from_bytes(output.getvalue())
    refusal(
        "import example\ndef chosen(): return example",
        "DEPENDENCY_METADATA_MISMATCH",
        dependency_lock=wheel_lock(dependency),
        dependencies=(dependency,),
    )


@pytest.mark.parametrize(
    "source",
    [
        "def chosen(): break",
        "def chosen(): await 1",
        "async def chosen():\n    yield 1\n    return 2",
    ],
)
def test_full_compiler_rejects_invalid_control_flow_that_symtable_accepts(source):
    refusal(source, "SOURCE_SYNTAX")


def test_long_free_names_have_bounded_diagnostics_with_explicit_truncation():
    failure = refusal("def chosen(): return " + "hidden_" + "x" * 1000)
    assert failure.details["diagnostic_truncated"]
    assert max(map(len, failure.details["free_variables"])) <= 128


def test_private_runtime_import_cannot_be_approved_by_a_fabricated_stdlib_lock():
    refusal(
        "import agent_meta_runtime.adapters.store\ndef chosen(): return agent_meta_runtime",
        "INVALID_DEPENDENCY_LOCK",
        dependency_lock=lock(stdlib=("agent_meta_runtime",)),
    )


@pytest.mark.parametrize("extra", [{"EXAMPLE/__init__.py": b""}, {"math.py": b""}])
def test_dependency_namespace_collisions_and_stdlib_shadowing_are_refused(extra):
    dependency = wheel(extra=extra)
    if "math.py" in extra:
        dependency_lock = wheel_lock(dependency, modules=["example", "math"])
        reason = "DEPENDENCY_MODULE_MISMATCH"
    else:
        dependency_lock = wheel_lock(dependency)
        reason = "INVALID_DEPENDENCY_WHEEL"
    refusal(
        "import example\ndef chosen(): return example",
        reason,
        dependency_lock=dependency_lock,
        dependencies=(dependency,),
    )


def test_input_artifact_hashes_sources_and_lock_closure_are_not_silently_widened():
    dependency = wheel()
    refusal(
        "def chosen(): return 1",
        "INVALID_DEPENDENCY_INPUTS",
        dependencies=(dependency,),
    )
    refusal(
        "def chosen(): return 1",
        "INVALID_DEPENDENCY_LOCK",
        dependency_lock=wheel_lock(dependency),
    )
    source = ScratchSource.from_text("def chosen(): return 1")
    refusal("", "INVALID_SOURCES", sources=(source, source))


def test_export_profile_does_not_run_under_a_different_compiler_abi(monkeypatch):
    import agent_meta_runtime.domain.scratch_export as module

    monkeypatch.setattr(module, "_ANALYZER_ABI", ("cpython", (3, 13)))
    failure = refusal("def chosen(): return 1", "ANALYZER_UNAVAILABLE")
    assert failure.code == "FEATURE_UNAVAILABLE"


@pytest.mark.parametrize(
    "expression",
    [
        'loader.import_module("math")',
        'getattr(loader,"import_module")("math")',
        'alias("math")',
    ],
)
def test_literal_dynamic_imports_are_not_static_dependency_evidence(expression):
    source = (
        "import importlib as loader\nfrom importlib import import_module as alias\ndef chosen(): return "
        + expression
    )
    refusal(source, dependency_lock=lock(stdlib=("importlib", "math")))


def test_export_strictness_does_not_change_existing_harness_literal_import_profile():
    from agent_meta_runtime.domain.harness_source import audit_harness_sources

    files = {"probe.py": b'import importlib\nvalue=importlib.import_module("math")\n'}
    assert audit_harness_sources(files) == ()
    assert any(
        "dynamic_import" in item
        for item in audit_harness_sources(files, allow_literal_dynamic_imports=False)
    )


def test_nul_in_raw_wheel_filename_is_not_hidden_by_zipinfo_normalization():
    dependency = wheel(extra={"example/a.py": b""})
    raw = dependency.content.replace(b"example/a.py", b"example/a\0py")
    corrupt = ExportArtifact.from_bytes(raw)
    refusal(
        "import example\ndef chosen(): return example",
        "INVALID_DEPENDENCY_WHEEL",
        dependency_lock=wheel_lock(corrupt),
        dependencies=(corrupt,),
    )
