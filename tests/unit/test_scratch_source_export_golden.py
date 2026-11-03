"""Same explicit LF/UTF-8 inputs must produce the same Windows/Linux package."""

import json
from pathlib import Path

from agent_meta_runtime.domain.ampak import decode_package
from agent_meta_runtime.domain.canonical import canonical_json, sha256_hex
from agent_meta_runtime.domain.scratch_export import (
    ExportArtifact,
    ScratchSource,
    build_scratch_export,
)

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/scratch_source_export_v1.json"


def build_golden():
    value = json.loads(FIXTURE.read_text(encoding="utf-8"))
    interface = "artifact://sha256/" + sha256_hex(
        canonical_json(value["interface_schema"])
    )
    contract = ExportArtifact.from_bytes(
        canonical_json(
            {
                "schema": "capability-contract/v1",
                "capability_id": "capability://scratch-golden",
                "contract_version": "1.0.0",
                "operations": [
                    {
                        "operation_id": "apply",
                        "input_schema_artifact_id": interface,
                        "output_schema_artifact_id": interface,
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
    )
    lock = ExportArtifact.from_bytes(
        canonical_json(
            {
                "schema": "scratch-python-dependency-lock/v1",
                "python_abi": "cp312",
                "stdlib_modules": ["math"],
                "wheels": [],
            }
        )
    )
    result = build_scratch_export(
        sources=tuple(ScratchSource.from_text(text) for text in value["source_texts"]),
        export_names=tuple(value["export_names"]),
        contract=contract,
        dependency_lock=lock,
        entrypoint=value["entrypoint"],
    )
    return value, result


def golden_observation():
    value, result = build_golden()
    manifest, files = decode_package(result.package.content)
    return {
        "package_artifact_id": result.package.artifact_id,
        "provenance_artifact_id": result.provenance.artifact_id,
        "source_artifact_ids": json.loads(result.provenance.content)[
            "source_artifact_ids"
        ],
        "source_file_sha256": sha256_hex(files["scratch_candidate.py"]),
        "generated_source": files["scratch_candidate.py"].decode("utf-8"),
        "entrypoint": manifest.package.entrypoint,
        "trust_class": result.trust_class,
    }


def test_source_export_matches_frozen_cross_platform_bytes():
    value, _ = build_golden()
    assert golden_observation() == value["expected"]


def test_generated_candidate_behaves_when_the_test_explicitly_executes_it():
    _, result = build_golden()
    _, files = decode_package(result.package.content)
    namespace = {}
    exec(
        compile(files["scratch_candidate.py"], "<test-owned-golden>", "exec"), namespace
    )
    assert namespace["chosen"](40.5) == 42
