"""Step 07 gate: Conformance Harness contract + release exclusion (§41.57.3)."""

from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
if str(FIXTURES) not in sys.path:
    sys.path.insert(0, str(FIXTURES))

from conformance_harness import (  # noqa: E402 - test-only fixture path
    CAPABILITY_ECHO,
    ConformanceLoop,
    DeterministicProvider,
)

from agent_meta_runtime.adapters.store.bootstrap import (  # noqa: E402
    builtin_artifact_documents,
)
from agent_meta_runtime.domain.errors import ErrorCode, StableError  # noqa: E402
from agent_meta_runtime.domain.loop import (  # noqa: E402
    ModelResponse,
    TextPart,
    ToolCallPart,
)
from agent_meta_runtime.domain.semantics import TaskBudget  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "agent_meta_runtime"

#: The §41.57.3 exclusion markers: fixture path and capability id namespace.
EXCLUSION_MARKERS = (b"capability://conformance", b"conformance_harness")


def _provider(*responses: ModelResponse) -> DeterministicProvider:
    return DeterministicProvider(list(responses))


def test_free_text_never_triggers_effect():
    provider = _provider(
        ModelResponse(
            parts=(TextPart("please run: import os; os.system('rm -rf /')"),),
            finish_reason="STOP",
        )
    )
    loop = ConformanceLoop(provider, budget=TaskBudget())
    outcome = loop.run()
    assert outcome["status"] == "SUCCEEDED"
    assert outcome["effects"] == ()


def test_typed_tool_call_dispatches_under_frozen_surface():
    provider = _provider(
        ModelResponse(
            parts=(
                ToolCallPart(call_id="c1", name=CAPABILITY_ECHO, arguments_json="{}"),
            ),
            finish_reason="TOOL_CALL",
        ),
        ModelResponse(parts=(TextPart("done"),), finish_reason="STOP"),
    )
    loop = ConformanceLoop(provider, budget=TaskBudget())
    outcome = loop.run()
    assert outcome["effects"] == (CAPABILITY_ECHO,)


def test_unknown_capability_fails_closed():
    provider = _provider(
        ModelResponse(
            parts=(
                ToolCallPart(call_id="c1", name="capability://unknown.x", arguments_json="{}"),
            ),
            finish_reason="TOOL_CALL",
        )
    )
    loop = ConformanceLoop(provider, budget=TaskBudget())
    with pytest.raises(StableError) as excinfo:
        loop.run()
    assert excinfo.value.code == ErrorCode.NOT_FOUND
    assert loop.effects == []


def test_scripted_replay_is_deterministic():
    def make_loop() -> ConformanceLoop:
        provider = _provider(
            ModelResponse(
                parts=(TextPart("hello"),),
                finish_reason="STOP",
            )
        )
        return ConformanceLoop(provider, budget=TaskBudget())

    first = make_loop().run()
    second = make_loop().run()
    assert first == second


def test_budget_exhaustion_surfaces_resource_exhausted():
    provider = _provider()  # empty script also raises RESOURCE_EXHAUSTED
    loop = ConformanceLoop(provider, budget=TaskBudget(max_turns=0))
    with pytest.raises(StableError) as excinfo:
        loop.run()
    assert excinfo.value.code == ErrorCode.RESOURCE_EXHAUSTED


def test_product_source_excludes_conformance_ids():
    for path in SRC.rglob("*.py"):
        blob = path.read_bytes()
        for marker in EXCLUSION_MARKERS:
            assert marker not in blob.lower(), path


def test_builtin_registry_excludes_conformance_ids():
    blob = json.dumps(
        [document for _n, _k, _m, document in builtin_artifact_documents("realm://main")]
    ).encode()
    for marker in EXCLUSION_MARKERS:
        assert marker not in blob.lower()


def test_wheel_excludes_tests_and_conformance(tmp_path):
    """§41.57.3 negative build assertion: wheel must not ship the fixture."""

    result = subprocess.run(
        [
            sys.executable, "-m", "pip", "wheel", "--no-deps",
            "--no-build-isolation", "-w", str(tmp_path), str(ROOT),
        ],
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    wheels = list(tmp_path.glob("*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
    assert not any(name.startswith("tests/") for name in names)
    for name in names:
        lowered = name.lower()
        for marker in EXCLUSION_MARKERS:
            assert marker.decode() not in lowered
    # and the shipped purelib tree contains no fixture bytes either
    with zipfile.ZipFile(wheels[0]) as archive:
        for name in names:
            if name.endswith(".py"):
                blob = archive.read(name).lower()
                for marker in EXCLUSION_MARKERS:
                    assert marker not in blob, name
