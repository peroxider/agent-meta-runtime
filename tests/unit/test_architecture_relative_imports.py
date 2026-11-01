"""Architecture gate rejects relative imports with the same rules as absolute."""

import importlib.util
from pathlib import Path

import pytest


def lint():
    path = Path(__file__).resolve().parents[2] / "scripts/arch_lint.py"
    spec = importlib.util.spec_from_file_location("relative_import_gate", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("package,source,forbidden", [
    ("domain", "from ..adapters import cas\n", "agent_meta_runtime.adapters"),
    ("application", "from ..adapters.store import execute_command\n", "agent_meta_runtime.adapters.store"),
    ("ports", "from ..application import reconciler\n", "agent_meta_runtime.application"),
    ("sdk", "from ..adapters.credentials import operator_signing_authority\n", "agent_meta_runtime.adapters.credentials"),
    ("application/nested", "from ...adapters import cas\n", "agent_meta_runtime.adapters"),
])
def test_relative_layer_violation_is_not_hidden_by_src_prefix(tmp_path, package, source, forbidden):
    target = tmp_path / "src/agent_meta_runtime" / package / "module.py"
    target.parent.mkdir(parents=True)
    target.write_text(source, encoding="utf-8")
    violations = lint().check_tree(tmp_path)
    assert violations and any(forbidden in issue for issue in violations)
    assert not any("src.agent_meta_runtime" in issue for issue in violations)


def test_allowed_relative_port_import_stays_allowed(tmp_path):
    target = tmp_path / "src/agent_meta_runtime/application/module.py"
    target.parent.mkdir(parents=True)
    target.write_text("from ..ports.repositories import FactAppendRequest\n", encoding="utf-8")
    assert lint().check_tree(tmp_path) == []
