"""Step 00 gate: config loading/redaction, daemon lock, adapters, versions."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agent_meta_runtime.adapters import daemon_lock, system_runtime
from agent_meta_runtime.application import config
from agent_meta_runtime.domain import canonical, ids
from agent_meta_runtime.protocols import versions

ROOT = Path(__file__).resolve().parents[2]

CONFIG_TOML = """
[store]
busy_timeout_ms = 250

[transport]
endpoint = "127.0.0.1:7411"

[logging]
level = "debug"
"""


# ------------------------------------------------------------------ config ---
def test_load_config_defaults(tmp_path: Path) -> None:
    cfg = config.load_config(env={}, default_data_dir=tmp_path)
    assert cfg.store_busy_timeout_ms == 5000
    assert cfg.logging_level == "INFO"
    assert cfg.logging_allowlist_only is True
    assert cfg.metrics_export_interval_s == 60
    assert cfg.shutdown_grace_s == 30
    assert cfg.data_dir == tmp_path


def test_load_config_file_and_env_override(tmp_path: Path) -> None:
    path = tmp_path / "runtime.toml"
    path.write_text(CONFIG_TOML, encoding="utf-8")
    cfg = config.load_config(
        config_path=path,
        env={"AGENT_META_STORE__BUSY_TIMEOUT_MS": "900"},
        default_data_dir=tmp_path,
    )
    assert cfg.store_busy_timeout_ms == 900  # env wins over file
    assert cfg.transport_endpoint == "127.0.0.1:7411"
    assert cfg.logging_level == "DEBUG"  # normalized upper-case


def test_load_config_unknown_key_fails(tmp_path: Path) -> None:
    path = tmp_path / "bad.toml"
    path.write_text("[store]\nbogus = 1\n", encoding="utf-8")
    with pytest.raises(config.ConfigError):
        config.load_config(config_path=path, env={}, default_data_dir=tmp_path)
    with pytest.raises(config.ConfigError):
        config.load_config(env={"AGENT_META_NOPE__KEY": "1"}, default_data_dir=tmp_path)


def test_load_config_type_errors_fail(tmp_path: Path) -> None:
    path = tmp_path / "bad.toml"
    path.write_text("[store]\nbusy_timeout_ms = 'fast'\n", encoding="utf-8")
    with pytest.raises(config.ConfigError):
        config.load_config(config_path=path, env={}, default_data_dir=tmp_path)
    with pytest.raises(config.ConfigError):
        config.load_config(
            env={"AGENT_META_METRICS__EXPORT_INTERVAL_S": "soon"},
            default_data_dir=tmp_path,
        )


def test_secret_from_multiple_sources_fails(tmp_path: Path) -> None:
    path = tmp_path / "secret.toml"
    path.write_text("[transport]\nauth_secret = 'from-file'\n", encoding="utf-8")
    with pytest.raises(config.ConfigError):
        config.load_config(
            config_path=path,
            env={"AGENT_META_TRANSPORT__AUTH_SECRET": "from-env"},
            default_data_dir=tmp_path,
        )


def test_secret_from_single_source_ok_and_redacted(tmp_path: Path) -> None:
    path = tmp_path / "secret.toml"
    path.write_text("[transport]\nauth_secret = 'from-file'\n", encoding="utf-8")
    cfg = config.load_config(config_path=path, env={}, default_data_dir=tmp_path)
    redacted = config.redact_config(cfg, env={})
    assert redacted["transport"]["auth_secret"] == {
        "source": "file",
        "handle": "transport.auth_secret",
        "present": True,
    }
    assert "from-file" not in json.dumps(redacted)


def test_env_bool_coercion(tmp_path: Path) -> None:
    cfg = config.load_config(
        env={"AGENT_META_LOGGING__ALLOWLIST_ONLY": "false"},
        default_data_dir=tmp_path,
    )
    assert cfg.logging_allowlist_only is False
    with pytest.raises(config.ConfigError):
        config.load_config(
            env={"AGENT_META_LOGGING__ALLOWLIST_ONLY": "maybe"},
            default_data_dir=tmp_path,
        )


def test_bad_log_level_and_relative_data_dir(tmp_path: Path) -> None:
    with pytest.raises(config.ConfigError):
        config.load_config(
            env={"AGENT_META_LOGGING__LEVEL": "trace"}, default_data_dir=tmp_path
        )
    with pytest.raises(config.ConfigError):
        config.load_config(env={"AGENT_META_DATA_DIR": "rel/dir"})


def test_fingerprint_stable_and_redaction_aware(tmp_path: Path) -> None:
    cfg_a = config.load_config(default_data_dir=tmp_path, env={})
    cfg_b = config.load_config(default_data_dir=tmp_path, env={})
    fp_a = config.config_fingerprint(config.redact_config(cfg_a, env={}))
    fp_b = config.config_fingerprint(config.redact_config(cfg_b, env={}))
    assert fp_a == fp_b
    cfg_c = config.load_config(
        default_data_dir=tmp_path, env={"AGENT_META_STORE__BUSY_TIMEOUT_MS": "7"}
    )
    fp_c = config.config_fingerprint(config.redact_config(cfg_c, env={}))
    assert fp_a != fp_c


def test_write_effective_config(tmp_path: Path) -> None:
    cfg = config.load_config(default_data_dir=tmp_path, env={})
    body = config.write_effective_config(tmp_path, cfg, env={})
    out = tmp_path / "diagnostics" / "effective-config.redacted.json"
    assert json.loads(out.read_text("utf-8")) == body
    assert body["config_fingerprint"] == canonical.sha256_hex(
        canonical.canonical_json(body["config"])
    )


def test_resolve_default_data_dir_platforms(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    home = Path.home()
    monkeypatch.setattr(sys, "platform", "linux")
    env = {"XDG_STATE_HOME": "/xdg"}
    assert config.resolve_default_data_dir(env) == Path("/xdg/agent-meta")
    assert config.resolve_default_data_dir({}) == home / ".local" / "state" / "agent-meta"
    monkeypatch.setattr(sys, "platform", "darwin")
    assert config.resolve_default_data_dir({}) == (
        home / "Library" / "Application Support" / "agent-meta"
    )
    monkeypatch.setattr(sys, "platform", "win32")
    assert config.resolve_default_data_dir({"LOCALAPPDATA": r"C:\ld"}) == (
        Path(r"C:\ld") / "agent-meta"
    )


# -------------------------------------------------------------- daemon lock ---
def test_daemon_lock_exclusive_and_released(tmp_path: Path) -> None:
    lock = daemon_lock.acquire_daemon_lock(tmp_path, "127.0.0.1:1", "inst-1")
    try:
        assert lock.info.instance_id == "inst-1"
        assert lock.info.pid == os.getpid()
        assert lock.path == tmp_path / "run" / "daemon.lock"
        owner = json.loads(lock.path.read_text("utf-8"))
        assert owner["endpoint"] == "127.0.0.1:1"
        with pytest.raises(daemon_lock.AlreadyRunning) as exc:
            daemon_lock.acquire_daemon_lock(tmp_path, "127.0.0.1:2", "inst-2")
        assert exc.value.code == "ALREADY_RUNNING"
        assert exc.value.details["owner_pid"] == os.getpid()
    finally:
        lock.release()
    # After release the same data dir can be claimed again.
    second = daemon_lock.acquire_daemon_lock(tmp_path, "127.0.0.1:2", "inst-2")
    second.release()


def test_already_running_is_stable_error() -> None:
    err = daemon_lock.AlreadyRunning("busy")
    assert err.retryable is False


# ------------------------------------------------------------ system adapter ---
def test_system_clock_and_ids() -> None:
    clock = system_runtime.SystemClock()
    assert isinstance(clock.now_us(), int)
    gen = system_runtime.SystemIdGenerator()
    value = gen.new_uuid7()
    assert ids.normalize_uuidv7(value) == value
    assert gen.new_uuid7() > value  # monotonic prefix


def test_canonical_serializer_round_trip() -> None:
    ser = system_runtime.CanonicalJsonSerializer()
    value = {"b": 1, "a": [True, None, "x"]}
    assert ser.from_json_bytes(ser.to_canonical_bytes(value)) == value
    assert ser.to_canonical_bytes(value) == canonical.canonical_json(value)
    with pytest.raises(ValueError):
        ser.to_canonical_bytes(float("nan"))


# ------------------------------------------------------ protocol versions ---
def test_protocol_versions_registry() -> None:
    assert versions.PROTOCOL_VERSIONS == {
        "agent_meta.public.v1": 1,
        "agent_meta.execution_backend.v1": 1,
        "agent_meta.facts.v1": 1,
    }
    assert versions.check_protocol_versions(dict(versions.PROTOCOL_VERSIONS)) == []
    assert versions.check_protocol_versions(
        {"agent_meta.public.v1": 2, "agent_meta.mystery.v9": 1}
    ) == [
        "unknown protocol identity: agent_meta.mystery.v9",
        "agent_meta.public.v1: generated v2 != registry v1",
    ]


# ---------------------------------------------------------------- arch lint ---
def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _lint_tree(tmp_path: Path) -> list[str]:
    sys.path.insert(0, str(ROOT / "scripts"))
    import arch_lint

    try:
        return arch_lint.check_tree(tmp_path)
    finally:
        sys.path.remove(str(ROOT / "scripts"))
        sys.modules.pop("arch_lint", None)


def test_arch_lint_catches_domain_to_adapter(tmp_path: Path) -> None:
    _write(
        tmp_path / "src" / "agent_meta_runtime" / "domain" / "evil.py",
        "import agent_meta_runtime.adapters.sqlite_store\n",
    )
    violations = _lint_tree(tmp_path)
    assert any(
        "imports forbidden 'agent_meta_runtime.adapters.sqlite_store'" in v
        for v in violations
    )


def test_arch_lint_catches_runtime_to_seed(tmp_path: Path) -> None:
    _write(
        tmp_path / "src" / "agent_meta_runtime" / "application" / "oops.py",
        "import seed_harness.runtime\n",
    )
    violations = _lint_tree(tmp_path)
    assert any("Runtime -> Seed import" in v for v in violations)


def test_arch_lint_catches_conformance_fixture_private_import(tmp_path: Path) -> None:
    _write(
        tmp_path / "tests" / "fixtures" / "conformance_harness" / "probe.py",
        "from agent_meta_runtime.adapters.memory import repo\n",
    )
    violations = _lint_tree(tmp_path)
    assert any("conformance fixture imports non-public" in v for v in violations)


def test_arch_lint_allows_public_sdk_import_in_fixture(tmp_path: Path) -> None:
    _write(
        tmp_path / "tests" / "fixtures" / "conformance_harness" / "ok.py",
        "from agent_meta_runtime.sdk import client\nimport json\n",
    )
    assert _lint_tree(tmp_path) == []


def test_arch_lint_main_exit_code(tmp_path: Path) -> None:
    _write(
        tmp_path / "src" / "agent_meta_runtime" / "domain" / "evil2.py",
        "import sqlite3\n",
    )
    sys.path.insert(0, str(ROOT / "scripts"))
    import arch_lint

    try:
        assert arch_lint.main([str(tmp_path)]) == 1
    finally:
        sys.path.remove(str(ROOT / "scripts"))
        sys.modules.pop("arch_lint", None)


def test_repo_arch_lint_clean() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "arch_lint.py")],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
