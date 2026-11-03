"""Configuration loading, fingerprint, data-dir resolution (§41.39.1).

Rules:
- Environment variables use the ``AGENT_META_`` prefix with ``__`` separating
  nested keys, e.g. ``AGENT_META_STORE__BUSY_TIMEOUT_MS``.
- Unknown config keys, type errors, or the same secret supplied by multiple
  sources fail startup.
- After loading, ``effective-config.redacted.json`` is written with JCS and a
  ``config_fingerprint``; secret values are replaced by ``{source, handle,
  present}``.
- Hot update in v0.1 covers only log level and metrics export interval.
"""

from __future__ import annotations

import os
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..domain.canonical import canonical_json, now_us, sha256_hex

__all__ = [
    "ConfigError",
    "RuntimeConfig",
    "config_fingerprint",
    "load_config",
    "redact_config",
    "resolve_default_data_dir",
    "write_effective_config",
]

ENV_PREFIX = "AGENT_META_"
ENV_SEP = "__"


class ConfigError(ValueError):
    """Invalid configuration; startup must fail (exit code 2)."""


def _schema() -> dict[str, Any]:
    """``section -> key -> (type, default, secret)`` for every known key."""

    return {
        "data_dir": {"": (str, "", False)},
        "store": {
            "busy_timeout_ms": (int, 5000, False),
            "wal_checkpoint_threshold_bytes": (int, 1024 * 1024 * 1024, False),
        },
        "transport": {
            "endpoint": (str, "", False),
            "auth_secret": (str, "", True),
        },
        "logging": {
            "level": (str, "INFO", False),
            "allowlist_only": (bool, True, False),
        },
        "metrics": {
            "export_interval_s": (int, 60, False),
        },
        "shutdown": {
            "grace_s": (int, 30, False),
        },
        "execution": {"host_backend": (str, "trusted_in_process", False)},
    }


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    data_dir: Path
    store_busy_timeout_ms: int
    store_wal_checkpoint_threshold_bytes: int
    transport_endpoint: str
    transport_auth_secret: str  # secret; never logged or fingerprinted raw
    logging_level: str
    logging_allowlist_only: bool
    metrics_export_interval_s: int
    shutdown_grace_s: int
    config_path: Path | None = None
    execution_backend: str = "trusted_in_process"

    def to_json(self) -> dict[str, Any]:
        return {
            "data_dir": str(self.data_dir),
            "store": {
                "busy_timeout_ms": self.store_busy_timeout_ms,
                "wal_checkpoint_threshold_bytes": self.store_wal_checkpoint_threshold_bytes,
            },
            "transport": {
                "endpoint": self.transport_endpoint,
                "auth_secret": self.transport_auth_secret,
            },
            "logging": {
                "level": self.logging_level,
                "allowlist_only": self.logging_allowlist_only,
            },
            "metrics": {"export_interval_s": self.metrics_export_interval_s},
            "shutdown": {"grace_s": self.shutdown_grace_s},
            "execution": {"host_backend": self.execution_backend},
        }


def resolve_default_data_dir(env: Mapping[str, str] | None = None) -> Path:
    """Platform default data directory (§41.39.1)."""

    env = os.environ if env is None else env
    if sys.platform == "win32":
        base = env.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "agent-meta"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "agent-meta"
    state_home = env.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(state_home) / "agent-meta"


def _coerce(section: str, key: str, raw: Any, expected: type) -> Any:
    label = f"{section}{ENV_SEP}{key}" if section else key
    if expected is bool:
        if isinstance(raw, bool):
            return raw
        raise ConfigError(f"{label} must be a boolean")
    if expected is int:
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise ConfigError(f"{label} must be an integer")
        return raw
    if expected is str:
        if not isinstance(raw, str):
            raise ConfigError(f"{label} must be a string")
        return raw
    raise ConfigError(f"unsupported type for {label}")  # pragma: no cover


def _coerce_env_value(label: str, raw: str, expected: type) -> Any:
    if expected is bool:
        if raw.lower() in ("true", "1", "yes"):
            return True
        if raw.lower() in ("false", "0", "no"):
            return False
        raise ConfigError(f"{label} must be a boolean")
    if expected is int:
        try:
            return int(raw)
        except ValueError as exc:
            raise ConfigError(f"{label} must be an integer") from exc
    return raw


def load_config(
    config_path: Path | None = None,
    env: Mapping[str, str] | None = None,
    default_data_dir: Path | None = None,
) -> RuntimeConfig:
    """Load defaults, optional TOML file, then environment overrides."""

    env = os.environ if env is None else env
    schema = _schema()

    values: dict[str, dict[str, Any]] = {
        section: {key: default for key, (_, default, _) in keys.items()}
        for section, keys in schema.items()
    }
    secret_sources: dict[str, set[str]] = {}
    data_dir_direct: str | None = None

    raw: dict[str, Any] = {}
    if config_path is not None:
        try:
            raw = tomllib.loads(Path(config_path).read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise ConfigError(f"cannot read config file: {exc}") from exc
        config_dir = Path(config_path).resolve().parent
        for section, keys in schema.items():
            if section not in raw:
                continue
            section_value = raw[section]
            if not isinstance(section_value, dict):
                raise ConfigError(f"config section {section!r} must be a table")
            for key in section_value:
                if key not in keys:
                    raise ConfigError(f"unknown config key: {section}.{key}")
            for key, (expected, _, secret) in keys.items():
                if key not in section_value:
                    continue
                value = _coerce(section, key, section_value[key], expected)
                if section == "data_dir" and value:
                    # Relative paths resolve against the config file directory.
                    value = str((config_dir / value).resolve())
                values[section][key] = value
                if section == "data_dir":
                    data_dir_direct = value
                if secret:
                    secret_sources.setdefault(f"{section}{ENV_SEP}{key}", set()).add("file")

    for var, value in env.items():
        if not var.startswith(ENV_PREFIX):
            continue
        remainder = var[len(ENV_PREFIX):]
        if not remainder:
            raise ConfigError(f"empty config key in environment: {var}")
        parts = remainder.split(ENV_SEP)
        if len(parts) == 1:
            section, key = "", parts[0].lower()
        elif len(parts) == 2:
            section, key = parts[0].lower(), parts[1].lower()
        else:
            raise ConfigError(f"malformed config key: {var}")
        if section not in schema or key not in schema[section]:
            raise ConfigError(f"unknown config key in environment: {var}")
        expected, _, secret = schema[section][key]
        label = f"{section}{ENV_SEP}{key}" if section else key
        coerced = _coerce_env_value(label, value, expected)
        if section == "":
            data_dir_direct = coerced
        else:
            values[section][key] = coerced
            if secret:
                secret_sources.setdefault(label, set()).add("env")
    for name, origin in secret_sources.items():
        if len(origin) > 1:
            raise ConfigError(f"secret {name} supplied by multiple sources: {sorted(origin)}")

    if default_data_dir is not None:
        data_dir = Path(default_data_dir)
    elif data_dir_direct:
        data_dir = Path(data_dir_direct).expanduser()
    elif "AGENT_META_DATA_DIR" in env:
        data_dir = Path(env["AGENT_META_DATA_DIR"]).expanduser()
    else:
        data_dir = resolve_default_data_dir(env)
    if not data_dir.is_absolute():
        raise ConfigError("data_dir must resolve to an absolute path")

    log_level = values["logging"]["level"].upper()
    if log_level not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        raise ConfigError("logging.level must be one of DEBUG/INFO/WARNING/ERROR")
    if values["execution"]["host_backend"] not in ("trusted_in_process", "in_memory"):
        raise ConfigError("execution.host_backend must be trusted_in_process/in_memory")

    return RuntimeConfig(
        data_dir=data_dir,
        store_busy_timeout_ms=values["store"]["busy_timeout_ms"],
        store_wal_checkpoint_threshold_bytes=values["store"]["wal_checkpoint_threshold_bytes"],
        transport_endpoint=values["transport"]["endpoint"],
        transport_auth_secret=values["transport"]["auth_secret"],
        logging_level=log_level,
        logging_allowlist_only=values["logging"]["allowlist_only"],
        metrics_export_interval_s=values["metrics"]["export_interval_s"],
        shutdown_grace_s=values["shutdown"]["grace_s"],
        config_path=Path(config_path) if config_path is not None else None,
        execution_backend=values["execution"]["host_backend"],
    )


def redact_config(config: RuntimeConfig, env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """JCS-ready mapping with every secret replaced by ``{source,handle,present}``."""

    env = os.environ if env is None else env
    body = config.to_json()
    body["transport"]["auth_secret"] = {
        "source": "env" if "AGENT_META_TRANSPORT__AUTH_SECRET" in env else "file",
        "handle": "transport.auth_secret",
        "present": bool(config.transport_auth_secret),
    }
    return body


def config_fingerprint(redacted: Mapping[str, Any]) -> str:
    """SHA-256 over the JCS encoding of the redacted effective config."""

    return sha256_hex(canonical_json(dict(redacted)))


def write_effective_config(
    data_dir: Path, config: RuntimeConfig, env: Mapping[str, str] | None = None
) -> dict[str, Any]:
    """Write ``effective-config.redacted.json`` and return the redacted body."""

    redacted = redact_config(config, env)
    body = {
        "config_fingerprint": config_fingerprint(redacted),
        "generated_at_us": now_us(),
        "config": redacted,
    }
    out_dir = data_dir / "diagnostics"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "effective-config.redacted.json").write_bytes(canonical_json(body))
    return body
