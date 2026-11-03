"""Closed backup metadata and portable paths; no filesystem reads or writes."""

from dataclasses import dataclass
import re

from ...domain.errors import ErrorCode, StableError
from ...domain.ids import validate_id
from .connection import APPLICATION_ID, USER_VERSION
from .migrations import MIGRATION_VERSION

MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_FILES = 65536
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_DEVICES = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{i}" for i in (*range(1, 10), "¹", "²", "³")),
        *(f"lpt{i}" for i in (*range(1, 10), "¹", "²", "³")),
    }
)


def invalid():
    return StableError(
        code=ErrorCode.INTEGRITY_ERROR, message="invalid backup manifest or path"
    )


@dataclass(frozen=True, slots=True)
class BackupFile:
    relpath: str
    size_bytes: int
    sha256: str


def portable_path(value):
    if type(value) is not str:
        raise invalid()
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise invalid() from None
    if not 1 <= size <= 4096:
        raise invalid()
    parts = value.split("/")
    if (
        len(parts) > 64
        or any(
            not part
            or part in (".", "..")
            or part[-1:] in (".", " ")
            or any(
                ord(char) < 32 or ord(char) == 127 or char in '\\:<>"|?*'
                for char in part
            )
            or part.split(".", 1)[0].casefold() in _DEVICES
            for part in parts
        )
        or not (
            value == "meta.db"
            or len(parts) >= 2
            and parts[0] in ("artifacts", "keys", "backend")
        )
    ):
        raise invalid()
    return value


def validate_manifest(value):
    fields = {
        "manifest_version",
        "created_at_us",
        "runtime_version",
        "api_version",
        "application_id",
        "db_schema_version",
        "migration_version",
        "realm_id",
        "epoch_id",
        "meta_revision",
        "fact_boundary",
        "backend",
        "files",
    }
    if type(value) is not dict or set(value) != fields:
        raise invalid()
    if type(value["manifest_version"]) is not int or value["manifest_version"] != 1:
        raise invalid()
    if (
        type(value["db_schema_version"]) is not int
        or value["db_schema_version"] != USER_VERSION
        or type(value["migration_version"]) is not int
        or value["migration_version"] != MIGRATION_VERSION
    ):
        raise StableError(
            code=ErrorCode.FAILED_PRECONDITION,
            message="backup schema version does not match this runtime",
        )
    if (
        type(value["application_id"]) is not int
        or value["application_id"] != APPLICATION_ID
        or value["api_version"] != "agent_meta.public.v1"
        or type(value["runtime_version"]) is not str
        or not 1 <= len(value["runtime_version"]) <= 128
        or type(value["created_at_us"]) is not int
        or not 0 < value["created_at_us"] <= 2**63 - 1
        or type(value["meta_revision"]) is not int
        or not 0 <= value["meta_revision"] <= 2**63 - 1
    ):
        raise invalid()
    try:
        for name, prefix in (("realm_id", "realm://"), ("epoch_id", "epoch://")):
            validate_id(value[name])
            if not value[name].startswith(prefix):
                raise ValueError("identity kind")
    except (ValueError, TypeError, AttributeError):
        raise invalid() from None
    boundary = value["fact_boundary"]
    if (
        type(boundary) is not dict
        or set(boundary) != {"last_seq", "head_hash"}
        or type(boundary["last_seq"]) is not int
        or not 0 <= boundary["last_seq"] <= 2**63 - 1
        or type(boundary["head_hash"]) is not str
        or _HASH.fullmatch(boundary["head_hash"]) is None
    ):
        raise invalid()
    backend = value["backend"]
    if (
        type(backend) is not dict
        or set(backend) != {"portable_db"}
        or type(backend["portable_db"]) is not bool
    ):
        raise invalid()
    entries = value["files"]
    if type(entries) is not list or not entries or len(entries) > MAX_MANIFEST_FILES:
        raise invalid()
    seen = set()
    files = []
    for entry in entries:
        if type(entry) is not dict or set(entry) != {"relpath", "size_bytes", "sha256"}:
            raise invalid()
        path = portable_path(entry["relpath"])
        folded = path.casefold()
        if (
            folded in seen
            or type(entry["size_bytes"]) is not int
            or not 0 <= entry["size_bytes"] <= 2**63 - 1
            or path == "keys/store.json"
            and entry["size_bytes"] > 65536
            or type(entry["sha256"]) is not str
            or _HASH.fullmatch(entry["sha256"]) is None
        ):
            raise invalid()
        seen.add(folded)
        files.append(BackupFile(path, entry["size_bytes"], entry["sha256"]))
    for path in seen:
        parts = path.split("/")
        if any("/".join(parts[:index]) in seen for index in range(1, len(parts))):
            raise invalid()
    if (
        "meta.db" not in seen
        or "keys/store.json" not in seen
        or ("backend/portable.db" in seen) != backend["portable_db"]
    ):
        raise invalid()
    return tuple(files)
