"""AMPAK1 canonical capability package encoding (§41.29).

Wire layout::

    ASCII magic ``AMPAK1\\n``
    8-byte big-endian manifest byte length
    RFC 8785 JCS manifest bytes
    per FILE entry, in manifest entry order:
        8-byte big-endian content length + raw bytes   (DIRECTORY: nothing)

Manifest is ``{format_version: 1, package, entries[]}`` with exactly the fixed
fields below; entries are sorted by path UTF-8 bytes ascending. Path identity
uses UTF-8 NFC with ``/`` separators; mtime/uid/gid/local ACL never participate.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Mapping

from .canonical import CanonicalJsonError, canonical_json

__all__ = [
    "AmpakError",
    "PackageEntry",
    "PackageManifest",
    "PackageMeta",
    "decode_package",
    "encode_package",
    "validate_package_path",
]

MAGIC = b"AMPAK1\n"
MAX_ENTRIES = 10_000
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_PACKAGE_BYTES = 1024 * 1024 * 1024
MAX_PATH_BYTES = 512

_PACKAGE_FIELDS = (
    "name",
    "version",
    "artifact_kind",
    "entrypoint",
    "contract_artifact_id",
    "dependency_lock_artifact_id",
    "state_schema_artifact_ids",
    "migration_artifact_ids",
    "runtime_constraints",
    "platform_constraints",
    "build_provenance_artifact_id",
)
_ENTRY_FIELDS = ("path", "kind", "permission_class", "size", "sha256")
_KINDS = frozenset({"FILE", "DIRECTORY"})
_PERMISSION_CLASSES = frozenset({"DATA", "EXECUTABLE"})

# Windows reserved device names, matched on each path segment.
_RESERVED_RE = re.compile(
    r"^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(\..*)?$", re.IGNORECASE
)


class AmpakError(ValueError):
    """Raised for any AMPAK1 encoding, decoding or validation failure."""


def _validate_artifact_ref(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.startswith("artifact://sha256/"):
        raise AmpakError(f"{field} must be an artifact://sha256/<hex> id or null")
    hex_part = value[len("artifact://sha256/") :]
    if not re.fullmatch(r"[0-9a-f]{64}", hex_part):
        raise AmpakError(f"{field} is not a lowercase sha256 artifact id")
    return value


@dataclass(frozen=True, slots=True)
class PackageMeta:
    """Fixed ``package`` fields of the AMPAK1 manifest."""

    name: str
    version: str
    artifact_kind: str
    entrypoint: str
    contract_artifact_id: str | None
    dependency_lock_artifact_id: str | None
    state_schema_artifact_ids: tuple[str, ...]
    migration_artifact_ids: tuple[str, ...]
    runtime_constraints: Mapping[str, Any]
    platform_constraints: Mapping[str, Any]
    build_provenance_artifact_id: str | None


@dataclass(frozen=True, slots=True)
class PackageEntry:
    path: str
    kind: str
    permission_class: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class PackageManifest:
    package: PackageMeta
    entries: tuple[PackageEntry, ...]

    @property
    def format_version(self) -> int:
        return 1


def validate_package_path(path: str) -> str:
    """Validate one package path against every §41.29 rule."""

    if not isinstance(path, str) or not path:
        raise AmpakError("path must be a non-empty string")
    if len(path.encode("utf-8")) > MAX_PATH_BYTES:
        raise AmpakError("path exceeds 512 UTF-8 bytes")
    if unicodedata.normalize("NFC", path) != path:
        raise AmpakError("path must be UTF-8 NFC")
    if "\\" in path or ":" in path or "\x00" in path:
        raise AmpakError("path must not contain backslash, colon or NUL")
    if path.startswith("/"):
        raise AmpakError("path must be relative")
    for seg in path.split("/"):
        if seg == "":
            raise AmpakError("path has an empty segment")
        if seg in (".", ".."):
            raise AmpakError("path must not contain '.' or '..' segments")
        if seg.endswith(".") or seg.endswith(" "):
            raise AmpakError("path segment must not end with dot or space")
        if _RESERVED_RE.match(seg):
            raise AmpakError(f"Windows reserved device name: {seg!r}")
    return path


def _validate_no_duplicates(entries: tuple[PackageEntry, ...]) -> None:
    seen_exact: set[str] = set()
    seen_folded: set[str] = set()
    for entry in entries:
        validate_package_path(entry.path)
        if entry.path in seen_exact:
            raise AmpakError(f"duplicate path: {entry.path!r}")
        folded = entry.path.casefold()
        if folded in seen_folded:
            raise AmpakError(f"case-fold duplicate path: {entry.path!r}")
        seen_exact.add(entry.path)
        seen_folded.add(folded)
        if entry.kind not in _KINDS:
            raise AmpakError(f"entry kind must be FILE or DIRECTORY: {entry.kind!r}")
        if entry.permission_class not in _PERMISSION_CLASSES:
            raise AmpakError(f"invalid permission_class: {entry.permission_class!r}")
        if entry.kind == "DIRECTORY":
            if entry.permission_class != "DATA":
                raise AmpakError("DIRECTORY entries use permission_class DATA")
            if entry.size != 0:
                raise AmpakError("DIRECTORY entries have size 0")
            if entry.sha256 != "":
                raise AmpakError("DIRECTORY entries have an empty sha256")
        else:
            if entry.size < 0 or entry.size > MAX_FILE_BYTES:
                raise AmpakError(f"file size out of range for {entry.path!r}")
            if not re.fullmatch(r"[0-9a-f]{64}", entry.sha256):
                raise AmpakError(f"entry sha256 must be lowercase hex: {entry.path!r}")
    # Directories must be explicitly listed and precede all children.
    listed_dirs = {e.path for e in entries if e.kind == "DIRECTORY"}
    file_paths = {e.path for e in entries if e.kind == "FILE"}
    order = {e.path: i for i, e in enumerate(entries)}
    for entry in entries:
        parts = entry.path.split("/")
        for depth in range(1, len(parts)):
            ancestor = "/".join(parts[:depth])
            if ancestor in file_paths:
                raise AmpakError(f"path below a FILE entry: {entry.path!r}")
            if ancestor not in listed_dirs:
                raise AmpakError(f"missing explicit DIRECTORY entry: {ancestor!r}")
            if order[ancestor] > order[entry.path]:
                raise AmpakError(f"directory must precede children: {ancestor!r}")


def _validate_meta(meta: PackageMeta) -> None:
    if not isinstance(meta.name, str) or not re.fullmatch(
        r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*", meta.name
    ):
        raise AmpakError("package name must match the stable-name grammar")
    if not isinstance(meta.version, str) or not meta.version:
        raise AmpakError("package version must be a non-empty string")
    if not isinstance(meta.artifact_kind, str) or not meta.artifact_kind:
        raise AmpakError("artifact_kind must be a non-empty string")
    if not isinstance(meta.entrypoint, str):
        raise AmpakError("entrypoint must be a string")
    for field in ("contract_artifact_id", "dependency_lock_artifact_id",
                  "build_provenance_artifact_id"):
        _validate_artifact_ref(getattr(meta, field), field)
    for field in ("state_schema_artifact_ids", "migration_artifact_ids"):
        ids = getattr(meta, field)
        if not isinstance(ids, (tuple, list)) or not all(
            isinstance(i, str) for i in ids
        ):
            raise AmpakError(f"{field} must be a list of artifact ids")
        if list(ids) != sorted(set(ids), key=lambda s: s.encode("utf-8")):
            raise AmpakError(f"{field} must be sorted by ArtifactId and deduplicated")
        for ref in ids:
            _validate_artifact_ref(ref, field)
    for field in ("runtime_constraints", "platform_constraints"):
        constraints = getattr(meta, field)
        if not isinstance(constraints, Mapping):
            raise AmpakError(f"{field} must be an object")


def _meta_to_json(meta: PackageMeta) -> dict[str, Any]:
    return {
        "name": meta.name,
        "version": meta.version,
        "artifact_kind": meta.artifact_kind,
        "entrypoint": meta.entrypoint,
        "contract_artifact_id": meta.contract_artifact_id,
        "dependency_lock_artifact_id": meta.dependency_lock_artifact_id,
        "state_schema_artifact_ids": list(meta.state_schema_artifact_ids),
        "migration_artifact_ids": list(meta.migration_artifact_ids),
        "runtime_constraints": dict(meta.runtime_constraints),
        "platform_constraints": dict(meta.platform_constraints),
        "build_provenance_artifact_id": meta.build_provenance_artifact_id,
    }


def build_manifest(meta: PackageMeta, files: Mapping[str, bytes]) -> PackageManifest:
    """Build and validate a manifest from raw file contents."""

    _validate_meta(meta)
    entries: list[PackageEntry] = []
    dirs: set[str] = set()
    for path in files:
        validate_package_path(path)
        parts = path.split("/")
        for depth in range(1, len(parts)):
            ancestor = "/".join(parts[:depth])
            if ancestor in files:
                raise AmpakError(f"file path conflicts with file entry: {ancestor!r}")
            dirs.add(ancestor)
    for path in sorted(dirs | set(files), key=lambda s: s.encode("utf-8")):
        if path in dirs:
            entries.append(
                PackageEntry(
                    path=path, kind="DIRECTORY", permission_class="DATA",
                    size=0, sha256="",
                )
            )
            continue
        content = files[path]
        if len(content) > MAX_FILE_BYTES:
            raise AmpakError(f"file exceeds 256 MiB: {path!r}")
        entries.append(
            PackageEntry(
                path=path,
                kind="FILE",
                permission_class="DATA",
                size=len(content),
                sha256=hashlib.sha256(content).hexdigest(),
            )
        )
    manifest = PackageManifest(package=meta, entries=tuple(entries))
    validate_manifest(manifest)
    return manifest


def validate_manifest(manifest: PackageManifest) -> None:
    if len(manifest.entries) > MAX_ENTRIES:
        raise AmpakError(f"package exceeds {MAX_ENTRIES} entries")
    _validate_meta(manifest.package)
    _validate_no_duplicates(manifest.entries)
    if list(manifest.entries) != sorted(manifest.entries, key=lambda e: e.path.encode("utf-8")):
        raise AmpakError("entries must be sorted by path UTF-8 bytes ascending")


def encode_package(manifest: PackageManifest, files: Mapping[str, bytes]) -> bytes:
    """Encode a validated manifest plus file contents to AMPAK1 bytes."""

    validate_manifest(manifest)
    body = {
        "format_version": 1,
        "package": _meta_to_json(manifest.package),
        "entries": [
            {
                "path": e.path,
                "kind": e.kind,
                "permission_class": e.permission_class,
                "size": e.size,
                "sha256": e.sha256,
            }
            for e in manifest.entries
        ],
    }
    try:
        manifest_bytes = canonical_json(body)
    except CanonicalJsonError as exc:
        raise AmpakError(f"manifest is not canonicalizable: {exc}") from exc
    out = bytearray(MAGIC)
    out += len(manifest_bytes).to_bytes(8, "big")
    out += manifest_bytes
    for entry in manifest.entries:
        if entry.kind != "FILE":
            continue
        if entry.path not in files:
            raise AmpakError(f"missing file content for entry: {entry.path!r}")
        content = files[entry.path]
        if len(content) != entry.size:
            raise AmpakError(f"size mismatch for {entry.path!r}")
        if hashlib.sha256(content).hexdigest() != entry.sha256:
            raise AmpakError(f"sha256 mismatch for {entry.path!r}")
        out += len(content).to_bytes(8, "big")
        out += content
    if len(out) > MAX_PACKAGE_BYTES:
        raise AmpakError("package exceeds 1 GiB")
    return bytes(out)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise AmpakError(f"duplicate manifest key: {key!r}")
        obj[key] = value
    return obj


def _parse_meta(raw: Any) -> PackageMeta:
    if not isinstance(raw, dict) or set(raw) != set(_PACKAGE_FIELDS):
        raise AmpakError("package object must contain exactly the fixed fields")
    for field in ("state_schema_artifact_ids", "migration_artifact_ids"):
        if not isinstance(raw[field], list):
            raise AmpakError(f"{field} must be an array")
    return PackageMeta(
        name=raw["name"],
        version=raw["version"],
        artifact_kind=raw["artifact_kind"],
        entrypoint=raw["entrypoint"],
        contract_artifact_id=raw["contract_artifact_id"],
        dependency_lock_artifact_id=raw["dependency_lock_artifact_id"],
        state_schema_artifact_ids=tuple(raw["state_schema_artifact_ids"]),
        migration_artifact_ids=tuple(raw["migration_artifact_ids"]),
        runtime_constraints=raw["runtime_constraints"],
        platform_constraints=raw["platform_constraints"],
        build_provenance_artifact_id=raw["build_provenance_artifact_id"],
    )


def _parse_entries(raw: Any) -> tuple[PackageEntry, ...]:
    if not isinstance(raw, list):
        raise AmpakError("entries must be a list")
    entries: list[PackageEntry] = []
    for item in raw:
        if not isinstance(item, dict) or set(item) != set(_ENTRY_FIELDS):
            raise AmpakError("entry must contain exactly the fixed fields")
        if not all(isinstance(item[field], str) for field in ("path", "kind", "permission_class", "sha256")):
            raise AmpakError("entry path/kind/permission_class/sha256 must be strings")
        size = item["size"]
        if not isinstance(size, int) or isinstance(size, bool):
            raise AmpakError("entry size must be an integer")
        entries.append(
            PackageEntry(
                path=item["path"],
                kind=item["kind"],
                permission_class=item["permission_class"],
                size=size,
                sha256=item["sha256"],
            )
        )
    ordered = sorted(entries, key=lambda e: e.path.encode("utf-8"))
    if ordered != entries:
        raise AmpakError("entries must be sorted by path UTF-8 bytes ascending")
    return tuple(entries)


def decode_package(data: bytes) -> tuple[PackageManifest, dict[str, bytes]]:
    """Decode and fully verify AMPAK1 bytes into manifest + file contents."""

    if not isinstance(data, bytes):
        raise AmpakError("package must be bytes")
    if len(data) > MAX_PACKAGE_BYTES:
        raise AmpakError("package exceeds 1 GiB")
    if not data.startswith(MAGIC):
        raise AmpakError("bad magic")
    if len(data) < len(MAGIC) + 8:
        raise AmpakError("truncated header")
    manifest_len = int.from_bytes(data[len(MAGIC): len(MAGIC) + 8], "big")
    start = len(MAGIC) + 8
    end = start + manifest_len
    if end > len(data):
        raise AmpakError("manifest length exceeds package size")
    try:
        body = json.loads(data[start:end], object_pairs_hook=_strict_object)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AmpakError(f"manifest is not valid JSON: {exc}") from exc
    if not isinstance(body, dict) or set(body) != {"format_version", "package", "entries"}:
        raise AmpakError("manifest must contain exactly format_version/package/entries")
    if type(body["format_version"]) is not int or body["format_version"] != 1:
        raise AmpakError("unsupported package format_version")
    try:
        if canonical_json(body) != data[start:end]:
            raise AmpakError("manifest must be RFC 8785 canonical JSON")
    except CanonicalJsonError as exc:
        raise AmpakError("manifest is not canonicalizable") from exc
    manifest = PackageManifest(
        package=_parse_meta(body["package"]), entries=_parse_entries(body["entries"])
    )
    validate_manifest(manifest)
    files: dict[str, bytes] = {}
    cursor = end
    for entry in manifest.entries:
        if entry.kind != "FILE":
            continue
        if cursor + 8 > len(data):
            raise AmpakError(f"truncated content header for {entry.path!r}")
        content_len = int.from_bytes(data[cursor: cursor + 8], "big")
        cursor += 8
        if cursor + content_len > len(data):
            raise AmpakError(f"truncated content for {entry.path!r}")
        content = data[cursor: cursor + content_len]
        if content_len != entry.size:
            raise AmpakError(f"size mismatch for {entry.path!r}")
        if hashlib.sha256(content).hexdigest() != entry.sha256:
            raise AmpakError(f"sha256 mismatch for {entry.path!r}")
        files[entry.path] = content
        cursor += content_len
    if cursor != len(data):
        raise AmpakError("trailing bytes after last file content")
    return manifest, files
