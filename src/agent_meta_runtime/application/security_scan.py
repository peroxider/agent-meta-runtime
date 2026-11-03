"""Built-in deterministic package/AST security scanner (§41.43).

Pure application module backing the ``security_policy`` assertion of
``deterministic-evaluation/v1``. Scans a candidate package file map
(relative path -> bytes) for native binaries, path escapes, case
conflicts and a frozen set of Python-level patterns (dynamic execution,
runtime mutation, process spawn, denied/private/non-allowlist imports).
No subprocesses, no network, no third-party dependencies: the same
files and allowlist always produce the same findings document (AC-M42).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from ..domain.canonical import canonical_json, sha256_hex

__all__ = [
    "DENYLIST_MODULES",
    "NATIVE_SUFFIXES",
    "Finding",
    "findings_document",
    "scan_package",
]

NATIVE_SUFFIXES = frozenset({".so", ".pyd", ".dll", ".exe", ".dylib", ".bin"})

_NATIVE_MAGIC = (b"\x7fELF", b"MZ")

DENYLIST_MODULES = frozenset(
    {"ctypes", "cffi", "subprocess", "socket", "multiprocessing"}
)

_DYNAMIC_CALLS = frozenset({"eval", "exec", "compile", "__import__"})

_RUNTIME_TARGETS = frozenset({"path", "modules"})

_PRIVATE_ROOT = "agent_meta_runtime"

_OS_SPAWN_ATTRS = frozenset({"system", "popen"})


@dataclass(frozen=True, slots=True)
class Finding:
    """One deterministic scan finding; ``node_hash`` anchors the AST node."""

    severity: str  # HIGH | MEDIUM | LOW
    code: str
    path: str
    node_hash: str
    detail: str


def _sort_key(finding: Finding) -> tuple[str, str, str, str, str]:
    return (
        finding.severity,
        finding.code,
        finding.path,
        finding.node_hash,
        finding.detail,
    )


def _node_hash(node: ast.AST) -> str:
    try:
        dumped = ast.dump(node, annotate_fields=False, include_attributes=False)
    except Exception:  # pragma: no cover - ast.dump of a parsed node
        return ""
    return sha256_hex(dumped.encode("utf-8"))


def _scan_python(
    path: str, source: bytes, import_allowlist: tuple[str, ...]
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(source.decode("utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        return (
            Finding(
                severity="HIGH",
                code="unparseable_source",
                path=path,
                node_hash="",
                detail="source is not valid UTF-8 Python",
            ),
        )

    def add(severity: str, code: str, node: ast.AST, detail: str) -> None:
        findings.append(Finding(severity, code, path, _node_hash(node), detail))

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            entries: list[tuple[str, int]] = []
            if isinstance(node, ast.Import):
                entries = [(alias.name.split(".")[0], 0) for alias in node.names]
            elif node.level > 0:
                entries = [("", node.level)]
            else:
                entries = [((node.module or "").split(".")[0], 0)]
            for root, level in entries:
                if level > 0:
                    add(
                        "HIGH",
                        "relative_import",
                        node,
                        "relative import escapes the package boundary",
                    )
                    continue
                if root in DENYLIST_MODULES:
                    add("HIGH", "denied_import", node,
                        f"module {root} is denied")
                elif root == _PRIVATE_ROOT:
                    add("HIGH", "private_runtime_import", node,
                        f"module {root} is runtime-private")
                elif import_allowlist and root not in import_allowlist:
                    add("MEDIUM", "non_allowlist_import", node,
                        f"module {root} is not in the import allowlist")
        elif isinstance(node, ast.Call):
            func = node.func
            attr = getattr(func, "attr", None)
            inner = getattr(func, "value", None)
            value_id = getattr(inner, "id", None)
            value_attr = getattr(inner, "attr", None)
            if getattr(func, "id", None) in _DYNAMIC_CALLS:
                add("HIGH", "dynamic_execution", func,
                    f"call to {func.id}()")
            if value_id == "os" and attr in _OS_SPAWN_ATTRS:
                add("HIGH", "process_spawn", func, f"os.{attr}()")
            if value_id == "sys" and value_attr in _RUNTIME_TARGETS:
                add("HIGH", "runtime_modification", func,
                    f"mutation of sys.{value_attr}")
            if isinstance(inner, ast.Attribute) and isinstance(
                inner.value, ast.Name
            ):
                if inner.value.id == "sys" and inner.attr in _RUNTIME_TARGETS:
                    add("HIGH", "runtime_modification", func,
                        f"mutation of sys.{inner.attr}")
    return tuple(findings)


def scan_package(
    files: Mapping[str, bytes], import_allowlist: Iterable[str] = ()
) -> tuple[Finding, ...]:
    """Scan a package file map; returns findings sorted deterministically."""

    allowlist = tuple(import_allowlist)
    findings: list[Finding] = []
    seen_lower: dict[str, str] = {}
    for path, content in files.items():
        normalized = path.replace("\\", "/")
        if (
            normalized.startswith("/")
            or ".." in normalized.split("/")
            or ":" in normalized
            or normalized != path
        ):
            findings.append(
                Finding(
                    severity="HIGH",
                    code="path_escape",
                    path=path,
                    node_hash="",
                    detail="package path escapes the package root",
                )
            )
            continue
        lowered = normalized.lower()
        if lowered in seen_lower and seen_lower[lowered] != normalized:
            findings.append(
                Finding(
                    severity="HIGH",
                    code="case_conflict",
                    path=path,
                    node_hash="",
                    detail=f"case-insensitive collision with {seen_lower[lowered]}",
                )
            )
        else:
            seen_lower[lowered] = normalized
        suffix = f".{normalized.rsplit('.', 1)[-1].lower()}" if "." in normalized else ""
        if any(content.startswith(magic) for magic in _NATIVE_MAGIC) or (
            suffix in NATIVE_SUFFIXES
        ):
            findings.append(
                Finding(
                    severity="HIGH",
                    code="native_binary",
                    path=normalized,
                    node_hash="",
                    detail="native binary content is not permitted",
                )
            )
            continue
        if normalized.endswith(".py"):
            findings.extend(_scan_python(normalized, content, allowlist))
    return tuple(sorted(findings, key=_sort_key))


def findings_document(findings: tuple[Finding, ...]) -> dict[str, Any]:
    """Deterministic findings document with ``high_count`` and ``scan_hash``."""

    ordered = sorted(findings, key=lambda f: (f.path, f.code, f.node_hash))
    entries = [
        {
            "severity": finding.severity,
            "code": finding.code,
            "path": finding.path,
            "node_hash": finding.node_hash,
            "detail": finding.detail,
        }
        for finding in ordered
    ]
    document: dict[str, Any] = {
        "findings": entries,
        "high_count": sum(
            1 for entry in entries if entry["severity"] == "HIGH"
        ),
    }
    document["scan_hash"] = sha256_hex(canonical_json(document))
    return document
