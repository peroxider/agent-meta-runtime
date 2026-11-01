"""Architecture lint: AST-based dependency enforcement (§41.50).

Checks, against ``architecture.toml``:
1. No module under ``src/agent_meta_runtime`` imports a forbidden module for
   its package (absolute or relative imports).
2. No Runtime module imports ``agent_meta_seed_harness`` or any
   ``seed_harness`` product module (Runtime -> Seed ban).
3. ``domain`` never imports sqlite3/IPython/grpc/provider SDKs.
4. ``tests/fixtures/conformance_harness`` may import only
   ``agent_meta_runtime.sdk``, public DTOs and the standard library — never
   ``agent_meta_runtime.adapters.*`` or private repository/UoW modules.

Exit code 0 when clean, 1 with a report on stderr otherwise.
"""

from __future__ import annotations

import ast
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ARCH_FILE = ROOT / "architecture.toml"

RUNTIME_PACKAGE = "agent_meta_runtime"
SEED_MODULES = ("agent_meta_seed_harness", "seed_harness")
DOMAIN_HARD_FORBIDDEN = ("sqlite3", "IPython", "grpc", "openai", "anthropic", "cordis")
CONFORMANCE_ROOTS = ("tests/fixtures/conformance_harness",)
SDK_ALLOWED_PREFIXES = (
    "agent_meta_runtime.sdk",
    "agent_meta_runtime.domain",
    "agent_meta_runtime.protocols",
)

_PACKAGES: list[dict] | None = None


def _declared_packages() -> list[dict]:
    global _PACKAGES
    if _PACKAGES is None:
        data = tomllib.loads(ARCH_FILE.read_text(encoding="utf-8"))
        _PACKAGES = data["package"]
        for pkg in _PACKAGES:
            if len(pkg["secondary_principles"]) > 2:
                raise ValueError(f"{pkg['name']}: more than two secondary principles")
            if not pkg["primary_principle"]:
                raise ValueError(f"{pkg['name']}: missing primary principle")
    return _PACKAGES


def _resolve_relative(root: Path, file: Path, node: ast.ImportFrom) -> str:
    if node.level == 0:
        return node.module or ""
    base = file.parent
    for _ in range(node.level - 1):
        base = base.parent
    import_root = root / "src" if file.is_relative_to(root / "src") else root
    parts = list(base.relative_to(import_root).parts)
    if node.module:
        parts.append(node.module)
    return ".".join(parts)


def _iter_imports(root: Path, file: Path) -> list[str]:
    tree = ast.parse(file.read_text(encoding="utf-8"), filename=str(file))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = _resolve_relative(root, file, node)
            if base:
                names.append(base)
            for alias in node.names:
                names.append(f"{base}.{alias.name}" if base else alias.name)
    return names


def _matches(imported: str, rule: str) -> bool:
    if imported == rule or imported.startswith(rule + "."):
        return True
    if "." not in rule:
        return imported.split(".")[0] == rule
    return False


def check_tree(root: Path = ROOT) -> list[str]:
    violations: list[str] = []
    src_pkg_root = root / "src" / RUNTIME_PACKAGE
    if src_pkg_root.exists():
        for file in sorted(src_pkg_root.rglob("*.py")):
            module = ".".join(file.relative_to(root / "src").with_suffix("").parts)
            package = next(
                (
                    p["name"]
                    for p in _declared_packages()
                    if module == p["name"] or module.startswith(p["name"] + ".")
                ),
                None,
            )
            if package is None:
                continue
            declared = next(p for p in _declared_packages() if p["name"] == package)
            forbidden = list(declared["forbidden"])
            if declared["layer"] == "domain":
                forbidden.extend(DOMAIN_HARD_FORBIDDEN)
            for imported in _iter_imports(root, file):
                if any(_matches(imported, seed) for seed in SEED_MODULES):
                    violations.append(f"{file}: Runtime -> Seed import {imported!r}")
                    continue
                for rule in forbidden:
                    if _matches(imported, rule):
                        violations.append(
                            f"{file}: {module} imports forbidden {imported!r}"
                        )
                        break
    for conformance_root in CONFORMANCE_ROOTS:
        fixture_dir = root / conformance_root
        if not fixture_dir.exists():
            continue
        for file in sorted(fixture_dir.rglob("*.py")):
            for imported in _iter_imports(root, file):
                if any(_matches(imported, seed) for seed in SEED_MODULES):
                    violations.append(
                        f"{file}: conformance fixture imports Seed {imported!r}"
                    )
                elif imported.startswith(RUNTIME_PACKAGE) and not any(
                    _matches(imported, allowed) for allowed in SDK_ALLOWED_PREFIXES
                ):
                    violations.append(
                        f"{file}: conformance fixture imports non-public {imported!r}"
                    )
    return violations


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    root = Path(argv[0]) if argv else ROOT
    violations = check_tree(root)
    for violation in violations:
        print(f"ARCH-LINT: {violation}", file=sys.stderr)
    if violations:
        print(
            f"architecture lint failed: {len(violations)} violation(s)",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
