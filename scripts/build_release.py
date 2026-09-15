"""Build the v0.1 release bundle (Runtime_09 steps 2-3).

Builds the wheel and sdist offline via hatchling's PEP 517 hooks, scans both
for forbidden content (Seed / Conformance-fixture / checkout paths), emits an
SBOM plus a release manifest whose evidence gates re-run the traceability
checker and the architecture lint. Exit code 1 on any gate failure.

Run: ``.venv/bin/python scripts/build_release.py``
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import sysconfig
from pathlib import Path
from zipfile import ZipFile

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

DIST_DIR = REPO_ROOT / "dist" / "release"
GOLDEN = REPO_ROOT / "tests" / "unit" / "golden" / "foundation_golden.json"

FORBIDDEN_WHEEL_SUBSTRINGS: tuple[str, ...] = (
    "seed-harness",
    "seed_harness",
    "agent_meta_seed",
    "agent-meta-seed",
    "conformance_harness",
    "conformance harness",
    "/mnt/",
    "C:\\WorkSpace",
    "tests/fixtures",
)

SBOM_SCHEMA = "agent-meta-sbom/1"
MANIFEST_VERSION = 1


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _scan_wheel(wheel: Path) -> list[str]:
    failures: list[str] = []
    with ZipFile(wheel) as archive:
        names = archive.namelist()
        record = [name for name in names if name.endswith(".dist-info/RECORD")]
        if len(record) != 1:
            return [f"{wheel.name}: expected one RECORD, found {len(record)}"]
        record_names = {
            line.split(",")[0] for line in archive.read(record[0]).decode().splitlines() if line
        }
        missing = sorted(set(names) - record_names - {record[0]})
        if missing:
            failures.append(f"{wheel.name}: files not listed in RECORD: {missing[:5]}")
        for name in names:
            text = archive.read(name).decode("utf-8", errors="replace")
            for needle in FORBIDDEN_WHEEL_SUBSTRINGS:
                if needle in text:
                    failures.append(f"{wheel.name}:{name}: forbidden content {needle!r}")
    return failures


def _build_sdist() -> tuple[Path | None, list[str]]:
    from hatchling.build import build_sdist

    try:
        name = build_sdist(str(DIST_DIR))
    except Exception as exc:  # noqa: BLE001 - reported as a gate failure
        return None, [f"sdist build failed: {exc}"]
    path = DIST_DIR / name
    import tarfile

    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            if member.name.endswith("PKG-INFO") and b"/mnt/" in archive.extractfile(
                member
            ).read():
                return path, [f"{path.name}:{member.name}: checkout path in PKG-INFO"]
    return path, []


def _build_wheel() -> tuple[Path | None, list[str]]:
    from hatchling.build import build_wheel

    try:
        name = build_wheel(str(DIST_DIR))
    except Exception as exc:  # noqa: BLE001 - reported as a gate failure
        return None, [f"wheel build failed: {exc}"]
    wheel = DIST_DIR / name
    failures = _scan_wheel(wheel)
    return wheel, failures


def _runtime_version(wheel: Path) -> str:
    marker = wheel.name[len("agent_meta_runtime-") : -len("-py3-none-any.whl")]
    return marker


def _dependencies() -> list[str]:
    from importlib.metadata import distributions

    names: list[str] = []
    for dist in distributions():
        name = dist.metadata["Name"]
        requires = dist.requires or []
        if name == "agent-meta-runtime" or any(
            "agent_meta_runtime" in (req or "").lower().replace("-", "_")
            for req in requires
        ):
            continue
        names.append(name)
    return sorted(set(names))


def _build_sbom(wheel: Path) -> dict:
    from importlib.metadata import distribution

    components = []
    with ZipFile(wheel) as archive:
        for name in sorted(archive.namelist()):
            if name.endswith("/"):
                continue
            data = archive.read(name)
            components.append(
                {
                    "name": name,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                }
            )
    return {
        "schema": SBOM_SCHEMA,
        "name": "agent-meta-runtime",
        "version": _runtime_version(wheel),
        "components": components,
        "dependencies": _dependencies(),
    }


def _evidence() -> list[str]:
    failures: list[str] = []
    for script in ("traceability_check.py", "arch_lint.py"):
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / script)],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        if result.returncode != 0:
            failures.append(f"{script} failed (exit {result.returncode})")
    return failures


def _db_identity() -> dict:
    from agent_meta_runtime.adapters.store.connection import APPLICATION_ID, USER_VERSION

    return {
        "db_application_id": APPLICATION_ID,
        "db_user_version": USER_VERSION,
    }


def _public_api() -> dict:
    from agent_meta_runtime.protocols.public_wire import (
        PUBLIC_API_MAJOR,
        PUBLIC_API_MINOR,
    )

    return {
        "major": PUBLIC_API_MAJOR,
        "minor": PUBLIC_API_MINOR,
    }


def main() -> int:
    from agent_meta_runtime import __version__ as version

    DIST_DIR.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []

    wheel, wheel_failures = _build_wheel()
    failures.extend(wheel_failures)
    sdist, sdist_failures = _build_sdist()
    failures.extend(sdist_failures)

    if wheel is None or sdist is None:
        for failure in failures:
            print(f"  - {failure}")
        return 1

    sbom = _build_sbom(wheel)
    sbom_path = DIST_DIR / "sbom-agent-meta-runtime.json"
    sbom_path.write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    evidence_failures = _evidence()
    failures.extend(evidence_failures)

    db_identity = _db_identity()
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "name": "agent-meta-runtime",
        "version": version,
        "wheel": _sha256_file(wheel),
        "sdist": _sha256_file(sdist),
        "sbom": _sha256_file(sbom_path),
        "golden": _sha256_file(GOLDEN),
        "public_api": _public_api(),
        **db_identity,
        "evidence": {
            "traceability_check": "pass" if not evidence_failures else "fail",
            "architecture_lint": "pass" if not evidence_failures else "fail",
        },
    }
    manifest_path = DIST_DIR / "release-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    if failures:
        print(f"release: {len(failures)} gate failure(s)")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"release: OK — wheel {wheel.name}, sdist {sdist.name}")
    print(f"release: SBOM {sbom_path.name}, manifest release-manifest.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
