"""Release E2E: independent Runtime flows in an empty data dir (Runtime_09).

Runs the full operator story offline — CLI ``init`` on an empty directory,
server restart with GetInfo, integrity doctor, sealed backup, restore into a
second empty directory, upgrade preflight, plus Conformance/Task/Harness
lifecycle flows — and asserts the release gate: no Seed / Conformance-fixture
module was ever imported.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests" / "trace"))

from agent_meta_runtime.adapters.store.backup import (  # noqa: E402
    create_backup,
    preflight_upgrade,
    restore_backup,
)
from agent_meta_runtime.adapters.store.connection import connect_store  # noqa: E402
from agent_meta_runtime.adapters.store.doctor import run_integrity_doctor  # noqa: E402
from agent_meta_runtime.interfaces.cli.main import main as cli_main  # noqa: E402
from scenarios import (  # noqa: E402
    conformance_bootstrap_offline,
    harness_lifecycle,
    task_lifecycle,
)

SEED_MODULE_MARKERS = ("agent_meta_seed", "seed_harness")


def _assert_no_seed_modules() -> None:
    loaded: list[str] = []
    for name, module in sys.modules.items():
        lowered = name.lower()
        if any(marker in lowered for marker in SEED_MODULE_MARKERS):
            loaded.append(name)
            continue
        if "conformance_harness" in lowered and name.startswith(
            "agent_meta_runtime"
        ):
            loaded.append(name)
    assert not loaded, f"Seed modules leaked into the Runtime process: {loaded}"


async def _serve_and_probe(data_dir: Path, db_path: Path):
    """Start a real local API server over an existing store, verify GetInfo,
    tear the server down, and hand back the underlying sqlite connection."""

    from agent_meta_runtime.adapters.cas import FilesystemCas
    from agent_meta_runtime.interfaces.local_api.connection import LocalConnection
    from agent_meta_runtime.interfaces.local_api.handlers import PublicApiHandlers
    from agent_meta_runtime.interfaces.local_api.server import LocalApiServer
    from agent_meta_runtime.interfaces.local_api.staging import ChunkedStaging
    from agent_meta_runtime.protocols._v1 import public_pb2 as pub

    def readiness():
        import types

        return types.SimpleNamespace(
            core_ready=True,
            serving_ready=True,
            core_reasons=[],
            serving_reasons=[],
        )

    conn = connect_store(db_path)
    cas = FilesystemCas(data_dir)
    staging = ChunkedStaging(cas, now_us=lambda: 1_000)
    handlers = PublicApiHandlers(
        conn,
        data_dir=data_dir,
        realm_id="realm://main",
        db_path=db_path,
        cas=cas,
        staging=staging,
        readiness=readiness,
        now_us=lambda: 1_000,
    )
    server = LocalApiServer(
        data_dir, handlers=handlers.handlers(), now_us=lambda: 1_000
    )
    socket_path = await server.start()
    client = LocalConnection(socket_path)
    await client.connect()
    try:
        info = await client.call(
            "agent_meta.public.v1.Runtime.GetInfo",
            pub.GetInfoRequest(),
            pub.RuntimeInfo,
        )
        assert info.core_ready is True
        assert info.serving_ready is True
    finally:
        await client.close()
        await server.close()
    return conn


def test_doc_proof_references_exist() -> None:
    """Every ``tests/...`` proof path cited in the release docs must exist."""

    import re

    for doc in (
        REPO_ROOT / "docs" / "runbook-v0.1.md",
        REPO_ROOT / "docs" / "feature-report-v0.1.md",
    ):
        text = doc.read_text(encoding="utf-8")
        for match in re.finditer(r"`(tests/[A-Za-z0-9_/.]+\.py)`", text):
            path = REPO_ROOT / match.group(1)
            assert path.is_file(), f"{doc.name} references missing proof: {match.group(1)}"


def test_release_e2e_offline_empty_dir(tmp_path: Path) -> None:
    data_dir = tmp_path / "primary"
    data_dir.mkdir()

    # 1. Independent init on an empty directory (CLI, offline, no daemon).
    rc = cli_main(["--data-dir", str(data_dir), "--output", "json", "init"])
    assert rc == 0, "CLI init failed on an empty data directory"
    assert (data_dir / "meta.db").is_file()

    # 2. Restart: real server over the existing store; GetInfo over the wire.
    conn = asyncio.run(_serve_and_probe(data_dir, data_dir / "meta.db"))

    # 3. Integrity doctor passes on the live store.
    report = run_integrity_doctor(
        data_dir / "meta.db", cas_root=data_dir / "artifacts"
    )
    assert report.ok, report.findings

    # 4. Sealed backup, restore into a second empty directory, upgrade
    #    preflight on the restored store.
    outcome = create_backup(conn, data_dir)
    backup_dir = Path(outcome.destination)
    assert backup_dir.is_dir()
    restore_backup(backup_dir, tmp_path / "restored")
    rconn = connect_store(tmp_path / "restored" / "meta.db")
    try:
        preflight_upgrade(rconn, tmp_path / "restored")
    finally:
        rconn.close()

    # 5. Task lifecycle, Conformance bootstrap and Harness install flows.
    task_result = task_lifecycle(tmp_path / "task")
    assert all(task_result.values()), task_result
    boot_result = conformance_bootstrap_offline(tmp_path / "boot")
    assert all(boot_result.values()), boot_result
    harness_result = harness_lifecycle(tmp_path / "harness")
    assert all(harness_result.values()), harness_result

    conn.close()

    # 6. Release gate: no Seed / Conformance-fixture module ever imported.
    _assert_no_seed_modules()
