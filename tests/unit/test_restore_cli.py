"""Native offline recovery console; no daemon/private material in responses."""

import json
import os
import sqlite3
import subprocess
import sys

import pytest

from agent_meta_runtime.adapters.store.backup import create_backup
from agent_meta_runtime.interfaces.cli.init import run_init


@pytest.mark.parametrize("mode", ["success", "occupied", "manifest", "key"])
def test_native_restore_console_uses_sealed_backup_and_stable_fail_closed_output(
    tmp_path, mode
):
    source = tmp_path / "source"
    run_init(source, insecure_dev_credential_file=os.name != "nt")
    connection = sqlite3.connect(source / "meta.db")
    try:
        outcome = create_backup(connection, source, tmp_path / "backup")
    finally:
        connection.close()
    target = tmp_path / "restored"
    if mode == "occupied":
        target.mkdir()
        (target / "sentinel").write_text("keep", encoding="utf-8")
    elif mode == "manifest":
        (outcome.destination / "backup-manifest.json").write_text(
            "{}", encoding="utf-8"
        )
    elif mode == "key":
        metadata = json.loads((outcome.destination / "keys/store.json").read_bytes())
        reference = metadata["handles"]["root"].rsplit("/", 1)[1]
        entry = next(
            item for item in outcome.manifest["files"] if reference in item["relpath"]
        )
        (outcome.destination / entry["relpath"]).unlink()
    flags = ["--insecure-dev-credential-file"] if os.name != "nt" else []
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "agent_meta_runtime.interfaces.cli.restore",
            "--source",
            str(outcome.destination),
            "--data-dir",
            str(target),
            *flags,
        ],
        capture_output=True,
        timeout=20,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    report = json.loads(result.stdout)
    assert report["schema"] == "runtime-restore/v1" and not result.stderr
    if mode == "success":
        assert result.returncode == 0 and report["ok"]
        assert report["result"]["realm_id"] == outcome.manifest["realm_id"]
        assert run_init(
            target, insecure_dev_credential_file=os.name != "nt"
        ).reinitialized
    elif mode == "occupied":
        assert (
            result.returncode == 6 and report["error"]["code"] == "FAILED_PRECONDITION"
        )
        assert (target / "sentinel").read_text() == "keep"
    else:
        assert result.returncode == 8 and report["error"]["code"] == "INTEGRITY_ERROR"
        assert not target.exists()
    assert all(
        word not in report.get("result", {})
        for word in ("secret", "root_key", "service_key", "handles")
    )
