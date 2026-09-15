"""Step 07 gate: core bootstrap init (§41.57.1)."""

from __future__ import annotations

import json
import stat

import pytest

from agent_meta_runtime.adapters.store.bootstrap import builtin_artifact_documents
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.interfaces.cli.init import REALM_ID, run_init
from agent_meta_runtime.interfaces.cli.main import main
from agent_meta_runtime.adapters.store.doctor import run_integrity_doctor


def test_fresh_init_creates_complete_bootstrap(tmp_path):
    report = run_init(tmp_path)
    assert report.realm_id == REALM_ID
    assert report.core_ready and not report.serving_ready
    assert report.recovery_code  # shown exactly once on fresh init
    assert not report.reinitialized
    assert len(report.builtin_artifacts) == len(builtin_artifact_documents(REALM_ID))

    # keys are 0600, data dir 0700
    assert stat.S_IMODE((tmp_path / "keys" / "root.key").stat().st_mode) == 0o600
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700

    import sqlite3

    conn = sqlite3.connect(tmp_path / "meta.db")
    try:
        assert conn.execute("SELECT COUNT(*) FROM realms").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM epochs").fetchone()[0] == 1
        kinds = dict(
            conn.execute(
                "SELECT kind, COUNT(*) FROM principals GROUP BY kind"
            ).fetchall()
        )
        assert kinds == {"OPERATOR_ROOT": 1, "SERVICE": 1}
        grants = conn.execute(
            "SELECT COUNT(*) FROM authority_grants WHERE status = 'ACTIVE'"
        ).fetchone()[0]
        assert grants == 2  # Root Grant + Service Grant
        refs = conn.execute(
            "SELECT desired_revision, serving_revision, realized_revision,"
            " reconcile_status FROM composition_refs"
        ).fetchone()
        assert refs == (0, 0, 0, "READY")  # revision 0 sentinel, no pseudo row
        assert conn.execute("SELECT COUNT(*) FROM compositions").fetchone()[0] == 0
        events = {
            row[0]
            for row in conn.execute(
                "SELECT DISTINCT event_type FROM facts"
            ).fetchall()
        }
        assert "runtime_initialized" in events
        assert "readiness_changed" in events
        assert conn.execute(
            "SELECT COUNT(*) FROM artifacts"
            " WHERE CAST(manifest_json AS TEXT) LIKE '%builtin%'"
        ).fetchone()[0] == len(report.builtin_artifacts)
    finally:
        conn.close()

    doctor = run_integrity_doctor(tmp_path / "meta.db", cas_root=tmp_path)
    assert doctor.ok, doctor.notes


def test_reinit_returns_existing_realm_without_new_secret(tmp_path):
    first = run_init(tmp_path)
    second = run_init(tmp_path)
    assert second.reinitialized
    assert second.realm_id == first.realm_id == REALM_ID
    assert second.epoch_id == first.epoch_id
    assert second.recovery_code is None  # never shown twice


def test_init_rejects_nonempty_dir_without_db(tmp_path):
    (tmp_path / "stray.txt").write_text("not a runtime dir")
    with pytest.raises(StableError) as excinfo:
        run_init(tmp_path)
    assert excinfo.value.code == ErrorCode.FAILED_PRECONDITION


def test_cli_init_envelope_prints_recovery_code_once(tmp_path, capsys):
    code = main(["--data-dir", str(tmp_path), "--output", "json", "init"])
    assert code == 0
    envelope = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert envelope["ok"] is True
    assert envelope["result"]["core_ready"] is True
    assert envelope["result"]["serving_ready"] is False
    assert envelope["result"]["recovery_code"]

    code = main(["--data-dir", str(tmp_path), "--output", "json", "init"])
    assert code == 0
    envelope2 = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert envelope2["result"]["reinitialized"] is True
    assert "recovery_code" not in envelope2["result"]


def test_builtin_documents_are_stable_canonical_sets():
    docs = builtin_artifact_documents(REALM_ID)
    names = [name for name, *_rest in docs]
    assert names == [
        "constitution",
        "schema_registry",
        "permission_registry",
        "redaction_policy",
        "retention_policy",
        "retry_policy",
        "budget_policy",
        "harness_contract",
    ]
    permission_doc = dict(docs[2][3])
    assert "task.submit" in permission_doc["permissions"]
    assert "harness.activate" in permission_doc["permissions"]
