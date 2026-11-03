"""Step 01 gate: CAS integrity (§41.7) and tamper-detecting doctor (AC-M52)."""

from __future__ import annotations

import shutil
import sqlite3
import json
import os
from pathlib import Path

import pytest

from agent_meta_runtime.adapters.cas import FilesystemCas
from agent_meta_runtime.adapters.store.doctor import run_integrity_doctor
from agent_meta_runtime.adapters.store.uow import execute_command
from agent_meta_runtime.domain.canonical import sha256_hex
from agent_meta_runtime.domain.deadline import Deadline
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.ports.repositories import FactAppendRequest
from agent_meta_runtime.interfaces.cli.init import run_init
from tests.unit.test_store_uow import ACTOR, _envelope, _mutator

DEADLINE = Deadline.after(5_000_000)

# A forged 64-char lowercase hash literal for tamper statements.
FORGED_HASH = "'q' || substr(hex(zeroblob(32)), 2)"


# ------------------------------------------------------------------- CAS ---
def test_put_and_open_round_trip(tmp_path) -> None:
    cas = FilesystemCas(tmp_path)
    data = b"print(1)\n" * 100
    digest = sha256_hex(data)
    relpath = cas.put(data)
    assert relpath == f"sha256/{digest[:2]}/{digest[2:4]}/{digest}"
    assert cas.open_blob(relpath, digest, len(data)) == data


def test_staging_preserves_every_binary_byte_and_completes_short_writes(tmp_path, monkeypatch):
    import os

    cas = FilesystemCas(tmp_path)
    data = bytes(range(256)) * 17
    write = os.write

    def short_write(fd, chunk):
        return write(fd, chunk[:19])

    monkeypatch.setattr(os, "write", short_write)
    path = cas.put(data)
    assert cas.open_blob(path, sha256_hex(data), len(data)) == data


def test_put_with_wrong_expected_hash_fails(tmp_path) -> None:
    cas = FilesystemCas(tmp_path)
    with pytest.raises(StableError) as exc:
        cas.put(b"data", expected_sha256="f" * 64)
    assert exc.value.code == ErrorCode.INTEGRITY_ERROR
    assert not list((tmp_path / "staging").iterdir())  # staging cleaned up


def test_put_reuses_existing_verified_content(tmp_path) -> None:
    cas = FilesystemCas(tmp_path)
    data = b"same content"
    assert cas.put(data) == cas.put(data)


def test_existing_content_mismatch_detected(tmp_path) -> None:
    cas = FilesystemCas(tmp_path)
    data = b"original"
    relpath = cas.put(data)
    (cas.artifacts_dir / relpath).write_bytes(b"tampered!")
    forged = type(
        "S",
        (),
        dict(
            staging_path=Path("/nonexistent"),
            sha256=sha256_hex(data),
            size_bytes=len(data),
        ),
    )()
    with pytest.raises(StableError) as exc:
        cas.publish(forged)
    assert exc.value.code == ErrorCode.INTEGRITY_ERROR


def test_open_blob_detects_corruption(tmp_path) -> None:
    cas = FilesystemCas(tmp_path)
    data = b"payload-bytes"
    relpath = cas.put(data)
    (cas.artifacts_dir / relpath).write_bytes(b"payload-nybbles")
    with pytest.raises(StableError) as exc:
        cas.open_blob(relpath, sha256_hex(data), len(data))
    assert exc.value.code == ErrorCode.INTEGRITY_ERROR
    with pytest.raises(StableError) as missing:
        cas.open_blob("sha256/ff/ff/" + "f" * 64, "f" * 64, 1)
    assert missing.value.code == ErrorCode.NOT_FOUND


def test_rejects_traversal_and_symlink(tmp_path) -> None:
    import os
    import subprocess

    cas = FilesystemCas(tmp_path)
    for bad in ("../escape", "a/../../b", "/abs/path", "a\\..\\b", "file:stream", "a//b"):
        with pytest.raises(StableError):
            cas.absolute_path(bad)
    real = cas.put(b"real")
    link = cas.artifacts_dir / "sha256" / "li" / "nk"
    link.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        # File symlinks require a Windows privilege that CI users may lack.
        # An actual directory junction exercises the same reparse-point denial
        # without skipping the required path-boundary proof.
        environment = dict(os.environ, AMR_TEST_LINK_PATH=str(link), AMR_TEST_TARGET_PATH=str((cas.artifacts_dir / real).parent))
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "New-Item -ItemType Junction -Path $env:AMR_TEST_LINK_PATH -Target $env:AMR_TEST_TARGET_PATH -ErrorAction Stop | Out-Null"], env=environment, capture_output=True, text=True, errors="replace", timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode == 0, result.stderr
        assert link.is_junction()
    else:
        link.symlink_to(cas.artifacts_dir / real)
    with pytest.raises(StableError) as exc:
        cas.absolute_path("sha256/li/nk")
    assert exc.value.code == ErrorCode.INTEGRITY_ERROR


def test_cas_publish_before_db_commit_leaves_only_orphan(tmp_path) -> None:
    """Crash after CAS publish but before DB commit leaves an orphan file —
    never a committed row pointing at missing bytes (AC-M14 direction)."""

    cas = FilesystemCas(tmp_path)
    staged = cas.stage(b"ordered-write")
    relpath = cas.publish(staged)
    assert (cas.artifacts_dir / relpath).is_file()
    # No DB row exists at all, so no committed row references missing bytes.


# ---------------------------------------------------------------- doctor ---
def _add_two_facts(store) -> None:
    conn, _realm, _ = store
    execute_command(conn, _envelope(), _mutator(), deadline=DEADLINE)
    execute_command(
        conn,
        _envelope(payload={"n": 2}),
        _mutator(payload={"ok": False}),
        deadline=DEADLINE,
    )


@pytest.fixture()
def healthy_store(store):
    _add_two_facts(store)
    return store


def test_healthy_store_passes_doctor(healthy_store) -> None:
    conn, _realm, tmp_path = healthy_store
    report = run_integrity_doctor(tmp_path / "meta.db")
    assert report.ok, report.findings
    assert report.facts_checked == 2 and report.realms_checked == 1


def _tamper(store, statements) -> Path:
    conn, _realm, tmp_path = store
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    copy_path = tmp_path / "tampered.db"
    shutil.copy(tmp_path / "meta.db", copy_path)
    raw = sqlite3.connect(copy_path)
    raw.execute("PRAGMA foreign_keys = OFF")
    for trigger in ("facts_no_update", "facts_no_delete"):
        raw.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    for statement in statements:
        raw.execute(statement)
    raw.commit()
    raw.close()
    return copy_path


@pytest.mark.parametrize(
    "statements,label",
    [
        ([f"UPDATE facts SET payload_json = zeroblob(32) WHERE seq = 1"], "payload"),
        ([f"UPDATE facts SET actor_id = {FORGED_HASH} WHERE seq = 1"], "actor"),
        (["UPDATE facts SET seq = 99 WHERE seq = 1"], "seq"),
        ([f"UPDATE facts SET prev_fact_hash = {FORGED_HASH} WHERE seq = 2"], "prev"),
        ([f"UPDATE facts SET fact_hash = {FORGED_HASH} WHERE seq = 1"], "hash"),
        (["DELETE FROM facts WHERE seq = 1"], "deleted"),
        (
            [
                "UPDATE facts SET fact_hash = 'x' || substr(fact_hash, 2) WHERE seq = 1",
                "UPDATE facts SET fact_hash = 'y' || substr(fact_hash, 2) WHERE seq = 2",
            ],
            "swapped",
        ),
        (["UPDATE realms SET fact_head_hash = CASE substr(fact_head_hash, 1, 1) WHEN 'f' THEN 'e' ELSE 'f' END || substr(fact_head_hash, 2)"], "head"),
    ],
)
def test_tampered_fact_detected(healthy_store, statements, label) -> None:
    copy_path = _tamper(healthy_store, statements)
    report = run_integrity_doctor(copy_path)
    assert not report.ok, label
    assert all(f["code"] == "INTEGRITY_ERROR" for f in report.findings), label


def test_correction_append_keeps_old_hash_and_validates(healthy_store) -> None:
    conn, realm, tmp_path = healthy_store
    before = conn.execute("SELECT fact_hash FROM facts WHERE seq = 1").fetchone()[0]
    head_before = conn.execute(
        "SELECT fact_head_hash FROM realms WHERE realm_id = ?", (realm,)
    ).fetchone()[0]

    result = execute_command(
        conn,
        _envelope(payload={"correction": True}),
        lambda tx: {
            "fact_id": tx.append_fact(
                FactAppendRequest(
                    entity_type="runtime",
                    entity_id="realm://main",
                    event_type="runtime_initialized",
                    schema_version=1,
                    payload={"corrects": before},
                    occurred_at_us=2,
                    actor_id=ACTOR,
                )
            )
        },
        deadline=DEADLINE,
    )
    assert result.first_seq == 3
    assert (
        before
        == conn.execute("SELECT fact_hash FROM facts WHERE seq = 1").fetchone()[0]
    )
    head_after = conn.execute(
        "SELECT fact_head_hash FROM realms WHERE realm_id = ?", (realm,)
    ).fetchone()[0]
    assert head_after != head_before
    assert run_integrity_doctor(tmp_path / "meta.db").ok


def test_doctor_reports_missing_cas_blob(healthy_store) -> None:
    conn, _realm, tmp_path = healthy_store
    content = b"restricted-bytes"
    conn.execute(
        "INSERT INTO artifacts(artifact_id, kind, media_type, size_bytes,"
        " schema_version, created_by, created_at_us, parents_json, manifest_json,"
        " integrity_status) VALUES (?, 'raw', 'application/octet-stream', ?, 1,"
        " ?, 1, ?, ?, 'VALID')",
        (
            "artifact://sha256/" + "c" * 64,
            len(content),
            ACTOR,
            b"[]",
            b"{}",
        ),
    )
    conn.execute(
        "INSERT INTO artifact_blobs(blob_id, artifact_id, realm_id, storage_class,"
        " size_bytes, storage_relpath, status, created_at_us, deleted_at_us)"
        " VALUES (?, 'artifact://sha256/"
        + "c" * 64
        + "', ?, 'PLAIN_CAS', ?,"
        " 'sha256/cc/cc/"
        + "c" * 64
        + "', 'ACTIVE', 1, NULL)",
        ("blob://sha256/" + "c" * 64, "realm://main", len(content)),
    )
    conn.commit()
    # Blob row committed but bytes never published -> doctor must flag it.
    report = run_integrity_doctor(tmp_path / "meta.db", cas_root=tmp_path)
    assert not report.ok
    assert any("CAS blob" in f["detail"] for f in report.findings)


@pytest.mark.parametrize('mode',['missing','corrupt','metadata'])
def test_doctor_verifies_bootstrap_artifacts_without_blob_rows(tmp_path,mode):
    run_init(tmp_path,insecure_dev_credential_file=os.name!='nt')
    connection=sqlite3.connect(tmp_path/'meta.db')
    try:
        artifact,raw=connection.execute('SELECT artifact_id,manifest_json FROM artifacts ORDER BY artifact_id LIMIT 1').fetchone()
        assert connection.execute('SELECT COUNT(*) FROM artifact_blobs WHERE artifact_id=?',(artifact,)).fetchone()[0]==0
        path=tmp_path/'artifacts'/json.loads(raw)['storage_relpath']
        if mode=='metadata':
            original=artifact
            artifact='artifact://sha256/'+sha256_hex(b'doctor malformed storage fixture')
            connection.execute('INSERT INTO artifacts SELECT ?,kind,media_type,size_bytes,schema_version,created_by,created_at_us,parents_json,?,integrity_status FROM artifacts WHERE artifact_id=?',
                (artifact,b'{}',original))
            connection.commit()
        elif mode=='missing':
            path.unlink()
        else:
            path.write_bytes(b'corrupted bootstrap Artifact')
    finally:
        connection.close()
    report=run_integrity_doctor(tmp_path/'meta.db',cas_root=tmp_path)
    assert not report.ok
    assert any(finding.get('artifact_id')==artifact and finding['detail']=='CAS inline Artifact verification failed'
        for finding in report.findings)
