"""Restore must validate private staging before publishing any data directory."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import errno
import subprocess

import pytest

from agent_meta_runtime.adapters.store.backup import (
    BACKUP_MANIFEST_NAME,
    create_backup,
    restore_backup,
)
from agent_meta_runtime.adapters.store.backup_manifest import (
    portable_path,
    validate_manifest,
)
from agent_meta_runtime.adapters.store.doctor import run_integrity_doctor
from agent_meta_runtime.adapters.credentials import operator_signing_authority
from agent_meta_runtime.domain.ids import validate_id
from agent_meta_runtime.domain.canonical import canonical_json
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.interfaces.cli.init import run_init


@pytest.fixture
def snapshot(tmp_path):
    source = tmp_path / "source"
    run_init(source, insecure_dev_credential_file=os.name != "nt")
    connection = sqlite3.connect(source / "meta.db")
    try:
        outcome = create_backup(connection, source, tmp_path / "backup")
    finally:
        connection.close()
    return outcome.destination, outcome.manifest


def save(backup, manifest):
    (backup / BACKUP_MANIFEST_NAME).write_bytes(canonical_json(manifest))


def test_parent_escape_is_rejected_before_creating_target(snapshot, tmp_path):
    backup, manifest = snapshot
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"ordinary fixture sentinel")
    manifest["files"].append(
        {
            "relpath": "../outside.txt",
            "size_bytes": outside.stat().st_size,
            "sha256": hashlib.sha256(outside.read_bytes()).hexdigest(),
        }
    )
    save(backup, manifest)
    target = tmp_path / "restored"
    assert (backup / "../outside.txt").resolve() == outside.resolve()
    with pytest.raises(StableError) as rejected:
        restore_backup(backup, target)
    assert rejected.value.code == ErrorCode.INTEGRITY_ERROR
    assert not target.exists()
    assert outside.read_bytes() == b"ordinary fixture sentinel"


def test_duplicate_file_is_rejected_before_publishing_partial_store(snapshot, tmp_path):
    backup, manifest = snapshot
    manifest["files"].append(dict(manifest["files"][0]))
    save(backup, manifest)
    target = tmp_path / "restored"
    with pytest.raises(StableError) as rejected:
        restore_backup(backup, target)
    assert rejected.value.code == ErrorCode.INTEGRITY_ERROR
    assert not target.exists()


@pytest.mark.parametrize(
    "field",
    ["realm_id", "epoch_id", "meta_revision", "fact_boundary", "application_id"],
)
def test_manifest_claims_must_match_verified_store_before_publish(
    snapshot, tmp_path, field
):
    backup, manifest = snapshot
    manifest[field] = {
        "realm_id": "realm://other",
        "epoch_id": "epoch://01900000-0000-7000-8000-000000000001",
        "meta_revision": manifest["meta_revision"] + 1,
        "fact_boundary": {"last_seq": 0, "head_hash": "0" * 64},
        "application_id": 0,
    }[field]
    save(backup, manifest)
    target = tmp_path / "restored"
    with pytest.raises(StableError) as rejected:
        restore_backup(backup, target)
    assert rejected.value.code == ErrorCode.INTEGRITY_ERROR
    assert not target.exists()


def test_staged_bytes_are_verified_after_copy_before_publish(
    snapshot, tmp_path, monkeypatch
):
    backup, _ = snapshot
    copy = shutil.copy2

    def changed(source, target, *args, **kwargs):
        result = copy(source, target, *args, **kwargs)
        if Path(source) == backup / "meta.db":
            with Path(target).open("ab") as handle:
                handle.write(b"changed after source verification")
        return result

    monkeypatch.setattr(shutil, "copy2", changed)
    target = tmp_path / "restored"
    with pytest.raises(StableError) as rejected:
        restore_backup(backup, target)
    assert rejected.value.code == ErrorCode.INTEGRITY_ERROR
    assert not target.exists()


@pytest.mark.parametrize(
    "path",
    [
        "../outside",
        "/outside",
        "C:/outside",
        r"C:\outside",
        r"\\server\share\file",
        "keys/../outside",
        "keys/./item",
        "keys//item",
        "keys/item:stream",
        "keys/item.",
        "keys/item ",
        "keys/NUL.txt",
        "keys/CoM1",
        "keys/LPT9.key",
        "keys/COM¹.dat",
        "keys/lpt².key",
        "keys/item\x00name",
        "run/agent-meta.sock",
        "workspaces/heap",
        ".restore-staging/meta.db",
        "META.DB",
        "keys/\\outside",
    ],
)
def test_portable_manifest_paths_reject_escape_alias_devices_and_runtime_state(path):
    with pytest.raises(StableError) as rejected:
        portable_path(path)
    assert rejected.value.code == ErrorCode.INTEGRITY_ERROR


@pytest.mark.parametrize(
    "mode",
    [
        "case_alias",
        "file_parent",
        "missing_database",
        "missing_metadata",
        "boolean_size",
        "unknown_field",
    ],
)
def test_manifest_file_set_is_closed_and_unambiguous(snapshot, mode):
    _, manifest = snapshot
    if mode == "case_alias":
        entry = dict(
            next(
                item
                for item in manifest["files"]
                if item["relpath"].startswith("artifacts/")
            )
        )
        entry["relpath"] = entry["relpath"].upper().replace("ARTIFACTS/", "artifacts/")
        manifest["files"].append(entry)
    elif mode == "file_parent":
        entry = dict(
            next(
                item
                for item in manifest["files"]
                if item["relpath"].startswith("artifacts/")
            )
        )
        entry["relpath"] = entry["relpath"].rsplit("/", 1)[0]
        manifest["files"].append(entry)
    elif mode in ("missing_database", "missing_metadata"):
        remove = "meta.db" if mode == "missing_database" else "keys/store.json"
        manifest["files"] = [
            item for item in manifest["files"] if item["relpath"] != remove
        ]
    elif mode == "boolean_size":
        manifest["files"][0]["size_bytes"] = True
    else:
        manifest["files"][0]["extra"] = "not a v1 field"
    with pytest.raises(StableError):
        validate_manifest(manifest)


@pytest.mark.parametrize("role", ["root", "service"])
def test_removed_signing_key_cannot_be_hidden_by_removing_manifest_entry(
    snapshot, tmp_path, role
):
    backup, manifest = snapshot
    config = json.loads((backup / "keys/store.json").read_bytes())
    handle = config["handles"][role]
    suffix = ".dpapi" if "windows-dpapi/" in handle else ".key"
    key = "keys/" + handle.rsplit("/", 1)[1] + suffix
    manifest["files"] = [item for item in manifest["files"] if item["relpath"] != key]
    save(backup, manifest)
    target = tmp_path / "restored"
    with pytest.raises(StableError) as rejected:
        restore_backup(backup, target, allow_insecure_credentials=os.name != "nt")
    assert rejected.value.code == ErrorCode.KEY_UNAVAILABLE
    assert not target.exists()


@pytest.mark.parametrize("kind", ["database", "artifact"])
def test_self_consistent_file_hashes_cannot_hide_invalid_store_content(
    snapshot, tmp_path, kind
):
    backup, manifest = snapshot
    entry = (
        next(item for item in manifest["files"] if item["relpath"] == "meta.db")
        if kind == "database"
        else next(
            item
            for item in manifest["files"]
            if item["relpath"].startswith("artifacts/")
        )
    )
    path = backup / entry["relpath"]
    path.unlink()  # break the CAS hardlink before altering this fixture backup
    path.write_bytes(b"not the committed store or Artifact")
    entry.update(
        size_bytes=path.stat().st_size,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
    )
    save(backup, manifest)
    target = tmp_path / "restored"
    with pytest.raises(StableError) as rejected:
        restore_backup(backup, target, allow_insecure_credentials=os.name != "nt")
    assert rejected.value.code == ErrorCode.INTEGRITY_ERROR
    assert not target.exists()


@pytest.mark.parametrize("existing", [False, True])
def test_publish_failure_leaves_no_partial_store_and_preserves_empty_target(
    snapshot, tmp_path, monkeypatch, existing
):
    backup, _ = snapshot
    target = tmp_path / "restored"
    if existing:
        target.mkdir()

    def unavailable(*args, **kwargs):
        raise OSError(errno.EIO, "fixture publication unavailable")

    monkeypatch.setattr(os, "rename", unavailable)
    with pytest.raises(StableError) as rejected:
        restore_backup(backup, target, allow_insecure_credentials=os.name != "nt")
    assert rejected.value.code == ErrorCode.BACKEND_UNAVAILABLE
    assert target.exists() == existing
    assert not existing or list(target.iterdir()) == []
    assert not list(tmp_path.glob(".restored.restore-*"))


@pytest.mark.parametrize("position", ["root", "file"])
def test_backup_links_or_windows_junctions_are_rejected_before_publish(
    snapshot, tmp_path, position
):
    backup, manifest = snapshot
    link = tmp_path / "linked-backup"
    if os.name == "nt":
        # Junction creation needs no Developer Mode or symbolic-link privilege.
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(backup)],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
            check=False,
        )
        assert result.returncode == 0, result.stderr.decode(errors="replace")
    else:
        link.symlink_to(backup, target_is_directory=True)
    source = link
    if position == "file":
        # A manifest-file junction/symlink component is rejected as well.
        for entry in manifest["files"]:
            if entry["relpath"].startswith("artifacts/"):
                entry["relpath"] = "artifacts/linked/" + entry["relpath"].removeprefix(
                    "artifacts/"
                )
        artifact_link = backup / "artifacts/linked"
        if os.name == "nt":
            result = subprocess.run(
                [
                    "cmd",
                    "/c",
                    "mklink",
                    "/J",
                    str(artifact_link),
                    str(backup / "artifacts"),
                ],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                check=False,
            )
            assert result.returncode == 0
        else:
            artifact_link.symlink_to(backup / "artifacts", target_is_directory=True)
        save(backup, manifest)
        source = backup
    target = tmp_path / "restored"
    with pytest.raises(StableError) as rejected:
        restore_backup(source, target, allow_insecure_credentials=os.name != "nt")
    assert rejected.value.code == ErrorCode.INTEGRITY_ERROR
    assert not target.exists()


def test_successful_restore_preserves_signing_identity_and_valid_fact_chain(
    snapshot, tmp_path
):
    backup, manifest = snapshot
    target = tmp_path / "restored"
    target.mkdir()
    result = restore_backup(backup, target, allow_insecure_credentials=os.name != "nt")
    assert (
        result["realm_id"] == manifest["realm_id"]
        and result["epoch_id"] == manifest["epoch_id"]
    )
    assert result["meta_revision"] == manifest["meta_revision"]
    assert run_integrity_doctor(target / "meta.db", cas_root=target).ok
    before, _ = operator_signing_authority(backup, allow_insecure=os.name != "nt")
    after, sign = operator_signing_authority(target, allow_insecure=os.name != "nt")
    assert before == after and len(sign(b"restore-boundary-proof")) == 64
    connection = sqlite3.connect(target / "meta.db")
    try:
        fact = connection.execute(
            "SELECT transaction_id,payload_json FROM facts WHERE fact_id=?",
            (result["fact_id"],),
        ).fetchone()
        assert validate_id(fact[0]).startswith("transaction://")
        assert (
            json.loads(fact[1])["manifest_sha256"]
            == hashlib.sha256((backup / BACKUP_MANIFEST_NAME).read_bytes()).hexdigest()
        )
    finally:
        connection.close()
