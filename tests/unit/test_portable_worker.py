"""Step 04 tests: worker identity, claims, minimal env, output caps,
process-tree cancellation (§41.48.1, §41.48.2, §41.48.3)."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess

import pytest

from agent_meta_runtime.adapters.execution_portable import cancellation, environment, worker
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.protocols.backend_wire import payload_hash


def test_process_start_identity_detects_pid() -> None:
    identity = worker.process_start_identity(os.getpid())
    assert identity and identity.isdigit()
    assert worker.process_start_identity(10**9) is None


def test_worker_identity_triple() -> None:
    nonce = worker.new_launch_nonce()
    identity = worker.worker_identity(os.getpid(), nonce)
    assert identity["pid"] == os.getpid()
    assert identity["nonce_hash"] == worker.nonce_hash(nonce)
    assert len(nonce) == 16


def test_request_directory_requires_uuid(tmp_path) -> None:
    with pytest.raises(StableError) as exc:
        worker.request_directory(tmp_path, "../../etc")
    assert exc.value.code == ErrorCode.INVALID_ARGUMENT
    rid = "01900000-0000-7000-8000-00000000000f"
    assert worker.request_directory(tmp_path, rid) == tmp_path / "backend" / "workloads" / rid


def test_claim_create_new_semantics(tmp_path) -> None:
    identity = {"pid": 1, "start_identity": "x", "nonce_hash": "h"}
    assert worker.create_claim(tmp_path, identity) is True
    assert worker.create_claim(tmp_path, identity) is False  # O_EXCL loses
    assert worker.read_claim(tmp_path) == identity


def test_run_worker_full_flow(tmp_path) -> None:
    payload = {"operation_kind": "test.echo", "hello": "world"}
    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    worker.write_request_file(tmp_path, payload_bytes)
    (tmp_path / "launch_nonce").write_bytes(worker.new_launch_nonce())

    def handler(loaded):
        assert loaded == payload
        return "SUCCEEDED", b"{}", b'{"echo":true}'

    result = worker.run_worker(
        tmp_path, expected_payload_hash=payload_hash(payload_bytes), handler=handler
    )
    assert result["status"] == "SUCCEEDED"
    assert (tmp_path / worker.STARTED_FILE).exists()
    assert worker.read_result(tmp_path)["status"] == "SUCCEEDED"


def test_run_worker_claim_taken(tmp_path) -> None:
    payload_bytes = b"{}"
    worker.write_request_file(tmp_path, payload_bytes)
    (tmp_path / "launch_nonce").write_bytes(worker.new_launch_nonce())
    worker.create_claim(tmp_path, {"pid": 1, "start_identity": "x", "nonce_hash": "h"})
    with pytest.raises(worker.ClaimTakenError):
        worker.run_worker(
            tmp_path,
            expected_payload_hash=payload_hash(payload_bytes),
            handler=lambda p: ("SUCCEEDED", b"{}", b"{}"),
        )


def test_request_payload_integrity(tmp_path) -> None:
    worker.write_request_file(tmp_path, b'{"a":1}')
    with pytest.raises(StableError) as exc:
        worker.read_request_payload(tmp_path, "0" * 64)
    assert exc.value.code == ErrorCode.INTEGRITY_ERROR
    loaded = worker.read_request_payload(tmp_path, payload_hash(b'{"a":1}'))
    assert loaded == {"a": 1}


def test_launch_nonce_validation(tmp_path) -> None:
    with pytest.raises(StableError) as exc:
        worker.load_launch_nonce(tmp_path)
    assert exc.value.code == ErrorCode.FAILED_PRECONDITION
    (tmp_path / "launch_nonce").write_bytes(b"short")
    with pytest.raises(StableError) as exc2:
        worker.load_launch_nonce(tmp_path)
    assert exc2.value.code == ErrorCode.INTEGRITY_ERROR


def test_build_worker_env_minimal_and_allowlist_guard() -> None:
    env = environment.build_worker_env(
        runtime_paths=["/opt/runtime/bin"],
        request_id="req-1",
        workspace_relpath="workloads/req-1",
        allowlist={"MY_TOOL_TOKEN": "t"},
    )
    assert env["PATH"] == "/opt/runtime/bin"
    assert env["AGENT_META_REQUEST_ID"] == "req-1"
    assert "HOME" not in env
    with pytest.raises(StableError):
        environment.build_worker_env(
            runtime_paths=[], request_id="r", workspace_relpath="w",
            allowlist={"HOME": "/evil"},
        )
    with pytest.raises(StableError):
        environment.build_worker_env(
            runtime_paths=[], request_id="r", workspace_relpath="w",
            allowlist={"AWS_SECRET_ACCESS_KEY": "leak"},
        )
    with pytest.raises(StableError):
        environment.build_worker_env(
            runtime_paths=[], request_id="r", workspace_relpath="w",
            allowlist={"HTTP_PROXY": "http://evil"},
        )


def test_output_capture_head_tail_retention() -> None:
    cap = environment.OutputCapture()
    cap.feed(b"x" * 1024)  # small
    assert cap.snapshot() == {"size_bytes": 1024, "output_truncated": False, "dropped_bytes": 0}
    big = environment.OutputCapture()
    big.feed(b"a" * (9 * 1024 * 1024))
    snap = big.snapshot()
    assert snap["output_truncated"] is True
    assert snap["size_bytes"] <= 8 * 1024 * 1024
    assert snap["dropped_bytes"] > 0


def test_workspace_quota_check(tmp_path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "blob").write_bytes(b"z" * 1000)
    usage = environment.check_quota(workspace, 2000)
    assert usage == 1000
    with pytest.raises(StableError) as exc:
        environment.check_quota(workspace, 500)
    assert exc.value.code == ErrorCode.RESOURCE_EXHAUSTED
    with pytest.raises(StableError):
        environment.check_quota(workspace, 1000, additional=1)


@pytest.fixture()
def fast_ladder(monkeypatch):
    monkeypatch.setattr(cancellation, "GRACEFUL_WAIT_S", 0.1)
    monkeypatch.setattr(cancellation, "TERM_WAIT_S", 0.1)


def _spawn_sleeper():
    return subprocess.Popen(
        ["sleep", "30"], start_new_session=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def test_cancellation_ladder_kills_process_group(tmp_path, fast_ladder) -> None:
    child = _spawn_sleeper()
    try:
        identity = worker.process_start_identity(child.pid)
        assert identity is not None
        confirmed, details = cancellation.cancel_process_tree(
            tmp_path, child.pid, identity, mode="GRACEFUL", reap=child.poll
        )
        assert confirmed is True
        assert "control_cancel" in details["steps"]
        child.wait(timeout=5)
        assert child.poll() is not None
    finally:
        child.kill()


def test_cancellation_refuses_recycled_pid(tmp_path, fast_ladder) -> None:
    child = _spawn_sleeper()
    try:
        # Wrong start identity: the ladder must never signal this PID.
        confirmed, _ = cancellation.cancel_process_tree(
            tmp_path, child.pid, "999999999", mode="GRACEFUL"
        )
        # Identity mismatch is treated as "already gone" — but the real
        # process with a different identity must still be alive.
        assert worker.process_start_identity(child.pid) is not None
        assert child.poll() is None
        assert confirmed is True  # observed "exit" of the mismatched identity
    finally:
        child.kill()
        child.wait(timeout=5)


def test_force_mode_marks_details(tmp_path, fast_ladder) -> None:
    child = _spawn_sleeper()
    try:
        identity = worker.process_start_identity(child.pid)
        confirmed, details = cancellation.cancel_process_tree(
            tmp_path, child.pid, identity, mode="FORCE", reap=child.poll
        )
        assert confirmed is True
        assert details["forced"] is True
        child.wait(timeout=5)
    finally:
        child.kill()
