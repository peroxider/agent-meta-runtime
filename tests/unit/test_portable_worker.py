"""Step 04 tests: worker identity, claims, minimal env, output caps,
process-tree cancellation (§41.48.1, §41.48.2, §41.48.3)."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time

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


def test_process_start_identity_rejects_exited_process_with_retained_parent_handle():
    with subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(.2)'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0) as process:
        assert worker.process_start_identity(process.pid)
        process.wait(timeout=5)
        assert worker.process_start_identity(process.pid) is None


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


@pytest.fixture()
def sleeper(tmp_path):
    job = None
    if os.name == 'nt':
        from agent_meta_runtime.adapters.owned_worker import OwnedWindowsJob
        job = OwnedWindowsJob(kind='portable')
        marker = tmp_path/'actual-pid'
        code = ('import os,sys,time; from pathlib import Path; '
            'from agent_meta_runtime.adapters.owned_worker import join_owner_job; '
            'join_owner_job(sys.argv[1]); Path(sys.argv[2]).write_text(str(os.getpid())); time.sleep(30)')
        args = [sys.executable, '-I', '-c', code, job.name, str(marker)]
    else:
        args = [sys.executable, '-I', '-c', 'import time;time.sleep(30)']
    child = subprocess.Popen(args, start_new_session=os.name!='nt',
        creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        pid = child.pid
        if job is not None:
            deadline = time.monotonic()+5
            while not marker.exists():
                assert child.poll() is None and time.monotonic()<deadline
                time.sleep(.02)
            pid = int(marker.read_text())
            assert job.contains(pid)
        yield child, pid, job
    finally:
        if job is not None:
            job.close()
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)


def test_cancellation_ladder_kills_process_group(tmp_path, fast_ladder, sleeper) -> None:
    child, pid, job = sleeper
    try:
        identity = worker.process_start_identity(pid)
        assert identity is not None
        confirmed, details = cancellation.cancel_process_tree(
            tmp_path, pid, identity, mode="GRACEFUL", reap=child.poll, windows_job=job
        )
        assert confirmed is True
        assert "control_cancel" in details["steps"]
        child.wait(timeout=5)
        assert child.poll() is not None
    finally:
        child.kill()


def test_cancellation_refuses_recycled_pid(tmp_path, fast_ladder, sleeper) -> None:
    child, pid, job = sleeper
    try:
        # Wrong start identity: the ladder must never signal this PID.
        confirmed, _ = cancellation.cancel_process_tree(
            tmp_path, pid, "999999999", mode="GRACEFUL", windows_job=job
        )
        # Identity mismatch is treated as "already gone" — but the real
        # process with a different identity must still be alive.
        assert worker.process_start_identity(pid) is not None
        assert child.poll() is None
        assert confirmed is (os.name != 'nt')  # Windows can still observe the owned tree alive.
    finally:
        child.kill()
        child.wait(timeout=5)


def test_force_mode_marks_details(tmp_path, fast_ladder, sleeper) -> None:
    child, pid, job = sleeper
    try:
        identity = worker.process_start_identity(pid)
        confirmed, details = cancellation.cancel_process_tree(
            tmp_path, pid, identity, mode="FORCE", reap=child.poll, windows_job=job
        )
        assert confirmed is True
        assert details["forced"] is True
        child.wait(timeout=5)
    finally:
        child.kill()


@pytest.mark.skipif(os.name != 'nt', reason='Windows retained Job tree API')
def test_windows_force_cancel_confirms_descendant_exit_after_leader_exits(tmp_path, fast_ladder):
    from agent_meta_runtime.adapters.owned_worker import OwnedWindowsJob, WorkerProcessLifetime
    marker = tmp_path/'tree-pids'
    code = ("import os,sys,time,json,subprocess; from pathlib import Path; "
        "from agent_meta_runtime.adapters.owned_worker import join_owner_job; "
        "join_owner_job(sys.argv[1]); "
        "child=subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(30)'],creationflags=subprocess.CREATE_NO_WINDOW); "
        "Path(sys.argv[2]).write_text(json.dumps([os.getpid(),child.pid])); "
        "stop=Path(sys.argv[3]); "
        "exec('while not stop.exists(): time.sleep(.01)'); os._exit(0)")
    with OwnedWindowsJob(kind='portable') as job:
        with subprocess.Popen([sys.executable,'-I','-c',code,job.name,str(marker),str(tmp_path/'control.cancel')],
                creationflags=subprocess.CREATE_NO_WINDOW, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as parent:
            deadline = time.monotonic()+5
            while not marker.exists():
                assert parent.poll() is None and time.monotonic()<deadline
                time.sleep(.02)
            pid, descendant = json.loads(marker.read_text())
            assert job.contains(pid) and job.contains(descendant)
            identity = worker.process_start_identity(pid)
            observed = WorkerProcessLifetime(descendant)
            try:
                confirmed, details = cancellation.cancel_process_tree(tmp_path,pid,identity,mode='FORCE',
                    reap=parent.poll,windows_job=job)
                # Observe the original process object through its retained
                # handle. Raw PID lookup after exit can name a reused PID or
                # race the final OS exit notification.
                assert confirmed and details['forced']
                assert job.active_processes == 0 and observed.wait(5)
            finally:
                observed.close()
            parent.wait(timeout=5)
