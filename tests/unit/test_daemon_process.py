"""Published console entry point in independent OS processes (real IPC)."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time


_ENTRY = "import importlib.metadata as m; import sys; e=next(e for e in m.distribution('agent-meta-runtime').entry_points if e.group=='console_scripts' and e.name=='agent-meta'); sys.exit(e.load()())"


def command(data_dir, *args):
    flags = ["--insecure-dev-credential-file"] if os.name != "nt" else []
    return [sys.executable, "-I", "-u", "-c", _ENTRY, "--data-dir", str(data_dir), "--output", "json", *flags, *args]


def run(data_dir, *args):
    return subprocess.run(command(data_dir, *args), capture_output=True, text=True, timeout=15)


def wait_started(process, output, errors):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"daemon exited {process.returncode}: {errors.read_text()}")
        for line in output.read_text().splitlines():
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if message.get("ok") and message.get("result", {}).get("state") == "RUNNING":
                return message["result"]
        time.sleep(.025)
    raise AssertionError("daemon did not become reachable")


def test_console_start_duplicate_owner_stop_and_abrupt_restart(tmp_path):
    data_dir = tmp_path / "data"
    initialized = run(data_dir, "init")
    assert initialized.returncode == 0
    output, errors = tmp_path / "stdout.jsonl", tmp_path / "stderr.txt"
    instances = []
    for attempt in range(2):
        with output.open("w", encoding="utf-8") as stdout, errors.open("w", encoding="utf-8") as stderr:
            process = subprocess.Popen(command(data_dir, "start"), stdout=stdout, stderr=stderr,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            try:
                started = wait_started(process, output, errors)
                instances.append(started["instance_id"])
                assert started["core_ready"] and not started["serving_ready"]
                duplicate = run(data_dir, "start")
                assert duplicate.returncode == 12
                assert json.loads(duplicate.stdout)["error"]["code"] == "ALREADY_RUNNING"
                assert run(data_dir, "init").returncode == 12
                info = run(data_dir, "info")
                assert info.returncode == 0 and json.loads(info.stdout)["result"]["core_ready"]
                if attempt == 0:
                    process.kill()
                    process.wait(timeout=10)
                else:
                    stopped = run(data_dir, "stop")
                    assert stopped.returncode == 0, stopped.stderr
                    assert json.loads(stopped.stdout)["result"]["instance_id"] == started["instance_id"]
                    assert process.wait(timeout=10) == 0
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
    assert len(set(instances)) == 2
    assert run(data_dir, "info").returncode != 0


def test_start_requires_complete_bootstrap_and_rejects_invalid_configuration(tmp_path):
    absent = run(tmp_path / "absent", "start")
    assert absent.returncode == 3
    data_dir = tmp_path / "data"
    assert run(data_dir, "init").returncode == 0
    config = tmp_path / "bad.toml"
    config.write_text("[shutdown]\ngrace_s = -1\n")
    bad = run(data_dir, "start", "--config", str(config))
    assert bad.returncode == 2
    # Failed startup has released the writer lock; re-init remains available.
    assert run(data_dir, "init").returncode == 0
