"""Step 06 gate: SDK facade and CLI behavior (§41.52)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os

import pytest

from agent_meta_runtime.domain.errors import ErrorCode
from agent_meta_runtime.interfaces.cli import build_parser, main
from agent_meta_runtime.sdk import AgentMetaClient
from test_local_server import LocalEnv, run_env


class SdkTransport:
    def __init__(self, connection) -> None:
        self._connection = connection

    async def call(self, method, request, *, deadline_us=None):
        return await self._connection.call_raw(method, request, deadline_us=deadline_us)

    async def close(self):
        await self._connection.close()


def test_sdk_get_info_and_task_submit(tmp_path):
    async def test(env):
        client = AgentMetaClient(SdkTransport(env.client), authority=env.authority)
        try:
            info = await client.get_info()
            assert info.core_ready and info.serving_ready
            handle = await client.submit_task(
                realm_id=env.realm,
                actor_id="principal://operator-root/01900000-0000-7000-8000-000000000000",
                input_artifact_id=env.input_artifact,
                budget={"max_turns": 3},
            )
            assert handle.status == "ACCEPTED" and handle.task_id
            execution = await client.get_task_execution(handle.task_id)
            assert execution["status"] == "ACCEPTED" and execution["invocations"] == execution["projections"] == []
            view = await client.get_view()
            assert view["realm_id"] == env.realm
            refs = await client.get_refs()
            assert refs["serving_revision"] == 1
            result = await client.why(handle.task_id)
            assert "root_id" in result
        finally:
            await client.aclose()

    run_env(test, tmp_path)


def test_sdk_artifact_upload_via_two_phase(tmp_path):
    async def test(env):
        client = AgentMetaClient(SdkTransport(env.client), authority=env.authority)
        try:
            content = json.dumps(
                {
                    "schema": "composition/v1",
                    "slots": {
                        "model": {"capability_id": "capability://cap-a", "descriptor_revision": 1}
                    },
                    "wiring": [],
                }
            ).encode()
            resource = await client.put_artifact(
                realm_id=env.realm,
                actor_id="principal://operator-root/01900000-0000-7000-8000-000000000000",
                content=content,
                kind="code",
                media_type="application/json",
            )
            expected = "artifact://sha256/" + hashlib.sha256(content).hexdigest()
            assert resource["artifact_id"] == expected
            ok, reason = await client.verify_artifact(resource["artifact_id"])
            assert ok and reason == "OK"
            valid, issues = await client.validate_composition(resource["artifact_id"])
            assert valid and issues == []
        finally:
            await client.aclose()

    run_env(test, tmp_path)


def test_cli_info_json_envelope(tmp_path, capsys):
    async def test(env):
        code = await asyncio.to_thread(
            main,
            [
                "--data-dir", str(env.tmp_path),
                "--output", "json",
                *(["--insecure-dev-credential-file"] if os.name != "nt" else []),
                "info",
            ],
        )
        assert code == 0
        envelope = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert envelope["api_version"] == "1.16"
        assert envelope["ok"] is True
        assert envelope["result"]["ready"] == envelope["result"]["core_ready"]

    run_env(test, tmp_path)


def test_cli_dry_run_submit_has_no_side_effect(tmp_path, capsys):
    """--dry-run validates and plans but must not admit a Task (§41.52)."""

    async def test(env):
        code = await asyncio.to_thread(
            main,
            [
                "--data-dir", str(env.tmp_path),
                "--output", "json",
                *(["--insecure-dev-credential-file"] if os.name != "nt" else []),
                "--dry-run",
                "task", "submit", "--input-artifact", env.input_artifact,
            ],
        )
        assert code == 0
        envelope = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert envelope["ok"] is True
        assert envelope["result"]["dry_run"] is True
        assert envelope["result"]["plan"]["payload_type"] == "task.submit/v1"
        # no task was created
        count = env.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
        assert count == 0

    run_env(test, tmp_path)


def test_cli_exit_code_not_found(tmp_path, capsys):
    async def test(env):
        code = await asyncio.to_thread(
            main,
            [
                "--data-dir", str(env.tmp_path),
                "--output", "json",
                *(["--insecure-dev-credential-file"] if os.name != "nt" else []),
                "task", "get", "task://does-not-exist",
            ],
        )
        assert code == 4
        envelope = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert envelope["ok"] is False
        assert envelope["error"]["code"] == ErrorCode.NOT_FOUND

    run_env(test, tmp_path)


def test_cli_parser_requires_data_dir():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["info"])
