"""ADR 043: signed wire validation happens before acceptance/staging."""

import asyncio

import pytest

from agent_meta_runtime.domain.canonical import canonical_json
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.interfaces.cli import build_parser
from agent_meta_runtime.interfaces.cli.main import cmd_task_submit
from agent_meta_runtime.protocols._v1 import public_pb2 as pub
from agent_meta_runtime.sdk import AgentMetaClient, connect
from test_local_server import ACTOR, make_envelope, run_env


BAD_FIELDS = [
    {"budget": False}, {"budget": 0}, {"budget": []}, {"budget": "8"}, {"budget": None},
    {"budget": {"max_steps": True}}, {"budget": {"max_steps": "3"}}, {"budget": {"max_steps": 1.5}},
    {"budget": {"max_steps": -1}}, {"budget": {"max_steps": None}}, {"budget": {"extra": 1}},
    {"deadline_at_us": False}, {"deadline_at_us": "100"}, {"deadline_at_us": 1.5}, {"deadline_at_us": -1},
    {"unknown": True}, {"input_artifact_id": 1},
]


@pytest.mark.parametrize("fields", BAD_FIELDS)
def test_malformed_signed_task_fields_do_not_stage_or_accept(tmp_path, fields):
    async def scenario(env):
        payload = {"input_artifact_id": env.input_artifact, **fields}
        envelope = make_envelope(env.realm, "task.submit/v1", payload)
        before = {table: env.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("tasks", "actions", "artifacts", "commands", "authority_uses")}
        blobs_before = set(env.cas.artifacts_dir.rglob("*"))
        with pytest.raises(StableError) as error:
            await env.client.call("agent_meta.public.v1.Task.Submit", pub.CommandRequest(command_envelope_jcs=canonical_json(envelope)), pub.MutationResponse)
        assert error.value.code == ErrorCode.INVALID_ARGUMENT
        assert before == {table: env.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in before}
        assert set(env.cas.artifacts_dir.rglob("*")) == blobs_before
    run_env(scenario, tmp_path)


def test_zero_deadline_is_preserved_in_the_accepted_record(tmp_path):
    async def scenario(env):
        client = await connect(env.tmp_path, authority=env.authority)
        try:
            task = await client.submit_task(realm_id=env.realm, actor_id=ACTOR, input_artifact_id=env.input_artifact, deadline_at_us=0)
            execution = await client.get_task_execution(task.task_id)
            assert execution["deadline_at_us"] == 0
        finally:
            await client.aclose()
    run_env(scenario, tmp_path)


@pytest.mark.parametrize("budget", [False, 0, [], "8", {"max_steps": True}, {"max_steps": 1.5}])
def test_sdk_does_not_drop_or_coerce_invalid_budget_before_sending(budget):
    class NoRequests:
        async def call(self, *args, **kwargs):
            raise AssertionError("invalid budget reached transport")
        async def close(self):
            pass
    async def scenario():
        client = AgentMetaClient(NoRequests())
        with pytest.raises(StableError) as error:
            await client.submit_task(realm_id="realm://main", actor_id=ACTOR, input_artifact_id="artifact://sha256/" + "a" * 64, budget=budget)
        assert error.value.code == ErrorCode.INVALID_ARGUMENT
    asyncio.run(scenario())


def test_cli_accepts_literal_zero_deadline_option():
    args = build_parser().parse_args(["--data-dir", "fixture", "task", "submit", "--input-artifact",
        "artifact://sha256/" + "a" * 64, "--deadline-at-us", "0"])
    assert args.deadline_at_us == 0


@pytest.mark.parametrize("raw", ["", "{", '{"max_steps":1,"max_steps":2}'])
@pytest.mark.parametrize("dry_run", [False, True])
def test_cli_bad_or_duplicate_budget_json_fails_before_any_client_action(raw, dry_run):
    arguments = ["--data-dir", "fixture", "task", "submit", "--input-artifact", "artifact://sha256/" + "a" * 64, "--budget", raw]
    if dry_run:
        arguments.insert(2, "--dry-run")
    args = build_parser().parse_args(arguments)
    class NoActions:
        def __getattr__(self, name):
            raise AssertionError("invalid budget reached client")
    async def scenario():
        with pytest.raises(StableError) as error:
            await cmd_task_submit(NoActions(), args)
        assert error.value.code == ErrorCode.INVALID_ARGUMENT
    asyncio.run(scenario())
