"""Retiring a serving Composition must retire its owned native Scratch too."""

import asyncio
import os

from agent_meta_runtime.interfaces.cli.init import run_init
from test_public_scratch_resources import environment, submit
from test_bound_harness import wait_refs
from agent_meta_runtime.sdk import connect
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.adapters.scratch_resources import OwnedScratchResources
import json


def test_harness_drain_confirms_scratch_cleanup_before_reporting_ready(tmp_path):
    run_init(tmp_path, insecure_dev_credential_file=os.name != "nt")

    async def run():
        daemon, client, actor = await environment(tmp_path, "keep")
        try:
            _, terminal, _ = await submit(client, actor, "value=42\n")
            assert terminal["status"] == "SUCCEEDED", terminal
            owners = list(daemon._scratch._calls._owners.items())
            assert len(owners) == 1
            session, (_, worker) = owners[0]
            assert worker.state == "ACTIVE"
            harness = (await client.list_harnesses(status="ACTIVE"))[0]
            await client.deactivate_harness(
                realm_id="realm://main",
                actor_id=actor.actor_id,
                harness_id=harness["harness_id"],
            )
            await wait_refs(client, status="READY", serving=0)
            assert daemon._conn.execute(
                "SELECT status FROM scratch_sessions WHERE session_id=?", (session,)
            ).fetchone() == ("RELEASED",)
            assert worker.state == "CLOSED"
            assert not daemon._scratch._calls._owners
            assert not list((tmp_path / "workspaces").iterdir())
            assert (await client.get_harness(harness["harness_id"]))[
                "status"
            ] == "INACTIVE"
            cleanup = daemon._conn.execute(
                "SELECT payload_json FROM facts WHERE event_type='workspace_cleanup_completed'"
            ).fetchone()
            cause = json.loads(cleanup[0])["lifecycle_cause"]
            assert cause["reason_code"] == "COMPOSITION_RETIRED"
            assert cause["requesting_service_id"] == daemon._service_id
        finally:
            await client.aclose()
            await daemon.close()

    asyncio.run(run())


def test_failed_native_cleanup_keeps_drain_degraded_and_binding_retained(
    tmp_path, monkeypatch
):
    original = OwnedScratchResources._cleanup
    blocked = True

    async def unavailable(host, session_id, **kwargs):
        if blocked and kwargs.get("lifecycle_cause") is not None:
            raise StableError(
                code=ErrorCode.BACKEND_UNAVAILABLE,
                message="fixture cleanup unavailable",
            )
        return await original(host, session_id, **kwargs)

    monkeypatch.setattr(OwnedScratchResources, "_cleanup", unavailable)
    run_init(tmp_path, insecure_dev_credential_file=os.name != "nt")

    async def run():
        nonlocal blocked
        daemon, client, actor = await environment(tmp_path, "keep")
        try:
            _, terminal, _ = await submit(client, actor, "value=42\n")
            assert terminal["status"] == "SUCCEEDED"
            harness = (await client.list_harnesses(status="ACTIVE"))[0]
            composition = next(iter(daemon._catalog.bindings))
            await client.deactivate_harness(
                realm_id="realm://main",
                actor_id=actor.actor_id,
                harness_id=harness["harness_id"],
            )
            await wait_refs(client, status="DEGRADED", serving=0)
            assert composition in daemon._catalog.bindings
            assert daemon._conn.execute(
                "SELECT DISTINCT status FROM capability_instances"
            ).fetchall() == [("ACTIVE",)]
            assert (
                next(iter(daemon._scratch._calls._owners.values()))[1].state == "ACTIVE"
            )
            assert daemon._conn.execute(
                "SELECT COUNT(*) FROM facts WHERE event_type='workspace_cleanup_completed'"
            ).fetchone() == (0,)
            blocked = False
            await wait_refs(client, status="READY", serving=0)
            assert composition not in daemon._catalog.bindings
            assert not daemon._scratch._calls._owners
            assert daemon._conn.execute(
                "SELECT status FROM scratch_sessions"
            ).fetchall() == [("RELEASED",)]
        finally:
            await client.aclose()
            await daemon.close()

    asyncio.run(run())


def test_drain_waits_for_actual_running_cell_before_closing_native_owner(tmp_path):
    run_init(tmp_path, insecure_dev_credential_file=os.name != "nt")

    async def run():
        daemon, client, actor = await environment(tmp_path, "keep")
        control = await connect(tmp_path, authority=actor)
        pending = asyncio.create_task(
            submit(
                client,
                actor,
                "from pathlib import Path\nPath('entered').write_text('ready')\nwhile True: pass",
            )
        )
        try:
            async with asyncio.timeout(15):
                while not list((tmp_path / "workspaces").glob("*/entered")):
                    await asyncio.sleep(0.02)
            harness = (await control.list_harnesses(status="ACTIVE"))[0]
            worker = next(iter(daemon._scratch._calls._owners.values()))[1]
            await control.deactivate_harness(
                realm_id="realm://main",
                actor_id=actor.actor_id,
                harness_id=harness["harness_id"],
            )
            async with asyncio.timeout(5):
                while (await control.get_view())["serving_revision"] != 0:
                    await asyncio.sleep(0.02)
            assert worker.state == "ACTIVE" and not pending.done()
            assert daemon._conn.execute(
                "SELECT COUNT(*) FROM facts WHERE event_type='workspace_cleanup_completed'"
            ).fetchone() == (0,)
            task = daemon._conn.execute(
                "SELECT task_id FROM tasks WHERE status='RUNNING'"
            ).fetchone()[0]
            await control.cancel_task(
                realm_id="realm://main", actor_id=actor.actor_id, task_id=task
            )
            _, terminal, _ = await pending
            assert terminal["status"] == "CANCELLED", terminal
            await wait_refs(control, status="READY", serving=0)
            assert worker.state == "CLOSED" and not daemon._scratch._calls._owners
            assert daemon._conn.execute(
                "SELECT status FROM scratch_sessions"
            ).fetchall() == [("RELEASED",)]
        finally:
            if not pending.done():
                pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
            await control.aclose()
            await client.aclose()
            await daemon.close()

    asyncio.run(run())
