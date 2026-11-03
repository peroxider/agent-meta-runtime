"""Actual public source-only export, authorization and atomic publication."""

import asyncio
import json
import os

import pytest

from agent_meta_runtime.interfaces.cli.init import run_init
from agent_meta_runtime.sdk.packages import canonical_json, decode_package, sha256_hex
from agent_meta_runtime.sdk import connect
from agent_meta_runtime.domain.scratch_export import (
    ScratchSource,
    build_scratch_export,
    ExportArtifact,
)
from test_public_scratch_resources import environment, submit

SOURCE = 'calls=[]\ndef chosen(value):\n    return value + 1\ncalls.append("only-original-cell")\n'


async def inputs(client, actor, *, schema_kind="export_input", nested=False):
    async def upload(value, kind="export_input"):
        raw = canonical_json(value)
        receipt = await client.put_artifact(
            realm_id="realm://main",
            actor_id=actor.actor_id,
            kind=kind,
            media_type="application/json",
            content=raw,
        )
        return ExportArtifact(receipt["artifact_id"], raw)

    leaf = (
        await upload({"type": "string", "title": "Scratch export leaf"})
        if nested
        else None
    )
    schema = await upload(
        {
            "type": "object",
            "title": "Scratch export interface",
            **({"$defs": {"leaf": {"$ref": leaf.artifact_id}}} if leaf else {}),
        },
        schema_kind,
    )
    contract = await upload(
        {
            "schema": "capability-contract/v1",
            "capability_id": "capability://exported",
            "contract_version": "1.0.0",
            "operations": [
                {
                    "operation_id": "apply",
                    "input_schema_artifact_id": schema.artifact_id,
                    "output_schema_artifact_id": schema.artifact_id,
                    "idempotency": "PURE",
                    "retry_semantics": "NEVER",
                    "effects": ["none"],
                    "required_permissions": ["capability.invoke"],
                }
            ],
            "requires": [],
            "provides": [],
            "state": {},
            "execution_requirements": {},
            "runtime_constraints": {},
        }
    )
    lock = await upload(
        {
            "schema": "scratch-python-dependency-lock/v1",
            "python_abi": "cp312",
            "stdlib_modules": [],
            "wheels": [],
        }
    )
    return (
        {
            "contract_artifact_id": contract.artifact_id,
            "dependency_lock_artifact_id": lock.artifact_id,
            "support_artifact_ids": [
                schema.artifact_id,
                *([leaf.artifact_id] if leaf else []),
            ],
            "export_names": ["chosen"],
            "entrypoint": "scratch_candidate:chosen",
        },
        contract,
        lock,
    )


def test_public_export_matches_source_constructor_and_records_complete_causal_closure(
    tmp_path,
):
    pytest.importorskip("ipykernel")
    run_init(tmp_path, insecure_dev_credential_file=os.name != "nt")

    async def run():
        daemon, client, actor = await environment(tmp_path, "export")
        try:
            options, contract, lock = await inputs(client, actor)
            _, terminal, execution = await submit(
                client, actor, SOURCE, extra={"export": options}
            )
            assert terminal["status"] == "SUCCEEDED", (terminal, execution)
            call = next(
                item
                for item in execution["invocations"]
                if item["target"].endswith("#fixture.scratch.export")
            )
            value = json.loads(
                await client.get_artifact_content(call["output_artifact_id"])
            )
            expected = build_scratch_export(
                sources=(ScratchSource.from_text(SOURCE),),
                export_names=("chosen",),
                contract=contract,
                dependency_lock=lock,
                entrypoint=options["entrypoint"],
            )
            assert value["package_artifact_id"] == expected.package.artifact_id
            assert value["provenance_artifact_id"] == expected.provenance.artifact_id
            package = await client.get_artifact_content(value["package_artifact_id"])
            assert (
                "artifact://sha256/" + sha256_hex(package)
                == value["package_artifact_id"]
            )
            manifest, files = decode_package(package)
            assert (
                files["scratch_candidate.py"]
                == b"def chosen(value):\n    return value + 1\n"
            )
            assert (
                manifest.package.runtime_constraints["trust_class"]
                == "trusted_candidate"
            )
            assert (
                value["experiment_promotion_required"] and not value["serving_changed"]
            )
            assert value["exported_by_action_id"] == call["action_id"]
            assert len(value["input_artifact_ids"]) == 4
            assert (
                value["source_cells"][0]["source_artifact_id"]
                == ScratchSource.from_text(SOURCE).artifact_id
            )
            record = daemon._conn.execute(
                "SELECT action_id,payload_json FROM facts WHERE event_type='scratch_candidate_exported'"
            ).fetchall()
            assert len(record) == 1 and record[0][0] == call["action_id"]
            assert set(json.loads(record[0][1])["input_artifact_ids"]) == set(
                value["input_artifact_ids"]
            )
            from agent_meta_runtime.adapters.store.gc import collect_marks

            marked = collect_marks(daemon._conn)
            assert all(
                reference.rsplit("/", 1)[1] in marked
                for reference in (
                    *value["input_artifact_ids"],
                    value["package_artifact_id"],
                    value["provenance_artifact_id"],
                )
            )
            assert daemon._conn.execute(
                "SELECT COUNT(*) FROM facts WHERE event_type='scratch_cell_reserved'"
            ).fetchone() == (1,)
            assert (await client.get_view())["serving_revision"] == 1
        finally:
            await client.aclose()
            await daemon.close()

    asyncio.run(run())


@pytest.mark.parametrize("complete", [True, False])
def test_export_requires_and_retains_transitive_json_support_closure(
    tmp_path, complete
):
    run_init(tmp_path, insecure_dev_credential_file=os.name != "nt")

    async def run():
        daemon, client, actor = await environment(tmp_path, "export")
        try:
            options, _, _ = await inputs(client, actor, nested=True)
            if not complete:
                options["support_artifact_ids"].pop()
            _, terminal, execution = await submit(
                client, actor, SOURCE, extra={"export": options}
            )
            if complete:
                assert terminal["status"] == "SUCCEEDED", terminal
                call = next(
                    item
                    for item in execution["invocations"]
                    if item["target"].endswith("#fixture.scratch.export")
                )
                receipt = json.loads(
                    await client.get_artifact_content(call["output_artifact_id"])
                )
                assert set(options["support_artifact_ids"]) <= set(
                    receipt["input_artifact_ids"]
                )
            else:
                assert terminal["error"] == "CONTRACT_INCOMPATIBLE", terminal
                assert daemon._conn.execute(
                    "SELECT COUNT(*) FROM facts WHERE event_type='scratch_candidate_exported'"
                ).fetchone() == (0,)
        finally:
            await client.aclose()
            await daemon.close()

    asyncio.run(run())


def test_export_rechecks_reserved_service_grant_at_atomic_publication(
    tmp_path, monkeypatch
):
    from agent_meta_runtime.adapters.store import scratch_export

    original = scratch_export.prepare
    run_init(tmp_path, insecure_dev_credential_file=os.name != "nt")

    async def run():
        daemon, client, actor = await environment(tmp_path, "export")
        control = await connect(tmp_path, authority=actor)

        async def revoked(store, task, invocation, request):
            prepared = await original(store, task, invocation, request)
            rows = daemon._conn.execute(
                "SELECT grant_id,permissions_json FROM authority_grants WHERE subject_id=? AND status='ACTIVE'",
                (daemon._service_id,),
            ).fetchall()
            grant = next(
                key for key, raw in rows if "scratch.export" in json.loads(raw)
            )
            await control.revoke_authority(
                realm_id="realm://main", actor_id=actor.actor_id, grant_id=grant
            )
            return prepared

        monkeypatch.setattr(scratch_export, "prepare", revoked)
        try:
            options, _, _ = await inputs(client, actor)
            _, terminal, _ = await submit(
                client, actor, SOURCE, extra={"export": options}
            )
            assert terminal["error"] == "AUTHORITY_DENIED", terminal
            assert daemon._conn.execute(
                "SELECT COUNT(*) FROM facts WHERE event_type='scratch_candidate_exported'"
            ).fetchone() == (0,)
            assert daemon._conn.execute(
                "SELECT COUNT(*) FROM artifacts WHERE kind='capability_package'"
            ).fetchone() == (0,)
        finally:
            await control.aclose()
            await client.aclose()
            await daemon.close()

    asyncio.run(run())


def test_confirmed_export_replay_does_not_rebuild_or_publish_again(
    tmp_path, monkeypatch
):
    from agent_meta_runtime.application.task_host import TaskSession
    from agent_meta_runtime.adapters.store import scratch_export

    original_prepare, original_call = scratch_export.prepare, TaskSession._resource_tool
    preparations, replayed = [], []

    async def prepared(*args):
        preparations.append(True)
        return await original_prepare(*args)

    async def repeated(session, call, *args):
        result = await original_call(session, call, *args)
        if call.name == "fixture.scratch.export":
            session._ordinal -= 1
            assert await original_call(session, call, *args) == result
            replayed.append(True)
        return result

    monkeypatch.setattr(scratch_export, "prepare", prepared)
    monkeypatch.setattr(TaskSession, "_resource_tool", repeated)
    run_init(tmp_path, insecure_dev_credential_file=os.name != "nt")

    async def run():
        daemon, client, actor = await environment(tmp_path, "export")
        try:
            options, _, _ = await inputs(client, actor)
            _, terminal, _ = await submit(
                client, actor, SOURCE, extra={"export": options}
            )
            assert terminal["status"] == "SUCCEEDED" and preparations == replayed == [
                True
            ]
            assert daemon._conn.execute(
                "SELECT COUNT(*) FROM facts WHERE event_type='scratch_candidate_exported'"
            ).fetchone() == (1,)
        finally:
            await client.aclose()
            await daemon.close()

    asyncio.run(run())


@pytest.mark.parametrize(
    "mode",
    ["closure", "unexecuted", "free_binding", "normalize", "kind_scope", "policy"],
)
def test_public_export_refuses_incomplete_or_opaque_sources_without_publishing(
    tmp_path, mode
):
    pytest.importorskip("ipykernel")
    run_init(tmp_path, insecure_dev_credential_file=os.name != "nt")

    async def run():
        daemon, client, actor = await environment(
            tmp_path, "export_invalid" if mode == "normalize" else "export"
        )
        try:
            options, _, _ = await inputs(
                client,
                actor,
                schema_kind="note" if mode == "kind_scope" else "export_input",
            )
            source = SOURCE
            if mode == "closure":
                options["support_artifact_ids"] = []
            elif mode == "unexecuted":
                foreign = await client.put_artifact(
                    realm_id="realm://main",
                    actor_id=actor.actor_id,
                    kind="source",
                    media_type="text/x-python",
                    content=b"def chosen(value): return 999\n",
                )
                options["source_artifact_ids"] = [foreign["artifact_id"]]
            elif mode == "free_binding":
                source = "hidden=7\ndef chosen(value):\n    return value + hidden\n"
            elif mode == "policy":
                source = "password='SOURCE_POLICY_SECRET'\ndef chosen(value):\n    return value + 1\n"
            _, terminal, execution = await submit(
                client, actor, source, extra={"export": options}
            )
            assert (
                terminal["error"]
                == {
                    "closure": "CONTRACT_INCOMPATIBLE",
                    "unexecuted": "AUTHORITY_DENIED",
                    "free_binding": "INVALID_ARGUMENT",
                    "normalize": "INVALID_RESULT",
                    "kind_scope": "AUTHORITY_DENIED",
                    "policy": "AUTHORITY_DENIED",
                }[mode]
            ), (terminal, execution)
            assert daemon._conn.execute(
                "SELECT COUNT(*) FROM facts WHERE event_type='scratch_candidate_exported'"
            ).fetchone() == (0,)
            assert daemon._conn.execute(
                "SELECT COUNT(*) FROM artifacts WHERE kind='capability_package'"
            ).fetchone() == (0,)
            assert daemon._conn.execute(
                "SELECT COUNT(*) FROM facts WHERE event_type='scratch_cell_reserved'"
            ).fetchone() == (1,)
        finally:
            await client.aclose()
            await daemon.close()

    asyncio.run(run())
