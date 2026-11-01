"""ADR 046: real IPC trace metadata plus Runtime-owned read-bound faults."""

import json
import hashlib
import struct

import pytest

from agent_meta_runtime.adapters.store.task_trace import task_trace
from agent_meta_runtime.domain.canonical import canonical_json
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.ids import new_uuid7
from agent_meta_runtime.protocols._v1 import public_pb2 as pub, transport_pb2 as t
from agent_meta_runtime.protocols.public_wire import encode_frame, parse_envelope
from agent_meta_runtime.sdk import connect
from test_local_server import ACTOR, _raw_hello, run_env


async def accepted(env, client):
    return await client.submit_task(realm_id=env.realm, actor_id=ACTOR, input_artifact_id=env.input_artifact)


def test_trace_returns_only_actual_persisted_task_metadata_without_writes(tmp_path):
    async def scenario(env):
        client = await connect(env.tmp_path, authority=env.authority)
        try:
            task = await accepted(env, client)
            before = env.conn.total_changes
            trace = await client.get_task_trace(task.task_id)
            assert trace == await client.get_task_trace(task.task_id)
            assert env.conn.total_changes == before and not env.conn.in_transaction
            assert trace["resource_type"] == "task-trace/v1" and trace["status"] == "ACCEPTED"
            assert trace["actions"][0]["action_id"] == task.root_action_id
            assert trace["actions"][0]["status"] == "CREATED"
            rows = env.conn.execute("SELECT fact_id,seq,event_type,entity_id FROM facts WHERE entity_id=? ORDER BY seq", (task.task_id,)).fetchall()
            assert [(e["fact_id"], e["seq"], e["event_type"], e["entity_id"]) for e in trace["events"]] == rows
            assert [e["event_type"] for e in trace["events"]] == ["task_accepted"]
            assert trace["events"][0]["old_status"] is None  # not reconstructed
            assert trace["fact_boundary_seq"] >= trace["events"][0]["seq"]
            assert all("payload" not in e and "payload_json" not in e for e in trace["events"])
            edges = {(e["edge_type"], e["from_id"], e["to_id"]) for e in trace["edges"]}
            assert ("part_of", task.root_action_id, task.task_id) in edges
            assert ("authorized_by", task.root_action_id, env.authority.authority_grant_id) in edges
            for realm, task_id in [("realm://other", task.task_id), (env.realm, "task://" + new_uuid7())]:
                with pytest.raises(StableError) as error:
                    task_trace(env.conn, realm_id=realm, task_id=task_id)
                assert error.value.code == ErrorCode.NOT_FOUND and not env.conn.in_transaction
        finally:
            await client.aclose()
    run_env(scenario, tmp_path)


def test_trace_holds_one_read_snapshot_across_a_concurrent_writer_commit(tmp_path):
    async def scenario(env):
        from agent_meta_runtime.adapters.store.connection import connect_store
        client = await connect(env.tmp_path, authority=env.authority)
        writer = connect_store(env.db_path)
        try:
            task = await accepted(env, client)
            before = env.conn.execute("SELECT current_meta_revision FROM realms").fetchone()[0]
            fired = False
            class Reader:
                @property
                def in_transaction(self):
                    return env.conn.in_transaction
                def rollback(self):
                    env.conn.rollback()
                def execute(self, sql, args=()):
                    nonlocal fired
                    result = env.conn.execute(sql, args)
                    if sql.startswith("SELECT current_meta_revision,next_seq-1") and not fired:
                        fired = True
                        writer.execute("UPDATE tasks SET status='RUNNING' WHERE task_id=?", (task.task_id,))
                        writer.execute("UPDATE actions SET status='RUNNING' WHERE action_id=?", (task.root_action_id,))
                        writer.execute("UPDATE realms SET current_meta_revision=current_meta_revision+1 WHERE realm_id=?", (env.realm,))
                        writer.commit()
                    return result
            # Deliberately interleave a Runtime-owned writer fixture after the
            # reader snapshot starts; no private mutation enters Seed proofs.
            trace = json.loads(task_trace(Reader(), realm_id=env.realm, task_id=task.task_id))
            assert fired and trace["snapshot_revision"] == before and trace["status"] == "ACCEPTED"
            assert trace["actions"][0]["status"] == "CREATED" and not env.conn.in_transaction
            current = await client.get_task_trace(task.task_id)
            assert current["snapshot_revision"] == before + 1 and current["status"] == current["actions"][0]["status"] == "RUNNING"
        finally:
            writer.close()
            await client.aclose()
    run_env(scenario, tmp_path)


@pytest.mark.parametrize("case", ["actions", "action_bytes", "facts", "fact_bytes", "edges", "response_bytes"])
def test_trace_refuses_every_bound_without_partial_success_or_mutation(tmp_path, case):
    async def scenario(env):
        client = await connect(env.tmp_path, authority=env.authority)
        try:
            task = await accepted(env, client)
            # Runtime-only corruption/size fixtures; no external execution claim.
            if case == "actions":
                env.conn.executemany("INSERT INTO actions(action_id,task_id,actor_id,intent,composition_id,status,budget_json,consumed_budget_json,created_at_us) "
                    "VALUES (?,?,?,'trace-fixture',?,'CREATED',?, ?,1)", [("action://" + new_uuid7(), task.task_id, ACTOR, env.composition, b"{}", b"{}") for _ in range(1000)])
            elif case in ("action_bytes", "response_bytes"):
                value = "x" * (4 * 1024 * 1024 + 1) if case == "action_bytes" else "\x01" * 750_000
                env.conn.execute("INSERT INTO actions(action_id,task_id,actor_id,intent,composition_id,status,budget_json,consumed_budget_json,created_at_us) "
                    "VALUES (?,?,?,?,?,'CREATED',?,?,1)", ("action://" + new_uuid7(), task.task_id, ACTOR, value, env.composition, b"{}", b"{}"))
            elif case in ("facts", "fact_bytes"):
                row = env.conn.execute("SELECT * FROM facts WHERE entity_id=? LIMIT 1", (task.task_id,)).fetchone()
                columns = [r[1] for r in env.conn.execute("PRAGMA table_info(facts)")]
                indexes = {name: i for i, name in enumerate(columns)}
                count = 4000 if case == "facts" else 1
                seq = env.conn.execute("SELECT next_seq FROM realms WHERE realm_id=?", (env.realm,)).fetchone()[0]
                values = []
                for i in range(count):
                    copy = list(row)
                    copy[indexes["fact_id"]], copy[indexes["seq"]] = "fact://" + new_uuid7(), seq + i
                    copy[indexes["fact_hash"]] = hashlib.sha256(copy[indexes["fact_id"]].encode()).hexdigest()
                    if case == "fact_bytes":
                        copy[indexes["payload_json"]] = canonical_json({"large": "x" * (8 * 1024 * 1024)})
                    values.append(tuple(copy))
                env.conn.executemany("INSERT INTO facts VALUES (" + ",".join("?" for _ in columns) + ")", values)
                env.conn.execute("UPDATE realms SET next_seq=? WHERE realm_id=?", (seq + count, env.realm))
            else:
                fact = env.conn.execute("SELECT fact_id FROM facts WHERE entity_id=?", (task.task_id,)).fetchone()[0]
                env.conn.executemany("INSERT INTO causal_edges(realm_id,from_id,to_id,edge_type,source_fact_id) VALUES (?,?,?,'part_of',?)",
                    [(env.realm, "action://" + new_uuid7(), task.task_id, fact) for _ in range(4097)])
            env.conn.commit()
            before = env.conn.total_changes
            with pytest.raises(StableError) as error:
                await client.get_task_trace(task.task_id)
            assert error.value.code == ErrorCode.RESOURCE_EXHAUSTED
            assert env.conn.total_changes == before and not env.conn.in_transaction
        finally:
            await client.aclose()
    run_env(scenario, tmp_path)


@pytest.mark.parametrize("payload", [b"{", b"[]", b'{"old_status":true}', b'{"new_status":{}}'])
def test_corrupt_fact_metadata_is_not_silently_reconstructed(tmp_path, payload):
    async def scenario(env):
        client = await connect(env.tmp_path, authority=env.authority)
        try:
            task = await accepted(env, client)
            # Disable only the immutable-row trigger for a Runtime corruption fixture.
            triggers = env.conn.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name='facts'").fetchall()
            for name, _ in triggers:
                env.conn.execute('DROP TRIGGER "' + name.replace('"', '""') + '"')
            env.conn.execute("UPDATE facts SET payload_json=? WHERE entity_id=?", (payload, task.task_id))
            for _, sql in triggers:
                env.conn.execute(sql)
            env.conn.commit()
            before = env.conn.total_changes
            with pytest.raises(StableError) as error:
                await client.get_task_trace(task.task_id)
            assert error.value.code == ErrorCode.INTEGRITY_ERROR
            assert env.conn.total_changes == before and not env.conn.in_transaction
        finally:
            await client.aclose()
    run_env(scenario, tmp_path)


@pytest.mark.parametrize("minor", [0, 1, 2, 3, 4])
def test_old_minor_refuses_trace_before_dispatch(tmp_path, minor):
    async def scenario(env):
        reader, writer = await _raw_hello(env.socket_path, minor=minor)()
        try:
            request = t.RpcEnvelope(protocol_major=1, protocol_minor=minor, request_id="old-trace", method="agent_meta.public.v1.Task.GetTrace",
                payload=pub.GetTaskRequest(task_id="task://" + new_uuid7()).SerializeToString())
            writer.write(encode_frame(request.SerializeToString()))
            await writer.drain()
            size = struct.unpack(">I", await reader.readexactly(4))[0]
            assert parse_envelope(await reader.readexactly(size)).error.code == ErrorCode.CONTRACT_INCOMPATIBLE
        finally:
            writer.close()
            await writer.wait_closed()
    run_env(scenario, tmp_path)
