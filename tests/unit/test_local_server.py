"""Step 06 gate: local RPC server end-to-end (§41.26, §41.46, §41.52)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import struct
import time
import types
from contextvars import ContextVar

import pytest

from agent_meta_runtime.adapters.cas import FilesystemCas
from agent_meta_runtime.adapters.store import bootstrap_realm, initialize_store
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.ids import new_uuid7
from agent_meta_runtime.domain.canonical import canonical_json
from agent_meta_runtime.domain.envelope import CommandEnvelope
from agent_meta_runtime.domain.deadline import Deadline
from agent_meta_runtime.sdk import CommandAuthority, encode_command, sign_command
from agent_meta_runtime.interfaces.local_api.connection import LocalConnection, open_local_streams
from agent_meta_runtime.interfaces.local_api.handlers import PublicApiHandlers
from agent_meta_runtime.interfaces.local_api.server import LocalApiServer
from agent_meta_runtime.interfaces.local_api.staging import ChunkedStaging
from agent_meta_runtime.protocols._v1 import public_pb2 as pub
from agent_meta_runtime.protocols._v1 import transport_pb2 as t
from agent_meta_runtime.protocols.public_wire import encode_frame, parse_envelope

ACTOR = "principal://operator-root/01900000-0000-7000-8000-000000000000"
_AUTHORITY = ContextVar("local_api_test_authority", default=None)


def make_envelope(realm, payload_type, payload, *, expected_meta_revision=None):
    authority = _AUTHORITY.get()
    if authority is None:
        raise RuntimeError("signed wire fixture must bind its authority")
    body = {
        "command_id": "task://" + new_uuid7(),
        "realm_id": realm,
        "actor_id": ACTOR,
        "authority_grant_id": authority.authority_grant_id,
        "expected_meta_revision": expected_meta_revision,
        "causal_parent_action_id": None,
        "payload_type": payload_type,
        "payload_schema_version": 1,
        "payload": payload,
        "auth_nonce": None,
        "auth_issued_at_us": None,
        "auth_signature": None,
    }
    return json.loads(encode_command(sign_command(CommandEnvelope(**body), authority)))


class LocalEnv:
    """Booted store + handlers + server + a connected client."""

    def __init__(self, tmp_path, *, serving_ready: bool = True) -> None:
        self.tmp_path = tmp_path
        self.db_path = tmp_path / "meta.db"
        self.conn = initialize_store(self.db_path)
        self.realm = "realm://main"
        bootstrap_realm(self.conn, self.realm, "epoch://" + new_uuid7())
        self.cas = FilesystemCas(tmp_path)
        self.staging = ChunkedStaging(self.cas, now_us=lambda: time.time_ns() // 1000)
        self.composition = "composition://" + new_uuid7()
        self.input_artifact = "artifact://sha256/" + hashlib.sha256(b"input").hexdigest()
        surface = "artifact://sha256/" + hashlib.sha256(b"surface").hexdigest()
        for art in (surface, self.input_artifact):
            self.conn.execute(
                "INSERT INTO artifacts(artifact_id, kind, media_type, size_bytes,"
                " schema_version, created_by, created_at_us, parents_json, manifest_json,"
                " integrity_status) VALUES (?, 'code', 'application/json', 0, 1, ?, 1, ?, ?, 'VALID')",
                (art, ACTOR, b"{}", b"{}"),
            )
        self.conn.execute(
            "INSERT INTO compositions(composition_id, realm_id, revision, parent_id,"
            " body_json, body_hash, created_by, created_at_us)"
            " VALUES (?, ?, 1, NULL, ?, 'h', ?, 1)",
            (self.composition, self.realm, b"{}", ACTOR),
        )
        self.conn.execute(
            "INSERT INTO capability_surfaces(realm_id, surface_revision, composition_id,"
            " artifact_id, authority_fingerprint, backend_profile_hash, created_at_us)"
            " VALUES (?, 1, ?, ?, 'afp', 'bph', 1)",
            (self.realm, self.composition, surface),
        )
        if serving_ready:
            self.conn.execute(
                "INSERT INTO composition_refs(realm_id, desired_revision, serving_revision,"
                " realized_revision, desired_cas, serving_cas, realized_cas, reconcile_status)"
                " VALUES (?, 1, 1, 1, 0, 0, 0, 'READY')",
                (self.realm,),
            )
        self.conn.commit()
        self._bootstrap_test_authority()
        self.serving_ready = serving_ready

    def _bootstrap_test_authority(self):
        from agent_meta_runtime.adapters.crypto import Ed25519KeyPair
        from agent_meta_runtime.adapters.store.authority import RootBootstrapRequest, bootstrap_root
        from agent_meta_runtime.adapters.store.uow import execute_command
        from agent_meta_runtime.adapters.credentials import InsecureDevCredentialStore, WindowsCredentialStore, write_store_config
        import os

        # Deterministic public fixture keys; this is Runtime's unit environment,
        # never an installed external consumer's security/Host release proof.
        pair = Ed25519KeyPair.from_private_bytes(bytes(range(32)))
        epoch = self.conn.execute("SELECT epoch_id FROM realms WHERE realm_id=?", (self.realm,)).fetchone()[0]
        bootstrap = CommandEnvelope("task://" + new_uuid7(), self.realm, ACTOR, None, None, None, "runtime.init/v1", 1, {}, None, None, None)
        result = execute_command(self.conn, bootstrap, bootstrap_root(RootBootstrapRequest(
            self.realm, epoch, ACTOR, pair.public_bytes_raw(), "a" * 64,
            constitution_artifact_id=self.input_artifact, meta_root_artifact_id=self.input_artifact,
        )), deadline=Deadline.after(5_000_000))
        assert not hasattr(result, "error")
        self.authority = CommandAuthority(ACTOR, result.receipt["grant_id"], pair.sign)
        self.conn.execute("INSERT INTO principals(principal_id,realm_id,kind,public_identity_json,status,created_at_us) VALUES (?,?,'SERVICE',?,'ACTIVE',1)",
                          ("principal://service/01900000-0000-7000-8000-000000000001", self.realm, canonical_json({"algorithm": "Ed25519", "public_key_hex": pair.public_bytes_raw().hex()})))
        self.conn.commit()
        store_type = WindowsCredentialStore if os.name == "nt" else InsecureDevCredentialStore
        store = store_type(self.tmp_path / "keys", create=True)
        handles = {name: store.create(bytearray(pair.private_bytes_raw()), purpose=f"{name}.ed25519") for name in ("root", "service")}
        write_store_config(store.root, profile=store.profile, handles=handles,
                           operator={"actor_id": ACTOR, "authority_grant_id": self.authority.authority_grant_id, "public_key_hex": pair.public_bytes_raw().hex()})

    def readiness(self):
        return types.SimpleNamespace(
            core_ready=True,
            serving_ready=self.serving_ready,
            core_reasons=[],
            serving_reasons=[] if self.serving_ready else ["serving composition not READY"],
        )

    async def start(self):
        handlers = PublicApiHandlers(
            self.conn,
            data_dir=self.tmp_path,
            realm_id=self.realm,
            db_path=self.db_path,
            cas=self.cas,
            staging=self.staging,
            readiness=self.readiness,
            now_us=lambda: time.time_ns() // 1000,
        )
        self.server = LocalApiServer(
            self.tmp_path, handlers=handlers.handlers(), now_us=lambda: time.time_ns() // 1000
        )
        self.socket_path = await self.server.start()
        self.client = LocalConnection(self.socket_path)
        await self.client.connect()
        return self

    async def stop(self):
        await self.client.close()
        await self.server.close()
        self.conn.close()


def run_env(test, tmp_path, *, serving_ready=True):
    """Boot an env, run ``test(env)`` as one coroutine, tear down."""

    async def body():
        env = LocalEnv(tmp_path, serving_ready=serving_ready)
        await env.start()
        binding = _AUTHORITY.set(env.authority)
        try:
            return await test(env)
        finally:
            _AUTHORITY.reset(binding)
            await env.stop()

    return asyncio.run(body())


def test_get_info_dual_readiness_and_ready_alias(tmp_path):
    async def test(env):
        info = await env.client.call(
            "agent_meta.public.v1.Runtime.GetInfo", pub.GetInfoRequest(), pub.RuntimeInfo
        )
        assert info.live
        assert info.ready == info.core_ready == 1  # alias MUST equal core_ready
        assert info.serving_ready == 1

    run_env(test, tmp_path)


def test_task_submit_gate_blocked_without_serving(tmp_path):
    async def test(env):
        envelope = make_envelope(
            env.realm, "task.submit/v1", {"input_artifact_id": env.input_artifact}
        )
        request = pub.CommandRequest(command_envelope_jcs=canonical_json(envelope))
        with pytest.raises(StableError) as excinfo:
            await env.client.call(
                "agent_meta.public.v1.Task.Submit", request, pub.MutationResponse
            )
        assert excinfo.value.code == ErrorCode.SERVING_NOT_READY

    run_env(test, tmp_path, serving_ready=False)


def test_task_submit_and_wait_roundtrip(tmp_path):
    async def test(env):
        envelope = make_envelope(
            env.realm,
            "task.submit/v1",
            {"input_artifact_id": env.input_artifact, "budget": {"max_turns": 2}},
        )
        request = pub.CommandRequest(command_envelope_jcs=canonical_json(envelope))
        mut = await env.client.call(
            "agent_meta.public.v1.Task.Submit", request, pub.MutationResponse
        )
        receipt = json.loads(bytes(mut.receipt_jcs))
        resource = json.loads(bytes(mut.resource_jcs))
        assert receipt["command_id"] == envelope["command_id"]
        assert resource["status"] == "ACCEPTED"

        # idempotent replay returns the same receipt
        mut2 = await env.client.call(
            "agent_meta.public.v1.Task.Submit", request, pub.MutationResponse
        )
        assert json.loads(bytes(mut2.receipt_jcs)) == receipt

        got = await env.client.call(
            "agent_meta.public.v1.Task.Get",
            pub.GetTaskRequest(task_id=resource["task_id"]),
            pub.ResourceResponse,
        )
        assert json.loads(bytes(got.resource_jcs))["task_id"] == resource["task_id"]

        waited = await env.client.call(
            "agent_meta.public.v1.Task.Wait",
            pub.WaitTaskRequest(
                task_id=resource["task_id"],
                wait_deadline_at_us=int(time.time() * 1e6) - 1_000_000,
            ),
            pub.TaskWaitResponse,
        )
        assert waited.terminal is False  # Wait timeout never terminates the Task

    run_env(test, tmp_path)


def test_artifact_two_phase_upload_and_verify(tmp_path):
    async def test(env):
        body_bytes = json.dumps({"schema": "composition/v1"}).encode()
        digest = hashlib.sha256(body_bytes).hexdigest()
        begin = await env.client.call(
            "agent_meta.public.v1.Artifact.BeginPut",
            pub.BeginPutRequest(expected_size=len(body_bytes), expected_sha256=digest),
            pub.BeginPutResponse,
        )
        assert begin.chunk_size == 1 << 20
        await env.client.call(
            "agent_meta.public.v1.Artifact.PutChunk",
            pub.PutChunkRequest(
                staging_handle=begin.staging_handle,
                offset=0,
                data=body_bytes,
                chunk_sha256=digest,
            ),
            pub.PutChunkResponse,
        )
        artifact_id = "artifact://sha256/" + digest
        envelope = make_envelope(
            env.realm,
            "artifact.put/v1",
            {
                "source_staging_handle": begin.staging_handle,
                "expected_sha256": digest,
                "expected_size": len(body_bytes),
                "kind": "code",
                "media_type": "application/json",
                "parents": [],
            },
        )
        mut = await env.client.call(
            "agent_meta.public.v1.Artifact.Put",
            pub.CommandRequest(command_envelope_jcs=canonical_json(envelope)),
            pub.MutationResponse,
        )
        assert json.loads(bytes(mut.resource_jcs))["artifact_id"] == artifact_id
        verify = await env.client.call(
            "agent_meta.public.v1.Artifact.Verify",
            pub.VerifyArtifactRequest(artifact_id=artifact_id),
            pub.VerifyArtifactResponse,
        )
        assert verify.ok

    run_env(test, tmp_path)


def test_unknown_method_maps_to_invalid_argument(tmp_path):
    async def test(env):
        with pytest.raises(StableError) as excinfo:
            await env.client.call(
                "agent_meta.public.v1.Bogus.Rpc", pub.GetInfoRequest(), pub.RuntimeInfo
            )
        assert excinfo.value.code == ErrorCode.INVALID_ARGUMENT

    run_env(test, tmp_path)


def _raw_hello(socket_path, *, minor=0):
    async def body():
        reader, writer = await open_local_streams(socket_path)
        hello = t.HelloRequest(supported=[t.VersionRange(major=1, min_minor=minor, max_minor=minor)])
        hello_env = t.RpcEnvelope(protocol_major=1, request_id="hello", method="Hello")
        hello_env.payload = hello.SerializeToString()
        writer.write(encode_frame(hello_env.SerializeToString()))
        await writer.drain()
        header = await reader.readexactly(4)
        await reader.readexactly(struct.unpack(">I", header)[0])
        return reader, writer

    return body


def test_duplicate_request_id_rejected_on_connection(tmp_path):
    async def test(env):
        get_info = pub.GetInfoRequest().SerializeToString()

        async def one(request_id):
            reader, writer = await _raw_hello(env.socket_path)()
            try:
                frame = t.RpcEnvelope(
                    protocol_major=1,
                    request_id=request_id,
                    method="agent_meta.public.v1.Runtime.GetInfo",
                )
                frame.payload = get_info
                writer.write(encode_frame(frame.SerializeToString()))
                await writer.drain()
                header = await reader.readexactly(4)
                return parse_envelope(
                    await reader.readexactly(struct.unpack(">I", header)[0])
                )
            finally:
                writer.close()

        first = await one("dup-1")
        assert not first.error.code
        second = await one("dup-1")  # fresh connection: same id is legal again
        assert not second.error.code

        # two in-flight uses of one id on the SAME connection: the second
        # use is rejected (serialized here, so the error comes as a reply)
        reader, writer = await _raw_hello(env.socket_path)()
        try:
            frame = t.RpcEnvelope(
                protocol_major=1,
                request_id="dup-2",
                method="agent_meta.public.v1.Runtime.GetInfo",
            )
            frame.payload = get_info
            writer.write(encode_frame(frame.SerializeToString()))
            await writer.drain()
            header = await reader.readexactly(4)
            first_reply = parse_envelope(
                await reader.readexactly(struct.unpack(">I", header)[0])
            )
            assert not first_reply.error.code
            # replaying the identical frame reuses the request_id
            writer.write(encode_frame(frame.SerializeToString()))
            await writer.drain()
            header = await reader.readexactly(4)
            replay = parse_envelope(
                await reader.readexactly(struct.unpack(">I", header)[0])
            )
            assert replay.error.code != 0
        finally:
            writer.close()

    run_env(test, tmp_path)


def test_client_response_envelope_closes_connection(tmp_path):
    async def test(env):
        reader, writer = await _raw_hello(env.socket_path)()
        try:
            bad = t.RpcEnvelope(protocol_major=1, request_id="x", method="Whatever")
            bad.is_response = True
            writer.write(encode_frame(bad.SerializeToString()))
            await writer.drain()
            with pytest.raises(asyncio.IncompleteReadError):
                await asyncio.wait_for(reader.readexactly(4), 5.0)
        finally:
            writer.close()

    run_env(test, tmp_path)


async def _put_bytes(env, data: bytes, kind: str) -> str:
    """Upload one artifact over the wire and return its artifact id."""

    digest = hashlib.sha256(data).hexdigest()
    begin = await env.client.call(
        "agent_meta.public.v1.Artifact.BeginPut",
        pub.BeginPutRequest(expected_size=len(data), expected_sha256=digest),
        pub.BeginPutResponse,
    )
    await env.client.call(
        "agent_meta.public.v1.Artifact.PutChunk",
        pub.PutChunkRequest(
            staging_handle=begin.staging_handle,
            offset=0,
            data=data,
            chunk_sha256=digest,
        ),
        pub.PutChunkResponse,
    )
    artifact_id = "artifact://sha256/" + digest
    envelope = make_envelope(
        env.realm,
        "artifact.put/v1",
        {
            "source_staging_handle": begin.staging_handle,
            "expected_sha256": digest,
            "expected_size": len(data),
            "kind": kind,
            "media_type": "application/json",
            "parents": [],
        },
    )
    await env.client.call(
        "agent_meta.public.v1.Artifact.Put",
        pub.CommandRequest(command_envelope_jcs=canonical_json(envelope)),
        pub.MutationResponse,
    )
    return artifact_id


def test_harness_lifecycle_over_wire(tmp_path):
    async def test(env):
        from tests.unit.test_public_package_contract import Bundle

        # A structurally plausible manifest with fake package bytes must not
        # pass validation. It used to do so before content validation landed.
        package_bytes = json.dumps({"ampak": 1}).encode()
        package_art = await _put_bytes(env, package_bytes, "code")
        manifest = {
            "schema": "harness-package/v1",
            "package_name": "org.example.harness",
            "package_version": "0.1.0",
            "package_artifact_id": package_art,
            "publisher_identity_artifact_id": package_art,
            "signature_artifact_id": package_art,
            "public_api_range": ">=1.0.0 <2.0.0",
            "harness_contract_range": ">=1.0.0 <2.0.0",
            "capability_contract_range": ">=1.0.0 <2.0.0",
            "artifact_format": "AMPAK1",
            "capability_descriptor_artifact_ids": [package_art],
            "composition_template_artifact_id": package_art,
            "grant_requests_artifact_id": package_art,
            "loop_policy_artifact_id": package_art,
            "required_backend_features": ["model.invoke"],
            "optional_backend_features": [],
            "build_provenance_artifact_id": package_art,
        }
        manifest_art = await _put_bytes(env, json.dumps(manifest).encode(), "contract")
        body_bytes = json.dumps({"schema": "composition/v1", "realm_id": env.realm}).encode()
        body_art = await _put_bytes(env, body_bytes, "composition")

        # ValidatePackage accepts a well-formed manifest
        report = await env.client.call(
            "agent_meta.public.v1.Harness.ValidatePackage",
            pub.ValidateHarnessPackageRequest(manifest_artifact_id=manifest_art),
            pub.ResourceResponse,
        )
        assert json.loads(bytes(report.resource_jcs))["valid"] is False

        bundle = Bundle()
        bundle.manifest["capability_descriptor_artifact_ids"] = [bundle.doc({
            "capability_id": "capability://example.fake", "descriptor_revision": 1,
            "artifact_id": bundle.manifest["package_artifact_id"], "placement": "isolated_process",
            "trust_class": "trusted_candidate", "operations": [], "provides": [], "requires": [],
        })]
        grants = [{"permission": "model.invoke", "scope": {"realm_id": env.realm, "targets": [{"type": "CAPABILITY", "id": "capability://example.fake"}]}}]
        bundle.manifest["grant_requests_artifact_id"] = bundle.doc({"schema": "harness-grant-requests/v1", "requests": grants})
        manifest_art = bundle.sign()
        for artifact_bytes in bundle.blobs.values():
            await _put_bytes(env, artifact_bytes, "code")
        package_art = bundle.manifest["package_artifact_id"]
        body_art = bundle.manifest["composition_template_artifact_id"]
        report = await env.client.call(
            "agent_meta.public.v1.Harness.ValidatePackage",
            pub.ValidateHarnessPackageRequest(manifest_artifact_id=manifest_art),
            pub.ResourceResponse,
        )
        report_body = json.loads(bytes(report.resource_jcs))
        assert report_body["valid"] is True, report_body

        # Install is idempotent over the wire
        install_env = make_envelope(
            env.realm,
            "harness.install/v1",
            {
                "package_name": bundle.meta.name,
                "package_version": "0.1.0",
                "manifest_artifact_id": manifest_art,
                "package_artifact_id": package_art,
                "contract_fingerprint": report_body["contract_fingerprint"],
            },
        )
        request = pub.CommandRequest(command_envelope_jcs=canonical_json(install_env))
        mut = await env.client.call(
            "agent_meta.public.v1.Harness.Install", request, pub.MutationResponse
        )
        harness_id = json.loads(bytes(mut.resource_jcs))["harness_id"]
        mut2 = await env.client.call(
            "agent_meta.public.v1.Harness.Install", request, pub.MutationResponse
        )
        assert json.loads(bytes(mut2.resource_jcs))["harness_id"] == harness_id

        got = await env.client.call(
            "agent_meta.public.v1.Harness.Get",
            pub.GetHarnessRequest(harness_id=harness_id),
            pub.ResourceResponse,
        )
        assert json.loads(bytes(got.resource_jcs))["status"] == "INSTALLED"

        # The bootstrapped Service receives a properly delegated scoped Grant.
        activate_env = make_envelope(
            env.realm,
            "harness.activate/v1",
            {
                "harness_id": harness_id,
                "composition_body_artifact_id": body_art,
                "grant_requests": grants,
                "plan_hash": report_body["plan_hash"],
                "grant_request_hash": hashlib.sha256(canonical_json(grants)).hexdigest(),
                "expected_serving_revision": 1,
            },
            expected_meta_revision=env.conn.execute("SELECT current_meta_revision FROM realms").fetchone()[0],
        )
        act = await env.client.call(
            "agent_meta.public.v1.Harness.Activate",
            pub.CommandRequest(command_envelope_jcs=canonical_json(activate_env)),
            pub.MutationResponse,
        )
        resource = json.loads(bytes(act.resource_jcs))
        # env seeds the semantic composition at revision 1; activation is revision 2
        assert resource["revision"] == 2 and len(resource["grant_ids"]) == 1

        listing = await env.client.call(
            "agent_meta.public.v1.Harness.List",
            pub.ListHarnessRequest(realm_id=env.realm),
            pub.ResourceResponse,
        )
        rows = json.loads(bytes(listing.resource_jcs))["harnesses"]
        assert [r["harness_id"] for r in rows] == [harness_id]

    run_env(test, tmp_path)


def test_evolution_surface_over_wire(tmp_path):
    async def test(env):
        from agent_meta_runtime.adapters.store.evolution import (
            CreateWorldRequest,
            RegisterCandidateRequest,
            create_world,
            register_candidate,
        )
        from agent_meta_runtime.domain.semantics import TaskBudget
        from conftest import _seed_artifact, artifact_id
        from test_evolution_runner import CRITERIA
        from test_evolution_store import _baseline_chain, _run, _seed_baseline

        # Store-level seed: capabilities, candidate artifact, baseline chain.
        for tag in ("cand", "suite"):
            _seed_artifact(env.conn, artifact_id(tag))
        for capability in ("capability://echo", "capability://extra"):
            descriptor = artifact_id("cap:" + capability)
            _seed_artifact(env.conn, descriptor)
            env.conn.execute(
                "INSERT INTO capabilities(capability_id, descriptor_revision,"
                " artifact_id, descriptor_json, created_at_us)"
                " VALUES (?, 1, ?, ?, 1)",
                (capability, descriptor, b"{}"),
            )
        baseline = _seed_baseline(env.conn)
        baseline_revision = int(
            env.conn.execute(
                "SELECT revision FROM compositions WHERE composition_id = ?",
                (baseline,),
            ).fetchone()[0]
        )
        _proposal_id, change_set_id = _baseline_chain(env.conn, baseline)
        candidate = _run(
            env.conn,
            register_candidate(
                RegisterCandidateRequest(
                    realm_id=env.realm,
                    change_set_id=change_set_id,
                    trust_class="trusted_candidate",
                    artifact_ids=(artifact_id("cand"),),
                )
            ),
        )
        fixture_bytes = json.dumps(
            {
                "fixtures": [
                    {"slot": "echo", "expected_capability": "capability://echo"},
                    {"slot": "extra", "expected_capability": "capability://extra"},
                ]
            }
        ).encode()
        fixture_art = await _put_bytes(env, fixture_bytes, "fixture")
        world_id = _run(
            env.conn,
            create_world(
                CreateWorldRequest(
                    realm_id=env.realm,
                    backend_profile_hash="bph",
                    fixture_artifact_ids=(fixture_art,),
                    state_snapshot_ids=(),
                    environment_allowlist=("python3",),
                    workspace_quota={"max_bytes": 1000},
                    budget=TaskBudget(max_turns=2, max_steps=4, max_model_calls=2),
                    seed=7,
                    replay_level="FULL",
                )
            ),
        )["world_id"]
        env.conn.commit()
        criteria_art = await _put_bytes(env, json.dumps(CRITERIA).encode(), "criteria")

        # Propose over the wire.
        propose_env = make_envelope(
            env.realm,
            "evolution.propose/v1",
            {
                "hypothesis": "swap echo artifact",
                "source_evidence_ids": [],
                "target_composition_id": baseline,
            },
        )
        prop = await env.client.call(
            "agent_meta.public.v1.Evolution.Propose",
            pub.CommandRequest(command_envelope_jcs=canonical_json(propose_env)),
            pub.MutationResponse,
        )
        assert json.loads(bytes(prop.resource_jcs))["proposal_id"].startswith(
            "proposal://"
        )

        # RunExperiment over the wire.
        run_envelope = make_envelope(
            env.realm,
            "experiment.run/v1",
            {
                "candidate_id": candidate["candidate_id"],
                "baseline_id": baseline,
                "world_id": world_id,
                "criteria_artifact_id": criteria_art,
            },
        )
        run = await env.client.call(
            "agent_meta.public.v1.Evolution.RunExperiment",
            pub.CommandRequest(command_envelope_jcs=canonical_json(run_envelope)),
            pub.MutationResponse,
        )
        run_resource = json.loads(bytes(run.resource_jcs))
        assert run_resource["status"] == "COMPLETED"
        assert run_resource["decision"] == "ACCEPT"
        experiment_id = run_resource["experiment_id"]

        got = await env.client.call(
            "agent_meta.public.v1.Evolution.GetExperiment",
            pub.GetExperimentRequest(experiment_id=experiment_id),
            pub.ResourceResponse,
        )
        assert json.loads(bytes(got.resource_jcs))["status"] == "COMPLETED"

        waited = await env.client.call(
            "agent_meta.public.v1.Evolution.WaitExperiment",
            pub.WaitExperimentRequest(
                experiment_id=experiment_id,
                wait_deadline_at_us=int(time.time() * 1e6) + 1_000_000,
            ),
            pub.TaskWaitResponse,
        )
        assert waited.terminal is True

        # Promote over the wire: serving stays at revision 1, desired moves.
        promote_envelope = make_envelope(
            env.realm,
            "candidate.promote/v1",
            {
                "candidate_id": candidate["candidate_id"],
                "evaluation_id": run_resource["evaluation_id"],
                "expected_serving_revision": 1,
            },
        )
        prom = await env.client.call(
            "agent_meta.public.v1.Evolution.Promote",
            pub.CommandRequest(command_envelope_jcs=canonical_json(promote_envelope)),
            pub.MutationResponse,
        )
        promoted = json.loads(bytes(prom.resource_jcs))
        assert promoted["desired_revision"] == candidate["revision"]
        assert promoted["reconcile_status"] == "PENDING"

        # Rollback over the wire: new tracked transition back to the parent.
        rollback_envelope = make_envelope(
            env.realm,
            "composition.rollback/v1",
            {
                "target_parent_id": baseline,
                "expected_serving_revision": 1,
                "state_strategy": "KEEP_COMPATIBLE",
                "reason_code": "operator_rollback",
            },
        )
        rb = await env.client.call(
            "agent_meta.public.v1.Evolution.Rollback",
            pub.CommandRequest(
                command_envelope_jcs=canonical_json(rollback_envelope)
            ),
            pub.MutationResponse,
        )
        rolled_back = json.loads(bytes(rb.resource_jcs))
        assert rolled_back["desired_revision"] == baseline_revision
        assert rolled_back["state_strategy"] == "KEEP_COMPATIBLE"

    run_env(test, tmp_path)
