"""ADR 042: actual IPC ordinary reads and classification/integrity guards."""

import asyncio
import hashlib
import json
from pathlib import Path
import struct

import pytest

from agent_meta_runtime.adapters.cas import FilesystemCas
from agent_meta_runtime.domain.canonical import canonical_json
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.protocols._v1 import public_pb2 as pub, transport_pb2 as t
from agent_meta_runtime.protocols.public_wire import encode_frame, parse_envelope
from agent_meta_runtime.sdk import AgentMetaClient, connect
from test_local_server import ACTOR, _raw_hello, run_env


async def upload(env, client, content):
    return (await client.put_artifact(realm_id=env.realm, actor_id=ACTOR, content=content,
        kind="data", media_type="application/octet-stream"))["artifact_id"]


@pytest.mark.parametrize("content", [b"", b"\x00\x1a\xff\r\n", bytes(range(256)) * 4096])
def test_public_sdk_reads_empty_binary_and_exact_one_mib_without_mutation(tmp_path, content):
    async def scenario(env):
        client = await connect(env.tmp_path, authority=env.authority)
        try:
            reference = await upload(env, client, content)
            before = env.conn.total_changes
            assert await client.get_artifact_content(reference) == content
            assert await client.get_artifact_content(reference) == content
            assert env.conn.total_changes == before
            response = await env.client.call("agent_meta.public.v1.Artifact.GetContent", pub.GetArtifactRequest(artifact_id=reference), pub.ResourceResponse)
            value = json.loads(response.resource_jcs)
            assert set(value) == {"artifact_id", "kind", "media_type", "size_bytes", "content_hex", "resource_type", "schema_version"}
            assert value["content_hex"] == content.hex()
        finally:
            await client.aclose()
    run_env(scenario, tmp_path)


def test_oversized_content_is_refused_before_opening_cas(tmp_path, monkeypatch):
    async def scenario(env):
        client = await connect(env.tmp_path, authority=env.authority)
        try:
            reference = await upload(env, client, b"x" * (1024 * 1024 + 1))
            def forbidden(*args):
                raise AssertionError("oversized read opened CAS")
            monkeypatch.setattr(env.cas, "open_blob", forbidden)
            before = env.conn.total_changes
            with pytest.raises(StableError) as error:
                await client.get_artifact_content(reference)
            assert error.value.code == ErrorCode.RESOURCE_EXHAUSTED and env.conn.total_changes == before
        finally:
            await client.aclose()
    run_env(scenario, tmp_path)


@pytest.mark.parametrize("fault,code", [("missing", "NOT_FOUND"), ("bytes", "INTEGRITY_ERROR"), ("registered_corrupt", "INTEGRITY_ERROR")])
def test_storage_failures_expose_no_private_path_or_content(tmp_path, fault, code):
    async def scenario(env):
        client = await connect(env.tmp_path, authority=env.authority)
        try:
            reference = await upload(env, client, b"original")
            manifest = json.loads(env.conn.execute("SELECT manifest_json FROM artifacts WHERE artifact_id=?", (reference,)).fetchone()[0])
            # Runtime-owned disk/metadata fault injection, never consumer proof.
            path = env.cas.absolute_path(manifest["storage_relpath"])
            if fault == "missing":
                path.unlink()
            elif fault == "bytes":
                path.write_bytes(b"secret corruption")
            else:
                env.conn.execute("UPDATE artifacts SET integrity_status='CORRUPT' WHERE artifact_id=?", (reference,))
                env.conn.commit()
            with pytest.raises(StableError) as error:
                await client.get_artifact_content(reference)
            assert error.value.code == code
            assert "storage_relpath" not in error.value.details
            assert str(tmp_path) not in str(error.value) and "secret corruption" not in str(error.value)
        finally:
            await client.aclose()
    run_env(scenario, tmp_path)


@pytest.mark.parametrize("classification", ["blob_active", "blob_deleted", "encryption_active", "encryption_crypto_erased"])
def test_restricted_or_tombstoned_metadata_cannot_fall_back_to_plaintext(tmp_path, monkeypatch, classification):
    async def scenario(env):
        client = await connect(env.tmp_path, authority=env.authority)
        try:
            reference = await upload(env, client, b"plaintext copy must not bypass classification")
            blob = "blob://sha256/" + hashlib.sha256(classification.encode()).hexdigest()
            # Classification-only fault fixtures do not claim encryption works.
            encrypted_row = classification.startswith("encryption_")
            env.conn.execute("INSERT INTO artifact_blobs(blob_id,artifact_id,realm_id,storage_class,size_bytes,storage_relpath,status,created_at_us) VALUES (?,?,?,?,1,?,?,1)",
                (blob, reference, env.realm, "PLAIN_CAS" if encrypted_row else "ENCRYPTED_RESTRICTED", "guard/" + classification,
                 "DELETED" if classification == "blob_deleted" else "ACTIVE"))
            if encrypted_row:
                env.conn.execute("INSERT INTO artifact_encryption(artifact_id,realm_id,encryption_revision,blob_id,algorithm,key_handle,wrapped_dek,content_nonce,wrap_nonce,aad_hash,ciphertext_hash,status,created_at_us) VALUES (?,?,1,?,'AES-256-GCM','never-read',?,?,?,?,?,?,1)",
                    (reference, env.realm, blob, b"wrapped", b"nonce", b"nonce", "0" * 64, "0" * 64,
                     "CRYPTO_ERASED" if classification.endswith("crypto_erased") else "ACTIVE"))
            env.conn.commit()
            def forbidden(*args):
                raise AssertionError("restricted read reached plaintext CAS")
            monkeypatch.setattr(env.cas, "open_blob", forbidden)
            with pytest.raises(StableError) as error:
                await client.get_artifact_content(reference)
            assert error.value.code == ErrorCode.AUTHORITY_DENIED
        finally:
            await client.aclose()
    run_env(scenario, tmp_path)


@pytest.mark.parametrize("minor", [0, 1, 2])
def test_older_negotiated_minor_refuses_content_method(tmp_path, minor):
    async def scenario(env):
        reader, writer = await _raw_hello(env.socket_path, minor=minor)()
        try:
            request = t.RpcEnvelope(protocol_major=1, protocol_minor=minor, request_id="old-content", method="agent_meta.public.v1.Artifact.GetContent",
                payload=pub.GetArtifactRequest(artifact_id=env.input_artifact).SerializeToString())
            writer.write(encode_frame(request.SerializeToString()))
            await writer.drain()
            size = struct.unpack(">I", await reader.readexactly(4))[0]
            response = parse_envelope(await reader.readexactly(size))
            assert response.error.code == ErrorCode.CONTRACT_INCOMPATIBLE
        finally:
            writer.close()
            await writer.wait_closed()
    run_env(scenario, tmp_path)


def test_cas_oversized_corruption_reads_only_expected_size_plus_one(tmp_path, monkeypatch):
    cas = FilesystemCas(tmp_path)
    path = cas.absolute_path(cas.put(b"abc"))
    path.write_bytes(b"corruption" * 1000)
    original = Path.open
    reads = []
    class Bounded:
        def __init__(self, file):
            self.file = file
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return self.file.__exit__(*args)
        def read(self, size=-1):
            reads.append(size)
            return self.file.read(size)
    def opened(target, *args, **kwargs):
        file = original(target, *args, **kwargs)
        return Bounded(file) if target == path else file
    monkeypatch.setattr(Path, "open", opened)
    with pytest.raises(StableError) as error:
        cas.open_blob(cas.relpath_for(hashlib.sha256(b"abc").hexdigest()), hashlib.sha256(b"abc").hexdigest(), 3)
    assert error.value.code == ErrorCode.INTEGRITY_ERROR and reads == [4]


@pytest.mark.parametrize("mutation", ["hash", "size_bool", "schema", "kind", "media_type", "noncanonical", "bad_hex", "uppercase_hex", "oversized"])
def test_sdk_independently_rejects_unverifiable_content_response(mutation):
    reference = "artifact://sha256/" + hashlib.sha256(b"ok").hexdigest()
    value = {"artifact_id": reference, "kind": "data", "media_type": "application/octet-stream", "size_bytes": 2,
        "content_hex": b"ok".hex(), "resource_type": "artifact-content/v1", "schema_version": 1}
    if mutation == "hash":
        value["content_hex"] = b"xx".hex()
    elif mutation == "size_bool":
        value["size_bytes"] = True
    elif mutation == "schema":
        value["schema_version"] = 2
    elif mutation in ("kind", "media_type"):
        value[mutation] = 7
    elif mutation == "bad_hex":
        value["content_hex"] = "zzzz"
    elif mutation == "uppercase_hex":
        value["content_hex"] = value["content_hex"].upper()
    elif mutation == "oversized":
        value["size_bytes"] = 1024 * 1024 + 1
    raw = canonical_json(value)
    if mutation == "noncanonical":
        raw += b" "
    class Reply:
        async def call(self, method, request, **kwargs):
            return pub.ResourceResponse(resource_jcs=raw).SerializeToString()
        async def close(self):
            pass
    async def scenario():
        client = AgentMetaClient(Reply())
        with pytest.raises(StableError) as error:
            await client.get_artifact_content(reference)
        assert error.value.code == (ErrorCode.CONTRACT_INCOMPATIBLE if mutation == "schema" else ErrorCode.INTEGRITY_ERROR)
    asyncio.run(scenario())
