"""Public wire identity proof and transactional authorization regressions."""

from dataclasses import replace
import time

import pytest

from agent_meta_runtime.adapters.store.authority import load_grant_row, _insert_grant
from agent_meta_runtime.adapters.store.command_authority import authorize_public_command, guard_public_command
from agent_meta_runtime.adapters.store.uow import execute_command, RejectedResult
from agent_meta_runtime.domain.authority import Scope, ScopeTarget, GrantConstraints
from agent_meta_runtime.domain.canonical import canonical_json
from agent_meta_runtime.domain.deadline import Deadline
from agent_meta_runtime.domain.errors import StableError, ErrorCode
from agent_meta_runtime.domain.ids import new_uuid7
from agent_meta_runtime.protocols._v1 import public_pb2 as pub
from agent_meta_runtime.sdk import CommandAuthority, decode_command, encode_command, sign_command
from test_local_server import make_envelope, run_env


def _submit(env):
    return decode_command(canonical_json(make_envelope(env.realm, "task.submit/v1", {
        "input_artifact_id": env.input_artifact, "budget": {"max_turns": 2},
    })))


async def _send(env, envelope):
    return await env.client.call("agent_meta.public.v1.Task.Submit",
        pub.CommandRequest(command_envelope_jcs=encode_command(envelope).encode()), pub.MutationResponse)


@pytest.mark.parametrize("variant", ["unsigned", "bad_signature", "stale", "future", "wrong_grant", "changed_payload"])
def test_wire_rejects_unproven_commands_without_side_effects(tmp_path, variant):
    async def test(env):
        envelope = _submit(env)
        if variant == "unsigned":
            envelope = replace(envelope, auth_nonce=None, auth_issued_at_us=None, auth_signature=None)
        elif variant == "bad_signature":
            envelope = replace(envelope, auth_signature=b"x" * 64)
        elif variant in ("stale", "future"):
            offset = -301_000_000 if variant == "stale" else 301_000_000
            envelope = sign_command(envelope, env.authority, issued_at_us=time.time_ns() // 1000 + offset)
        elif variant == "wrong_grant":
            authority = replace(env.authority, authority_grant_id="grant://" + new_uuid7())
            envelope = sign_command(replace(envelope, authority_grant_id=authority.authority_grant_id), authority)
        else:
            envelope = replace(envelope, payload={**envelope.payload, "budget": {"max_turns": 9}})
        before = env.conn.execute("SELECT current_meta_revision FROM realms").fetchone()[0]
        uses = env.conn.execute("SELECT COUNT(*) FROM authority_uses").fetchone()[0]
        with pytest.raises(StableError) as denied:
            await _send(env, envelope)
        assert denied.value.code == ErrorCode.AUTHORITY_DENIED
        assert env.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0
        assert env.conn.execute("SELECT COUNT(*) FROM authority_uses").fetchone()[0] == uses
        assert env.conn.execute("SELECT current_meta_revision FROM realms").fetchone()[0] == before
    run_env(test, tmp_path)


def test_committed_replay_after_revocation_requires_signature_and_does_not_charge(tmp_path):
    async def test(env):
        envelope = _submit(env)
        first = await _send(env, envelope)
        uses = env.conn.execute("SELECT COUNT(*) FROM authority_uses").fetchone()[0]
        assert uses == 1
        env.conn.execute("UPDATE authority_grants SET status='REVOKED' WHERE grant_id=?", (env.authority.authority_grant_id,))
        env.conn.commit()
        env.serving_ready = False
        env.conn.execute("UPDATE composition_refs SET serving_revision=0")
        env.conn.commit()
        replay = await _send(env, envelope)
        assert replay == first
        assert env.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1
        assert env.conn.execute("SELECT COUNT(*) FROM authority_uses").fetchone()[0] == uses
        unsigned = replace(envelope, auth_nonce=None, auth_issued_at_us=None, auth_signature=None)
        with pytest.raises(StableError) as denied:
            await _send(env, unsigned)
        assert denied.value.code == ErrorCode.AUTHORITY_DENIED
        with pytest.raises(StableError) as denied:
            await _send(env, _submit(env))
        assert denied.value.code == ErrorCode.AUTHORITY_DENIED
    run_env(test, tmp_path)


def test_nonce_cannot_be_reused_by_a_different_command(tmp_path):
    async def test(env):
        envelope = _submit(env)
        await _send(env, envelope)
        other = sign_command(replace(envelope, command_id="task://" + new_uuid7()), env.authority,
                             nonce=envelope.auth_nonce, issued_at_us=envelope.auth_issued_at_us)
        with pytest.raises(StableError) as denied:
            await _send(env, other)
        assert denied.value.details["reason_code"] == "NONCE_REUSED"
        # Simulate a nonce being claimed between read-only preview and BEGIN.
        result = execute_command(env.conn, other, guard_public_command(other, lambda txn: {"bad": True}),
                                 deadline=Deadline.after(5_000_000))
        assert isinstance(result, RejectedResult)
        assert result.error.details["reason_code"] == "NONCE_REUSED"
        assert env.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1
        assert env.conn.execute("SELECT COUNT(*) FROM authority_uses").fetchone()[0] == 1
    run_env(test, tmp_path)


@pytest.mark.parametrize("variant", ["permission", "scope", "epoch", "expired", "exhausted", "revoked", "subject"])
def test_valid_signature_cannot_expand_grant_authority(tmp_path, variant):
    async def test(env):
        parent = load_grant_row(env.conn, env.authority.authority_grant_id)
        changes = {"grant_id": "grant://" + new_uuid7(), "parent_grant_id": parent.grant_id}
        if variant == "permission":
            changes["permissions"] = frozenset({"task.cancel"})
        elif variant == "scope":
            changes["scope"] = Scope(env.realm, (ScopeTarget("TASK", "task://" + new_uuid7()),))
        elif variant == "epoch":
            changes["epoch_id"] = "epoch://" + new_uuid7()
        elif variant == "expired":
            changes["constraints"] = GrantConstraints(expires_at_us=1)
        elif variant == "exhausted":
            changes["constraints"] = GrantConstraints(max_uses=0)
        elif variant == "revoked":
            changes["status"] = "REVOKED"
        else:
            changes["subject_id"] = "principal://service/01900000-0000-7000-8000-000000000001"
        grant = replace(parent, **changes)
        seed = replace(_submit(env), command_id="task://" + new_uuid7(), auth_nonce=None, auth_signature=None, auth_issued_at_us=None)
        execute_command(env.conn, seed, lambda txn: (_insert_grant(txn, grant) or {}), deadline=Deadline.after(5_000_000))
        authority = replace(env.authority, authority_grant_id=grant.grant_id)
        envelope = sign_command(replace(_submit(env), authority_grant_id=grant.grant_id), authority)
        with pytest.raises(StableError) as denied:
            await _send(env, envelope)
        assert denied.value.code == ErrorCode.AUTHORITY_DENIED
        assert env.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0
    run_env(test, tmp_path)


def test_guard_rolls_back_business_mutation_and_use_on_business_failure(tmp_path):
    async def test(env):
        envelope = _submit(env)
        def broken(txn):
            txn._conn.execute("UPDATE realms SET current_meta_revision=999 WHERE realm_id=?", (env.realm,))
            raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="synthetic business failure")
        before = env.conn.execute("SELECT current_meta_revision FROM realms").fetchone()[0]
        result = execute_command(env.conn, envelope, guard_public_command(envelope, broken), deadline=Deadline.after(5_000_000))
        assert isinstance(result, RejectedResult)
        assert env.conn.execute("SELECT current_meta_revision FROM realms").fetchone()[0] == before
        assert env.conn.execute("SELECT COUNT(*) FROM authority_uses").fetchone()[0] == 0
    run_env(test, tmp_path)


def test_transaction_guard_rechecks_authority_after_preview(tmp_path):
    async def test(env):
        envelope = _submit(env)
        authorize_public_command(env.conn, envelope, now_us=time.time_ns() // 1000, replay_lookup=True)
        env.conn.execute("UPDATE authority_grants SET status='REVOKED' WHERE grant_id=?", (env.authority.authority_grant_id,))
        env.conn.commit()
        mutated = []
        result = execute_command(env.conn, envelope,
            guard_public_command(envelope, lambda txn: (mutated.append(True) or {})), deadline=Deadline.after(5_000_000))
        assert isinstance(result, RejectedResult)
        assert result.error.code == ErrorCode.AUTHORITY_DENIED
        assert not mutated
        assert env.conn.execute("SELECT COUNT(*) FROM authority_uses").fetchone()[0] == 0
    run_env(test, tmp_path)


def test_stale_meta_revision_rejected_before_mutation(tmp_path):
    async def test(env):
        envelope = sign_command(replace(_submit(env), expected_meta_revision=0), env.authority)
        with pytest.raises(StableError) as denied:
            await _send(env, envelope)
        assert denied.value.code == ErrorCode.REVISION_CONFLICT
        assert env.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0
        assert env.conn.execute("SELECT COUNT(*) FROM authority_uses").fetchone()[0] == 0
    run_env(test, tmp_path)
