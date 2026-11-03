"""State authority is bound to immutable Realm Facts, not shared owner IDs."""
import pytest

from agent_meta_runtime.adapters.store import (
    StateCreateRequest, StateWriteRequest, StateRevisionRegistration,
    StateMigrationCutoverRequest, bootstrap_realm, initialize_store,
    create_state, write_state_revision, register_migration_target,
    migrate_state_cutover, execute_command, get_current_view, get_historical_view,
)
from agent_meta_runtime.domain.deadline import Deadline
from agent_meta_runtime.domain.envelope import CommandEnvelope
from agent_meta_runtime.domain.ids import new_uuid7
from agent_meta_runtime.domain.canonical import canonical_json
from agent_meta_runtime.domain.errors import StableError
from agent_meta_runtime.adapters.store.task_snapshot import acceptance_view
from agent_meta_runtime.adapters.store.experiment_runner import _clone_states

ACTOR = 'principal://operator-root/01900000-0000-7000-8000-000000000000'
OWNER = 'capability://shared-owner'
A, B = 'realm://a', 'realm://b'
ARTIFACT = 'artifact://sha256/' + 'a' * 64


def command(conn, realm, mutator):
    envelope = CommandEnvelope(command_id='task://' + new_uuid7(), realm_id=realm,
        actor_id=ACTOR, authority_grant_id=None, expected_meta_revision=None,
        causal_parent_action_id=None, payload_type='task.submit/v1',
        payload_schema_version=1, payload={}, auth_nonce=None,
        auth_issued_at_us=None, auth_signature=None)
    return execute_command(conn, envelope, mutator, deadline=Deadline.after(5_000_000))


@pytest.fixture
def realms(tmp_path):
    conn = initialize_store(tmp_path / 'meta.db')
    for realm in (A, B):
        bootstrap_realm(conn, realm, 'epoch://' + new_uuid7())
    conn.execute("INSERT INTO artifacts(artifact_id,kind,media_type,size_bytes,schema_version,created_by,created_at_us,parents_json,manifest_json,integrity_status) VALUES (?, 'code', 'application/json',0,1,?,1,?,?,'VALID')", (ARTIFACT, ACTOR, b'{}', b'{}'))
    conn.commit()
    created = []
    for realm in (A, B):
        result = command(conn, realm, create_state(StateCreateRequest(
            owner_id=OWNER, schema_id='schema://state', artifact_id=ARTIFACT)))
        assert not hasattr(result, 'error'), result
        created.append(dict(result.receipt))
    yield conn, *created
    conn.close()


@pytest.mark.parametrize('historical', [False, True])
def test_state_views_exclude_other_realms(realms, historical):
    conn, left, right = realms
    for realm, own in ((A, left), (B, right)):
        view = get_historical_view(conn, realm, 1) if historical else get_current_view(conn, realm)
        assert view.state_revision_bindings == {own['state_id']: own['state_revision_id']}


@pytest.mark.parametrize('operation', ['write', 'register', 'cutover'])
def test_state_mutations_cannot_move_another_realms_state(realms, operation):
    conn, left, right = realms
    binding = StateRevisionRegistration(state_id=left['state_id'],
        source_revision_id=left['state_revision_id'], schema_id='schema://state', artifact_id=ARTIFACT)
    target = command(conn, A, register_migration_target(binding))
    assert not hasattr(target, 'error')
    before = tuple(conn.execute('SELECT current_revision_id,cas_revision FROM managed_states WHERE state_id=?', (left['state_id'],)).fetchone())
    if operation == 'write':
        mutator = write_state_revision(StateWriteRequest(left['state_id'], left['state_revision_id'], 1, 'schema://state', ARTIFACT, ACTOR))
    elif operation == 'register':
        mutator = register_migration_target(binding)
    else:
        registered = StateRevisionRegistration(state_id=left['state_id'], source_revision_id=left['state_revision_id'],
            schema_id='schema://state', artifact_id=ARTIFACT, state_revision_id=target.receipt['state_revision_id'])
        mutator = migrate_state_cutover(StateMigrationCutoverRequest([registered]))
    result = command(conn, B, mutator)
    assert hasattr(result, 'error') and result.error.code == 'NOT_FOUND'
    assert tuple(conn.execute('SELECT current_revision_id,cas_revision FROM managed_states WHERE state_id=?', (left['state_id'],)).fetchone()) == before


def test_acceptance_freezes_only_states_in_its_own_realm(realms):
    conn, left, right = realms
    composition = 'composition://' + new_uuid7()
    body = canonical_json({'slots': {'tool': {'capability_id': OWNER}}})
    conn.execute('INSERT INTO compositions(composition_id,realm_id,revision,parent_id,body_json,body_hash,created_by,created_at_us) VALUES (?,?,1,NULL,?,?,?,1)',
        (composition, A, body, 'fixture', ACTOR))
    conn.execute("INSERT INTO composition_refs(realm_id,serving_revision,reconcile_status) VALUES (?,1,'READY')", (A,))
    conn.commit()
    frozen = acceptance_view(conn, realm_id=A, actor_id=ACTOR, composition_id=composition,
        serving_revision=1, surface_artifact_id=ARTIFACT, authority_fingerprint='fixture', backend_profile_hash='fixture')
    assert frozen['value']['state_snapshot'] == {left['state_id']: left['state_revision_id']}


def test_state_history_uses_realm_revision_numbers_and_retains_old_heads(realms):
    conn, left, right = realms
    changed = command(conn, A, write_state_revision(StateWriteRequest(
        left['state_id'], left['state_revision_id'], 1, 'schema://state', ARTIFACT, ACTOR)))
    assert not hasattr(changed, 'error')
    assert get_current_view(conn, A).state_revision_bindings == {left['state_id']: changed.receipt['state_revision_id']}
    assert get_historical_view(conn, A, 1).state_revision_bindings == {left['state_id']: left['state_revision_id']}
    assert get_historical_view(conn, B, 1).state_revision_bindings == {right['state_id']: right['state_revision_id']}


def test_experiment_clone_cannot_read_other_realm_state(realms):
    conn, left, right = realms
    before = conn.execute('SELECT COUNT(*) FROM managed_states').fetchone()[0]
    result = command(conn, B, lambda txn: {'result': _clone_states(txn, {'states': {'foreign': {'state_id': left['state_id']}}})})
    assert hasattr(result, 'error') and result.error.code == 'NOT_FOUND'
    assert conn.execute('SELECT COUNT(*) FROM managed_states').fetchone()[0] == before


def test_inconsistent_state_head_cannot_import_other_realm_revision(realms):
    conn, left, right = realms
    conn.execute('UPDATE managed_states SET current_revision_id=? WHERE state_id=?', (right['state_revision_id'], left['state_id']))
    conn.commit()
    with pytest.raises(StableError) as caught:
        get_current_view(conn, A)
    assert caught.value.code == 'INTEGRITY_ERROR'
