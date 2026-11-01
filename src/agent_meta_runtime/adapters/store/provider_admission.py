"""Recheck frozen operator approval at admission and before native dispatch."""

import json

from ...domain.canonical import now_us, sha256_hex
from ...domain.errors import ErrorCode, StableError
from ...domain.host_contract import ProviderRequestPlan
from ...domain.provider_profile import load_profile
from ...domain.provider_transport import ProviderHttpRequest
from .provider_configuration import provider_configuration, provider_configuration_at


def frozen_configuration(store, task, capability_id, *, require_current=True):
    """Read the committed acceptance View, never a caller-supplied projection."""
    record = store.check(task.task_id)
    if task.realm_id != store.realm_id or (record.realm_id, record.actor_id, record.root_action_id, record.serving_composition_id) != (
            store.realm_id, task.actor_id, task.root_action_id, task.serving_composition_id):
        raise StableError(code=ErrorCode.AUTHORITY_DENIED,message='Provider Task identity differs from admission')
    rows = store.conn.execute("SELECT payload_json FROM facts WHERE realm_id=? AND entity_id=? AND event_type='task_accepted'", (store.realm_id,task.task_id)).fetchall()
    try:
        if len(rows) != 1:
            raise ValueError('acceptance Fact')
        reference = json.loads(rows[0][0])['acceptance_view_artifact_id']
        raw = store.read_artifact(reference)
        if reference != 'artifact://sha256/' + sha256_hex(raw):
            raise ValueError('acceptance hash')
        view = json.loads(raw)
        model_capability = view['composition']['slots']['model']['capability_id']
        epoch = store.conn.execute('SELECT epoch_id FROM realms WHERE realm_id=?',(store.realm_id,)).fetchone()[0]
        if (view['schema'] != 'task-acceptance-view/v1' or view['realm_id'] != store.realm_id
                or view['actor_id'] != record.actor_id or view['epoch_id'] != epoch
                or view['composition_id'] != record.serving_composition_id
                or view['serving_revision'] != record.serving_revision):
            raise ValueError('frozen Task scope')
    except (ValueError,TypeError,KeyError,IndexError):
        raise StableError(code=ErrorCode.INTEGRITY_ERROR,message='Provider Task acceptance View is invalid') from None
    reference = view.get('provider_configuration_fact_id')
    if reference is None:
        raise StableError(code=ErrorCode.FAILED_PRECONDITION,message='Task has no frozen Provider approval')
    configuration = provider_configuration_at(store.conn,store.realm_id,reference)
    if (not configuration['enabled'] or configuration['epoch_id'] != epoch
            or configuration['package_artifact_id'] != view.get('package_artifact_id')
            or configuration['capability_id'] != capability_id
            or model_capability != capability_id):
        raise StableError(code=ErrorCode.AUTHORITY_DENIED,message='Provider approval differs from the frozen model binding')
    if require_current:
        installation = store.conn.execute('SELECT realm_id,package_artifact_id,status FROM harness_installations WHERE harness_id=?', (configuration['harness_id'],)).fetchone()
        current = provider_configuration(store.conn,store.realm_id,configuration['harness_id'])
        if (installation is None or installation[:2] != (store.realm_id,configuration['package_artifact_id'])
                or installation[2] == 'UNINSTALLED' or current != configuration):
            raise StableError(code=ErrorCode.AUTHORITY_DENIED,message='Provider approval changed after Task acceptance')
    return configuration


def authorize_configuration(store, task, capability_id, reservation, request):
    """Pure bounded profile checks within the caller's writer transaction.

    This performs no native credential resolution or network I/O. Recomputing
    maximum cost here prevents a prepared callback from under-reserving it.
    Internal v1 accounting fixtures retain their distinct, unconfigured scope.
    """
    if reservation.configuration_fact_id is None:
        return
    if not store.conn.in_transaction:
        raise StableError(code=ErrorCode.INTERNAL,message='Provider approval must be checked in the admission transaction')
    configuration = frozen_configuration(store,task,capability_id)
    if (configuration['configuration_fact_id'] != reservation.configuration_fact_id
            or configuration['profile_artifact_id'] != reservation.profile_artifact_id
            or type(request) is not ProviderHttpRequest
            or request.scope_hash != reservation.request_hash
            or request.deadline_at_us != reservation.deadline_at_us
            or request.credential_handle != configuration['credential_handle']):
        raise StableError(code=ErrorCode.AUTHORITY_DENIED,message='Provider request differs from its approved binding')
    profile,closure = load_profile(configuration['profile_artifact_id'],store.read_artifact)
    if (list(closure) != configuration['verified_artifact_ids']
            or profile.price_policy_artifact_id != reservation.pricing_artifact_id
            or profile.tokenizer_artifact_id != reservation.tokenizer_artifact_id
            or profile.policy != request.policy or profile.model_id != request.model
            or profile.timeout_us != request.timeout_us
            or profile.maximum_response_bytes != request.maximum_response_bytes):
        raise StableError(code=ErrorCode.AUTHORITY_DENIED,message='Provider transport differs from the frozen profile')
    tokens,output,cost = profile.preflight(ProviderRequestPlan(profile.artifact_id,request.body))
    if (tokens,output,cost) != (reservation.input_tokens,reservation.maximum_output_tokens,reservation.maximum_cost_microunits):
        raise StableError(code=ErrorCode.AUTHORITY_DENIED,message='Provider amounts differ from independent profile accounting')
    record = store.check(task.task_id)
    current = now_us()
    if (request.deadline_at_us <= current or request.deadline_at_us > current + profile.timeout_us
            or record.deadline_at_us is not None and request.deadline_at_us > record.deadline_at_us):
        raise StableError(code=ErrorCode.DEADLINE_EXCEEDED,message='Provider deadline exceeds the admitted Task')
