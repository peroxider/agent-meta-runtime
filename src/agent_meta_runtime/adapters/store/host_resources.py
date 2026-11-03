"""Task-scoped Meta resource admission and atomic terminal effects (ADR 060)."""

import json

from ...domain.authority import ScopeTarget, authorize
from ...domain.canonical import canonical_json, sha256_hex
from ...domain.context_contract import context_document, _redactor
from ...domain.errors import ErrorCode, StableError
from ...domain.host_schema import validate_host_value
from ...domain.ids import new_uuid7
from ...domain.resource_contract import (ArtifactRead, ArtifactPut, StateRead, StateWrite,
    ResourceReceipt, resource_request_document, validate_resource_operation, RESOURCE_OPERATION_RULES,
    MAX_RESOURCE_CONTENT_BYTES)
from ...ports.repositories import FactAppendRequest
from .artifact_content import read_artifact_content
from .authority import _GRANT_COLUMNS, _grant_from_row, _reserve_use_row, load_grant_row
from .state import require_state_realm, _insert_revision, _state_ref_history
from .state_management import origin
from .semantic import InvocationFinishRequest, finish_invocation, _append_edge
from .task_snapshot import register_staged_artifact


def _fail(code, message):
    raise StableError(code=code, message=message)


def redact_value(task, value):
    if task.context is None:
        _fail(ErrorCode.FAILED_PRECONDITION, 'resource execution requires a frozen redaction policy')
    artifacts = dict(task.context.artifacts)
    profile = context_document(artifacts[task.context.profile_artifact_id])
    return _redactor(context_document(artifacts[profile['redaction_policy_artifact_id']]))(value)


def sanitize_request(task, request):
    resource_request_document(request)
    if type(request) is ArtifactPut:
        if request.media_type == 'application/json':
            raw = canonical_json(redact_value(task, context_document(request.content)))
        else:
            try:
                raw = redact_value(task, request.content.decode('utf-8')).encode('utf-8')
            except UnicodeError:
                _fail(ErrorCode.INVALID_ARGUMENT, 'resource text must be valid UTF-8')
        return ArtifactPut(request.kind, request.media_type, raw)
    return request


def _ordinary(store, reference):
    value = json.loads(read_artifact_content(store.conn, store.catalog.cas, reference))
    return value['kind'], value['media_type'], bytes.fromhex(value['content_hex'])


def _frozen_state(store, task, state_id):
    require_state_realm(store.conn, state_id, task.realm_id)
    frozen = dict(task.state_snapshot).get(state_id)
    if frozen is None:
        _fail(ErrorCode.AUTHORITY_DENIED, 'State is outside the frozen Task bindings')
    view = context_document(task.acceptance_view_content)
    cas = view.get('state_cas_snapshot', {}).get(state_id)
    # The own overlay is anchored by a successful resource commit Fact, never
    # by a later global head or a mutable invocation projection alone.
    rows = store.conn.execute(
        "SELECT f.payload_json FROM facts f JOIN invocations i ON i.invocation_id=f.entity_id "
        "JOIN actions a ON a.action_id=i.action_id WHERE f.realm_id=? AND a.task_id=? "
        "AND f.event_type='resource_call_committed' AND i.status='SUCCEEDED' ORDER BY f.seq", (task.realm_id, task.task_id))
    for row in rows:
        value = json.loads(row[0])
        receipt = value['receipt']
        if receipt.get('state_id') == state_id and value['contract'] == 'state.write/v1':
            frozen, cas = receipt['state_revision_id'], receipt['cas_revision']
    row = store.conn.execute('SELECT owner_id,schema_id,artifact_id FROM state_revisions WHERE state_id=? AND state_revision_id=?',
        (state_id, frozen)).fetchone()
    if row is None:
        _fail(ErrorCode.INTEGRITY_ERROR, 'frozen State revision is unavailable')
    return {'state_id': state_id, 'state_revision_id': frozen, 'cas_revision': cas,
        'owner_id': row[0], 'schema_id': row[1], 'content_artifact_id': row[2],
        **origin(store.conn,state_id,task.realm_id)}


def _state_target(store, task, owner):
    slots = context_document(task.composition_content)['slots']
    if owner in {slot['capability_id'] for slot in slots.values()}:
        return ScopeTarget('CAPABILITY', owner)
    if owner == task.serving_composition_id:
        row = store.conn.execute('SELECT DISTINCT h.harness_id FROM harness_installations h '
            'JOIN harness_installation_history x ON x.harness_id=h.harness_id '
            'WHERE h.realm_id=? AND x.composition_id=?', (task.realm_id, task.serving_composition_id)).fetchall()
        if len(row) == 1:
            return ScopeTarget('HARNESS', row[0][0])
    _fail(ErrorCode.AUTHORITY_DENIED, 'State owner is outside this installation')


def _service_generation(store, task):
    row = store.conn.execute(
        "SELECT f.payload_json FROM facts f JOIN transactions t ON t.transaction_id=f.transaction_id "
        "WHERE f.realm_id=? AND f.event_type='harness_activated' "
        "AND json_extract(CAST(f.payload_json AS TEXT),'$.phase')='requested' "
        "AND json_extract(CAST(f.payload_json AS TEXT),'$.composition_id')=? "
        "AND t.meta_revision<=? ORDER BY f.seq DESC LIMIT 1",
        (task.realm_id, task.serving_composition_id, task.accepted_meta_revision)).fetchone()
    return set(json.loads(row[0])['grant_ids']) if row else set()


def _claim_target(permission, target):
    return {'permission': permission, 'target': {'type': target.type, 'id': target.id}}


def _find_grant(store, txn, task, subject, claim, generation):
    if txn._conn.execute('SELECT status FROM principals WHERE realm_id=? AND principal_id=?', (task.realm_id, subject)).fetchone() != ('ACTIVE',):
        _fail(ErrorCode.AUTHORITY_DENIED, 'resource principal is inactive')
    epoch = txn._conn.execute('SELECT epoch_id FROM realms WHERE realm_id=?', (task.realm_id,)).fetchone()[0]
    if epoch != context_document(task.acceptance_view_content)['epoch_id']:
        _fail(ErrorCode.AUTHORITY_DENIED, 'resource Task belongs to a previous Epoch')
    for row in txn._conn.execute(f'SELECT {_GRANT_COLUMNS} FROM authority_grants WHERE subject_id=? ORDER BY grant_id', (subject,)):
        grant = _grant_from_row(row)
        if grant.constraints.resource_ceiling or subject == store.service_id and grant.grant_id not in generation:
            continue
        count = txn._conn.execute('SELECT COUNT(*) FROM authority_uses WHERE grant_id=?', (grant.grant_id,)).fetchone()[0]
        if authorize(grant, subject_id=subject, permission=claim['permission'], resource_realm=task.realm_id,
                resource_target=ScopeTarget(**claim['target']), epoch_id=epoch, now_us=txn.recorded_at_us, uses_count=count) is None:
            return grant.grant_id
    _fail(ErrorCode.AUTHORITY_DENIED, 'resource authority denied')


def admission(store, txn, task, capability_id, operation, request):
    from ...domain.scratch_execution import is_scratch_request
    if is_scratch_request(request):
        from .scratch_admission import admission as scratch_admission
        return scratch_admission(store, txn, task, capability_id, operation, request)
    validate_resource_operation(operation)
    document = resource_request_document(request)
    contract = document['schema']
    if operation.get('resource_contract') != contract:
        _fail(ErrorCode.INVALID_RESULT, 'resource plan differs from the frozen operation')
    current = store.check(task.task_id)
    if (current.realm_id, current.actor_id, current.root_action_id, current.serving_composition_id) != (
            task.realm_id, task.actor_id, task.root_action_id, task.serving_composition_id):
        _fail(ErrorCode.INTEGRITY_ERROR, 'resource Task binding differs from its admission')
    binding = {}
    additional_claims = []
    if type(request) in (StateRead, StateWrite):
        binding = _frozen_state(store, task, request.state_id)
        if binding['purpose'] != 'GENERAL':
            _fail(ErrorCode.AUTHORITY_DENIED, 'session State is reserved for its controller')
        target = _state_target(store, task, binding['owner_id'])
        permission = 'state.write' if type(request) is StateWrite else 'state.read'
        if type(request) is StateWrite:
            if request.expected_state_revision_id != binding['state_revision_id']:
                _fail(ErrorCode.REVISION_CONFLICT, 'State expected revision differs from the Task snapshot')
            if type(binding['cas_revision']) is not int:
                _fail(ErrorCode.FAILED_PRECONDITION, 'Task has no frozen State CAS revision')
            head = txn._conn.execute('SELECT current_revision_id,cas_revision,schema_id,status FROM managed_states WHERE state_id=?', (request.state_id,)).fetchone()
            if head != (binding['state_revision_id'], binding['cas_revision'], binding['schema_id'], 'ACTIVE'):
                _fail(ErrorCode.REVISION_CONFLICT, 'State changed since the Task snapshot')
            source_kind = _ordinary(store, request.content_artifact_id)[0]
            additional_claims.append(_claim_target('capability.invoke', ScopeTarget('ARTIFACT_KIND', source_kind)))
    else:
        kind = request.kind if type(request) is ArtifactPut else _ordinary(store, request.artifact_id)[0]
        target, permission = ScopeTarget('ARTIFACT_KIND', kind), 'artifact.put' if type(request) is ArtifactPut else 'capability.invoke'
    claims = [_claim_target('capability.invoke', ScopeTarget('CAPABILITY', capability_id)), _claim_target(permission, target)]
    claims.extend(additional_claims)
    claims.extend(_claim_target(permission, ScopeTarget('CAPABILITY', capability_id)) for permission in sorted(
        set(operation['required_permissions']) - RESOURCE_OPERATION_RULES[contract][2] - {'capability.invoke'}))
    generation = _service_generation(store, task)
    reserved = {}
    for subject in (task.actor_id, store.service_id):
        for claim in claims:
            grant_id = _find_grant(store, txn, task, subject, claim, generation)
            if claim not in reserved.setdefault(grant_id, []):
                reserved[grant_id].append(claim)
    return {'schema': 'host-resource-reservation/v1', 'request': document, 'binding': binding,
        'operation_sha256': sha256_hex(canonical_json(operation)), 'grants': reserved}


def fact(txn, invocation_id, event, payload):
    action_id, actor = txn._conn.execute('SELECT i.action_id,a.actor_id FROM invocations i JOIN actions a ON a.action_id=i.action_id WHERE i.invocation_id=?', (invocation_id,)).fetchone()
    return txn.append_fact(FactAppendRequest(entity_type='invocation', entity_id=invocation_id, event_type=event,
        schema_version=1, payload=payload, actor_id=actor, action_id=action_id, occurred_at_us=txn.recorded_at_us))


def create_child(txn, task, increments, *, resource=True, grant_ids=(), input_artifact_id=None):
    action = 'action://' + new_uuid7()
    budget = txn._conn.execute('SELECT budget_json FROM tasks WHERE task_id=?', (task.task_id,)).fetchone()[0]
    txn._conn.execute("INSERT INTO actions(action_id,task_id,actor_id,intent,composition_id,causal_parent_action_id,status,budget_json,consumed_budget_json,created_at_us,started_at_us) "
        "VALUES (?,?,?,?,?,?,'RUNNING',?,?,?,?)",
        (action, task.task_id, task.actor_id, 'capability_resource' if resource else 'capability_tool', task.serving_composition_id, task.root_action_id, budget,
            canonical_json(increments), txn.recorded_at_us, txn.recorded_at_us))
    source = txn.append_fact(FactAppendRequest(entity_type='action', entity_id=action, event_type='action_started',
        schema_version=1, actor_id=task.actor_id, action_id=action, occurred_at_us=txn.recorded_at_us,
        payload={'old_status': 'CREATED', 'new_status': 'RUNNING', 'reason_code': 'RESOURCE_TOOL' if resource else 'TOOL_DISPATCHED'}))
    _append_edge(txn, fact_id=source, edge_type='caused_by', from_id=action, to_id=task.root_action_id)
    for grant_id in sorted(grant_ids):
        _append_edge(txn, fact_id=source, edge_type='authorized_by', from_id=action, to_id=grant_id)
    if input_artifact_id is not None:
        _append_edge(txn, fact_id=source, edge_type='used', from_id=action, to_id=input_artifact_id)
    return action


def finish_child(txn, invocation_id, error=None, *, raise_error=True):
    row = txn._conn.execute('SELECT a.action_id,a.actor_id,a.status,i.backend_ref_json,a.intent,a.causal_parent_action_id,t.root_action_id FROM actions a '
        'JOIN invocations i ON i.action_id=a.action_id JOIN tasks t ON t.task_id=a.task_id WHERE i.invocation_id=?', (invocation_id,)).fetchone()
    if row is None or row[4] not in ('capability_resource','capability_tool') or row[5] != row[6] or row[2] not in ('CREATED', 'RUNNING'):
        return
    resource = 'resource' in json.loads(row[3] or b'{}')
    status = 'FAILED' if error else 'SUCCEEDED'
    txn._conn.execute('UPDATE actions SET status=?,completed_at_us=?,error_json=? WHERE action_id=?',
        (status, txn.recorded_at_us, canonical_json(error) if error else None, row[0]))
    txn.append_fact(FactAppendRequest(entity_type='action', entity_id=row[0], event_type='action_finished',
        schema_version=1, actor_id=row[1], action_id=row[0], occurred_at_us=txn.recorded_at_us,
        payload={'old_status': row[2], 'new_status': status, 'reason_code': error or ('RESOURCE_COMMITTED' if resource else 'TOOL_COMMITTED')}))
    if error and resource:
        fact(txn, invocation_id, 'resource_call_failed', {'error_code': error, 'raise_error': raise_error})


def replay(store, task, ordinal, capability_id, operation, content):
    row = store.conn.execute('SELECT i.invocation_id,i.status,i.input_artifact_id,i.output_artifact_id,i.error_json,'
        'i.backend_ref_json,i.target FROM invocations i JOIN actions a ON a.action_id=i.action_id '
        "WHERE a.task_id=? AND json_extract(CAST(i.backend_ref_json AS TEXT),'$.ordinal')=?", (task.task_id, ordinal)).fetchone()
    if row is None:
        return None
    journal = json.loads(row[5])
    reservation = read_reservation(store, row[0])
    if (journal.get('request_hash') != sha256_hex(content) or row[2] != 'artifact://sha256/' + sha256_hex(content)
            or row[6] != capability_id + '#' + operation['operation_id']
            or reservation['operation_sha256'] != sha256_hex(canonical_json(operation))):
        _fail(ErrorCode.IDEMPOTENCY_CONFLICT, 'replayed resource invocation differs')
    if row[1] == 'SUCCEEDED':
        terminal = store.conn.execute("SELECT payload_json FROM facts WHERE entity_id=? AND event_type='resource_call_committed'", (row[0],)).fetchall()
        if len(terminal) != 1 or json.loads(terminal[0][0]).get('output_artifact_id') != row[3]:
            _fail(ErrorCode.INTEGRITY_ERROR, 'resource terminal differs from its Fact')
        return {'invocation_id': row[0], 'content': store.read_artifact(row[3]), 'error_code': None}
    if row[1] == 'FAILED':
        error = json.loads(row[4])
        terminal = store.conn.execute("SELECT payload_json FROM facts WHERE entity_id=? AND event_type='resource_call_failed'", (row[0],)).fetchall()
        failure = json.loads(terminal[0][0]) if len(terminal)==1 else {}
        if set(failure) != {'error_code','raise_error'} or failure['error_code'] != error or type(failure['raise_error']) is not bool:
            _fail(ErrorCode.INTEGRITY_ERROR, 'failed resource terminal differs from its Fact')
        return {'invocation_id': row[0], 'content': None, 'error_code': error, 'raise_error':failure['raise_error']}
    _fail(ErrorCode.EXTERNAL_EFFECT_UNKNOWN, 'unfinished resource invocation cannot be repeated')


def read_reservation(store, invocation_id):
    journal, action = store._journal(store.conn, invocation_id)
    resource = journal.get('resource')
    rows = store.conn.execute("SELECT payload_json FROM facts WHERE entity_id=? AND event_type='resource_call_reserved'", (invocation_id,)).fetchall()
    if resource is None or len(rows) != 1 or json.loads(rows[0][0]) != resource:
        _fail(ErrorCode.INTEGRITY_ERROR, 'resource reservation differs from its Fact')
    return resource


def reauthorize(store, txn, task, invocation_id, reservation):
    store.check(task.task_id)
    epoch = txn._conn.execute('SELECT epoch_id FROM realms WHERE realm_id=?', (task.realm_id,)).fetchone()[0]
    generation = _service_generation(store, task)
    for grant_id, claims in reservation['grants'].items():
        grant = load_grant_row(txn._conn, grant_id)
        if (grant is None or grant.subject_id not in (task.actor_id, store.service_id) or grant.constraints.resource_ceiling
                or grant.subject_id == store.service_id and grant_id not in generation):
            _fail(ErrorCode.AUTHORITY_DENIED, 'resource admission grant is unavailable')
        if txn._conn.execute('SELECT status FROM principals WHERE realm_id=? AND principal_id=?', (task.realm_id, grant.subject_id)).fetchone() != ('ACTIVE',):
            _fail(ErrorCode.AUTHORITY_DENIED, 'resource principal is inactive')
        use = txn._conn.execute("SELECT amount_json FROM authority_uses WHERE grant_id=? AND action_id=? AND use_kind='host_invocation'", (grant_id, invocation_id)).fetchone()
        if use is None or json.loads(use[0]) != {'claims': claims}:
            _fail(ErrorCode.INTEGRITY_ERROR, 'resource authority reservation differs')
        count = txn._conn.execute('SELECT COUNT(*) FROM authority_uses WHERE grant_id=?', (grant_id,)).fetchone()[0]
        for claim in claims:
            if authorize(grant, subject_id=grant.subject_id, permission=claim['permission'], resource_realm=task.realm_id,
                    resource_target=ScopeTarget(**claim['target']), epoch_id=epoch, now_us=txn.recorded_at_us, uses_count=count-1) is not None:
                _fail(ErrorCode.AUTHORITY_DENIED, 'resource admission grant no longer authorizes commit')


def prepare(store, task, invocation_id, request):
    reservation = read_reservation(store, invocation_id)
    if reservation['request'] != resource_request_document(request):
        _fail(ErrorCode.INTEGRITY_ERROR, 'resource plan differs from its reservation')
    # Authorize before exposing any content to the external normalizer. This
    # writer holds no package callback and releases before returning the receipt.
    store.run_command(lambda txn: (reauthorize(store, txn, task, invocation_id, reservation) or {}))
    state = reservation['binding']
    if type(request) is ArtifactPut:
        media_type, raw = request.media_type, request.content
    else:
        reference = (request.artifact_id if type(request) is ArtifactRead else request.content_artifact_id
            if type(request) is StateWrite else state['content_artifact_id'])
        _, media_type, raw = _ordinary(store, reference)
    if media_type == 'application/json':
        original = context_document(raw)
        if state:
            schema = context_document(store.read_artifact(state['schema_id']))
            validate_host_value(schema, original)
        if state and state.get('redaction_policy_artifact_id'):
            original = _redactor(context_document(store.read_artifact(state['redaction_policy_artifact_id'])))(original)
        raw = canonical_json(redact_value(task, original))
        if state:
            validate_host_value(schema, context_document(raw))
    elif media_type == 'text/plain; charset=utf-8' and not state:
        try:
            raw = redact_value(task, raw.decode('utf-8')).encode('utf-8')
        except UnicodeError:
            _fail(ErrorCode.INVALID_RESULT, 'resource content is not UTF-8')
    else:
        _fail(ErrorCode.FEATURE_UNAVAILABLE, 'resource serializer is unavailable')
    if len(raw) > MAX_RESOURCE_CONTENT_BYTES:
        _fail(ErrorCode.RESOURCE_EXHAUSTED, 'redacted resource exceeds content ceiling')
    staged = store.stage(raw)
    revision = 'state-revision://' + new_uuid7() if type(request) is StateWrite else state.get('state_revision_id')
    receipt = ResourceReceipt(reservation['request']['schema'], staged['artifact_id'], media_type, raw,
        state.get('state_id'), revision)
    return receipt, staged


def commit(store, task, invocation_id, request, receipt, staged, output):
    output_stage = store.stage(output)
    reservation = read_reservation(store, invocation_id)
    def mutate(txn):
        if read_reservation(store, invocation_id) != reservation:
            _fail(ErrorCode.INTEGRITY_ERROR, 'resource reservation changed before commit')
        reauthorize(store, txn, task, invocation_id, reservation)
        row = txn._conn.execute('SELECT status,action_id FROM invocations WHERE invocation_id=?', (invocation_id,)).fetchone()
        if row[0] not in ('DISPATCHED', 'RUNNING'):
            _fail(ErrorCode.FAILED_PRECONDITION, 'resource invocation is already terminal')
        action_id = row[1]
        parents = [staged['artifact_id']]
        from ...domain.scratch_export_plan import ScratchExportCandidate
        if type(request) is ScratchExportCandidate:
            from .scratch_export import commit as commit_export
            parents.extend(commit_export(store, txn, task, invocation_id, request, staged))
        existing = txn._conn.execute('SELECT kind,media_type FROM artifacts WHERE artifact_id=?', (receipt.artifact_id,)).fetchone()
        if type(request) is ArtifactPut and existing is not None and existing != (request.kind, receipt.media_type):
            _fail(ErrorCode.CONTRACT_INCOMPATIBLE, 'existing Artifact metadata differs from publication request')
        register_staged_artifact(txn, staged, kind=request.kind if type(request) is ArtifactPut else 'resource_content', media_type=receipt.media_type)
        result = {'artifact_id': receipt.artifact_id}
        if type(request) is StateWrite:
            state = reservation['binding']
            require_state_realm(txn._conn, request.state_id, task.realm_id)
            _insert_revision(txn, state_id=request.state_id, owner_id=state['owner_id'], schema_id=state['schema_id'],
                parent_revision_id=state['state_revision_id'], artifact_id=receipt.artifact_id,
                created_by=task.actor_id, state_revision_id=receipt.state_revision_id)
            cursor = txn._conn.execute('UPDATE managed_states SET current_revision_id=?,cas_revision=cas_revision+1,updated_at_us=? '
                'WHERE state_id=? AND current_revision_id=? AND cas_revision=? AND schema_id=? AND status=\'ACTIVE\'',
                (receipt.state_revision_id, txn.recorded_at_us, request.state_id, state['state_revision_id'], state['cas_revision'], state['schema_id']))
            if cursor.rowcount != 1:
                _fail(ErrorCode.REVISION_CONFLICT, 'State changed before resource terminal commit')
            state_fact = txn.append_fact(FactAppendRequest(entity_type='state', entity_id=request.state_id,
                event_type='state_revision_created', schema_version=1, actor_id=task.actor_id, action_id=action_id,
                occurred_at_us=txn.recorded_at_us,
                payload={'state_revision_id': receipt.state_revision_id, 'initial': 'false', 'invocation_id': invocation_id}))
            _state_ref_history(txn, state_id=request.state_id, state_revision_id=receipt.state_revision_id, source_fact_id=state_fact)
            _append_edge(txn, fact_id=state_fact, edge_type='caused_by', from_id=receipt.state_revision_id, to_id=action_id)
            _append_edge(txn, fact_id=state_fact, edge_type='supersedes', from_id=receipt.state_revision_id, to_id=state['state_revision_id'])
            result.update(state_id=request.state_id, state_revision_id=receipt.state_revision_id, cas_revision=state['cas_revision']+1)
        register_staged_artifact(txn, output_stage, kind='invocation_output', parents=parents)
        finish_invocation(InvocationFinishRequest(invocation_id, output_artifact_id=output_stage['artifact_id']))(txn)
        payload = {'contract': receipt.contract, 'request': reservation['request'], 'receipt': result,
            'output_artifact_id': output_stage['artifact_id']}
        source = fact(txn, invocation_id, 'resource_call_committed', payload)
        for reference in set(parents + [output_stage['artifact_id']]):
            _append_edge(txn, fact_id=source, edge_type='produced', from_id=invocation_id, to_id=reference)
        finish_child(txn, invocation_id)
        return {'output_artifact_id': output_stage['artifact_id']}
    return store.run_command(mutate)
