"""Signed management State commands; caller code never runs in the writer."""
import json

from ...domain.authority import ScopeTarget, authorize
from ...domain.canonical import canonical_json, sha256_hex
from ...domain.context_contract import context_document, _redactor, _MIN_REDACT_KEYS, _PATTERNS
from ...domain.errors import ErrorCode, StableError
from ...domain.host_schema import validate_host_value
from ...domain.state_contract import state_payload
from ...ports.repositories import FactAppendRequest
from .artifact_content import read_artifact_content, MAX_PUBLIC_CONTENT_BYTES
from .authority import load_grant_row
from .state import StateCreateRequest, StateWriteRequest, create_state, write_state_revision, require_state_realm
from .task_snapshot import register_staged_artifact
from .semantic import _append_edge


def _fail(code, message):
    raise StableError(code=code, message=message)


def origin(conn, state_id, realm_id):
    require_state_realm(conn,state_id,realm_id)
    rows=conn.execute("SELECT f.payload_json,f.actor_id FROM facts f JOIN state_revisions r ON r.state_id=f.entity_id "
        "AND r.state_revision_id=json_extract(CAST(f.payload_json AS TEXT),'$.state_revision_id') "
        "WHERE f.realm_id=? AND f.entity_type='state' AND f.entity_id=? AND f.event_type='state_revision_created' "
        "AND json_extract(CAST(f.payload_json AS TEXT),'$.initial')='true' AND r.parent_revision_id IS NULL", (realm_id,state_id)).fetchall()
    if len(rows)!=1:
        _fail(ErrorCode.INTEGRITY_ERROR,'State origin is unavailable or ambiguous')
    value=json.loads(rows[0][0])
    return {'purpose':value.get('purpose','GENERAL'),
        'controller_principal_id':value.get('controller_principal_id',rows[0][1]),
        'redaction_policy_artifact_id':value.get('redaction_policy_artifact_id')}


def owner_target(conn, realm_id, owner):
    if owner.startswith('capability://'):
        row=conn.execute("SELECT 1 FROM capabilities c JOIN harness_installations h ON h.package_artifact_id=c.artifact_id "
            "WHERE h.realm_id=? AND h.status!='UNINSTALLED' AND c.capability_id=? LIMIT 1",(realm_id,owner)).fetchone()
        if row:
            return ScopeTarget('CAPABILITY',owner)
    elif owner.startswith('composition://'):
        rows=conn.execute("SELECT DISTINCT h.harness_id FROM compositions c JOIN harness_installation_history x ON x.composition_id=c.composition_id "
            "JOIN harness_installations h ON h.harness_id=x.harness_id WHERE c.composition_id=? AND c.realm_id=? "
            "AND h.realm_id=? AND h.status!='UNINSTALLED'",(owner,realm_id,realm_id)).fetchall()
        if len(rows)==1:
            return ScopeTarget('HARNESS',rows[0][0])
    _fail(ErrorCode.NOT_FOUND,'State owner is not installed in this Realm')


def command_target(conn, envelope):
    payload=state_payload(envelope.payload_type,dict(envelope.payload))
    if envelope.payload_type=='state.create/v1':
        return owner_target(conn,envelope.realm_id,payload['owner_id'])
    require_state_realm(conn,payload['state_id'],envelope.realm_id)
    owner=conn.execute('SELECT owner_id FROM managed_states WHERE state_id=?',(payload['state_id'],)).fetchone()[0]
    return owner_target(conn,envelope.realm_id,owner)


def _controller(conn, envelope, birth):
    if birth['purpose']=='GENERAL' or envelope.actor_id==birth['controller_principal_id']:
        return
    root=conn.execute('SELECT e.authority_root_principal_id FROM realms r JOIN epochs e ON e.epoch_id=r.epoch_id '
        'AND e.realm_id=r.realm_id WHERE r.realm_id=?',(envelope.realm_id,)).fetchone()
    if root is None or envelope.actor_id!=root[0]:
        _fail(ErrorCode.AUTHORITY_DENIED,'session State belongs to a different controller')


def _bounded(value, maximum, depth=48):
    stack=[(value,0)]; count=0
    while stack:
        item,level=stack.pop(); count+=1
        if count>maximum or level>depth:
            _fail(ErrorCode.RESOURCE_EXHAUSTED,'State JSON structure exceeds its ceiling')
        if isinstance(item,dict):
            stack.extend((v,level+1) for v in item.values())
        elif isinstance(item,list):
            stack.extend((v,level+1) for v in item)


def _schema(schema):
    _bounded(schema,2048,32)
    stack=[schema]
    while stack:
        node=stack.pop()
        if type(node) is bool:
            continue
        if not isinstance(node,dict):
            _fail(ErrorCode.INVALID_ARGUMENT,'State schema must contain JSON Schema objects')
        properties=node.get('properties',{})
        required=node.get('required',[])
        if (not isinstance(properties,dict) or len(properties)>256 or not isinstance(required,list)
                or len(required)>256 or not all(isinstance(name,str) for name in required)
                or len(set(required))!=len(required)):
            _fail(ErrorCode.INVALID_ARGUMENT,'invalid State object schema')
        if 'enum' in node and (not isinstance(node['enum'],list) or len(node['enum'])>128):
            _fail(ErrorCode.RESOURCE_EXHAUSTED,'State enum exceeds its schema ceiling')
        stack.extend(properties.values())
        for name in ('items','additionalProperties'):
            if name in node:
                stack.append(node[name])
        try:
            validate_host_value(node,None)
        except StableError as exc:
            if exc.code!=ErrorCode.INVALID_RESULT:
                raise


def _read(conn,cas,reference):
    item=json.loads(read_artifact_content(conn,cas,reference))
    return item,bytes.fromhex(item['content_hex'])


def _source_permission(txn,envelope,kind):
    grant=load_grant_row(txn._conn,envelope.authority_grant_id)
    epoch=txn._conn.execute('SELECT epoch_id FROM realms WHERE realm_id=?',(envelope.realm_id,)).fetchone()[0]
    uses=txn._conn.execute('SELECT COUNT(*) FROM authority_uses WHERE grant_id=?',(grant.grant_id,)).fetchone()[0]
    # The command guard already reserved precisely one use for this command.
    if authorize(grant,subject_id=envelope.actor_id,permission='capability.invoke',resource_realm=envelope.realm_id,
            resource_target=ScopeTarget('ARTIFACT_KIND',kind),epoch_id=epoch,now_us=txn.recorded_at_us,uses_count=uses-1) is not None:
        _fail(ErrorCode.AUTHORITY_DENIED,'State source Artifact authority denied')


def _stage(cas,raw):
    return {'content':raw,'artifact_id':'artifact://sha256/'+sha256_hex(raw),
        'manifest':{'storage_relpath':cas.put(raw),'size_bytes':len(raw)}}


def _content(txn,cas,envelope,payload,birth=None):
    schema_meta,schema_raw=_read(txn._conn,cas,payload['schema_id'])
    content_meta,raw=_read(txn._conn,cas,payload['content_artifact_id'])
    for kind in {schema_meta['kind'],content_meta['kind']}:
        _source_permission(txn,envelope,kind)
    if content_meta['media_type']!='application/json':
        _fail(ErrorCode.FEATURE_UNAVAILABLE,'managed State requires JSON content')
    schema=context_document(schema_raw); _schema(schema)
    value=context_document(raw); _bounded(value,8192)
    reference=(birth or {}).get('redaction_policy_artifact_id') or payload.get('redaction_policy_artifact_id')
    if reference:
        policy_meta,policy_raw=_read(txn._conn,cas,reference)
        if birth is None:
            _source_permission(txn,envelope,policy_meta['kind'])
    else:
        policy_raw=canonical_json({'schema':'context-redaction-policy/v1','redact_keys':sorted(_MIN_REDACT_KEYS),
            'patterns':sorted(_PATTERNS),'replacement':'[REDACTED]'})
    redact=_redactor(context_document(policy_raw))
    try:
        validate_host_value(schema,value)
        value=redact(value)
        validate_host_value(schema,value)
    except StableError as exc:
        if exc.code==ErrorCode.INVALID_RESULT:
            _fail(ErrorCode.INVALID_ARGUMENT,'State content violates schema or redaction invariants')
        raise
    redacted=canonical_json(value)
    if len(redacted)>MAX_PUBLIC_CONTENT_BYTES:
        _fail(ErrorCode.RESOURCE_EXHAUSTED,'redacted State content exceeds the 1 MiB ceiling')
    content=_stage(cas,redacted); policy=_stage(cas,policy_raw)
    register_staged_artifact(txn,content,kind='state_content',parents=(payload['content_artifact_id'],))
    register_staged_artifact(txn,policy,kind='state_redaction_policy')
    return content['artifact_id'],policy['artifact_id']


def snapshot(conn,realm_id,state_id,revision=None,*,created_origin=None):
    birth=created_origin if created_origin is not None else origin(conn,state_id,realm_id)
    row=conn.execute('SELECT owner_id,schema_id,current_revision_id,cas_revision,status FROM managed_states WHERE state_id=?',(state_id,)).fetchone()
    selected=revision or row[2]
    item=conn.execute('SELECT schema_id,artifact_id,parent_revision_id FROM state_revisions WHERE state_id=? AND state_revision_id=?',(state_id,selected)).fetchone()
    if item is None:
        _fail(ErrorCode.NOT_FOUND,'State revision not found')
    return {'state_id':state_id,'owner_id':row[0],'schema_id':item[0],'content_artifact_id':item[1],
        'state_revision_id':selected,'current_revision_id':row[2],'cas_revision':row[3],
        'parent_revision_id':item[2],'status':row[4],**birth}


def manage(cas,envelope):
    payload=state_payload(envelope.payload_type,dict(envelope.payload))
    def mutate(txn):
        grant=load_grant_row(txn._conn,envelope.authority_grant_id)
        if grant.constraints.resource_ceiling:
            _fail(ErrorCode.FEATURE_UNAVAILABLE,'State management resource ceilings are unsupported')
        parent=envelope.causal_parent_action_id
        if parent is not None:
            row=txn._conn.execute('SELECT a.actor_id FROM actions a JOIN compositions c ON c.composition_id=a.composition_id '
                'WHERE a.action_id=? AND c.realm_id=?',(parent,envelope.realm_id)).fetchone()
            if row is None:
                _fail(ErrorCode.NOT_FOUND,'State causal parent not found in this Realm')
            if row[0]!=envelope.actor_id:
                _controller(txn._conn,envelope,{'purpose':'SESSION_JOURNAL','controller_principal_id':row[0]})
        if envelope.payload_type=='state.create/v1':
            if txn._conn.execute('SELECT 1 FROM managed_states WHERE state_id=?',(payload['state_id'],)).fetchone():
                _fail(ErrorCode.ALREADY_EXISTS,'State ID is already registered')
            content,policy=_content(txn,cas,envelope,payload)
            created=create_state(StateCreateRequest(payload['owner_id'],payload['schema_id'],content,payload['state_id'],
                payload.get('purpose','GENERAL'),policy,envelope.actor_id))(txn)
            source=txn.fact_ids[-1]
            _append_edge(txn,fact_id=source,edge_type='derived_from',from_id=created['state_revision_id'],to_id=content)
            if parent is not None:
                _append_edge(txn,fact_id=source,edge_type='caused_by',from_id=created['state_revision_id'],to_id=parent)
            # The UoW publishes its transaction row after this mutator returns.
            # This receipt uses only the birth data just inserted by this
            # command; normal reads still require a committed origin Fact.
            return snapshot(txn._conn,envelope.realm_id,payload['state_id'],created_origin={
                'purpose':payload.get('purpose','GENERAL'),'controller_principal_id':envelope.actor_id,
                'redaction_policy_artifact_id':policy})
        else:
            birth=origin(txn._conn,payload['state_id'],envelope.realm_id)
            _controller(txn._conn,envelope,birth)
            if envelope.payload_type=='state.read/v1':
                result=snapshot(txn._conn,envelope.realm_id,payload['state_id'],payload.get('state_revision_id'))
                txn.append_fact(FactAppendRequest(entity_type='state',entity_id=payload['state_id'],event_type='state_accessed',schema_version=1,
                    actor_id=envelope.actor_id,occurred_at_us=txn.recorded_at_us,
                    payload={'state_revision_id':result['state_revision_id'],'cas_revision':result['cas_revision']}))
                return result
            current=snapshot(txn._conn,envelope.realm_id,payload['state_id'])
            if (current['state_revision_id'],current['cas_revision'],current['schema_id'],current['status']) != (
                    payload['expected_state_revision_id'],payload['expected_cas_revision'],payload['schema_id'],'ACTIVE'):
                _fail(ErrorCode.REVISION_CONFLICT,'State revision, CAS, schema or status changed')
            content,_=_content(txn,cas,envelope,payload,birth)
            changed=write_state_revision(StateWriteRequest(payload['state_id'],payload['expected_state_revision_id'],payload['expected_cas_revision'],
                payload['schema_id'],content,envelope.actor_id))(txn)
            source=txn.fact_ids[-1]
            _append_edge(txn,fact_id=source,edge_type='supersedes',from_id=changed['state_revision_id'],to_id=payload['expected_state_revision_id'])
            _append_edge(txn,fact_id=source,edge_type='derived_from',from_id=changed['state_revision_id'],to_id=content)
            if parent is not None:
                _append_edge(txn,fact_id=source,edge_type='caused_by',from_id=changed['state_revision_id'],to_id=parent)
        return snapshot(txn._conn,envelope.realm_id,payload['state_id'])
    return mutate
