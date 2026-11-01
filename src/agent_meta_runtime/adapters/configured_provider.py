"""Root composition for approved Provider calls, restricted to loopback tests.

No production placement/EffectIntent gate is advertised by this assembly.
The package supplies only a plan and terminal normalizer; Root owns the
profile, protected store, request, firm reservation and original-wire billing.
"""

from dataclasses import replace
import ipaddress
import json

from ..domain.canonical import now_us
from ..domain.errors import ErrorCode, StableError
from ..domain.host_contract import ProviderTerminalResponse, decode_model_response, encode_model_response
from ..domain.host_schema import validate_host_value
from ..domain.loop import ProviderUsage
from ..domain.provider_accounting import ProviderReservation
from ..domain.provider_profile import load_profile
from ..domain.provider_transport import ProviderHttpRequest
from ..ports.host_execution import HostCallValue, PreparedProviderCall
from .private_paths import require_private_path
from .provider_credentials import open_provider_store
from .provider_host import ProviderHostCalls
from .provider_worker import ProviderWorkerController
from .provider_worker_wire import ProviderWorkerBootstrap
from .store.provider_accounting import read_provider
from .store.provider_admission import frozen_configuration


class ControlledConfiguredProviderHost:
    def __init__(self, store, *, data_dir, trust, epoch_id, signer, test_ca_pem, allow_insecure=False):
        if type(test_ca_pem) is not bytes or not 0 < len(test_ca_pem) <= 65536:
            raise StableError(code=ErrorCode.INVALID_ARGUMENT,message='controlled Provider requires an explicit bounded test TLS anchor')
        self.store,self.data_dir,self.trust = store,data_dir,trust
        self.epoch_id,self.signer = epoch_id,signer
        self._ca,self._allow_insecure = test_ca_pem,allow_insecure
        self._worker = None
        self._closed = False

    def _credentials(self, handle):
        # Metadata/presence only. Plaintext resolution remains in the certified
        # native worker, after TLS and token checks. A damaged purpose/envelope
        # is refused there before the HTTP request is sent.
        try:
            store = open_provider_store(self.data_dir,realm_id=self.store.realm_id,allow_insecure=self._allow_insecure)
            path = store._path(handle)
            require_private_path(path)
            if not path.is_file():
                raise OSError('not an item')
        except OSError:
            raise StableError(code=ErrorCode.KEY_UNAVAILABLE,message='approved Provider credential item is unavailable') from None
        return store

    def prepare(self, *, task, ordinal, capability_id, operation, plan, projection, normalize):
        if self._closed:
            raise StableError(code=ErrorCode.FAILED_PRECONDITION,message='Provider Host is closed')
        configuration = frozen_configuration(self.store,task,capability_id,require_current=False)
        profile,closure = load_profile(configuration['profile_artifact_id'],self.store.read_artifact)
        tokens,output,cost = profile.preflight(plan)
        if (configuration['epoch_id'] != self.epoch_id or now_us() >= self.trust.expires_at_us
                or list(closure) != configuration['verified_artifact_ids']):
            raise StableError(code=ErrorCode.FAILED_PRECONDITION,message='frozen Provider execution trust is unavailable')
        # A test label alone cannot permit paid/public traffic. This Root-only
        # assembly supports only scoped loopback networks and synthetic prices.
        if (profile.policy.profile != 'CONTROLLED_TEST_ONLY' or profile.pricing.currency != 'TEST'
                or not all(ipaddress.ip_network(net).is_loopback for net in profile.policy.networks)):
            raise StableError(code=ErrorCode.FAILED_PRECONDITION,message='configured Provider placement supports only loopback TEST profiles')
        if (projection.manifest.tokenizer_id != profile.tokenizer_id
                or projection.manifest.composition_id != task.serving_composition_id):
            raise StableError(code=ErrorCode.FAILED_PRECONDITION,message='Context and Provider exact tokenizer/binding differ')
        old = self.store.conn.execute("SELECT invocation_id,backend_ref_json FROM invocations WHERE action_id=? AND json_extract(CAST(backend_ref_json AS TEXT),'$.ordinal')=?", (task.root_action_id,ordinal)).fetchone()
        if old is None:
            frozen_configuration(self.store,task,capability_id)
            self._credentials(configuration['credential_handle'])
            deadline = min(now_us()+profile.timeout_us,task.deadline_at_us) if task.deadline_at_us is not None else now_us()+profile.timeout_us
        else:
            provider = read_provider(self.store.conn,old[0],json.loads(old[1]))
            if provider is None or provider['reservation'].get('configuration_fact_id') != configuration['configuration_fact_id']:
                raise StableError(code=ErrorCode.IDEMPOTENCY_CONFLICT,message='replayed configured Provider admission differs')
            deadline = provider['reservation']['deadline_at_us']
        request = ProviderHttpRequest(task.task_id+'/invocation/'+str(ordinal),profile.policy,profile.model_id,
            configuration['credential_handle'],plan.body,profile.timeout_us,profile.maximum_response_bytes,deadline)
        reservation = ProviderReservation(profile.artifact_id,profile.price_policy_artifact_id,profile.tokenizer_artifact_id,
            request.scope_hash,tokens,output,cost,configuration['configuration_fact_id'],deadline)

        def terminal(raw):
            usage = profile.usage(raw)
            try:
                value = normalize(ProviderTerminalResponse(profile.artifact_id,raw))
                if type(value) is not HostCallValue or value.content is None or value.backend_result is not None:
                    raise ValueError('invalid package normalization')
                response = replace(decode_model_response(value.content),usage=ProviderUsage(**usage))
                content = encode_model_response(response)
                validate_host_value(json.loads(self.store.read_artifact(operation['output_schema_artifact_id'])),json.loads(content))
                return HostCallValue(content=content,usage=usage)
            except (Exception,SystemExit):
                # A package/schema failure cannot erase independently known
                # billing, including a cost/token overrun in the wire response.
                return HostCallValue(error_code=ErrorCode.INVALID_RESULT,usage=usage,raise_error=True)
        return PreparedProviderCall(reservation,request,terminal)

    def _controller(self, handle):
        if self._closed:
            raise StableError(code=ErrorCode.FAILED_PRECONDITION,message='Provider Host is closed')
        if self._worker is None:
            credentials = self._credentials(handle)
            row = self.store.conn.execute("SELECT p.principal_id,p.public_identity_json FROM epochs e JOIN principals p ON p.principal_id=e.authority_root_principal_id AND p.realm_id=e.realm_id WHERE e.epoch_id=? AND e.realm_id=? AND p.status='ACTIVE'", (self.epoch_id,self.store.realm_id)).fetchone()
            if row is None:
                raise StableError(code=ErrorCode.KEY_UNAVAILABLE,message='current Provider Root trust is unavailable')
            bootstrap = ProviderWorkerBootstrap(row[0],bytes.fromhex(json.loads(row[1])['public_key_hex']),
                self.store.realm_id,self.epoch_id,self.trust.certificate,'new-controller',str(credentials.root),credentials.profile,self._ca)
            self._worker = ProviderWorkerController(bootstrap)
        return self._worker

    async def invoke(self, *, task, invocation_id, prepared):
        try:
            worker = self._controller(prepared.request.credential_handle)
            permissions = {'model.invoke',*self._permissions(invocation_id)}
        except BaseException as exc:
            self.store.finish_invocation(invocation_id,error=exc.code if isinstance(exc,StableError) else ErrorCode.INTERNAL,
                provider_outcome='NOT_SENT',require_undispatched=True)
            raise
        return await ProviderHostCalls(self.store,worker=worker,trust=self.trust,epoch_id=self.epoch_id,signer=self.signer).invoke(
            task=task,invocation_id=invocation_id,request=prepared.request,
            required_permissions=permissions,normalize=prepared.normalize)

    def _permissions(self, invocation_id):
        # Use exactly the committed admission, never a newer grant generation.
        rows = self.store.conn.execute("SELECT amount_json FROM authority_uses WHERE action_id=? AND use_kind='host_invocation'", (invocation_id,)).fetchall()
        return {permission for row in rows for permission in json.loads(row[0])['permissions']}

    async def close(self):
        self._closed = True
        if self._worker is not None:
            await self._worker.close()
