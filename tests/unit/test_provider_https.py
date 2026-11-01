"""Actual local TLS/HTTP, real signatures, synthetic credentials only.

These are transport unit proofs, not a live Provider/worker/price profile.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import secrets
import socket
import ssl
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest

from agent_meta_runtime.adapters.provider_https import ScopedProviderHttps
from agent_meta_runtime.domain.canonical import canonical_json
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.ids import new_uuid7
from agent_meta_runtime.domain.provider_transport import ProviderEgressPolicy, ProviderHttpRequest
from test_execution_tokens import Chain, NOW

SECRET = b"synthetic-provider-secret-never-real"
HANDLE = "credential://insecure-dev/00000000-0000-4000-8000-000000000001"


class Credentials:
    profile = "INSECURE_TEST_ONLY"

    def __init__(self, secret=SECRET):
        self.secret, self.uses, self.buffers = secret, 0, []

    @contextmanager
    def get_for_scoped_use(self, handle, *, purpose):
        assert handle == HANDLE and purpose == "provider"
        self.uses += 1
        buffer = bytearray(self.secret)
        self.buffers.append(buffer)
        try:
            yield buffer
        finally:
            buffer[:] = b"\0" * len(buffer)


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # fixture deliberately disconnects; never dump HTTP credentials


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        self.server.seen.append((self.path, self.headers.get('Authorization'), body))
        mode = self.server.mode
        if mode == 'hold':
            self.server.release.wait(10)
        if mode == 'disconnect':
            self.connection.shutdown(socket.SHUT_RDWR)
            self.close_connection = True
            return
        if mode == 'drip':
            for byte in b'HTTP/1.1 200 OK\r\nX-Slow: never-ending-header':
                self.connection.sendall(bytes([byte]))
                time.sleep(.025)
            return
        status = 307 if mode == 'redirect' else 429 if mode == 'rate' else 503 if mode == 'server_error' else 200
        self.send_response(status)
        self.send_header('Content-Type', 'text/plain' if mode == 'badtype' else 'application/json')
        self.send_header('Connection', 'close')
        if mode == 'redirect':
            self.send_header('Location', 'https://forbidden.invalid/steal')
        if mode == 'rate':
            self.send_header('Retry-After', '2')
        content = canonical_json({'reply': 'synthetic', 'Authorization': self.headers['Authorization']}) if mode in ('echo', 'escaped_echo', 'rate') else b'{"reply":"synthetic"}'
        if mode == 'escaped_echo':
            content = content.replace(b'synthetic-provider-secret-never-real', b'\\u0073ynthetic-provider-secret-never-real')
        if mode == 'invalid_json':
            content = b'{"bad":NaN}'
        if mode == 'messages':
            content = self.server.message_response
        if mode == 'oversized':
            content = b' ' * 129
        if mode == 'chunked_oversized':
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()
            content = b' ' * 129
            self.wfile.write(b'81\r\n' + content + b'\r\n0\r\n\r\n')
            self.close_connection = True
            return
        self.send_header('Content-Length', str(len(content) + (10 if mode == 'truncated' else 0)))
        self.end_headers()
        self.wfile.write(content)
        self.close_connection = True


@pytest.fixture
def edge(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'provider.test')])
    current = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(current - timedelta(days=1))
        .not_valid_after(current + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('provider.test'), x509.DNSName('localhost')]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
    certificate, private = tmp_path/'test-cert.pem', tmp_path/'test-key.pem'
    certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    server = QuietServer(('127.0.0.1', 0), Handler)
    server.seen, server.mode = [], 'ok'
    server.release = threading.Event()
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certificate, private)
    server.socket = server_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
    thread.start()
    trusted_ca_pem = certificate.read_bytes()
    calls = []
    def resolve(host, port, *args):
        calls.append((host, port))
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('127.0.0.1', port))]
    chain, credentials = Chain(), Credentials()
    policy = ProviderEgressPolicy('provider.test', server.server_port, '/compatible/v1/messages',
        ('127.0.0.1/32',), 'CONTROLLED_TEST_ONLY')
    request = ProviderHttpRequest('provider-call-1', policy, 'glm-5.3-flash', HANDLE,
        canonical_json({'model': 'glm-5.3-flash', 'messages': [{'role': 'user', 'content': 'synthetic'}],
            'max_tokens': 16, 'stream': False}), 2_000_000, 128)
    transport = ScopedProviderHttps(verifier=chain.verifier, credential_store=credentials,
        trusted_ca_pem=trusted_ca_pem, resolver=resolve)
    yield server, transport, request, chain, credentials, calls, trusted_ca_pem, resolve
    server.release.set()
    server.shutdown(); server.server_close(); thread.join(timeout=2)


def signed(request, chain, **changes):
    binding = replace(chain.binding, target_scope_hash=request.scope_hash, resource_ceiling=request.required_ceiling)
    token = chain.token(target_scope_hash=request.scope_hash, resource_ceiling=request.required_ceiling,
        token_id=new_uuid7(), nonce=secrets.token_hex(16), **changes)
    return dict(authorization=token, binding=binding, now_us=NOW)


def test_actual_tls_post_binds_path_model_and_only_resolves_provider_secret(edge, monkeypatch):
    server, transport, request, chain, credentials, dns, *_ = edge
    monkeypatch.setenv('HTTPS_PROXY', 'http://127.0.0.1:1')
    result = transport.post(request, **signed(request, chain))
    assert result.state == 'RESPONSE' and result.content == b'{"reply":"synthetic"}'
    assert server.seen == [(request.policy.path, 'Bearer ' + SECRET.decode(), request.body)]
    assert dns == [('provider.test', server.server_port)] and credentials.uses == 1
    assert all(not any(buffer) for buffer in credentials.buffers)
    assert SECRET not in repr(result).encode()


@pytest.mark.parametrize('mutation', ['signature', 'actor', 'expiry', 'ceiling', 'scope'])
def test_real_authorization_is_required_before_dns_or_secret_resolution(edge, mutation):
    server, transport, request, chain, credentials, dns, *_ = edge
    auth = signed(request, chain)
    if mutation == 'signature':
        doc = json.loads(auth['authorization']); doc['signature'] = '00' * 64
        auth['authorization'] = canonical_json(doc)
    elif mutation == 'actor':
        auth['binding'] = replace(auth['binding'], actor_id='principal://agent/01900000-0000-7000-8000-000000000009')
    elif mutation == 'expiry':
        auth['now_us'] = NOW + 60_000_000
    elif mutation == 'scope':
        auth['binding'] = replace(auth['binding'], target_scope_hash='00' * 32)
    else:
        ceiling = {**request.required_ceiling, 'request_bytes': len(request.body) - 1}
        auth['authorization'] = chain.token(target_scope_hash=request.scope_hash, resource_ceiling=ceiling)
    with pytest.raises(StableError) as error:
        transport.post(request, **auth)
    assert error.value.code == ErrorCode.AUTHORITY_DENIED
    assert not dns and not server.seen and credentials.uses == 0


@pytest.mark.parametrize('address', ['127.0.0.1', '10.1.2.3', '169.254.169.254', '::1', '::ffff:8.8.8.8', '224.0.0.1'])
def test_public_policy_never_admits_private_metadata_mapped_or_multicast_ips(address):
    assert not ProviderEgressPolicy('provider.test', 443, '/v1/messages').permits_ip(address)


def test_public_profile_refuses_insecure_credentials_before_dns(edge):
    server, transport, request, chain, credentials, dns, *_ = edge
    request = replace(request, policy=replace(request.policy, profile='PUBLIC_HTTPS'))
    with pytest.raises(StableError) as error:
        transport.post(request, **signed(request, chain))
    assert error.value.code == ErrorCode.KEY_UNAVAILABLE and not dns and not server.seen


def test_mixed_dns_answer_denies_whole_resolution_before_credential_use(edge):
    server, transport, request, chain, credentials, dns, trusted_ca_pem, resolve = edge
    def mixed(*args):
        return resolve(*args) + [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('169.254.169.254', server.server_port))]
    transport = ScopedProviderHttps(verifier=chain.verifier, credential_store=credentials, trusted_ca_pem=trusted_ca_pem, resolver=mixed)
    result = transport.post(request, **signed(request, chain))
    assert result.state == 'NOT_SENT' and result.error_code == ErrorCode.AUTHORITY_DENIED
    assert credentials.uses == 0 and not server.seen


@pytest.mark.parametrize('mode,code,reason', [
    ('redirect', ErrorCode.AUTHORITY_DENIED, 'REDIRECT_FORBIDDEN'),
    ('rate', ErrorCode.RESOURCE_EXHAUSTED, 'HTTP_FAILURE'),
    ('badtype', ErrorCode.INVALID_RESULT, 'RESPONSE_ENCODING'),
    ('oversized', ErrorCode.INVALID_RESULT, 'RESPONSE_SIZE'),
    ('chunked_oversized', ErrorCode.INVALID_RESULT, 'RESPONSE_SIZE'),
    ('echo', ErrorCode.INTEGRITY_ERROR, 'CREDENTIAL_IN_RESPONSE'),
    ('escaped_echo', ErrorCode.INTEGRITY_ERROR, 'CREDENTIAL_IN_RESPONSE'),
    ('invalid_json', ErrorCode.INVALID_RESULT, 'RESPONSE_JSON'),
])
def test_response_errors_are_bounded_sanitized_and_not_followed_or_retried(edge, mode, code, reason):
    server, transport, request, chain, credentials, dns, *_ = edge
    server.mode = mode
    auth = signed(request, chain)
    result = transport.post(request, **auth)
    assert result.state == 'RESPONSE' and result.error_code == code and result.reason_code == reason
    assert result.content is None and SECRET not in repr(result).encode()
    assert transport.post(request, **auth) == result
    assert len(server.seen) == len(dns) == credentials.uses == 1
    assert result.retry_after_us == (2_000_000 if mode == 'rate' else None)


@pytest.mark.parametrize('mode', ['disconnect', 'truncated', 'drip', 'server_error'])
def test_accepted_or_partial_request_failure_stays_unknown_without_a_second_send(edge, mode):
    server, transport, request, chain, credentials, dns, *_ = edge
    server.mode = mode
    request = replace(request, timeout_us=200_000 if mode == 'drip' else 2_000_000)
    auth = signed(request, chain)
    start = time.monotonic()
    result = transport.post(request, **auth)
    assert result.state == 'UNKNOWN' and result.error_code == ErrorCode.EXTERNAL_EFFECT_UNKNOWN
    assert time.monotonic() - start < 1.5
    assert transport.post(request, **auth) == result
    assert len(server.seen) == len(dns) == credentials.uses == 1
    assert all(not any(buffer) for buffer in credentials.buffers)


def test_wrong_tls_hostname_cannot_resolve_or_send_credentials(edge):
    server, transport, request, chain, credentials, dns, *_ = edge
    request = replace(request, policy=replace(request.policy, host='wrong-host.test'))
    result = transport.post(request, **signed(request, chain))
    assert result.state == 'NOT_SENT' and not server.seen and credentials.uses == 0


def test_concurrent_exact_replay_sends_only_once_in_a_session(edge):
    server, transport, request, chain, credentials, dns, *_ = edge
    auth = signed(request, chain)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: transport.post(request, **auth), range(4)))
    assert all(result == results[0] for result in results) and results[0].content is not None
    assert len(server.seen) == len(dns) == credentials.uses == 1


@pytest.mark.parametrize('field,value', [
    ('actor_id','principal://agent/01900000-0000-7000-8000-000000000009'),
    ('action_id','action://01900000-0000-7000-8000-000000000009'),
    ('backend_session_id','different-session'),
])
def test_fresh_valid_token_cannot_reuse_another_contexts_cached_response(edge, field, value):
    server, transport, request, chain, credentials, dns, *_ = edge
    original = transport.post(request, **signed(request, chain))
    assert original.content is not None
    chain.binding = replace(chain.binding, **{field:value})
    chain.payload[field] = value
    with pytest.raises(StableError) as error:
        transport.post(request, **signed(request, chain))
    assert error.value.code == ErrorCode.IDEMPOTENCY_CONFLICT
    assert len(server.seen) == len(dns) == credentials.uses == 1


def test_same_request_id_cannot_change_model_request_bytes(edge):
    server, transport, request, chain, credentials, dns, *_ = edge
    assert transport.post(request, **signed(request, chain)).content is not None
    body = json.loads(request.body); body['messages'][0]['content'] = 'different'
    changed = replace(request, body=canonical_json(body))
    with pytest.raises(StableError) as error:
        transport.post(changed, **signed(changed, chain))
    assert error.value.code == ErrorCode.IDEMPOTENCY_CONFLICT
    assert len(server.seen) == len(dns) == credentials.uses == 1


def test_session_capacity_does_not_evict_results_and_repeat_effects(edge):
    server, _transport, request, chain, credentials, dns, ca, resolve = edge
    transport = ScopedProviderHttps(verifier=chain.verifier, credential_store=credentials,
        trusted_ca_pem=ca, resolver=resolve, maximum_requests=1)
    first_auth = signed(request, chain)
    original = transport.post(request, **first_auth)
    changed = replace(request, request_id='provider-call-2')
    with pytest.raises(StableError) as error:
        transport.post(changed, **signed(changed, chain))
    assert error.value.code == ErrorCode.RESOURCE_EXHAUSTED
    assert transport.post(request, **first_auth) == original
    assert len(server.seen) == len(dns) == credentials.uses == 1


def test_dns_failure_remains_not_sent_without_implicit_retry_after_dns_recovers(edge):
    server, _transport, request, chain, credentials, dns, ca, resolve = edge
    attempts = []
    def unavailable(*args):
        attempts.append(1)
        if len(attempts) == 1:
            raise socket.gaierror('synthetic lookup failure')
        return resolve(*args)
    transport = ScopedProviderHttps(verifier=chain.verifier, credential_store=credentials,
        trusted_ca_pem=ca, resolver=unavailable)
    auth = signed(request, chain)
    result = transport.post(request, **auth)
    assert result.state == 'NOT_SENT'
    assert transport.post(request, **auth) == result
    assert len(attempts) == 1 and not dns and not server.seen and credentials.uses == 0


@pytest.mark.parametrize('secret', [b'too-short', b'synthetic-key\r\nInjected: yes'])
def test_malformed_credential_is_never_written_as_an_http_header(edge, secret):
    server, transport, request, chain, credentials, dns, *_ = edge
    credentials.secret = secret
    result = transport.post(request, **signed(request, chain))
    assert result.state == 'NOT_SENT' and result.error_code == ErrorCode.KEY_UNAVAILABLE
    assert not server.seen and credentials.uses == 1
    assert all(not any(buffer) for buffer in credentials.buffers)


def test_untrusted_tls_certificate_is_refused_before_decryption(edge):
    server, _transport, request, chain, credentials, dns, _ca, resolve = edge
    transport = ScopedProviderHttps(verifier=chain.verifier, credential_store=credentials, resolver=resolve)
    result = transport.post(request, **signed(request, chain))
    assert result.state == 'NOT_SENT' and not server.seen and credentials.uses == 0


@pytest.mark.skipif(os.name != 'nt', reason='real Windows DPAPI fixture')
@pytest.mark.parametrize('purpose', ['provider', 'root.ed25519'])
def test_actual_dpapi_handle_is_resolved_only_for_provider_purpose(edge, tmp_path, purpose):
    from agent_meta_runtime.adapters.credentials import WindowsCredentialStore
    server, _transport, request, chain, _credentials, dns, ca, resolve = edge
    store = WindowsCredentialStore(tmp_path/'protected-credentials', create=True)
    secret = bytearray(SECRET)
    try:
        handle = store.create(secret, purpose=purpose)
    finally:
        secret[:] = b'\0' * len(secret)
    request = replace(request, credential_handle=handle)
    transport = ScopedProviderHttps(verifier=chain.verifier, credential_store=store,
        trusted_ca_pem=ca, resolver=resolve)
    result = transport.post(request, **signed(request, chain))
    if purpose == 'provider':
        assert result.content is not None and len(server.seen) == 1
    else:
        assert result.state == 'NOT_SENT' and result.error_code == ErrorCode.KEY_UNAVAILABLE and not server.seen
    assert SECRET not in repr(result).encode()


@pytest.mark.parametrize('field,value', [('host','provider.test@other.test'), ('host','127.0.0.1'),
    ('host','Provider.test'), ('port',True), ('path','//other.test/messages'), ('path','/../messages'),
    ('path','/messages?token=no'), ('path','/messages\r\nX:bad'), ('networks',('127.0.0.1/8',))])
def test_ambiguous_url_or_network_encodings_fail_closed(field, value):
    with pytest.raises(StableError):
        replace(ProviderEgressPolicy('provider.test',443,'/v1/messages'), **{field:value})
