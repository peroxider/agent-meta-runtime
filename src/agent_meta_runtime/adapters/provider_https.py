"""Runtime-owned HTTPS edge: signed scope, pinned DNS/TLS, scoped credentials.

There is no proxy discovery, redirect following, retry, package callback or
environment credential lookup here. A future Provider worker calls this edge
only after the durable Invocation/attempt and budget reservation commit.
The per-session cache prevents duplicate sends; it is not restart recovery.
"""
from dataclasses import dataclass, field
import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time

from ..domain.errors import ErrorCode, StableError
from ..domain.provider_transport import ProviderHttpOutcome, ProviderHttpRequest, _pairs, authorize_provider_request


def _deny(reason):
    return StableError(code=ErrorCode.AUTHORITY_DENIED, message="controlled Provider authorization rejected",
        details={"reason_code": reason})


def _failure(state, code, reason, *, status=None, retry=None):
    return ProviderHttpOutcome(state, error_code=code, reason_code=reason, http_status=status, retry_after_us=retry)


@dataclass
class _Admission:
    fingerprint: str
    done: threading.Event = field(default_factory=threading.Event)
    result: ProviderHttpOutcome | None = None


class ScopedProviderHttps:
    """Enforcement-only object; never exported through a Host facade.

    Python cannot zero every immutable TLS/HTTP-library copy. Secret resolution
    is limited to this Runtime-owned edge, with mutable buffers cleared by the
    CredentialStore and no headers/raw exceptions in returned outcomes.
    """
    def __init__(self, *, verifier, credential_store, trusted_ca_pem=None, resolver=None,
                 maximum_requests=128):
        if type(maximum_requests) is not int or not 0 < maximum_requests <= 1024:
            raise ValueError("invalid Provider session capacity")
        if trusted_ca_pem is not None and (type(trusted_ca_pem) is not bytes or not 0 < len(trusted_ca_pem) <= 65536):
            raise ValueError("invalid Provider trust anchor")
        # Own the context. Accepting an externally mutable SSLContext would let
        # a later configuration mutation disable verified certificate checks.
        context = ssl.create_default_context(cadata=trusted_ca_pem.decode("ascii") if trusted_ca_pem else None)
        self._verifier = verifier
        self._credentials = credential_store
        self._context = context
        self._resolver = resolver if resolver is not None else socket.getaddrinfo
        self._maximum = maximum_requests
        self._lock = threading.Lock()
        self._requests = {}

    def post(self, request: ProviderHttpRequest, *, authorization: bytes, binding, now_us: int):
        _audit, remaining, fingerprint = authorize_provider_request(self._verifier, request,
            authorization=authorization, binding=binding, now_us=now_us)
        if request.policy.profile == "PUBLIC_HTTPS" and self._credentials.profile != "WINDOWS_DPAPI_CURRENT_USER":
            raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="public Provider use requires protected credential storage")
        if remaining <= 0:
            raise StableError(code=ErrorCode.DEADLINE_EXCEEDED, message="Provider execution authorization expired")
        with self._lock:
            row = self._requests.get(request.request_id)
            if row is not None:
                if row.fingerprint != fingerprint:
                    raise StableError(code=ErrorCode.IDEMPOTENCY_CONFLICT, message="Provider request identity changed")
                owner = False
            else:
                if len(self._requests) >= self._maximum:
                    raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="Provider session request retention is full")
                row = self._requests[request.request_id] = _Admission(fingerprint)
                owner = True
        if not owner:
            if row.done.wait(remaining / 1_000_000):
                return row.result
            return _failure("UNKNOWN", ErrorCode.EXTERNAL_EFFECT_UNKNOWN, "IN_FLIGHT")
        result = _failure("UNKNOWN", ErrorCode.EXTERNAL_EFFECT_UNKNOWN, "OWNER_INTERRUPTED")
        try:
            result = self._send(request, remaining)
            return result
        finally:
            with self._lock:
                row.result = result
                row.done.set()

    def _addresses(self, request):
        answers = self._resolver(request.policy.host, request.policy.port, socket.AF_UNSPEC,
            socket.SOCK_STREAM, socket.IPPROTO_TCP)
        if not answers or len(answers) > 64:
            raise _deny("DNS_ANSWERS")
        result = []
        for family, kind, protocol, _canonical, address in answers:
            if family not in (socket.AF_INET, socket.AF_INET6) or kind != socket.SOCK_STREAM or protocol != socket.IPPROTO_TCP:
                raise _deny("DNS_ADDRESS_KIND")
            if not isinstance(address, tuple) or len(address) != (2 if family == socket.AF_INET else 4) or address[1] != request.policy.port:
                raise _deny("DNS_ADDRESS_BINDING")
            if not request.policy.permits_ip(address[0]) or (family == socket.AF_INET6 and (address[2] != 0 or address[3] != 0)):
                raise _deny("DNS_IP_POLICY")
            parsed = ipaddress.ip_address(address[0])
            if parsed.version != (4 if family == socket.AF_INET else 6):
                raise _deny("DNS_ADDRESS_FAMILY")
            candidate = (family, address)
            if candidate not in result:
                result.append(candidate)
        return sorted(result, key=lambda item: (item[0] != socket.AF_INET, ipaddress.ip_address(item[1][0]).packed))

    @staticmethod
    def _timeout(sock, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        sock.settimeout(remaining)

    @staticmethod
    def _secret_in_response(raw, secret):
        if secret in raw:
            return True
        body = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("invalid JSON constant")))
        text = secret.decode("ascii")
        pending = [(body, 0)]
        count = 0
        while pending:
            value, depth = pending.pop()
            count += 1
            if depth > 32 or count > 16384:
                raise ValueError("Provider response complexity exceeded")
            if isinstance(value, str) and text in value:
                return True
            if isinstance(value, dict):
                pending.extend((item, depth + 1) for item in value.values())
                pending.extend((key, depth + 1) for key in value)
            elif isinstance(value, list):
                pending.extend((item, depth + 1) for item in value)
        return False

    def _send(self, request, timeout_us):
        deadline = time.monotonic() + timeout_us / 1_000_000
        connection = plain = secure = watchdog = response = None
        started = False
        try:
            addresses = self._addresses(request)
            if time.monotonic() >= deadline:
                raise TimeoutError()
            # One pinned address/one attempt. A second DNS lookup or address
            # fallback must not silently create an unjournaled HTTP attempt.
            family, address = addresses[0]
            plain = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            self._timeout(plain, deadline)
            plain.connect(address)
            self._timeout(plain, deadline)
            secure = self._context.wrap_socket(plain, server_hostname=request.policy.host)
            self._timeout(secure, deadline)
            # A socket timeout alone can be extended indefinitely by trickled
            # header bytes. Interrupt the whole HTTP phase at its total limit.
            def interrupt():
                try:
                    secure.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            watchdog = threading.Timer(max(0, deadline - time.monotonic()), interrupt)
            watchdog.daemon = True
            watchdog.start()
            connection = http.client.HTTPConnection(request.policy.host, request.policy.port)
            connection.sock = secure
            with self._credentials.get_for_scoped_use(request.credential_handle, purpose="provider") as secret:
                if not isinstance(secret, bytearray) or not 16 <= len(secret) <= 8192 or not re.fullmatch(rb"[A-Za-z0-9._~+/-]+=*", secret):
                    return _failure("NOT_SENT", ErrorCode.KEY_UNAVAILABLE, "CREDENTIAL_FORMAT")
                # Mark uncertainty before the first HTTP write. Even a partial
                # request can have been accepted; an exception is not a retry.
                started = True
                connection.request("POST", request.policy.path, request.body, headers={
                    "Authorization": "Bearer " + secret.decode("ascii"),
                    "Content-Type": "application/json", "Accept": "application/json",
                    "Accept-Encoding": "identity", "anthropic-version": "2023-06-01"})
                self._timeout(secure, deadline)
                # Own the TLS socket through the whole bounded response read.
                # HTTPConnection.getresponse() closes its socket immediately
                # for Connection: close, defeating our deadline management.
                response = http.client.HTTPResponse(secure, method="POST")
                response.begin()
                status = response.status
                if 300 <= status < 400:
                    return _failure("RESPONSE", ErrorCode.AUTHORITY_DENIED, "REDIRECT_FORBIDDEN", status=status)
                if not 200 <= status < 300:
                    if status >= 500 or status == 408:
                        return _failure("UNKNOWN", ErrorCode.EXTERNAL_EFFECT_UNKNOWN, "HTTP_UNCERTAIN", status=status)
                    retry = response.getheader("Retry-After")
                    retry = int(retry) * 1_000_000 if retry is not None and re.fullmatch(r"[0-9]{1,4}", retry) and int(retry) <= 3600 else None
                    return _failure("RESPONSE", ErrorCode.RESOURCE_EXHAUSTED if status == 429 else ErrorCode.BACKEND_UNAVAILABLE,
                        "HTTP_FAILURE", status=status, retry=retry)
                if response.getheader("Content-Encoding", "identity").lower() != "identity" or response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                    return _failure("RESPONSE", ErrorCode.INVALID_RESULT, "RESPONSE_ENCODING", status=status)
                length = response.getheader("Content-Length")
                if length is not None and (not re.fullmatch(r"[0-9]{1,10}", length) or int(length) > request.maximum_response_bytes):
                    return _failure("RESPONSE", ErrorCode.INVALID_RESULT, "RESPONSE_SIZE", status=status)
                chunks, size = [], 0
                while True:
                    self._timeout(secure, deadline)
                    chunk = response.read1(min(16384, request.maximum_response_bytes + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > request.maximum_response_bytes:
                        return _failure("RESPONSE", ErrorCode.INVALID_RESULT, "RESPONSE_SIZE", status=status)
                raw = b"".join(chunks)
                if length is not None and size != int(length):
                    return _failure("UNKNOWN", ErrorCode.EXTERNAL_EFFECT_UNKNOWN, "INCOMPLETE_RESPONSE", status=status)
                try:
                    if self._secret_in_response(raw, secret):
                        return _failure("RESPONSE", ErrorCode.INTEGRITY_ERROR, "CREDENTIAL_IN_RESPONSE", status=status)
                except (ValueError, TypeError, UnicodeError, RecursionError):
                    return _failure("RESPONSE", ErrorCode.INVALID_RESULT, "RESPONSE_JSON", status=status)
                return ProviderHttpOutcome("RESPONSE", content=raw, http_status=status)
        except StableError as error:
            return _failure("UNKNOWN" if started else "NOT_SENT",
                ErrorCode.EXTERNAL_EFFECT_UNKNOWN if started else error.code, "CONTROLLED_EDGE_REJECTED")
        except (OSError, ValueError, http.client.HTTPException, ssl.SSLError):
            return _failure("UNKNOWN" if started else "NOT_SENT",
                ErrorCode.EXTERNAL_EFFECT_UNKNOWN if started else ErrorCode.BACKEND_UNAVAILABLE, "TRANSPORT_FAILURE")
        except Exception:
            return _failure("UNKNOWN" if started else "NOT_SENT",
                ErrorCode.EXTERNAL_EFFECT_UNKNOWN if started else ErrorCode.INTERNAL, "CONTROLLED_EDGE_FAILURE")
        finally:
            if watchdog is not None:
                watchdog.cancel()
            if response is not None:
                response.close()
            if connection is not None:
                connection.close()
            if secure is not None:
                secure.close()
            if plain is not None:
                plain.close()
