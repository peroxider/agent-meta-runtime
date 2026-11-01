"""Fixed single-request enforcement entrypoint. No Harness code or key env."""
import argparse
from pathlib import Path
import os
import sys

from ..domain.canonical import now_us
from ..domain.errors import ErrorCode, StableError
from ..domain.provider_transport import ProviderHttpOutcome, authorize_provider_request
from .credentials import InsecureDevCredentialStore, WindowsCredentialStore
from .owned_worker import establish_owner_lifetime
from .provider_https import ScopedProviderHttps
from .provider_worker_wire import read_frame, write_frame, parse_command, outcome_document


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--parent-pid", required=True, type=int)
    parser.add_argument("--job-name")
    args = parser.parse_args()
    try:
        establish_owner_lifetime(parent_pid=args.parent_pid, job_name=args.job_name)
    except Exception:
        write_frame(sys.stdout.buffer, {"schema": "provider-worker-ready/v1", "status": "UNAVAILABLE", "pid": os.getpid()})
        return 1
    # No request/token/profile has been read yet. The parent must verify this
    # actual process's ownership before it writes the signed control frame.
    write_frame(sys.stdout.buffer, {"schema": "provider-worker-ready/v1", "status": "READY", "pid": os.getpid()})
    request = None
    try:
        bootstrap, request, authorization, binding = parse_command(read_frame(sys.stdin.buffer))
        if request.deadline_at_us is None:
            raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="worker absolute deadline required")
        verifier = bootstrap.verifier()
        _audit, remaining, _fingerprint = authorize_provider_request(verifier, request,
            authorization=authorization, binding=binding, now_us=now_us())
        if remaining <= 0:
            raise StableError(code=ErrorCode.DEADLINE_EXCEEDED, message="worker deadline expired")
        if bootstrap.credential_profile == "WINDOWS_DPAPI_CURRENT_USER":
            credentials = WindowsCredentialStore(Path(bootstrap.credential_root))
        elif request.policy.profile == "CONTROLLED_TEST_ONLY":
            credentials = InsecureDevCredentialStore(Path(bootstrap.credential_root))
        else:
            raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="insecure Provider storage is unavailable")
        transport = ScopedProviderHttps(verifier=verifier, credential_store=credentials,
            trusted_ca_pem=bootstrap.trusted_ca_pem, maximum_requests=1)
        outcome = transport.post(request, authorization=authorization, binding=binding, now_us=now_us())
    except StableError as error:
        # The HTTP edge contains all errors after its first write; this branch
        # rejects bootstrap/authorization/storage before a Provider request.
        outcome = ProviderHttpOutcome("NOT_SENT", error_code=error.code, reason_code="WORKER_PRECONDITION")
    except Exception:
        outcome = ProviderHttpOutcome("NOT_SENT", error_code=ErrorCode.INVALID_ARGUMENT, reason_code="WORKER_CONTROL_FRAME")
    write_frame(sys.stdout.buffer, outcome_document(outcome,
        request_id=request.request_id if request is not None else None,
        scope_hash=request.scope_hash if request is not None else None))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BrokenPipeError, EOFError):
        raise SystemExit(1) from None
