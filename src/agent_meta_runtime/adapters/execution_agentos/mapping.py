"""Field-level translation between the frozen backend contract and the
vendored ``agentos.kernel.v1`` ABI (docs/plans/agentos-execution-kernel-bridge.md §1).

Deterministic name derivation makes Submit idempotent end to end:
``realm_name = "meta-" + sha256(realm_id)[:16]``, ``process_name =
realm_name + "-host"``, ``activity_name = "act-" + request_id``. Kernel-side
request ids are minted here as UUIDv4 (the kernel ABI requires v4 in
``RequestMeta``); the caller-side UUIDv7 identity never crosses the bridge.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from google.protobuf.json_format import MessageToDict

from ...domain.canonical import canonical_json
from ...domain.errors import ErrorCode, StableError
from ...protocols._kernel_v1 import common_pb2 as kcommon
from ...protocols._kernel_v1 import types_pb2 as ktypes

__all__ = [
    "KERNEL_ABI_VERSION",
    "activity_name",
    "decode_ref",
    "encode_ref",
    "kernel_error_to_jcs",
    "map_kernel_error",
    "meta_request",
    "process_name",
    "realm_name",
    "status_of",
    "terminal_state",
    "ts_to_us",
    "usage_to_jcs",
]

KERNEL_ABI_VERSION = "v1"

#: Client id for ``RequestMeta`` (diagnostics only, never authorization):
#: ASCII [A-Za-z0-9._-]{1,64} per agentos.kernel.v1 common.proto.
KERNEL_CLIENT_ID = "agent-meta-runtime"


# -- deterministic naming (§0 decision 2) -------------------------------------

def realm_name(realm_id: str) -> str:
    """Stable kernel realm name for a meta-runtime realm id."""

    return "meta-" + hashlib.sha256(realm_id.encode("utf-8")).hexdigest()[:16]


def process_name(name: str) -> str:
    """One long-lived host process per realm (ActivitySpec.process_name)."""

    return name + "-host"


def activity_name(request_id: str) -> str:
    """Idempotency key: the kernel activity name derived from the v7 request."""

    return "act-" + request_id


# -- ObjectRef ↔ opaque_handle (§0 decision 3) ---------------------------------

def encode_ref(ref: kcommon.ObjectRef) -> bytes:
    """JCS ``{"name","generation","revision"}`` encoding of a kernel ObjectRef."""

    return canonical_json(
        {
            "name": ref.name,
            "generation": int(ref.generation),
            "revision": int(ref.revision),
        }
    )


def decode_ref(opaque_handle: bytes) -> tuple[str, int, int]:
    """Decode an ``opaque_handle`` back into ``(name, generation, revision)``."""

    try:
        data = json.loads(bytes(opaque_handle).decode("utf-8"))
        name = data["name"]
        generation = int(data["generation"])
        revision = int(data["revision"])
    except (ValueError, UnicodeDecodeError, KeyError, TypeError) as exc:
        raise StableError(
            code=ErrorCode.INTEGRITY_ERROR,
            message="opaque_handle is not a decodable kernel ObjectRef",
        ) from exc
    if not isinstance(name, str) or not name or generation <= 0 or revision <= 0:
        raise StableError(
            code=ErrorCode.INTEGRITY_ERROR,
            message="opaque_handle carries an invalid kernel ObjectRef",
        )
    return name, generation, revision


# -- state word list (§1.1) -----------------------------------------------------

_ACTIVITY_STATUS: dict[int, str] = {
    ktypes.ACTIVITY_STATE_NEW: "RUNNING",
    ktypes.ACTIVITY_STATE_READY: "RUNNING",
    ktypes.ACTIVITY_STATE_RUNNING: "RUNNING",
    ktypes.ACTIVITY_STATE_BLOCKED: "RUNNING",
    ktypes.ACTIVITY_STATE_SUSPENDED: "RUNNING",
    ktypes.ACTIVITY_STATE_CANCELLING: "CANCELLING",
    ktypes.ACTIVITY_STATE_KILLING: "CANCELLING",
    ktypes.ACTIVITY_STATE_COMPLETED: "COMPLETED",
    ktypes.ACTIVITY_STATE_FAILED: "FAILED",
    ktypes.ACTIVITY_STATE_CANCELLED: "CANCELLED",
    ktypes.ACTIVITY_STATE_TIMED_OUT: "TIMED_OUT",
    # KILLED maps to FAILED with a killed marker in error_jcs (§1.1).
    ktypes.ACTIVITY_STATE_KILLED: "FAILED",
}

_TERMINAL_STATES = frozenset(
    (
        ktypes.ACTIVITY_STATE_COMPLETED,
        ktypes.ACTIVITY_STATE_FAILED,
        ktypes.ACTIVITY_STATE_CANCELLED,
        ktypes.ACTIVITY_STATE_TIMED_OUT,
        ktypes.ACTIVITY_STATE_KILLED,
    )
)


def status_of(state: int) -> str:
    """kernel ``ActivityState`` → backend status word (§1.1)."""

    try:
        return _ACTIVITY_STATUS[state]
    except KeyError:
        raise StableError(
            code=ErrorCode.INTERNAL,
            message="unknown kernel ActivityState",
            details={"state": int(state)},
        ) from None


def terminal_state(state: int) -> bool:
    return state in _TERMINAL_STATES


# -- error mapping (§1.2) --------------------------------------------------------

#: kernel ``KernelErrorCode`` → meta ``ErrorCode``. NOT_FOUND is contextual
#: (HANDLE_EXPIRED when the name came from a decoded handle — resolved first —
#: NOT_FOUND otherwise); unlisted codes fall to INTERNAL.
_KERNEL_ERROR_MAP: dict[int, str] = {
    kcommon.INVALID_ARGUMENT: ErrorCode.INVALID_ARGUMENT,
    kcommon.NOT_FOUND: ErrorCode.NOT_FOUND,
    kcommon.ALREADY_EXISTS: ErrorCode.ALREADY_EXISTS,
    kcommon.INVALID_STATE: ErrorCode.FAILED_PRECONDITION,
    kcommon.PERMISSION_DENIED: ErrorCode.AUTHORITY_DENIED,
    kcommon.RESOURCE_EXHAUSTED: ErrorCode.RESOURCE_EXHAUSTED,
    kcommon.ADMISSION_REJECTED: ErrorCode.RESOURCE_EXHAUSTED,
    kcommon.DEADLINE_EXCEEDED: ErrorCode.DEADLINE_EXCEEDED,
}

_HANDLE_CONTEXT_CODES = frozenset(
    (kcommon.NOT_FOUND, kcommon.STALE_GENERATION)
)


def kernel_error_name(code: int) -> str:
    try:
        return kcommon.KernelErrorCode.Name(code)
    except ValueError:
        return str(int(code))


def map_kernel_error(
    code: int, message: str, *, handle_context: bool = False, metadata: dict[str, str] | None = None
) -> StableError:
    """kernel ``KernelError`` → ``StableError`` (§1.2, retryable from registry)."""

    if handle_context and code in _HANDLE_CONTEXT_CODES:
        meta_code = ErrorCode.HANDLE_EXPIRED
    else:
        meta_code = _KERNEL_ERROR_MAP.get(code, ErrorCode.INTERNAL)
    details: dict[str, Any] = {"kernel_code": kernel_error_name(code)}
    if metadata:
        details["kernel_metadata"] = dict(metadata)
    return StableError(code=meta_code, message=message, details=details)


def kernel_error_to_jcs(code: int, message: str) -> bytes:
    """JCS projection of a kernel KernelError for ``error_jcs`` (§1.2)."""

    return canonical_json(
        {"kernel_code": kernel_error_name(code), "message": message}
    )


# -- RequestMeta (§1.3) -----------------------------------------------------------

def meta_request(
    *,
    deadline_us: int = 0,
    claimed_principal: str = "",
    trace: dict[str, str] | None = None,
) -> kcommon.RequestMeta:
    """Build a kernel ``RequestMeta`` with a fresh UUIDv4 request id.

    The bridge-side UUIDv7 never enters kernel calls (§3 gap 1); trace keys
    pass through unchanged; ``deadline`` is unset for 0.
    """

    meta = kcommon.RequestMeta(
        request_id=str(uuid.uuid4()),
        client_id=KERNEL_CLIENT_ID,
        abi_version=KERNEL_ABI_VERSION,
        claimed_principal_name=claimed_principal,
    )
    if deadline_us:
        meta.deadline.FromMicroseconds(deadline_us)
    if trace:
        meta.trace_context.update(trace)
    return meta


# -- value projections -------------------------------------------------------------

def ts_to_us(timestamp: Any) -> int:
    return int(timestamp.seconds) * 1_000_000 + int(timestamp.nanos) // 1000


def _quantity_to_json(quantity: kcommon.ResourceQuantity) -> dict[str, Any]:
    which = quantity.WhichOneof("value")
    if which == "rate":
        rate = quantity.rate
        rate_json: dict[str, Any] = {
            "burst": int(rate.burst),
            "refill_amount": int(rate.refill_amount),
        }
        if rate.HasField("refill_period"):
            rate_json["refill_period_s"] = (
                rate.refill_period.seconds + rate.refill_period.nanos / 1e9
            )
        return {"rate": rate_json}
    if which is None:
        return {}
    return {which: int(getattr(quantity, which))}


def usage_to_jcs(usage: Any, *, exit_code: int | None = None) -> bytes:
    """JCS of a kernel UsageSnapshot; ``exit_code`` folds in (§2.3)."""

    data: dict[str, Any] = {
        "cpu_nanos": int(usage.cpu_nanos),
        "memory_peak_bytes": int(usage.memory_peak_bytes),
        "io_read_bytes": int(usage.io_read_bytes),
        "io_write_bytes": int(usage.io_write_bytes),
        "adapter_usage": {
            key: _quantity_to_json(value) for key, value in usage.adapter_usage.items()
        },
        "partial": bool(usage.partial),
        "missing_fields": list(usage.missing_fields),
    }
    if usage.HasField("observed_at"):
        data["observed_at_us"] = ts_to_us(usage.observed_at)
    if exit_code is not None:
        data["exit_code"] = int(exit_code)
    return canonical_json(data)


def record_to_jcs(record: Any) -> bytes:
    """JCS of a kernel record (OperationRecord etc.) for ``details_jcs`` (§2.4)."""

    return canonical_json(
        MessageToDict(record, preserving_proto_field_name=True, use_integers_for_enums=True)
    )
