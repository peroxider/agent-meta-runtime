"""Portable worker entrypoint (§41.48.1).

Run as ``<venv python> -m agent_meta_runtime.adapters.execution_portable.worker_entry
<request_dir> <expected_payload_hash>`` inside an isolated worker environment
(minimal env, new workspace cwd, new process group). Structured results are
written to ``result.jcs`` — never to stdout, which is capture-only.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

from .worker import ClaimTakenError, run_worker, write_result

__all__ = ["BUILTIN_HANDLERS", "main"]


def _echo(payload: dict[str, Any]) -> tuple[str, bytes, bytes]:
    return "SUCCEEDED", b"{}", json.dumps(payload, sort_keys=True).encode("utf-8")


def _fail(payload: dict[str, Any]) -> tuple[str, bytes, bytes]:
    error = payload.get("error", {"code": "INVALID_RESULT", "message": "test failure"})
    return "FAILED", b"{}", json.dumps(error, sort_keys=True).encode("utf-8")


def _sleep(payload: dict[str, Any]) -> tuple[str, bytes, bytes]:
    """Cooperative sleep; honors the control.cancel GRACEFUL signal."""

    seconds = float(payload.get("seconds", 0.2))
    request_dir = Path(payload["__request_dir__"])
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if (request_dir / "control.cancel").exists():
            return "CANCELLED", b"{}", b'{"cancelled": true}'
        time.sleep(0.02)
    return "SUCCEEDED", b"{}", b'{"slept": true}'


BUILTIN_HANDLERS = {
    "test.echo": _echo,
    "test.fail": _fail,
    "test.sleep": _sleep,
}


def _payload_wrapper(request_dir: Path, payload: dict[str, Any]) -> dict[str, Any]:
    wrapped = dict(payload)
    wrapped["__request_dir__"] = str(request_dir)
    return wrapped


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: worker_entry <request_dir> <expected_payload_hash>", file=sys.stderr)
        return 2
    request_dir = Path(argv[0])
    expected_hash = argv[1]
    raw = (request_dir / "request.jcs").read_bytes()
    operation_kind = json.loads(raw.decode("utf-8")).get("operation_kind", "")
    handler = BUILTIN_HANDLERS.get(operation_kind)
    if handler is None:
        print(f"unknown operation_kind: {operation_kind}", file=sys.stderr)
        return 3
    try:
        run_worker(
            request_dir,
            expected_payload_hash=expected_hash,
            handler=lambda payload: handler(_payload_wrapper(request_dir, payload)),
        )
    except ClaimTakenError:
        # Another worker owns this request: exit quietly, no result written.
        return 0
    except Exception as exc:  # noqa: BLE001 - worker must record a failure
        write_result(
            request_dir,
            {
                "status": "FAILED",
                "usage_jcs": "{}",
                "result_jcs": json.dumps({"error": repr(exc)}, sort_keys=True),
            },
        )
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - subprocess entry
    raise SystemExit(main(sys.argv[1:]))
