"""Native operator recovery into an empty directory, without a daemon.

This bootstrap tool is separate from the ordinary API proxy CLI. It accepts
only explicit native paths; it never emits credentials or snapshot contents.
"""

import argparse
import json
from pathlib import Path

from ...adapters.store.backup import restore_backup
from ...domain.errors import ErrorCode, StableError


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "invalid restore arguments; use --help\n")


def main(argv=None):
    parser = _Parser(prog="agent-meta-restore", description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        required=True,
        help="absolute path to a sealed private backup",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        required=True,
        help="absolute nonexistent or empty target; never merge",
    )
    parser.add_argument(
        "--insecure-dev-credential-file",
        action="store_true",
        help="explicit fixture-only key-file recovery",
    )
    args = parser.parse_args(argv)
    try:
        result = restore_backup(
            args.source,
            args.data_dir,
            allow_insecure_credentials=args.insecure_dev_credential_file,
        )
        print(
            json.dumps(
                {"schema": "runtime-restore/v1", "ok": True, "result": result},
                sort_keys=True,
            ),
            flush=True,
        )
        return 0
    except StableError as exc:
        print(
            json.dumps(
                {
                    "schema": "runtime-restore/v1",
                    "ok": False,
                    "error": {"code": exc.code, "message": exc.message},
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return {
            ErrorCode.INVALID_ARGUMENT: 2,
            ErrorCode.NOT_FOUND: 4,
            ErrorCode.REVISION_CONFLICT: 5,
            ErrorCode.FAILED_PRECONDITION: 6,
            ErrorCode.FEATURE_UNAVAILABLE: 6,
            ErrorCode.BACKEND_UNAVAILABLE: 7,
            ErrorCode.RESOURCE_EXHAUSTED: 7,
            ErrorCode.KEY_UNAVAILABLE: 8,
            ErrorCode.INTEGRITY_ERROR: 8,
        }.get(exc.code, 70)
    except (Exception, KeyboardInterrupt):
        print(
            json.dumps(
                {
                    "schema": "runtime-restore/v1",
                    "ok": False,
                    "error": {"code": ErrorCode.INTERNAL, "message": "restore failed"},
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
