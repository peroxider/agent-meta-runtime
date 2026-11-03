"""Regenerate the frozen v1 protobuf modules (§41.41).

The ``proto/`` sources are authoritative; this script only stamps the
generated modules into ``src/agent_meta_runtime/protocols/_v1/`` and rewrites
the cross-package import so the modules live inside ``agent_meta_runtime``.
The vendored ``agentos.kernel.v1`` ABI (upstream frozen contract, see
``proto/agentos/README.md``) is stamped into
``src/agent_meta_runtime/protocols/_kernel_v1/`` the same way.
Run after any additive proto change; field numbers and the registry version
are guarded by tests.

Usage: ``.venv/bin/python scripts/generate_protos.py``
"""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
PROTO_ROOT = ROOT / "proto"

GENERATION_TARGETS = (
    (
        # Frozen meta-runtime contracts (§41.41).
        (
            "agent_meta/transport/v1/transport.proto",
            "agent_meta/execution_backend/v1/execution_backend.proto",
            "agent_meta/public/v1/public.proto",
        ),
        ROOT / "src" / "agent_meta_runtime" / "protocols" / "_v1",
        re.compile(r"^from agent_meta(\.[a-z0-9_.]+) import ([a-z_0-9]+)_pb2 as (\w+)$"),
    ),
    (
        # Vendored upstream kernel ABI (frozen; do not edit the .proto files).
        (
            "agentos/kernel/v1/common.proto",
            "agentos/kernel/v1/types.proto",
            "agentos/kernel/v1/resources.proto",
            "agentos/kernel/v1/control.proto",
            "agentos/kernel/v1/service.proto",
        ),
        ROOT / "src" / "agent_meta_runtime" / "protocols" / "_kernel_v1",
        re.compile(r"^from agentos(\.[a-z0-9_.]+) import ([a-z_0-9]+)_pb2 as (\w+)$"),
    ),
)


def main() -> int:
    protoc = shutil.which("protoc")
    if protoc is None:
        print("protoc not found on PATH", file=sys.stderr)
        return 1
    for proto_files, out_pkg, import_re in GENERATION_TARGETS:
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(
                [
                    protoc,
                    f"--proto_path={PROTO_ROOT}",
                    f"--python_out={tmp}",
                    *proto_files,
                ],
                check=True,
                cwd=ROOT,
            )
            generated = sorted(pathlib.Path(tmp).rglob("*_pb2.py"))
            out_pkg.mkdir(parents=True, exist_ok=True)
            for path in generated:
                text = path.read_text(encoding="utf-8")
                lines = []
                for line in text.splitlines(keepends=True):
                    match = import_re.match(line.rstrip("\n"))
                    if match:
                        line = f"from . import {match.group(2)}_pb2 as {match.group(3)}\n"
                    lines.append(line)
                (out_pkg / path.name).write_text("".join(lines), encoding="utf-8")
        init = out_pkg / "__init__.py"
        if not init.exists():
            init.write_text(
                '"""Generated protobuf modules (do not edit; regenerate via'
                ' scripts/generate_protos.py)."""\n',
                encoding="utf-8",
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
