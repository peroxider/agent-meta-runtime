"""Protocol and schema version registry (§41.39.3, Step 00 item 6).

Versioned protocol identities are frozen here even before generated protobuf
code lands (Backend v1 / Public API v1 arrive in Steps 04 and 06). Generated
code must never be committed as the only protocol source: the ``proto/``
sources plus this registry are authoritative, and generated modules must
declare the registry version they were generated against.
"""

from __future__ import annotations

__all__ = [
    "BACKEND_PROTOCOL_VERSION",
    "FACT_SCHEMA_VERSION",
    "PROTOCOL_VERSIONS",
    "PUBLIC_API_VERSION",
    "check_protocol_versions",
]

FACT_SCHEMA_VERSION = 1
PUBLIC_API_VERSION = 1
BACKEND_PROTOCOL_VERSION = 1

PROTOCOL_VERSIONS: dict[str, int] = {
    "agent_meta.public.v1": PUBLIC_API_VERSION,
    "agent_meta.execution_backend.v1": BACKEND_PROTOCOL_VERSION,
    "agent_meta.facts.v1": FACT_SCHEMA_VERSION,
}


def check_protocol_versions(declared: dict[str, int]) -> list[str]:
    """Return mismatch descriptions for declared generated-module versions."""

    problems: list[str] = []
    for name, version in sorted(declared.items()):
        expected = PROTOCOL_VERSIONS.get(name)
        if expected is None:
            problems.append(f"unknown protocol identity: {name}")
        elif version != expected:
            problems.append(f"{name}: generated v{version} != registry v{expected}")
    return problems
