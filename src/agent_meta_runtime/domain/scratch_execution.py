"""Secretless Scratch intents; Runtime owns workers, authorization and storage."""

from dataclasses import dataclass

from .ids import parse_uri
from .reflection import InspectBudget
from .scratch_export_plan import ScratchExportCandidate


@dataclass(frozen=True, slots=True)
class ScratchBindings:
    session_id: str

    def __post_init__(self):
        parse_uri(self.session_id, expected="scratch-session")

    def document(self):
        return {"schema": "scratch.bindings/v1", "session_id": self.session_id}


@dataclass(frozen=True, slots=True)
class ScratchInspect:
    session_id: str
    name: str | None = None
    handle: str | None = None
    max_depth: int = 8
    max_items: int = 10_000
    max_bytes: int = 1024 * 1024
    max_ms: int = 50

    def __post_init__(self):
        parse_uri(self.session_id, expected="scratch-session")
        if (self.name is None) == (self.handle is None):
            raise ValueError("Scratch inspect requires one name or handle")
        if self.name is not None and (
            type(self.name) is not str
            or not 1 <= len(self.name) <= 128
            or not self.name.isidentifier()
        ):
            raise ValueError("Scratch inspect requires a binding identifier")
        if self.handle is not None and (
            type(self.handle) is not str
            or not 1 <= len(self.handle) <= 128
            or not self.handle.startswith("obs:")
        ):
            raise ValueError("Scratch inspect requires an observed weak handle")
        self.budget()

    def budget(self):
        return InspectBudget(
            max_depth=self.max_depth,
            max_items=self.max_items,
            max_bytes=self.max_bytes,
            max_ms=self.max_ms,
        )

    def document(self):
        return {
            "schema": "scratch.inspect/v1",
            "session_id": self.session_id,
            **(
                {"name": self.name}
                if self.name is not None
                else {"handle": self.handle}
            ),
            "budget": {
                key: getattr(self, key)
                for key in ("max_depth", "max_items", "max_bytes", "max_ms")
            },
        }


@dataclass(frozen=True, slots=True)
class ScratchCreate:
    idle_ttl_us: int = 1_800_000_000
    wall_ttl_us: int = 14_400_000_000

    def __post_init__(self):
        if (
            type(self.idle_ttl_us) is not int
            or not 0 < self.idle_ttl_us <= 1_800_000_000
            or type(self.wall_ttl_us) is not int
            or not self.idle_ttl_us <= self.wall_ttl_us <= 14_400_000_000
        ):
            raise ValueError("Scratch lifetime exceeds its fixed profile")

    def document(self):
        return {
            "schema": "scratch.create/v1",
            "idle_ttl_us": self.idle_ttl_us,
            "wall_ttl_us": self.wall_ttl_us,
        }


@dataclass(frozen=True, slots=True)
class ScratchRelease:
    session_id: str

    def __post_init__(self):
        parse_uri(self.session_id, expected="scratch-session")

    def document(self):
        return {"schema": "scratch.release/v1", "session_id": self.session_id}


@dataclass(frozen=True, slots=True)
class ScratchExecution:
    session_id: str
    source_artifact_id: str
    deadline_at_us: int
    timeout_us: int = 30_000_000

    def __post_init__(self):
        parse_uri(self.session_id, expected="scratch-session")
        parse_uri(self.source_artifact_id, expected="artifact")
        if (
            type(self.deadline_at_us) is not int
            or not 0 <= self.deadline_at_us <= 2**53 - 1
        ):
            raise ValueError("Scratch requires an absolute integer deadline")
        if type(self.timeout_us) is not int or not 0 < self.timeout_us <= 30_000_000:
            raise ValueError("Scratch execution budget exceeds its ceiling")

    def document(self):
        return {
            "schema": "scratch.execute/v1",
            "session_id": self.session_id,
            "source_artifact_id": self.source_artifact_id,
            "deadline_at_us": self.deadline_at_us,
            "timeout_us": self.timeout_us,
        }


def is_scratch_request(value):
    return type(value) in (
        ScratchCreate,
        ScratchExecution,
        ScratchRelease,
        ScratchBindings,
        ScratchInspect,
        ScratchExportCandidate,
    )
