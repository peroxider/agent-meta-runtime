"""Immutable public intent for source-only candidate construction."""

from dataclasses import dataclass

from .harness import is_artifact_id
from .ids import parse_uri


@dataclass(frozen=True, slots=True)
class ScratchExportCandidate:
    session_id: str
    source_artifact_ids: tuple[str, ...]
    export_names: tuple[str, ...]
    contract_artifact_id: str
    dependency_lock_artifact_id: str
    entrypoint: str
    dependency_artifact_ids: tuple[str, ...] = ()
    support_artifact_ids: tuple[str, ...] = ()
    name: str = "scratch-candidate"
    version: str = "0.1.0"

    def __post_init__(self):
        if type(self.session_id) is not str:
            raise ValueError("Scratch export requires an immutable session identity")
        parse_uri(self.session_id, expected="scratch-session")
        for values, minimum, maximum in (
            (self.source_artifact_ids, 1, 64),
            (self.dependency_artifact_ids, 0, 64),
            (self.support_artifact_ids, 0, 256),
        ):
            if (
                type(values) is not tuple
                or not minimum <= len(values) <= maximum
                or not all(
                    type(value) is str and is_artifact_id(value) for value in values
                )
                or len(set(values)) != len(values)
            ):
                raise ValueError(
                    "Scratch export requires bounded unique Artifact identities"
                )
        if not all(
            type(value) is str and is_artifact_id(value)
            for value in (self.contract_artifact_id, self.dependency_lock_artifact_id)
        ):
            raise ValueError("Scratch export requires contract and lock Artifacts")
        if (
            type(self.export_names) is not tuple
            or not 1 <= len(self.export_names) <= 100
            or any(
                type(value) is not str
                or not 1 <= len(value) <= 128
                or not value.isidentifier()
                for value in self.export_names
            )
            or len(set(self.export_names)) != len(self.export_names)
        ):
            raise ValueError("Scratch export requires selected definition names")
        if (
            type(self.entrypoint) is not str
            or len(self.entrypoint) > 160
            or self.entrypoint
            not in tuple("scratch_candidate:" + value for value in self.export_names)
        ):
            raise ValueError("Scratch export requires a selected entrypoint")
        if any(
            type(value) is not str or not 1 <= len(value) <= 128
            for value in (self.name, self.version)
        ):
            raise ValueError("Scratch export requires bounded package metadata")

    def inputs(self):
        return tuple(
            dict.fromkeys(
                (
                    *self.source_artifact_ids,
                    self.contract_artifact_id,
                    self.dependency_lock_artifact_id,
                    *self.dependency_artifact_ids,
                    *self.support_artifact_ids,
                )
            )
        )

    def document(self):
        return {
            "schema": "scratch.export/v1",
            "session_id": self.session_id,
            "source_artifact_ids": list(self.source_artifact_ids),
            "export_names": list(self.export_names),
            "contract_artifact_id": self.contract_artifact_id,
            "dependency_lock_artifact_id": self.dependency_lock_artifact_id,
            "entrypoint": self.entrypoint,
            "dependency_artifact_ids": list(self.dependency_artifact_ids),
            "support_artifact_ids": list(self.support_artifact_ids),
            "name": self.name,
            "version": self.version,
        }
