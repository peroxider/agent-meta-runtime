"""Bounded ordinary-content operator read; restricted data never falls back."""

import json

from ...domain.canonical import canonical_json
from ...domain.errors import ErrorCode, StableError
from ...domain.harness import is_artifact_id


MAX_PUBLIC_CONTENT_BYTES = 1024 * 1024


def read_artifact_content(conn, cas, artifact_id):
    if not is_artifact_id(artifact_id):
        raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="invalid ArtifactId")
    row = conn.execute("SELECT kind,media_type,size_bytes,manifest_json,integrity_status FROM artifacts WHERE artifact_id=?",
        (artifact_id,)).fetchone()
    if row is None:
        raise StableError(code=ErrorCode.NOT_FOUND, message="unknown Artifact")
    restricted = conn.execute("SELECT EXISTS (SELECT 1 FROM artifact_encryption WHERE artifact_id=?) OR "
        "EXISTS (SELECT 1 FROM artifact_blobs WHERE artifact_id=? AND storage_class='ENCRYPTED_RESTRICTED')",
        (artifact_id, artifact_id)).fetchone()[0]
    if restricted:
        raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="restricted Artifact content is unavailable through this interface")
    kind, media_type, size, raw_manifest, integrity = row
    if integrity != "VALID":
        raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="Artifact is not registered as valid")
    if size > MAX_PUBLIC_CONTENT_BYTES:
        raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="Artifact exceeds the 1 MiB public content-read ceiling")
    try:
        manifest = json.loads(raw_manifest)
        if not isinstance(manifest, dict) or type(manifest.get("size_bytes")) is not int or manifest["size_bytes"] != size or not isinstance(manifest.get("storage_relpath"), str):
            raise ValueError("invalid storage metadata")
    except (ValueError, TypeError, UnicodeError) as exc:
        raise StableError(code=ErrorCode.DATA_LOSS, message="Artifact storage metadata is invalid") from exc
    try:
        content = cas.open_blob(manifest["storage_relpath"], artifact_id.rsplit("/", 1)[1], size)
    except StableError as exc:
        raise StableError(code=exc.code, message="Artifact content is unavailable or failed integrity verification") from exc
    except OSError as exc:
        raise StableError(code=ErrorCode.DATA_LOSS, message="Artifact content cannot be read") from exc
    encoded = canonical_json({"artifact_id": artifact_id, "kind": kind, "media_type": media_type,
        "size_bytes": len(content), "content_hex": content.hex(), "resource_type": "artifact-content/v1", "schema_version": 1})
    if len(encoded) > 2 * MAX_PUBLIC_CONTENT_BYTES + 4096:
        raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="Artifact content metadata exceeds its response ceiling")
    return encoded
