"""Step 00 gate: identity, canonical encoding and AMPAK1 golden/negative tests."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from agent_meta_runtime.domain import ampak, canonical, ids

GOLDEN = json.loads(
    (Path(__file__).parent / "golden" / "foundation_golden.json").read_text("utf-8")
)


# --------------------------------------------------------------- identity ---
def test_uuid7_structure() -> None:
    value = ids.new_uuid7(now_ms=1_700_000_000_000)
    assert re_fullmatch_uuid7(value)
    assert ids.normalize_uuidv7(value) == value
    raw = value.replace("-", "")
    ms = int(raw[:12], 16)
    assert ms == 1_700_000_000_000


def re_fullmatch_uuid7(value: str) -> bool:
    import re

    return bool(
        re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            value,
        )
    )


def test_uuid7_monotonic_prefix() -> None:
    assert ids.new_uuid7(now_ms=1) < ids.new_uuid7(now_ms=2)


@pytest.mark.parametrize(
    "bad",
    [
        "018f6a2c-1234-7ABC-9DEF-000000000000",
        "018f6a2c12347abc9def000000000000",
        "018f6a2c-1234-4abc-9def-000000000000",  # version 4
        "018f6a2c-1234-7abc-cdef-000000000000",  # variant 11xx
        "not-a-uuid",
    ],
)
def test_uuid7_rejects_malformed(bad: str) -> None:
    with pytest.raises(ids.IdError):
        ids.normalize_uuidv7(bad)


@pytest.mark.parametrize(
    "good",
    [
        "artifact://sha256/" + "a" * 64,
        "blob://sha256/" + "b" * 64,
        "realm://main",
        "capability://my-cap.v2",
        "principal://operator-root/01900000-0000-7000-8000-000000000000",
        "context://projection/01900000-0000-7000-8000-000000000000",
        "task://01900000-0000-7000-8000-000000000000",
    ],
)
def test_validate_id_accepts(good: str) -> None:
    assert ids.validate_id(good) == good


@pytest.mark.parametrize(
    "bad",
    [
        "artifact://sha256/" + "A" * 64,
        "artifact://sha256/short",
        "bogus://01900000-0000-7000-8000-000000000000",
        "principal://superuser/01900000-0000-7000-8000-000000000000",
        "context://01900000-0000-7000-8000-000000000000",
        "realm://Main",
        "realm://" + "a" * 129,
        "task://01900000-0000-7000-8000-000000000000/",
        "task://01900000-0000-7000-8000-000000000000x",
    ],
)
def test_validate_id_rejects(bad: str) -> None:
    with pytest.raises(ids.IdError):
        ids.validate_id(bad)


def test_stable_name_grammar() -> None:
    assert ids.validate_stable_name("a") == "a"
    assert ids.validate_stable_name("cap.one-two_3") == "cap.one-two_3"
    for bad in ("A", "1abc", "a--b-", "a//b", "", "a#b"):
        with pytest.raises(ids.IdError):
            ids.validate_stable_name(bad)


# ------------------------------------------------------- canonical (JCS) ---
def test_jcs_golden_vectors() -> None:
    for vector in GOLDEN["jcs"]:
        parsed = vector["input"]
        assert canonical.canonical_json_str(parsed) == vector["expected"], vector["name"]
        assert canonical.canonical_json(parsed) == vector["expected"].encode("utf-8")


def test_jcs_rejects_out_of_range_and_non_finite() -> None:
    for bad in (2**53, -(2**53) - 1, float("nan"), float("inf"), float("-inf")):
        with pytest.raises(canonical.CanonicalJsonError):
            canonical.canonical_json(bad)


def test_jcs_rejects_non_json_types() -> None:
    for bad in (object(), b"bytes", {1, 2}, complex(1, 2)):
        with pytest.raises(canonical.CanonicalJsonError):
            canonical.canonical_json(bad)


def test_sha256_and_payload_hash() -> None:
    assert canonical.sha256_hex(b"") == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert canonical.payload_hash({"a": 1}) == canonical.payload_hash({"a": 1})
    assert canonical.payload_hash({"a": 1}) != canonical.payload_hash({"a": 2})


def test_rfc3339() -> None:
    assert canonical.rfc3339(0) == "1970-01-01T00:00:00.000000Z"
    assert canonical.rfc3339(1_700_000_000_123_456) == "2023-11-14T22:13:20.123456Z"
    with pytest.raises(canonical.CanonicalJsonError):
        canonical.rfc3339(1.5)


# ----------------------------------------------------------------- AMPAK ---
def _decode(name: str) -> tuple[ampak.PackageManifest, dict[str, bytes]]:
    vector = next(v for v in GOLDEN["ampak"] if v["name"] == name)
    return ampak.decode_package(base64.b64decode(vector["encoded_b64"]))


def test_ampak_golden_vectors() -> None:
    empty, empty_files = _decode("empty_package")
    assert empty.package.name == "empty-pkg"
    assert empty_files == {}
    assert empty.entries == ()
    sample, sample_files = _decode("sample_package")
    by_path = {e.path: e for e in sample.entries}
    assert by_path["src/main.py"].sha256 == canonical.sha256_hex(b"print(1)\n")
    assert by_path["src"].kind == "DIRECTORY"
    unicode, unicode_files = _decode("unicode_paths")
    assert unicode_files["目录/文件.txt"] == "内容\n".encode("utf-8")
    paths = [e.path for e in unicode.entries]
    assert paths == sorted(paths, key=lambda s: s.encode("utf-8"))


def test_ampak_round_trip() -> None:
    files = {"pkg/main.py": b"x = 1\n", "data/deep/nested.bin": bytes(1024)}
    meta = ampak.PackageMeta(
        name="rt", version="0.1.0", artifact_kind="capability",
        entrypoint="pkg.main:run", contract_artifact_id=None,
        dependency_lock_artifact_id=None, state_schema_artifact_ids=[],
        migration_artifact_ids=[], runtime_constraints={},
        platform_constraints={}, build_provenance_artifact_id=None,
    )
    blob = ampak.encode_package(ampak.build_manifest(meta, files), files)
    manifest, decoded = ampak.decode_package(blob)
    assert decoded == files
    assert manifest.package.name == "rt"


def test_ampak_magic_prefix() -> None:
    assert ampak.MAGIC == b"AMPAK1\n"


@pytest.mark.parametrize(
    "bad_path",
    [
        "/absolute",
        "a/../b",
        "./x",
        "a//b",
        "trailing/",
        "back\\slash",
        "ads:colon",
        "CON",
        "com1.txt",
        "NUL",
        "ends.",
        "ends ",
        "NUL/sub",
    ],
)
def test_ampak_rejects_bad_paths(bad_path: str) -> None:
    with pytest.raises(ampak.AmpakError):
        ampak.validate_package_path(bad_path)


def test_ampak_rejects_case_fold_duplicates() -> None:
    meta = _meta("dup")
    with pytest.raises(ampak.AmpakError):
        ampak.build_manifest(meta, {"A.txt": b"1", "a.txt": b"2"})


def test_ampak_rejects_normalization_duplicates() -> None:
    meta = _meta("dup")
    nfd = "é.txt"  # NFD form of é
    with pytest.raises(ampak.AmpakError):
        ampak.build_manifest(meta, {"é.txt": b"1", nfd: b"2"})


def test_ampak_rejects_corrupt_payloads() -> None:
    manifest, files = _decode("sample_package")
    blob = ampak.encode_package(manifest, files)
    corrupted = bytearray(blob)
    corrupted[-1] ^= 0xFF
    with pytest.raises(ampak.AmpakError):
        ampak.decode_package(bytes(corrupted))
    with pytest.raises(ampak.AmpakError):
        ampak.decode_package(blob + b"\x00")
    with pytest.raises(ampak.AmpakError):
        ampak.decode_package(b"XMPAK1\n" + blob[7:])


def test_ampak_rejects_unknown_manifest_fields() -> None:
    from agent_meta_runtime.domain.canonical import canonical_json

    manifest, files = _decode("sample_package")
    blob = ampak.encode_package(manifest, files)
    mlen = int.from_bytes(blob[7:15], "big")
    body = json.loads(blob[15 : 15 + mlen])
    body["extra"] = 1
    new_manifest = canonical_json(body)
    forged = ampak.MAGIC + len(new_manifest).to_bytes(8, "big") + new_manifest
    with pytest.raises(ampak.AmpakError):
        ampak.decode_package(forged + blob[15 + mlen :])


def test_ampak_file_conflict() -> None:
    with pytest.raises(ampak.AmpakError):
        ampak.build_manifest(_meta("conflict"), {"a": b"x", "a/b": b"y"})


def _meta(name: str) -> ampak.PackageMeta:
    return ampak.PackageMeta(
        name=name, version="1", artifact_kind="k", entrypoint="",
        contract_artifact_id=None, dependency_lock_artifact_id=None,
        state_schema_artifact_ids=[], migration_artifact_ids=[],
        runtime_constraints={}, platform_constraints={},
        build_provenance_artifact_id=None,
    )
