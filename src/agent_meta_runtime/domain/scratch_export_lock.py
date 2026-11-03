"""Verify Scratch export lock declarations against actual immutable wheel bytes.

No dependency is imported, installed or extracted. Platform/ABI materialization
and executable package validation remain requirements of the later World build.
"""

from email.parser import BytesParser
import io
import keyword
import re
import stat
import struct
import sys
import unicodedata
import zipfile

from .canonical import sha256_hex
from .errors import ErrorCode, StableError
from .harness import is_artifact_id

MAX_WHEEL_BYTES = 32 * 1024 * 1024
MAX_TOTAL_WHEEL_BYTES = 64 * 1024 * 1024
MAX_WHEEL_ENTRIES = 10_000


def _fail(reason):
    raise StableError(
        code=ErrorCode.INVALID_ARGUMENT,
        message="Scratch dependency lock was refused",
        details={"reason_code": reason},
    ) from None


def _root(value):
    return (
        type(value) is str
        and len(value) <= 128
        and value.isidentifier()
        and unicodedata.normalize("NFKC", value) == value
        and not keyword.iskeyword(value)
    )


def _distribution(value):
    if (
        type(value) is not str
        or len(value) > 128
        or not re.fullmatch(r"[A-Za-z0-9]+(?:[-_.][A-Za-z0-9]+)*", value)
    ):
        _fail("INVALID_DEPENDENCY_LOCK")
    return re.sub(r"[-_.]+", "-", value).lower()


def _wheel_roots(raw, distribution, version):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_WHEEL_BYTES:
        _fail("DEPENDENCY_SIZE")
    # Bound the central directory before ZipFile allocates its entry objects.
    # ZIP64/multi-volume inputs are outside this small dependency profile.
    end = raw.rfind(b"PK\x05\x06", max(0, len(raw) - 65557))
    if end < 0 or end + 22 > len(raw):
        _fail("INVALID_DEPENDENCY_WHEEL")
    disk, start_disk, disk_count, count, size, offset, comment = struct.unpack_from(
        "<HHHHIIH", raw, end + 4
    )
    if (
        disk
        or start_disk
        or disk_count != count
        or not 1 <= count <= MAX_WHEEL_ENTRIES
        or size > 1024 * 1024
        or offset + size != end
        or end + 22 + comment != len(raw)
    ):
        _fail("INVALID_DEPENDENCY_WHEEL")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            if (
                len(entries) != count
                or len({entry.filename for entry in entries}) != count
            ):
                _fail("INVALID_DEPENDENCY_WHEEL")
            identities = [
                unicodedata.normalize("NFC", entry.filename).casefold()
                for entry in entries
            ]
            if len(set(identities)) != len(identities):
                _fail("INVALID_DEPENDENCY_WHEEL")
            roots, metadata = set(), []
            wheel_headers = {}
            records = set()
            for entry in entries:
                path = entry.orig_filename
                if path != entry.filename:
                    _fail("INVALID_DEPENDENCY_WHEEL")
                parts = path.rstrip("/").split("/")
                if (
                    not path
                    or "\\" in path
                    or "\0" in path
                    or ":" in path
                    or path.startswith("/")
                    or any(part in ("", ".", "..") for part in parts)
                    or entry.flag_bits & 1
                    or stat.S_ISLNK(entry.external_attr >> 16)
                ):
                    _fail("INVALID_DEPENDENCY_WHEEL")
                if (
                    len(parts) == 2
                    and parts[0].endswith(".dist-info")
                    and parts[1] == "METADATA"
                ):
                    if entry.file_size > 64 * 1024:
                        _fail("DEPENDENCY_SIZE")
                    with archive.open(entry) as stream:
                        metadata.append(
                            (
                                parts[0],
                                BytesParser().parsebytes(stream.read(64 * 1024 + 1)),
                            )
                        )
                if (
                    len(parts) == 2
                    and parts[0].endswith(".dist-info")
                    and parts[1] == "WHEEL"
                ):
                    if entry.file_size > 16 * 1024:
                        _fail("DEPENDENCY_SIZE")
                    with archive.open(entry) as stream:
                        wheel_headers[parts[0]] = BytesParser().parsebytes(
                            stream.read(16 * 1024 + 1)
                        )
                if (
                    len(parts) == 2
                    and parts[0].endswith(".dist-info")
                    and parts[1] == "RECORD"
                ):
                    records.add(parts[0])
                if parts[0].endswith(".data"):
                    if len(parts) < 3 or parts[1] not in ("purelib", "platlib"):
                        continue
                    parts = parts[2:]
                if parts[0].endswith((".dist-info", ".data")) or entry.is_dir():
                    continue
                leaf = parts[-1]
                if not leaf.endswith((".py", ".so", ".pyd")):
                    continue
                root = parts[0] if len(parts) > 1 else leaf.split(".")[0]
                if _root(root):
                    roots.add(root)
            if len(metadata) != 1:
                _fail("INVALID_DEPENDENCY_WHEEL")
            directory, document = metadata[0]
            header = wheel_headers.get(directory)
            if (
                header is None
                or directory not in records
                or set(wheel_headers) != {directory}
            ):
                _fail("INVALID_DEPENDENCY_WHEEL")
            if (
                header.get_all("Wheel-Version", []) != ["1.0"]
                or header.get_all("Root-Is-Purelib", []) not in (["true"], ["false"])
                or not header.get_all("Tag", [])
                or any(
                    not re.fullmatch(
                        r"[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+", tag
                    )
                    for tag in header.get_all("Tag", [])
                )
            ):
                _fail("INVALID_DEPENDENCY_WHEEL")
            names, versions = document.get_all("Name", []), document.get_all(
                "Version", []
            )
            if (
                len(names) != 1
                or len(versions) != 1
                or _distribution(names[0]) != distribution
                or versions[0] != version
                or not roots
            ):
                _fail("DEPENDENCY_METADATA_MISMATCH")
            return roots
    except (
        zipfile.BadZipFile,
        RuntimeError,
        ValueError,
        OSError,
        UnicodeError,
        NotImplementedError,
    ):
        _fail("INVALID_DEPENDENCY_WHEEL")


def validate_export_lock(document, artifacts):
    """Return import roots proven by this lock's declared stdlib/wheel inputs.

    Artifacts are an internal tuple of (ArtifactId, bytes), obtained by Root
    through authorized reads. Wheel module declarations must match their actual
    importable archive paths; top_level.txt alone is not accepted as evidence.
    """
    if (
        type(document) is not dict
        or set(document) != {"schema", "python_abi", "stdlib_modules", "wheels"}
        or document["schema"] != "scratch-python-dependency-lock/v1"
        or document["python_abi"] != "cp312"
    ):
        _fail("INVALID_DEPENDENCY_LOCK")
    standard, wheels = document["stdlib_modules"], document["wheels"]
    if (
        type(standard) is not list
        or len(standard) > 256
        or not all(_root(name) for name in standard)
        or standard != sorted(set(standard))
        or not set(standard) <= sys.stdlib_module_names
        or type(wheels) is not list
        or len(wheels) > 32
    ):
        _fail("INVALID_DEPENDENCY_LOCK")
    if type(artifacts) is not tuple or len(artifacts) > 32:
        _fail("INVALID_DEPENDENCY_INPUTS")
    blobs = {}
    total = 0
    for pair in artifacts:
        if type(pair) is not tuple or len(pair) != 2:
            _fail("INVALID_DEPENDENCY_INPUTS")
        reference, raw = pair
        if (
            not is_artifact_id(reference)
            or type(raw) is not bytes
            or len(raw) > MAX_WHEEL_BYTES
            or reference in blobs
            or reference != "artifact://sha256/" + sha256_hex(raw)
        ):
            _fail("INVALID_DEPENDENCY_INPUTS")
        total += len(raw)
        if total > MAX_TOTAL_WHEEL_BYTES:
            _fail("DEPENDENCY_SIZE")
        blobs[reference] = raw
    allowed, used, distributions = set(standard), set(), []
    for wheel in wheels:
        if type(wheel) is not dict or set(wheel) != {
            "distribution",
            "version",
            "artifact_id",
            "modules",
        }:
            _fail("INVALID_DEPENDENCY_LOCK")
        distribution, version = _distribution(wheel["distribution"]), wheel["version"]
        modules, reference = wheel["modules"], wheel["artifact_id"]
        if (
            wheel["distribution"] != distribution
            or type(version) is not str
            or not 1 <= len(version) <= 128
            or type(modules) is not list
            or not modules
            or not all(_root(name) for name in modules)
            or modules != sorted(set(modules))
            or not is_artifact_id(reference)
            or reference not in blobs
            or reference in used
            or distribution in distributions
        ):
            _fail("INVALID_DEPENDENCY_LOCK")
        actual = _wheel_roots(blobs[reference], distribution, version)
        if set(modules) != actual or actual & sys.stdlib_module_names:
            _fail("DEPENDENCY_MODULE_MISMATCH")
        used.add(reference)
        distributions.append(distribution)
        allowed.update(actual)
    if used != set(blobs) or distributions != sorted(distributions):
        _fail("INVALID_DEPENDENCY_INPUTS")
    return frozenset(allowed)
