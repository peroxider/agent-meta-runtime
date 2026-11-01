"""Scoped Windows DPAPI credential storage (§41.55).

Only Authority/Backend/CLI enforcement code may resolve these handles. A handle
is an identifier, not authority. Caller enforcement must authorize each use;
this adapter additionally binds ciphertext to its purpose and handle identity.
"""

from __future__ import annotations

import base64
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import re
import uuid

from ..domain.canonical import canonical_json
from ..domain.errors import ErrorCode, StableError
from .windows_security import is_owner_only, secure_owner_only
from .private_paths import require_private_path, secure_private_path

_MAX_SECRET_BYTES = 64 * 1024
_HANDLE = re.compile(r"credential://windows-dpapi/([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\Z")
_PURPOSES = frozenset({"root.ed25519", "service.ed25519", "artifact.kek", "provider"})


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _dpapi(value: bytearray, entropy: bytes, *, decrypt: bool):
    if os.name != "nt":
        raise OSError("Windows DPAPI is unavailable")
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    input_buffer = (ctypes.c_ubyte * len(value)).from_buffer(value)
    entropy_buffer = (ctypes.c_ubyte * len(entropy)).from_buffer_copy(entropy)
    input_blob = _Blob(len(value), input_buffer)
    entropy_blob = _Blob(len(entropy), entropy_buffer)
    output = _Blob()
    function = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    description_type = ctypes.POINTER(wintypes.LPWSTR) if decrypt else wintypes.LPCWSTR
    function.argtypes = [ctypes.POINTER(_Blob), description_type, ctypes.POINTER(_Blob), ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
    function.restype = wintypes.BOOL
    # UI_FORBIDDEN, without LOCAL_MACHINE: keys belong to CurrentUser.
    if not function(ctypes.byref(input_blob), None, ctypes.byref(entropy_blob), None, None, 1, ctypes.byref(output)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if decrypt:
            if not 0 < output.cbData <= _MAX_SECRET_BYTES:
                raise ValueError("decrypted credential size invalid")
            result = bytearray(output.cbData)
            destination = (ctypes.c_ubyte * len(result)).from_buffer(result)
            ctypes.memmove(destination, output.pbData, output.cbData)
            return result
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        if output.pbData:
            if decrypt:
                ctypes.memset(output.pbData, 0, output.cbData)
            kernel.LocalFree(output.pbData)


class WindowsCredentialStore:
    """Encrypted files under an owner-only, explicitly supplied storage root."""

    profile = "WINDOWS_DPAPI_CURRENT_USER"

    def __init__(self, root: Path, *, create: bool = False):
        if os.name != "nt":
            raise StableError(code=ErrorCode.FEATURE_UNAVAILABLE, message="Windows credential store unavailable")
        self.root = Path(root)
        if self.root.is_symlink() or self.root.is_junction():
            raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="credential root cannot be a reparse point")
        if create:
            self.root.mkdir(parents=True, exist_ok=True)
            secure_owner_only(self.root)
        self._check_permissions(self.root)

    @staticmethod
    def _check_permissions(path):
        try:
            if not is_owner_only(path):
                raise OSError("credential permissions differ")
        except OSError as exc:
            raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="credential storage is not owner-only") from exc

    def _path(self, handle: str) -> Path:
        match = _HANDLE.fullmatch(handle) if isinstance(handle, str) else None
        if match is None:
            raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="unknown credential handle format")
        return self.root / (match.group(1) + ".dpapi")

    @staticmethod
    def _entropy(handle: str, purpose: str) -> bytes:
        if not isinstance(purpose, str) or purpose not in _PURPOSES:
            raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="credential purpose is not registered")
        return b"agent-meta-credential-v1\x00" + purpose.encode("ascii") + b"\x00" + handle.encode("ascii")

    def create(self, secret: bytearray, *, purpose: str) -> str:
        if not isinstance(secret, bytearray) or not 0 < len(secret) <= _MAX_SECRET_BYTES:
            raise ValueError("credential must be a bounded mutable byte buffer")
        self._check_permissions(self.root)
        handle = "credential://windows-dpapi/" + str(uuid.uuid4())
        path = self._path(handle)
        try:
            encrypted = _dpapi(secret, self._entropy(handle, purpose), decrypt=False)
            document = canonical_json({"schema": "credential-item/v1", "handle": handle, "purpose": purpose, "ciphertext": base64.b64encode(encrypted).decode("ascii")})
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_BINARY, 0o600)
            try:
                secure_owner_only(path)
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(document)
                    stream.flush()
                    os.fsync(fd)
            finally:
                os.close(fd)
            return handle
        except (OSError, ValueError) as exc:
            path.unlink(missing_ok=True)
            raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="credential encryption or durable storage failed") from exc

    @contextmanager
    def get_for_scoped_use(self, handle: str, *, purpose: str):
        path = self._path(handle)
        entropy = self._entropy(handle, purpose)
        secret = None
        try:
            self._check_permissions(self.root)
            self._check_permissions(path)
            if path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError("credential envelope exceeds limit")
            raw = path.read_bytes()
            document = json.loads(raw)
            if set(document) != {"schema", "handle", "purpose", "ciphertext"} or document["schema"] != "credential-item/v1" or document["handle"] != handle or document["purpose"] != purpose:
                raise ValueError("credential envelope binding differs")
            if canonical_json(document) != raw:
                raise ValueError("credential envelope must be canonical JSON")
            encrypted = bytearray(base64.b64decode(document["ciphertext"], validate=True))
            secret = _dpapi(encrypted, entropy, decrypt=True)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="credential cannot be resolved for this scope") from exc
        try:
            yield secret
        finally:
            if secret is not None:
                secret[:] = b"\x00" * len(secret)

    def rotate(self, handle: str, secret: bytearray, *, purpose: str) -> str:
        # Verify ownership/purpose before creating a new independent item.
        # The caller still owns signed identity/DEK cutover and retirement.
        with self.get_for_scoped_use(handle, purpose=purpose):
            return self.create(secret, purpose=purpose)

    def delete_metadata(self, handle: str, *, reference_count: int) -> None:
        if type(reference_count) is not int or reference_count < 0:
            raise ValueError("credential dependency count invalid")
        if reference_count:
            raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="credential still has active references", details={"reference_count": reference_count})
        path = self._path(handle)
        self._check_permissions(self.root)
        if path.exists():
            self._check_permissions(path)
            path.unlink()


class InsecureDevCredentialStore:
    """Explicit fixture-only storage; never advertises a product profile."""

    profile = "INSECURE_TEST_ONLY"

    def __init__(self, root: Path, *, create: bool = False):
        self.root = Path(root)
        if create:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            self._secure(self.root)
        self._check(self.root)

    @staticmethod
    def _secure(path):
        secure_private_path(path)

    @staticmethod
    def _check(path):
        try:
            require_private_path(path)
        except OSError:
            raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="dev credential storage is unavailable") from None

    def _path(self, handle):
        prefix = "credential://insecure-dev/"
        value = handle.removeprefix(prefix) if isinstance(handle, str) and handle.startswith(prefix) else ""
        try:
            if str(uuid.UUID(value, version=4)) != value:
                raise ValueError("noncanonical dev handle")
        except ValueError as exc:
            raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="unknown dev credential handle") from exc
        return self.root / (value + ".key")

    def create(self, secret: bytearray, *, purpose: str) -> str:
        if not isinstance(secret, bytearray) or not 0 < len(secret) <= _MAX_SECRET_BYTES:
            raise ValueError("credential must be a bounded mutable byte buffer")
        handle = "credential://insecure-dev/" + str(uuid.uuid4())
        WindowsCredentialStore._entropy("fixture", purpose)
        self._check(self.root)
        path = self._path(handle)
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600)
        try:
            self._secure(path)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(canonical_json({"schema": "insecure-dev-credential/v1", "handle": handle, "purpose": purpose, "value": base64.b64encode(secret).decode("ascii")}))
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        return handle

    @contextmanager
    def get_for_scoped_use(self, handle: str, *, purpose: str):
        path = self._path(handle)
        WindowsCredentialStore._entropy("fixture", purpose)
        self._check(self.root)
        self._check(path)
        try:
            if path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError("dev credential exceeds limit")
            document = json.loads(path.read_bytes())
            if set(document) != {"schema", "handle", "purpose", "value"} or document["schema"] != "insecure-dev-credential/v1" or document["handle"] != handle or document["purpose"] != purpose:
                raise ValueError("dev credential scope differs")
            secret = bytearray(base64.b64decode(document["value"], validate=True))
            if not 0 < len(secret) <= _MAX_SECRET_BYTES:
                raise ValueError("dev credential size invalid")
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="dev credential unavailable for this scope") from exc
        try:
            yield secret
        finally:
            secret[:] = b"\x00" * len(secret)

    def rotate(self, handle: str, secret: bytearray, *, purpose: str) -> str:
        with self.get_for_scoped_use(handle, purpose=purpose):
            return self.create(secret, purpose=purpose)

    def delete_metadata(self, handle: str, *, reference_count: int) -> None:
        if type(reference_count) is not int or reference_count < 0:
            raise ValueError("credential dependency count invalid")
        if reference_count:
            raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="credential still referenced", details={"reference_count": reference_count})
        self._check(self.root)
        path = self._path(handle)
        if path.exists():
            self._check(path)
            path.unlink()


def write_store_config(root: Path, *, profile: str, handles: dict[str, str], operator: dict[str, str]) -> Path:
    """Local adapter metadata contains handles only, never secret material."""
    path = Path(root) / "store.json"
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600)
    try:
        secure_private_path(path)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(canonical_json({"schema": "credential-store-config/v1", "profile": profile, "handles": handles, "operator": operator}))
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    return path


def open_key_store(data_dir: Path, *, allow_insecure: bool = False):
    root = Path(data_dir) / "keys"
    path = root / "store.json"
    try:
        require_private_path(root)
        require_private_path(path)
        document = json.loads(path.read_bytes())
        if set(document) != {"schema", "profile", "handles", "operator"} or document["schema"] != "credential-store-config/v1" or set(document["handles"]) != {"root", "service"} or set(document["operator"]) != {"actor_id", "authority_grant_id", "public_key_hex"}:
            raise ValueError("key store metadata invalid")
        if document["profile"] == WindowsCredentialStore.profile:
            store = WindowsCredentialStore(root)
        elif document["profile"] == InsecureDevCredentialStore.profile and allow_insecure:
            store = InsecureDevCredentialStore(root)
        else:
            raise ValueError("credential profile unavailable or not explicitly allowed")
        return store, dict(document["handles"])
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="credential store metadata unavailable; explicit recovery required") from exc


def operator_signing_authority(data_dir: Path, *, allow_insecure: bool = False):
    """Return public operator identity and a scoped signing callback, not keys."""
    from .crypto import Ed25519KeyPair

    store, handles = open_key_store(data_dir, allow_insecure=allow_insecure)
    operator = json.loads((Path(data_dir) / "keys/store.json").read_bytes())["operator"]

    def sign(preimage: bytes) -> bytes:
        with store.get_for_scoped_use(handles["root"], purpose="root.ed25519") as material:
            pair = Ed25519KeyPair.from_private_bytes(bytes(material))
            if pair.public_bytes_raw().hex() != operator["public_key_hex"]:
                raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="operator credential differs from recorded public identity")
            return pair.sign(preimage)

    return dict(operator), sign


def service_signing_authority(data_dir: Path, *, expected_public_key: bytes, allow_insecure: bool = False):
    """Kernel-only scoped Service signer; does not read the Root private key."""
    from .crypto import Ed25519KeyPair

    if not isinstance(expected_public_key, bytes) or len(expected_public_key) != 32:
        raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="committed Service public identity is invalid")
    store, handles = open_key_store(data_dir, allow_insecure=allow_insecure)
    def sign(preimage: bytes) -> bytes:
        with store.get_for_scoped_use(handles["service"], purpose="service.ed25519") as material:
            pair = Ed25519KeyPair.from_private_bytes(bytes(material))
            if pair.public_bytes_raw() != expected_public_key:
                raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="Service credential differs from committed public identity")
            return pair.sign(preimage)
    return sign
