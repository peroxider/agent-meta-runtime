"""Actual Windows DPAPI + DACL proofs; no plaintext fixture substitution."""

import base64
import json
import os
from pathlib import Path

import pytest

from agent_meta_runtime.adapters.credentials import WindowsCredentialStore
from agent_meta_runtime.adapters.windows_security import current_user_sid, inspect_dacl, is_owner_only
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.canonical import canonical_json

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI/DACL contract")


def test_dpapi_roundtrip_reopens_after_restart_and_zeroizes_use_buffer(tmp_path):
    secret = bytearray(b"test-key-material-only-" * 3)
    store = WindowsCredentialStore(tmp_path / "credentials", create=True)
    handle = store.create(secret, purpose="root.ed25519")
    assert handle.startswith("credential://windows-dpapi/")
    files = list(store.root.glob("*.dpapi"))
    assert len(files) == 1
    assert bytes(secret) not in files[0].read_bytes()
    assert is_owner_only(store.root) and is_owner_only(files[0])
    acl = inspect_dacl(files[0])
    assert acl["protected"]
    assert [entry["sid"] for entry in acl["entries"]] == [current_user_sid()]
    restarted = WindowsCredentialStore(store.root)
    with restarted.get_for_scoped_use(handle, purpose="root.ed25519") as resolved:
        assert resolved == secret
        observed = resolved
    assert observed == bytearray(len(secret))


def test_wrong_purpose_unknown_handle_and_ciphertext_tamper_fail_closed(tmp_path):
    store = WindowsCredentialStore(tmp_path / "credentials", create=True)
    handle = store.create(bytearray(b"provider-test-secret"), purpose="provider")
    with pytest.raises(StableError):
        with store.get_for_scoped_use(handle, purpose="root.ed25519"):
            pytest.fail("purpose change must not decrypt")
    for bad in ("credential://windows-dpapi/../root", "credential://local-keyfile/1", "not-a-handle"):
        with pytest.raises(StableError):
            with store.get_for_scoped_use(bad, purpose="provider"):
                pytest.fail("unknown handle must not resolve")
    path = next(store.root.glob("*.dpapi"))
    document = json.loads(path.read_bytes())
    encrypted = bytearray(base64.b64decode(document["ciphertext"]))
    encrypted[-1] ^= 1
    document["ciphertext"] = base64.b64encode(encrypted).decode("ascii")
    path.write_bytes(canonical_json(document))
    with pytest.raises(StableError) as error:
        with store.get_for_scoped_use(handle, purpose="provider"):
            pytest.fail("tampered ciphertext must not decrypt")
    assert error.value.code == ErrorCode.KEY_UNAVAILABLE
    assert "test-secret" not in str(error.value.to_json())


def test_valid_ciphertext_cannot_be_substituted_under_another_handle(tmp_path):
    store = WindowsCredentialStore(tmp_path / "credentials", create=True)
    first = store.create(bytearray(b"first-test-value"), purpose="provider")
    second = store.create(bytearray(b"second-test-value"), purpose="provider")
    documents = {json.loads(path.read_bytes())["handle"]: (path, json.loads(path.read_bytes())) for path in store.root.glob("*.dpapi")}
    target, document = documents[first]
    document["ciphertext"] = documents[second][1]["ciphertext"]
    target.write_bytes(canonical_json(document))
    with pytest.raises(StableError):
        with store.get_for_scoped_use(first, purpose="provider"):
            pytest.fail("DPAPI entropy must bind ciphertext to the durable handle")


def test_buffer_is_zeroized_even_when_scoped_consumer_raises(tmp_path):
    store = WindowsCredentialStore(tmp_path / "credentials", create=True)
    handle = store.create(bytearray(b"test-only-value"), purpose="artifact.kek")
    with pytest.raises(RuntimeError):
        with store.get_for_scoped_use(handle, purpose="artifact.kek") as value:
            observed = value
            raise RuntimeError("consumer failed")
    assert not any(observed)


def test_rotation_keeps_old_item_until_zero_reference_retirement(tmp_path):
    store = WindowsCredentialStore(tmp_path / "credentials", create=True)
    old = store.create(bytearray(b"old-test-key"), purpose="artifact.kek")
    new = store.rotate(old, bytearray(b"new-test-key"), purpose="artifact.kek")
    assert new != old
    with store.get_for_scoped_use(old, purpose="artifact.kek") as value:
        assert value == b"old-test-key"
    with store.get_for_scoped_use(new, purpose="artifact.kek") as value:
        assert value == b"new-test-key"
    with pytest.raises(StableError) as error:
        store.delete_metadata(old, reference_count=1)
    assert error.value.code == ErrorCode.FAILED_PRECONDITION
    store.delete_metadata(old, reference_count=0)
    store.delete_metadata(old, reference_count=0)
    with pytest.raises(StableError):
        with store.get_for_scoped_use(old, purpose="artifact.kek"):
            pytest.fail("deleted item cannot resolve")


def test_non_owner_only_acl_is_rejected_before_decryption(tmp_path):
    import ctypes
    from ctypes import wintypes

    store = WindowsCredentialStore(tmp_path / "credentials", create=True)
    handle = store.create(bytearray(b"test-only"), purpose="provider")
    path = next(store.root.glob("*.dpapi"))
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    convert = security.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    convert.restype = wintypes.BOOL
    apply = security.SetFileSecurityW
    apply.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    apply.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    descriptor = ctypes.c_void_p()
    assert convert(f"D:P(A;;FA;;;{current_user_sid()})(A;;FR;;;WD)", 1, ctypes.byref(descriptor), None)
    try:
        assert apply(str(path), 0x80000004, descriptor)
    finally:
        kernel.LocalFree(descriptor)
    assert not is_owner_only(path)
    with pytest.raises(StableError) as error:
        with store.get_for_scoped_use(handle, purpose="provider"):
            pytest.fail("broad ACL must not decrypt")
    assert error.value.code == ErrorCode.KEY_UNAVAILABLE
