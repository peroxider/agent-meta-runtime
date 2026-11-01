"""Owner-only Windows filesystem DACLs (§41.55/§41.57).

No ACL change is made to a parent of the explicitly supplied object. Reparse
points are refused. Native handles/pointers always use pointer-sized ctypes.
"""

from __future__ import annotations

from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import os
from pathlib import Path


def _libraries():
    if os.name != "nt":
        raise OSError("Windows security is unavailable on this platform")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    return kernel, security


def _sid_text(sid, kernel, security) -> str:
    convert = security.ConvertSidToStringSidW
    convert.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    convert.restype = wintypes.BOOL
    text = wintypes.LPWSTR()
    if not convert(sid, ctypes.byref(text)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return text.value
    finally:
        kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))


def current_user_sid() -> str:
    kernel, security = _libraries()
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    security.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    security.OpenProcessToken.restype = wintypes.BOOL
    security.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    security.GetTokenInformation.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    if not security.OpenProcessToken(kernel.GetCurrentProcess(), 0x8, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        needed = wintypes.DWORD()
        security.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if not 0 < needed.value <= 65536:
            raise OSError("invalid TokenUser buffer")
        buffer = ctypes.create_string_buffer(needed.value)
        if not security.GetTokenInformation(token, 1, buffer, needed, ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        return _sid_text(ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0], kernel, security)
    finally:
        kernel.CloseHandle(token)


@contextmanager
def owner_security_descriptor(*, directory: bool, access: str = "FA"):
    """Yield a native protected DACL descriptor; release it with LocalFree."""
    if access not in ("FA", "GA"):
        raise ValueError("unsupported owner descriptor access mask")
    kernel, security = _libraries()
    function = security.ConvertStringSecurityDescriptorToSecurityDescriptorW
    function.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.ULONG)]
    function.restype = wintypes.BOOL
    descriptor = ctypes.c_void_p()
    flags = "OICI" if directory else ""
    text = f"D:P(A;{flags};{access};;;{current_user_sid()})"
    if not function(text, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        yield descriptor
    finally:
        kernel.LocalFree(descriptor)


def secure_owner_only(path: Path) -> None:
    path = Path(path)
    if path.is_symlink() or path.is_junction():
        raise OSError("refusing to set credential permissions on a reparse point")
    _, security = _libraries()
    get_dacl = security.GetSecurityDescriptorDacl
    get_dacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
    get_dacl.restype = wintypes.BOOL
    apply = security.SetNamedSecurityInfoW
    apply.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    apply.restype = wintypes.DWORD
    with owner_security_descriptor(directory=path.is_dir()) as descriptor:
        present, defaulted, acl = wintypes.BOOL(), wintypes.BOOL(), ctypes.c_void_p()
        if not get_dacl(descriptor, ctypes.byref(present), ctypes.byref(acl), ctypes.byref(defaulted)) or not present or not acl:
            raise OSError("owner DACL is unavailable")
        result = apply(str(path), 1, 0x80000004, None, None, acl, None)
        if result:
            raise ctypes.WinError(result)
    if not is_owner_only(path):
        raise OSError("owner-only DACL verification failed")


def inspect_dacl(path: Path) -> dict:
    kernel, security = _libraries()
    get = security.GetNamedSecurityInfoW
    get.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    get.restype = wintypes.DWORD
    control_fn = security.GetSecurityDescriptorControl
    control_fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD)]
    control_fn.restype = wintypes.BOOL
    info_fn = security.GetAclInformation
    info_fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int]
    info_fn.restype = wintypes.BOOL
    ace_fn = security.GetAce
    ace_fn.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    ace_fn.restype = wintypes.BOOL
    descriptor, acl = ctypes.c_void_p(), ctypes.c_void_p()
    result = get(str(path), 1, 4, None, None, ctypes.byref(acl), None, ctypes.byref(descriptor))
    if result:
        raise ctypes.WinError(result)
    try:
        control, revision = wintypes.WORD(), wintypes.DWORD()
        if not control_fn(descriptor, ctypes.byref(control), ctypes.byref(revision)) or not acl:
            raise OSError("missing DACL")
        info = (wintypes.DWORD * 3)()
        if not info_fn(acl, info, ctypes.sizeof(info), 2):
            raise ctypes.WinError(ctypes.get_last_error())
        entries = []
        for index in range(info[0]):
            ace = ctypes.c_void_p()
            if not ace_fn(acl, index, ctypes.byref(ace)):
                raise ctypes.WinError(ctypes.get_last_error())
            header = ctypes.string_at(ace, 4)
            kind, flags = header[0], header[1]
            if kind not in (0, 1):
                entries.append({"type": kind, "flags": flags, "sid": None, "mask": None})
                continue
            mask = ctypes.cast(ace.value + 4, ctypes.POINTER(wintypes.DWORD))[0]
            entries.append({"type": kind, "flags": flags, "mask": mask, "sid": _sid_text(ace.value + 8, kernel, security)})
        return {"protected": bool(control.value & 0x1000), "entries": entries}
    finally:
        kernel.LocalFree(descriptor)


def is_owner_only(path: Path) -> bool:
    path = Path(path)
    if path.is_symlink() or path.is_junction():
        return False
    observed = inspect_dacl(path)
    entries = observed["entries"]
    expected_flags = 3 if path.is_dir() else 0
    return observed["protected"] and len(entries) == 1 and entries[0] == {
        "type": 0, "flags": expected_flags, "sid": current_user_sid(), "mask": 0x1F01FF,
    }
