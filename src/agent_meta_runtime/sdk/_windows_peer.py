"""Windows named-pipe peer identity, checked before the Hello exchange.

Only OS public identifiers are returned. No credential handles or key material
cross this boundary. All ctypes handles are pointer-sized and closed on error.
"""

from __future__ import annotations

import os

from ..domain.errors import ErrorCode, StableError


def _process_sid(pid: int) -> str:
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel.LocalFree.restype = wintypes.HLOCAL
    security.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    security.OpenProcessToken.restype = wintypes.BOOL
    security.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    security.GetTokenInformation.restype = wintypes.BOOL
    security.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    security.ConvertSidToStringSidW.restype = wintypes.BOOL
    process = kernel.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
    if not process:
        raise ctypes.WinError(ctypes.get_last_error())
    token = wintypes.HANDLE()
    try:
        if not security.OpenProcessToken(process, 0x0008, ctypes.byref(token)):  # TOKEN_QUERY
            raise ctypes.WinError(ctypes.get_last_error())
        needed = wintypes.DWORD()
        security.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if not needed.value or needed.value > 64 * 1024:
            raise OSError("invalid TokenUser buffer size")
        buffer = ctypes.create_string_buffer(needed.value)
        if not security.GetTokenInformation(token, 1, buffer, needed, ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        text = wintypes.LPWSTR()
        if not security.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return text.value
        finally:
            kernel.LocalFree(ctypes.cast(text, wintypes.HLOCAL))
    finally:
        if token:
            kernel.CloseHandle(token)
        kernel.CloseHandle(process)


def require_same_pipe_user(pipe, *, server_side: bool) -> None:
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    function = kernel.GetNamedPipeClientProcessId if server_side else kernel.GetNamedPipeServerProcessId
    function.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    function.restype = wintypes.BOOL
    process_id = wintypes.ULONG()
    try:
        if pipe is None or not function(pipe.fileno(), ctypes.byref(process_id)) or not process_id.value:
            raise OSError("named pipe peer unavailable")
        if _process_sid(process_id.value) != _process_sid(os.getpid()):
            raise OSError("named pipe user mismatch")
    except OSError as exc:
        raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="local named pipe peer identity rejected") from exc
