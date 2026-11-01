"""Native parent-lifetime containment for fixed Runtime worker entrypoints.

Windows workers join the owner-only Job themselves before reading a request.
This covers venv redirectors whose actual Python PID differs from Popen.pid.
Linux entrypoints arm PDEATHSIG and check the creator PID on both sides.
This is process lifetime ownership, not a strong execution/network sandbox.
"""
import ctypes
from ctypes import wintypes
import os
import re
import signal
import select
import sys
import uuid

from .windows_security import owner_security_descriptor

_NAME = re.compile(r"Local\\agent-meta-provider-[0-9a-f]{32}\Z")


class _BasicLimits(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]


class _Counters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in ("ReadOperationCount", "WriteOperationCount",
        "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _BasicLimits), ("IoInfo", _Counters),
        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", wintypes.BOOL)]


def _kernel():
    if os.name != "nt":
        raise OSError("Windows worker ownership is unavailable")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.POINTER(_SecurityAttributes), wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.OpenJobObjectW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    kernel.OpenJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.QueryInformationJobObject.restype = wintypes.BOOL
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    kernel.IsProcessInJob.restype = wintypes.BOOL
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    return kernel


class OwnedWindowsJob:
    def __init__(self):
        kernel = self._kernel = _kernel()
        self.name = "Local\\agent-meta-provider-" + uuid.uuid4().hex
        self._handle = None
        with owner_security_descriptor(directory=False, access="GA") as descriptor:
            attrs = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
            ctypes.set_last_error(0)
            handle = kernel.CreateJobObjectW(ctypes.byref(attrs), self.name)
            created_error = ctypes.get_last_error()
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        if created_error == 183:
            kernel.CloseHandle(handle)
            raise OSError("worker Job identity already exists")
        self._handle = handle
        try:
            limits = _ExtendedLimits()
            limits.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
            if not kernel.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
                raise ctypes.WinError(ctypes.get_last_error())
            observed = _ExtendedLimits()
            if not kernel.QueryInformationJobObject(handle, 9, ctypes.byref(observed), ctypes.sizeof(observed), None) or observed.BasicLimitInformation.LimitFlags != 0x2000:
                raise OSError("worker Job limit was not applied")
        except BaseException:
            self.close()
            raise

    def contains(self, pid):
        if type(pid) is not int or pid <= 0 or self._handle is None:
            return False
        process = self._kernel.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
        if not process:
            return False
        try:
            result = wintypes.BOOL()
            if not self._kernel.IsProcessInJob(process, self._handle, ctypes.byref(result)):
                raise ctypes.WinError(ctypes.get_last_error())
            return bool(result.value)
        finally:
            self._kernel.CloseHandle(process)

    def close(self):
        if self._handle is not None:
            handle = self._handle
            if not self._kernel.CloseHandle(handle):
                raise ctypes.WinError(ctypes.get_last_error())
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def join_owner_job(name):
    """Worker entrypoint only; close its extra handle BEFORE READY/input."""
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise OSError("invalid worker Job identity")
    kernel = _kernel()
    handle = kernel.OpenJobObjectW(0x1 | 0x4, False, name)  # ASSIGN_PROCESS | QUERY
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        current, present = kernel.GetCurrentProcess(), wintypes.BOOL()
        if not kernel.IsProcessInJob(current, handle, ctypes.byref(present)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not present.value and not kernel.AssignProcessToJobObject(handle, current):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        if not kernel.CloseHandle(handle):
            raise ctypes.WinError(ctypes.get_last_error())


def establish_owner_lifetime(*, parent_pid, job_name=None):
    """Must succeed before a fixed Runtime worker receives its request."""
    if type(parent_pid) is not int or parent_pid <= 0:
        raise OSError("invalid worker parent identity")
    if os.name == "nt":
        join_owner_job(job_name)
    elif sys.platform.startswith("linux"):
        if job_name is not None or os.getppid() != parent_pid:
            raise OSError("worker parent is no longer present")
        library = ctypes.CDLL(None, use_errno=True)
        library.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
        library.prctl.restype = ctypes.c_int
        if library.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
            raise OSError(ctypes.get_errno(), "worker parent lifetime guard failed")
        if os.getppid() != parent_pid:
            raise OSError("worker parent changed before lifetime guard")
    else:
        raise OSError("worker parent lifetime guard is unavailable on this platform")


class WorkerProcessLifetime:
    """Retain actual process identity across exit; never infer death by PID."""
    def __init__(self, pid):
        if type(pid) is not int or pid <= 0:
            raise OSError("invalid worker process identity")
        self._handle = None
        self._kernel = None
        if os.name == "nt":
            self._kernel = _kernel()
            self._handle = self._kernel.OpenProcess(0x100000 | 0x1000, False, pid)
            if not self._handle:
                raise ctypes.WinError(ctypes.get_last_error())
        elif sys.platform.startswith("linux") and hasattr(os, "pidfd_open"):
            self._handle = os.pidfd_open(pid)
        else:
            raise OSError("worker process lifetime observation unavailable")

    def wait(self, timeout_seconds):
        if self._handle is None:
            raise OSError("worker process lifetime observation is closed")
        if self._kernel is not None:
            status = self._kernel.WaitForSingleObject(self._handle, max(0, int(timeout_seconds * 1000)))
            if status not in (0, 258):
                raise ctypes.WinError(ctypes.get_last_error())
            return status == 0
        return bool(select.select([self._handle], [], [], max(0, timeout_seconds))[0])

    def close(self):
        if self._handle is not None:
            if self._kernel is not None:
                if not self._kernel.CloseHandle(self._handle):
                    raise ctypes.WinError(ctypes.get_last_error())
            else:
                os.close(self._handle)
            self._handle = None
