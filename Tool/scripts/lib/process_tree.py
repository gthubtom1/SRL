#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run external commands inside a lifecycle-bound process tree.

Windows starts the child suspended, assigns it to a Job Object with
``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE``, and only then resumes its primary
thread.  This ordering closes the usual race where a child of the command can
escape before the parent joins the job.  POSIX commands run in a dedicated
session/process group and the whole group is killed on timeout or cleanup.

The public ``run`` function mirrors the commonly used ``subprocess.run``
surface so callers keep their existing argv, text/encoding, timeout, check and
capture_output semantics.
"""
from __future__ import annotations

import os
import signal
import subprocess
from typing import Any


class ProcessTreeError(OSError):
    """The command could not be placed in a lifecycle-bound process tree."""


if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _CREATE_SUSPENDED = 0x00000004
    _CREATE_NEW_PROCESS_GROUP = 0x00000200
    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _THREAD_SUSPEND_RESUME = 0x0002
    _TH32CS_SNAPTHREAD = 0x00000004
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class _THREADENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("dwCntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    _kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD
    ]
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.TerminateJobObject.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(_THREADENTRY32)]
    _kernel32.Thread32First.restype = wintypes.BOOL
    _kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(_THREADENTRY32)]
    _kernel32.Thread32Next.restype = wintypes.BOOL
    _kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenThread.restype = wintypes.HANDLE
    _kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    _kernel32.ResumeThread.restype = wintypes.DWORD

    def _win_error(prefix: str) -> ProcessTreeError:
        return ProcessTreeError(prefix, ctypes.get_last_error())

    def _close_handle(handle: Any) -> None:
        if handle and handle != _INVALID_HANDLE_VALUE:
            _kernel32.CloseHandle(handle)

    class _WindowsJob:
        def __init__(self) -> None:
            self.handle = _kernel32.CreateJobObjectW(None, None)
            if not self.handle:
                raise _win_error("CreateJobObjectW failed")
            information = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            information.BasicLimitInformation.LimitFlags = (
                _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            )
            if not _kernel32.SetInformationJobObject(
                self.handle,
                _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(information),
                ctypes.sizeof(information),
            ):
                error = _win_error("SetInformationJobObject failed")
                self.close()
                raise error

        def assign(self, process: subprocess.Popen[Any]) -> None:
            handle = getattr(process, "_handle", None)
            if not handle:
                raise ProcessTreeError("Popen has no Windows process handle")
            if not _kernel32.AssignProcessToJobObject(
                self.handle, wintypes.HANDLE(int(handle))
            ):
                raise _win_error("AssignProcessToJobObject failed")

        def terminate(self, exit_code: int = 1) -> None:
            if self.handle:
                _kernel32.TerminateJobObject(self.handle, exit_code)

        def close(self) -> None:
            if self.handle:
                _close_handle(self.handle)
                self.handle = None

    def _resume_suspended_process(pid: int) -> int:
        """Resume the suspended process using Toolhelp thread enumeration.

        Popen closes the primary-thread handle returned by CreateProcess, so the
        process-wide thread snapshot is the safe stdlib route back to it.
        """

        snapshot = _kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0)
        if snapshot == _INVALID_HANDLE_VALUE:
            raise _win_error("CreateToolhelp32Snapshot failed")
        resumed = 0
        try:
            entry = _THREADENTRY32()
            entry.dwSize = ctypes.sizeof(entry)
            ok = _kernel32.Thread32First(snapshot, ctypes.byref(entry))
            while ok:
                if entry.th32OwnerProcessID == pid:
                    thread = _kernel32.OpenThread(
                        _THREAD_SUSPEND_RESUME, False, entry.th32ThreadID
                    )
                    if not thread:
                        raise _win_error("OpenThread failed")
                    try:
                        previous = _kernel32.ResumeThread(thread)
                        if previous == 0xFFFFFFFF:
                            raise _win_error("ResumeThread failed")
                        resumed += 1
                    finally:
                        _close_handle(thread)
                entry.dwSize = ctypes.sizeof(entry)
                ok = _kernel32.Thread32Next(snapshot, ctypes.byref(entry))
        finally:
            _close_handle(snapshot)
        if not resumed:
            raise ProcessTreeError("suspended child has no resumable thread")
        return resumed


class _ProcessTree:
    def __init__(self, process: subprocess.Popen[Any]) -> None:
        self.process = process
        self.job: Any = None

    @classmethod
    def spawn(cls, args: Any, kwargs: dict[str, Any]) -> "_ProcessTree":
        if os.name == "nt":
            flags = int(kwargs.pop("creationflags", 0))
            if flags & 0x00000008:  # DETACHED_PROCESS would escape supervision.
                raise ValueError("DETACHED_PROCESS is incompatible with process-tree isolation")
            kwargs["creationflags"] = flags | _CREATE_SUSPENDED | _CREATE_NEW_PROCESS_GROUP
            process = subprocess.Popen(args, **kwargs)
            tree = cls(process)
            try:
                tree.job = _WindowsJob()
                tree.job.assign(process)
                _resume_suspended_process(process.pid)
                return tree
            except BaseException:
                if tree.job is not None:
                    tree.job.terminate()
                    tree.job.close()
                else:
                    try:
                        process.kill()
                    except OSError:
                        pass
                try:
                    process.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    pass
                raise

        flags = int(kwargs.pop("creationflags", 0))
        if flags:
            raise ValueError("creationflags is not supported for POSIX process-tree isolation")
        if kwargs.pop("start_new_session", False):
            raise ValueError("callers cannot disable the dedicated POSIX process group")
        kwargs["start_new_session"] = True
        return cls(subprocess.Popen(args, **kwargs))

    def terminate(self) -> None:
        if os.name == "nt":
            if self.job is not None:
                self.job.terminate()
            elif self.process.poll() is None:
                self.process.kill()
            return
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            if self.process.poll() is None:
                self.process.kill()

    def close(self) -> None:
        # Closing a kill-on-close Windows job also removes any descendants that
        # survived after the root command returned.  POSIX gets the same
        # cleanup by probing and killing the dedicated process group.
        if os.name == "nt" and self.job is not None:
            self.job.close()
            self.job = None
            return
        if os.name != "nt":
            try:
                os.killpg(self.process.pid, 0)
            except ProcessLookupError:
                pass
            except OSError:
                pass
            else:
                self.terminate()


def _install_posix_handlers(tree: _ProcessTree) -> dict[int, Any]:
    if os.name == "nt":
        return {}
    old: dict[int, Any] = {}

    def cleanup(signum: int, _frame: Any) -> None:
        tree.terminate()
        raise SystemExit(128 + signum)

    for signum in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None),
                   getattr(signal, "SIGHUP", None)):
        if signum is None:
            continue
        try:
            old[signum] = signal.getsignal(signum)
            signal.signal(signum, cleanup)
        except ValueError:
            # Only the main thread may install signal handlers.
            pass
    return old


def _restore_posix_handlers(old: dict[int, Any]) -> None:
    for signum, handler in old.items():
        try:
            signal.signal(signum, handler)
        except ValueError:
            pass


def run(args: Any, *, timeout: float | None = None, check: bool = False,
        capture_output: bool = False, input: Any = None,
        **kwargs: Any) -> subprocess.CompletedProcess[Any]:
    """Run a command with its descendants bound to one lifecycle.

    Supported keyword arguments follow ``subprocess.run``, including ``cwd``,
    ``env``, stdin/stdout/stderr, text/encoding/errors and timeout.
    """

    if input is not None:
        if kwargs.get("stdin") is not None:
            raise ValueError("stdin and input arguments may not both be used")
        kwargs["stdin"] = subprocess.PIPE
    if capture_output:
        if kwargs.get("stdout") is not None or kwargs.get("stderr") is not None:
            raise ValueError("stdout and stderr arguments may not be used with capture_output")
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE

    tree = _ProcessTree.spawn(args, kwargs)
    process = tree.process
    old_handlers = _install_posix_handlers(tree)
    try:
        try:
            stdout, stderr = process.communicate(input, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            tree.terminate()
            stdout, stderr = process.communicate()
            error.stdout = stdout
            error.stderr = stderr
            raise
        except BaseException:
            tree.terminate()
            try:
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
            raise
    finally:
        tree.close()
        _restore_posix_handlers(old_handlers)

    completed = subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
    if check:
        completed.check_returncode()
    return completed


__all__ = ["ProcessTreeError", "run"]
