"""Process hardening shared by commands that handle secret device state."""

from __future__ import annotations

import ctypes
import errno
import resource


def disable_core_dumps() -> None:
    """Fail closed unless Linux marks this process non-dumpable."""
    pr_set_dumpable = 4
    pr_get_dumpable = 3
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    prctl.restype = ctypes.c_int

    if prctl(pr_set_dumpable, 0, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, errno.errorcode.get(error, "prctl failed"))
    if prctl(pr_get_dumpable, 0, 0, 0, 0) != 0:
        raise RuntimeError("failed to verify that the process is non-dumpable")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
