# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import os
import re
import subprocess
import sys
from contextlib import suppress
from pathlib import Path

from .constants import _DOWNLOAD_MIN_RANGE_SIZE

_MIB = 1024 * 1024


def available_cpu_count() -> int:
    process_cpu_count = getattr(os, "process_cpu_count", None)
    count = (process_cpu_count() if process_cpu_count is not None else None) or os.cpu_count() or 1
    with suppress(AttributeError, OSError):
        count = min(count, len(os.sched_getaffinity(0)))
    return max(1, count)


def _linux_available_memory() -> int | None:
    try:
        with Path("/proc/meminfo").open(encoding="ascii") as info:
            for line in info:
                if line.startswith("MemAvailable:"):
                    amount = int(line.split()[1]) * 1024
                    break
            else:
                return None
    except (OSError, ValueError, IndexError):
        return None

    for limit_path, usage_path in (
        ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory.current"),
        ("/sys/fs/cgroup/memory/memory.limit_in_bytes", "/sys/fs/cgroup/memory/memory.usage_in_bytes"),
    ):
        try:
            limit = int(Path(limit_path).read_text(encoding="ascii").strip())
            usage = int(Path(usage_path).read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            continue
        amount = min(amount, max(0, limit - usage))
    return max(0, amount)


def _windows_available_memory() -> int | None:
    import ctypes

    class MemoryStatus(ctypes.Structure):
        _fields_ = [
            ("length", ctypes.c_ulong),
            ("memory_load", ctypes.c_ulong),
            ("total_phys", ctypes.c_ulonglong),
            ("avail_phys", ctypes.c_ulonglong),
            ("total_page_file", ctypes.c_ulonglong),
            ("avail_page_file", ctypes.c_ulonglong),
            ("total_virtual", ctypes.c_ulonglong),
            ("avail_virtual", ctypes.c_ulonglong),
            ("avail_extended_virtual", ctypes.c_ulonglong),
        ]

    status = MemoryStatus()
    status.length = ctypes.sizeof(status)
    try:
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return int(status.avail_phys)
    except (AttributeError, OSError):
        pass
    return None


def _macos_available_memory() -> int | None:
    try:
        output = subprocess.run(["vm_stat"], capture_output=True, text=True, check=True, timeout=2).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    header = re.search(r"page size of (\d+) bytes", output)
    if header is None:
        return None
    pages = 0
    for line in output.splitlines():
        name, _, value = line.partition(":")
        if name in {"Pages free", "Pages inactive", "Pages speculative"}:
            with suppress(ValueError):
                pages += int(value.strip().rstrip("."))
    return pages * int(header.group(1)) if pages else None


def available_memory() -> int | None:
    if sys.platform.startswith("linux"):
        amount = _linux_available_memory()
    elif sys.platform == "win32":
        amount = _windows_available_memory()
    elif sys.platform == "darwin":
        amount = _macos_available_memory()
    else:
        amount = None
    if amount is not None:
        return amount
    try:
        amount = os.sysconf("SC_AVPHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    except (AttributeError, OSError, ValueError):
        return None
    return amount if amount > 0 else None


def download_worker_count(total_size: int | None = None) -> int:
    workers = min(4, max(1, (available_cpu_count() + 1) // 2))
    memory = available_memory()
    if memory is not None:
        workers = min(workers, max(1, memory // (16 * _MIB)))
    if total_size is not None and total_size > 0:
        workers = min(workers, max(1, (total_size + _DOWNLOAD_MIN_RANGE_SIZE - 1) // _DOWNLOAD_MIN_RANGE_SIZE))
    return max(1, workers)


def decrypt_worker_count() -> int:
    workers = available_cpu_count()
    memory = available_memory()
    if memory is not None:
        workers = min(workers, max(1, memory // (16 * _MIB)))
    return max(1, workers)


def ota_worker_count() -> int:
    workers = available_cpu_count()
    memory = available_memory()
    if memory is None:
        return 1
    return max(1, min(workers, memory // (768 * _MIB)))


def ota_operation_max_bytes(total_workers: int) -> int:
    memory = available_memory()
    if memory is None:
        return 32 * _MIB
    return max(_MIB, min(32 * _MIB, memory // (max(1, total_workers) * 8)))
