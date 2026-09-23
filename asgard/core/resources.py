# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import os

from .constants import _DOWNLOAD_MIN_RANGE_SIZE

try:
    import psutil
except (ImportError, OSError):
    psutil = None

_MIB = 1024 * 1024


def available_cpu_count() -> int:
    process_cpu_count = getattr(os, "process_cpu_count", None)
    count = (process_cpu_count() if process_cpu_count is not None else None) or os.cpu_count() or 1
    if psutil is not None:
        try:
            count = min(count, len(psutil.Process().cpu_affinity()))
        except (AttributeError, NotImplementedError, psutil.Error):
            pass
    return max(1, count)


def available_memory() -> int | None:
    if psutil is not None:
        try:
            amount = psutil.virtual_memory().available
            if amount > 0:
                return amount
        except (AttributeError, OSError, psutil.Error):
            pass
    return None


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
    if memory is not None:
        workers = min(workers, max(1, memory // (384 * _MIB)))
    else:
        workers = max(1, (workers + 1) // 2)
    return max(1, workers)


def ota_operation_max_bytes(total_workers: int) -> int:
    memory = available_memory()
    if memory is None:
        return 32 * _MIB
    return max(_MIB, min(32 * _MIB, memory // (max(1, total_workers) * 8)))
