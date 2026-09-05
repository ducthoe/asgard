# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

from .constants import (
    _AES_BLOCK_SIZE,
    _DOWNLOAD_MIN_RANGE_SIZE,
    _DOWNLOAD_RANGE_SIZE,
    _DOWNLOAD_WORKERS,
)


def split_download_ranges(ranges: list[dict[str, int]], *, workers: int = _DOWNLOAD_WORKERS) -> list[dict[str, int]]:
    if workers <= 0:
        raise ValueError("threads must be positive")
    remaining = sum(item["end"] + 1 - item["offset"] for item in ranges)
    per_range = (remaining + workers * 4 - 1) // (workers * 4)
    per_range = (per_range + _AES_BLOCK_SIZE - 1) // _AES_BLOCK_SIZE * _AES_BLOCK_SIZE
    range_size = min(_DOWNLOAD_RANGE_SIZE, max(_DOWNLOAD_MIN_RANGE_SIZE, per_range))
    runs: list[dict[str, int]] = []

    def append_run(start: int, end: int, *, complete: bool) -> None:
        if runs and runs[-1]["end"] + 1 == start and (runs[-1]["offset"] > runs[-1]["end"]) == complete:
            runs[-1]["end"] = end
            if complete:
                runs[-1]["offset"] = end + 1
        else:
            runs.append({"start": start, "end": end, "offset": end + 1 if complete else start})

    for item in ranges:
        start, end, offset = item["start"], item["end"], item["offset"]
        if offset > start:
            append_run(start, offset - 1, complete=True)
        if offset <= end:
            append_run(offset, end, complete=False)

    result: list[dict[str, int]] = []
    for item in runs:
        start, end = item["start"], item["end"]
        if item["offset"] > end:
            result.append(item)
            continue
        while start <= end:
            stop = min(end + 1, (start // range_size + 1) * range_size)
            result.append({"start": start, "end": stop - 1, "offset": start})
            start = stop
    return result


def load_resume_ranges(
    payload: object, total_size: int, file_size: int, *, alignment: int = 1
) -> list[dict[str, int]] | None:
    if not isinstance(payload, dict) or payload.get("size") != total_size:
        return None
    items = payload.get("ranges")
    if not isinstance(items, list):
        return None
    result: list[dict[str, int]] = []
    next_start = 0
    for item in items:
        if not isinstance(item, dict):
            return None
        start, end, offset = (item.get(key) for key in ("start", "end", "offset"))
        if any(type(value) is not int for value in (start, end, offset)):
            return None
        if start != next_start or not start <= offset <= end + 1 or not start <= end < total_size:
            return None
        if start % alignment or (end + 1) % alignment or offset % alignment:
            return None
        available = max(start, min(offset, file_size))
        available -= available % alignment
        result.append({"start": start, "end": end, "offset": available})
        next_start = end + 1
    return result if next_start == total_size else None
