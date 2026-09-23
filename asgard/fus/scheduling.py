# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import threading
import time
from math import isqrt

from ..core.constants import (
    _AES_BLOCK_SIZE,
    _DOWNLOAD_MIN_RANGE_SIZE,
    _DOWNLOAD_RANGE_SIZE,
    _RATE_LIMIT_COOLDOWN_S,
)
from ..core.resources import download_worker_count


class AdaptiveDownloadGate:
    """Probe for useful concurrency and make throttled workers cool down together."""

    def __init__(self, max_workers: int):
        if max_workers <= 0:
            raise ValueError("threads must be positive")
        self.max_workers = max_workers
        self.limit = min(max_workers, max(1, isqrt(max_workers)))
        self.active = 0
        self._condition = threading.Condition()
        self._cooldown_until = 0.0
        self._last_throttle = 0.0
        self._throttle_count = 0
        self._successful_starts = 0
        self._slow_start = True

    def acquire(self, stop_event: threading.Event) -> bool:
        with self._condition:
            while not stop_event.is_set():
                now = time.monotonic()
                if self.active < self.limit and now >= self._cooldown_until:
                    self.active += 1
                    return True
                delay = max(0.0, self._cooldown_until - now)
                self._condition.wait(min(0.25, delay) if delay else 0.25)
        return False

    def release(self) -> None:
        with self._condition:
            self.active -= 1
            self._condition.notify_all()

    def accepted(self) -> None:
        with self._condition:
            if time.monotonic() < self._cooldown_until or self.limit >= self.max_workers:
                return
            self._successful_starts += 1
            threshold = 1 if self._slow_start else self.limit
            if self._successful_starts >= threshold:
                self.limit += 1
                self._successful_starts = 0
                self._condition.notify_all()

    def throttled(self, retry_after_s: float | None) -> None:
        with self._condition:
            now = time.monotonic()
            if now >= self._cooldown_until:
                if now - self._last_throttle >= 60:
                    self._throttle_count = 0
                self._throttle_count += 1
                self._last_throttle = now
                self.limit = max(1, self.limit // 2)
                self._slow_start = False
                self._successful_starts = 0
            fallback = min(120.0, _RATE_LIMIT_COOLDOWN_S * 2 ** min(self._throttle_count - 1, 5))
            delay = max(fallback, retry_after_s or 0.0)
            self._cooldown_until = max(self._cooldown_until, now + delay)
            self._condition.notify_all()


def split_download_ranges(ranges: list[dict[str, int]], *, workers: int | None = None) -> list[dict[str, int]]:
    remaining = sum(item["end"] + 1 - item["offset"] for item in ranges)
    if workers is None:
        workers = download_worker_count(remaining)
    if workers <= 0:
        raise ValueError("threads must be positive")
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
