# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import threading
import time

from ..core.constants import (
    _AES_BLOCK_SIZE,
    _DOWNLOAD_MIN_RANGE_SIZE,
    _DOWNLOAD_RANGE_SIZE,
    _DOWNLOAD_REQUEST_INTERVAL_S,
    _DOWNLOAD_SAMPLE_INTERVAL_S,
    _RATE_LIMIT_COOLDOWN_S,
)
from ..core.resources import download_worker_count


class AdaptiveDownloadGate:
    """Probe for useful concurrency and make throttled workers cool down together."""

    def __init__(self, max_workers: int):
        if max_workers <= 0:
            raise ValueError("threads must be positive")
        self.max_workers = max_workers
        self.limit = 1
        self.active = 0
        self._condition = threading.Condition()
        self._cooldown_until = 0.0
        self._last_throttle = 0.0
        self._throttle_count = 0
        self._next_start = 0.0
        self._waiting = 0
        self._sample_time = 0.0
        self._sample_bytes: int | None = None
        self._sample_active = 0
        self._probe_baseline: float | None = None
        self._probe_after = 0.0

    def acquire(self, stop_event: threading.Event) -> bool:
        with self._condition:
            self._waiting += 1
            try:
                while not stop_event.is_set():
                    now = time.monotonic()
                    deadline = max(self._cooldown_until, self._next_start)
                    if self.active < self.limit and now >= deadline:
                        self.active += 1
                        self._next_start = now + _DOWNLOAD_REQUEST_INTERVAL_S
                        return True
                    delay = max(0.0, deadline - now)
                    self._condition.wait(min(0.25, delay) if delay else 0.25)
            finally:
                self._waiting -= 1
        return False

    def release(self) -> None:
        with self._condition:
            self.active -= 1
            self._condition.notify_all()

    def observe(self, transferred: int) -> None:
        with self._condition:
            now = time.monotonic()
            if self._sample_bytes is None or self._sample_active != self.active:
                self._sample_time = now
                self._sample_bytes = transferred
                self._sample_active = self.active
                return
            elapsed = now - self._sample_time
            if elapsed < _DOWNLOAD_SAMPLE_INTERVAL_S:
                return
            speed = max(0, transferred - self._sample_bytes) / elapsed
            self._sample_time = now
            self._sample_bytes = transferred
            if now < max(self._cooldown_until, self._probe_after) or self.active != self.limit or speed <= 0:
                return
            if self._probe_baseline is not None:
                baseline = self._probe_baseline
                self._probe_baseline = None
                if speed < baseline * 1.10:
                    self.limit = max(1, self.limit - 1)
                    self._probe_after = now + 30.0
                    return
            if self.limit < self.max_workers and self._waiting:
                self._probe_baseline = speed
                self.limit += 1
                self._sample_bytes = None
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
                self._probe_baseline = None
                self._sample_bytes = None
            fallback = min(120.0, _RATE_LIMIT_COOLDOWN_S * 2 ** min(self._throttle_count - 1, 5))
            delay = max(fallback, retry_after_s or 0.0)
            self._cooldown_until = max(self._cooldown_until, now + delay)
            self._probe_after = max(self._probe_after, self._cooldown_until + 30.0)
            self._condition.notify_all()


def split_download_ranges(ranges: list[dict[str, int]], *, workers: int | None = None) -> list[dict[str, int]]:
    remaining = sum(item["end"] + 1 - item["offset"] for item in ranges)
    if workers is None:
        workers = download_worker_count(remaining)
    if workers <= 0:
        raise ValueError("threads must be positive")
    per_range = (remaining + workers * 2 - 1) // (workers * 2)
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
