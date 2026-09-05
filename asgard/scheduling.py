# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

from .constants import (
    _DOWNLOAD_INITIAL_WORKERS,
    _DOWNLOAD_RANGE_SIZE,
    _DOWNLOAD_TUNE_COOLDOWN_S,
    _DOWNLOAD_TUNE_INTERVAL_S,
)


def split_download_ranges(ranges: list[dict[str, int]]) -> list[dict[str, int]]:
    result: list[dict[str, int]] = []
    for item in ranges:
        start, end, offset = item["start"], item["end"], item["offset"]
        if offset > start:
            if result and result[-1]["offset"] == result[-1]["end"] + 1 and result[-1]["offset"] == start:
                result[-1].update(end=offset - 1, offset=offset)
            else:
                result.append({"start": start, "end": offset - 1, "offset": offset})
        start = offset
        while start <= end:
            stop = min(end + 1, (start // _DOWNLOAD_RANGE_SIZE + 1) * _DOWNLOAD_RANGE_SIZE)
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


class DownloadConcurrency:
    def __init__(self, limit: int, *, adaptive: bool, now: float, done: int, rate_limit: int = 0):
        self.limit = limit
        self.adaptive = adaptive
        self.target = min(_DOWNLOAD_INITIAL_WORKERS, limit) if adaptive else limit
        self.rate_limit = rate_limit
        self._time = now
        self._done = done
        self._probe_rate: float | None = None
        self._hold_until = now

    def backoff(self, now: float, done: int) -> None:
        if not self.adaptive:
            return
        self.target = max(1, self.target // 2)
        self._probe_rate = None
        self._hold_until = now + _DOWNLOAD_TUNE_COOLDOWN_S
        self._time, self._done = now, done

    def sample(self, now: float, done: int, *, pending: bool) -> None:
        elapsed = now - self._time
        if not self.adaptive or elapsed < _DOWNLOAD_TUNE_INTERVAL_S:
            return
        rate = max(0, done - self._done) / elapsed
        self._time, self._done = now, done
        if now < self._hold_until or not pending:
            return
        if self._probe_rate is not None:
            if rate < self._probe_rate * 1.05:
                self.target = max(1, self.target - 1)
                self._hold_until = now + _DOWNLOAD_TUNE_COOLDOWN_S
            self._probe_rate = None
        elif rate > 0 and self.target < self.limit and (not self.rate_limit or rate < self.rate_limit * 0.9):
            self._probe_rate = rate
            self.target += 1
