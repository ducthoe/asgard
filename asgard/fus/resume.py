# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import json
from pathlib import Path

from ..constants import (
    _AES_BLOCK_SIZE,
    _DOWNLOAD_WORKERS,
)
from ..scheduling import load_resume_ranges

_DOWNLOAD_THREADS = _DOWNLOAD_WORKERS


def _partial_output_path(path: Path) -> Path:
    return path.with_name(f"{path.name}.part")


def _resume_state_path(path: Path) -> Path:
    return path.with_name(f"{path.name}.resume.json")


def _build_range_parts(total_size: int, part_count: int = _DOWNLOAD_THREADS) -> list[dict[str, int]]:
    if total_size <= 0:
        return []
    block_size = _AES_BLOCK_SIZE
    max_parts = max(1, total_size // block_size)
    parts = max(1, min(int(part_count), max_parts))
    ranges: list[dict[str, int]] = []
    start = 0
    for idx in range(parts):
        if idx == parts - 1:
            end = total_size - 1
        else:
            remaining_parts = parts - idx
            remaining_bytes = total_size - start
            seg_len = max(block_size, (remaining_bytes // remaining_parts) // block_size * block_size)
            max_len = remaining_bytes - (remaining_parts - 1) * block_size
            seg_len = min(seg_len, max_len)
            end = start + seg_len - 1
        ranges.append({"start": start, "end": end, "offset": start})
        start = end + 1
    return ranges


def _save_range_resume_state(meta_path: Path, total_size: int, ranges: list[dict[str, int]]) -> None:
    tmp_path = meta_path.with_name(f"{meta_path.name}.tmp")
    tmp_path.write_text(json.dumps({"size": total_size, "ranges": ranges}), encoding="utf-8")
    tmp_path.replace(meta_path)


def _resume_done_bytes(ranges: list[dict[str, int]]) -> int:
    return sum(max(0, int(item["offset"]) - int(item["start"])) for item in ranges)


def _prepare_range_resume_state(
    data_path: Path,
    total_size: int,
    resume: bool,
    *,
    part_count: int = _DOWNLOAD_THREADS,
    alignment: int = 1,
) -> tuple[list[dict[str, int]], Path]:
    meta_path = _resume_state_path(data_path)
    default_ranges = _build_range_parts(total_size, part_count=part_count)
    ranges = default_ranges
    if resume and data_path.is_file() and meta_path.is_file():
        try:
            payload = json.loads(meta_path.read_text(encoding="utf-8"))
            loaded = load_resume_ranges(payload, total_size, data_path.stat().st_size, alignment=alignment)
            if loaded is not None:
                ranges = loaded
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            ranges = default_ranges

    data_path.parent.mkdir(parents=True, exist_ok=True)
    if resume and data_path.exists():
        with data_path.open("r+b") as fh:
            fh.truncate(total_size)
    else:
        with data_path.open("wb") as fh:
            fh.truncate(total_size)
    return (ranges if resume else default_ranges), meta_path
