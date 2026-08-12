# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import os
import sys
import time

_QUIET = False


def set_quiet(quiet: bool) -> None:
    global _QUIET
    _QUIET = bool(quiet)


def is_quiet() -> bool:
    return _QUIET


def print_info(message: str) -> None:
    if _QUIET:
        return
    print(message, flush=True)


def format_bytes(size: float) -> str:
    value = float(size)
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{value:.2f} TiB"


_PROGRESS_LINE_WIDTH = 0


def render_progress(
    label: str,
    done: int,
    total: int,
    started_at: float,
    *,
    speed_done: int | None = None,
    complete: bool = False,
) -> None:
    if _QUIET:
        return
    elapsed = max(time.monotonic() - started_at, 0.001)
    speed = (done if speed_done is None else speed_done) / elapsed
    if total > 0:
        percent = min(100.0, (done / total) * 100.0)
        progress_text = f"{percent:6.2f}% {format_bytes(done)}/{format_bytes(total)}"
    else:
        progress_text = format_bytes(done)
    line = f"{label}: {progress_text} {format_bytes(speed)}/s"
    if os.name == "nt":
        global _PROGRESS_LINE_WIDTH
        padding = " " * max(0, _PROGRESS_LINE_WIDTH - len(line))
        sys.stdout.write(f"\r{line}{padding}")
        _PROGRESS_LINE_WIDTH = 0 if complete else len(line)
    else:
        sys.stdout.write(f"\r\033[2K{line}")
    if complete:
        sys.stdout.write("\n")
    sys.stdout.flush()
