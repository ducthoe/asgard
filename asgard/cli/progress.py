# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import math
import os
import shutil
import sys
import threading
import time
from collections import OrderedDict, deque
from functools import lru_cache

from .pipeline import current_pipeline, display_message

_QUIET = False


def set_quiet(quiet: bool) -> None:
    global _QUIET
    _QUIET = bool(quiet)


def print_info(message: str) -> None:
    if _QUIET:
        return
    if display_message(message):
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
_PROGRESS_LOCK = threading.Lock()
_RATES: OrderedDict[tuple[str, float], ProgressRate] = OrderedDict()
_LAST_PLAIN_RENDER = 0.0


class ProgressRate:
    def __init__(self, started_at: float, initial: int):
        self.samples = deque([(started_at, initial)])
        self.last_change = started_at

    def update(self, now: float, done: int) -> tuple[float, float]:
        if done < self.samples[-1][1] or now < self.samples[-1][0]:
            self.samples.clear()
            self.samples.append((now, done))
            self.last_change = now
        if done > self.samples[-1][1]:
            self.last_change = now
        if now == self.samples[-1][0]:
            self.samples[-1] = (now, done)
        else:
            self.samples.append((now, done))
        while len(self.samples) > 2 and self.samples[1][0] <= now - 10.0:
            self.samples.popleft()
        if now - self.last_change >= 2.0:
            return 0.0, 0.0
        first = self.samples[0]
        recent = first
        for sample in reversed(self.samples):
            recent = sample
            if sample[0] <= now - 2.0:
                break
        speed = max(0, done - recent[1]) / max(now - recent[0], 0.001)
        eta_speed = max(0, done - first[1]) / max(now - first[0], 0.001)
        return speed, eta_speed


def _eta(done: int, total: int, speed: float, complete: bool) -> str:
    if total > 0 and done >= total or complete and total <= 0:
        return "00:00"
    if complete or total <= 0 or speed <= 0:
        return "--:--"
    seconds = math.ceil(max(0, total - done) / speed)
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02}:{minutes:02}:{seconds:02}" if hours else f"{minutes:02}:{seconds:02}"


@lru_cache(maxsize=4)
def _bar_symbols(encoding: str) -> tuple[str, str, str]:
    try:
        "█░".encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return "=", "-", ""
    try:
        "▏▎▍▌▋▊▉".encode(encoding)
        partials = "▏▎▍▌▋▊▉"
    except UnicodeEncodeError:
        partials = "▌" if "▌".encode(encoding, errors="ignore") else ""
    return "█", "░", partials


def _shorten(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    return text[: width - 3] + "..." if width > 3 else text[:width]


def _compact_amount(done: int, total: int) -> str:
    total_text = format_bytes(total)
    number, unit = total_text.split()
    divisor = 1024 ** ("B", "KiB", "MiB", "GiB", "TiB").index(unit)
    return f"{done / divisor:.2f}/{number} {unit}"


def progress_line(
    label: str,
    done: int,
    total: int,
    speed: float,
    eta_speed: float,
    *,
    now: float,
    width: int,
    complete: bool = False,
    detail: str = "",
    reserve: int = 0,
) -> str:
    width = max(1, width)
    left_width = max(0, min(32, (width - 7) // 2))
    bar_start = left_width + 1 if left_width else 0
    bar_width = max(3, min(40, width - bar_start - 35))
    right_width = max(0, width - bar_start - bar_width - 3 - reserve)
    fraction = min(1.0, max(0.0, done / total)) if total > 0 else None
    percent = f"{fraction * 100:5.1f}%" if fraction is not None else ""
    amount = f"{format_bytes(done)}/{format_bytes(total)}" if total > 0 else format_bytes(done)
    prefix = f"{label}: "
    if total > 0 and len(prefix) + len(amount) > left_width:
        amount = _compact_amount(done, total)
    if len(prefix) + len(amount) > left_width:
        amount = format_bytes(done)
    left = prefix + amount if len(prefix) + len(amount) <= left_width else _shorten(label, left_width)
    eta = _eta(done, total, eta_speed, complete)
    candidates = (
        " ".join(part for part in (percent, f"{format_bytes(speed)}/s", f"ETA {eta}") if part),
        " ".join(part for part in (percent, f"ETA {eta}") if part),
        f"ETA {eta}",
        eta,
    )
    right = next((text for text in candidates if len(text) <= right_width), eta[:right_width])
    if detail and right_width - len(right) >= 11:
        right += f" ({_shorten(detail, right_width - len(right) - 3)})"
    filled_symbol, empty_symbol, partials = _bar_symbols(sys.stdout.encoding or "utf-8")
    if fraction is not None or complete:
        filled = int(fraction * bar_width) if fraction is not None else bar_width
        partial = ""
        if fraction is not None and filled < bar_width and partials:
            part = int((fraction * bar_width - filled) * (len(partials) + 1))
            if part:
                partial = partials[part - 1]
        bar = filled_symbol * filled + partial + empty_symbol * (bar_width - filled - len(partial))
    elif speed > 0:
        pulse = min(3, max(1, bar_width // 4))
        travel = bar_width - pulse
        step = int(now * 3) % max(1, 2 * travel)
        position = min(step, 2 * travel - step)
        bar = empty_symbol * position + filled_symbol * pulse + empty_symbol * (bar_width - position - pulse)
    else:
        bar = empty_symbol * bar_width
    line = left.ljust(bar_start) + f"[{bar}]" + (f" {right}" if right else "")
    return line[: max(0, width - reserve)]


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
    pipeline = current_pipeline()
    if pipeline is not None:
        pipeline.update_decode(label, done, total, started_at, speed_done=speed_done, complete=complete)
        return
    with _PROGRESS_LOCK:
        global _LAST_PLAIN_RENDER
        now = time.monotonic()
        interactive = sys.stdout.isatty()
        if not interactive and not complete and now - _LAST_PLAIN_RENDER < 1.0:
            return
        key = (label, started_at)
        rate = _RATES.get(key)
        if rate is None:
            rate = ProgressRate(started_at, done - speed_done if speed_done is not None else 0)
            _RATES[key] = rate
        _RATES.move_to_end(key)
        speed, eta_speed = rate.update(now, done)
        width = max(1, shutil.get_terminal_size(fallback=(80, 24)).columns - 1)
        line = progress_line(label, done, total, speed, eta_speed, now=now, width=width, complete=complete)
        if not interactive:
            _LAST_PLAIN_RENDER = now
            sys.stdout.write(line + "\n")
        elif os.name == "nt":
            global _PROGRESS_LINE_WIDTH
            padding = " " * max(0, _PROGRESS_LINE_WIDTH - len(line))
            sys.stdout.write(f"\r{line}{padding}")
            _PROGRESS_LINE_WIDTH = 0 if complete else len(line)
        else:
            sys.stdout.write(f"\r\033[2K{line}")
        if complete:
            _RATES.pop(key, None)
            if interactive:
                sys.stdout.write("\n")
        while len(_RATES) > 32:
            _RATES.popitem(last=False)
        sys.stdout.flush()
