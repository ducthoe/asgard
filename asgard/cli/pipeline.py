# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import os
import shutil
import sys
import threading
import time
from contextvars import ContextVar

from ..core.constants import _PROGRESS_REFRESH_S

_CURRENT: ContextVar[PipelineProgress | None] = ContextVar("asgard_pipeline", default=None)
_LOCK = threading.RLock()
_ACTIVE: list[PipelineProgress] = []
_ROWS = 0
_LAST_RENDER = 0.0


def current_pipeline() -> PipelineProgress | None:
    return _CURRENT.get()


def _interactive() -> bool:
    return sys.stdout.isatty() and (os.name != "nt" or bool(os.environ.get("WT_SESSION")))


def _erase() -> None:
    global _ROWS
    if _ROWS:
        sys.stdout.write(f"\033[{_ROWS}A\r\033[J")
        _ROWS = 0


def _draw(*, force: bool = False) -> None:
    global _ROWS, _LAST_RENDER
    now = time.monotonic()
    interactive = _interactive()
    if not force and now - _LAST_RENDER < (_PROGRESS_REFRESH_S if interactive else 1.0):
        return
    lines = [line for progress in _ACTIVE for line in progress.lines(now)]
    if lines:
        if interactive:
            width = max(1, shutil.get_terminal_size().columns - 1)
            lines = [line[:width] for line in lines]
            frame = f"\033[{_ROWS}A" if _ROWS else ""
            frame += "".join(f"\r{line}\033[K\n" for line in lines)
            extra = max(0, _ROWS - len(lines))
            if extra:
                frame += "\r\033[K\n" * extra + f"\033[{extra}A"
        else:
            frame = "\n".join(lines) + "\n"
        sys.stdout.write(frame)
        sys.stdout.flush()
        _ROWS = len(lines) if interactive else 0
    _LAST_RENDER = now


def display_message(message: str) -> bool:
    with _LOCK:
        if not _ACTIVE:
            return False
        _erase()
        print(message, flush=True)
        _draw(force=True)
        return True


class PipelineProgress:
    def __init__(self, *, download_total: int | None = None, initial_download: int = 0):
        from .progress import ProgressRate

        self.received = initial_download
        self.download_total = download_total or 0
        self.started_at = time.monotonic()
        self.decoding = None
        self.enabled = False
        self.download_rate = ProgressRate(self.started_at, initial_download)
        self.decode_rate = None
        self.finished = False
        self.stop = threading.Event()
        self.refresh_thread = None

    def __enter__(self) -> PipelineProgress:
        from .progress import _QUIET

        self.token = _CURRENT.set(self)
        self.enabled = not _QUIET
        if self.enabled:
            with _LOCK:
                if not _ACTIVE and _interactive():
                    sys.stdout.write("\033[?25l")
                _ACTIVE.append(self)
                _draw(force=True)
            self.refresh_thread = threading.Thread(target=self._refresh, name="asgard-progress", daemon=True)
            self.refresh_thread.start()
        return self

    def _refresh(self) -> None:
        while not self.stop.wait(_PROGRESS_REFRESH_S):
            with _LOCK:
                _draw()

    def __exit__(self, kind, _value, _traceback) -> None:
        self.stop.set()
        if self.refresh_thread is not None:
            self.refresh_thread.join()
        try:
            if self.enabled:
                with _LOCK:
                    _erase()
                    self.finished = kind is None
                    status = "stopped" if kind is not None else "finished"
                    lines = self.lines(time.monotonic(), reserve=len(status) + 3)
                    width = max(1, shutil.get_terminal_size().columns - 1)
                    print("\n".join(f"{line} ({status})"[:width] for line in lines), flush=True)
                    _ACTIVE.remove(self)
                    self.enabled = False
                    _draw(force=True)
                    if not _ACTIVE and _interactive():
                        sys.stdout.write("\033[?25h")
                        sys.stdout.flush()
        finally:
            _CURRENT.reset(self.token)

    def add_download(self, size: int) -> None:
        if self.enabled:
            with _LOCK:
                self.received += size
                _draw()

    def update_decode(self, label, done, total, started_at, *, speed_done=None, complete=False) -> None:
        from .progress import ProgressRate

        if self.enabled:
            with _LOCK:
                if self.decoding is None or (self.decoding[0], self.decoding[3]) != (label, started_at):
                    self.decode_rate = ProgressRate(started_at, done - speed_done if speed_done is not None else 0)
                self.decoding = (label, done, total, started_at, speed_done, complete)
                _draw(force=complete)

    def lines(self, now: float, *, reserve: int = 0) -> tuple[str, str]:
        from .progress import progress_line

        width = max(1, shutil.get_terminal_size(fallback=(80, 24)).columns - 1)
        speed, eta_speed = self.download_rate.update(now, self.received)
        download = progress_line(
            "Download",
            self.received,
            self.download_total,
            speed,
            eta_speed,
            now=now,
            width=width,
            complete=self.finished,
            reserve=reserve,
        )
        if self.decoding is None:
            return download, progress_line(
                "Decode", 0, 0, 0, 0, now=now, width=width, detail="waiting for data", reserve=reserve
            )
        label, done, total, _started_at, _speed_done, complete = self.decoding
        speed, eta_speed = self.decode_rate.update(now, done)
        return download, progress_line(
            "Decode",
            done,
            total,
            speed,
            eta_speed,
            now=now,
            width=width,
            complete=complete,
            detail=label,
            reserve=reserve,
        )
