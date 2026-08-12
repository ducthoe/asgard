# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import io
import os
import queue
import threading
import time
from contextlib import contextmanager
from typing import Iterator

from .constants import _ARCHIVE_COPY_CHUNK_SIZE, _PROGRESS_REFRESH_S
from .errors import FUSError
from .progress import render_progress


class _PrefetchReader(io.RawIOBase):
    def __init__(self, source: io.BufferedIOBase):
        super().__init__()
        self._source = source
        self._queue: queue.Queue[bytes | BaseException | None] = queue.Queue(maxsize=2)
        self._stop = threading.Event()
        self._buffer = b""
        self._buffer_offset = 0
        self._eof = False
        self._thread = threading.Thread(target=self._produce, name="asgard-prefetch", daemon=True)
        self._thread.start()

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: bytearray | memoryview) -> int:
        self._checkClosed()
        if not buffer or self._eof:
            return 0
        if self._buffer_offset >= len(self._buffer):
            item = self._queue.get()
            if item is None:
                self._eof = True
                return 0
            if isinstance(item, BaseException):
                raise item
            self._buffer = item
            self._buffer_offset = 0

        view = memoryview(buffer)
        amount = min(len(view), len(self._buffer) - self._buffer_offset)
        view[:amount] = memoryview(self._buffer)[self._buffer_offset : self._buffer_offset + amount]
        self._buffer_offset += amount
        return amount

    def close(self) -> None:
        if not self.closed:
            self._stop.set()
            while True:
                try:
                    self._queue.get_nowait()
                except queue.Empty:
                    break
            self._thread.join()
        super().close()

    def _put(self, item: bytes | BaseException | None) -> bool:
        while not self._stop.is_set():
            try:
                self._queue.put(item, timeout=0.1)
                return True
            except queue.Full:
                continue
        return False

    def _produce(self) -> None:
        try:
            while not self._stop.is_set():
                chunk = self._source.read(_ARCHIVE_COPY_CHUNK_SIZE)
                if not chunk:
                    self._put(None)
                    return
                if not self._put(chunk):
                    return
        except BaseException as exc:
            self._put(exc)


@contextmanager
def open_prefetched_stream(source: io.BufferedIOBase) -> Iterator[io.BufferedReader]:
    prefetched = _PrefetchReader(source)
    buffered = io.BufferedReader(prefetched, buffer_size=64 * 1024)
    try:
        yield buffered
    finally:
        buffered.close()


def copy_stream_with_progress(
    source: io.BufferedIOBase,
    output: io.BufferedWriter,
    *,
    label: str,
    total_size: int,
    initial: bytes = b"",
    initial_done: int = 0,
) -> int:
    started_at = time.monotonic()
    last_render = 0.0
    done = int(initial_done) + len(initial)
    if initial:
        output.write(initial)
    while True:
        chunk = source.read(_ARCHIVE_COPY_CHUNK_SIZE)
        if not chunk:
            break
        output.write(chunk)
        done += len(chunk)
        now = time.monotonic()
        if now - last_render >= _PROGRESS_REFRESH_S and (not total_size or done < total_size):
            render_progress(label, done, total_size, started_at)
            last_render = now
    render_progress(label, done, total_size, started_at, complete=True)
    return done


def read_exact_stream(source: io.BufferedIOBase, size: int, description: str) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = source.read(remaining)
        if not chunk:
            raise FUSError(f"unexpected end of {description}")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def is_zero_data(data: bytes) -> bool:
    return not data or (data[0] == 0 and data[-1] == 0 and data.count(0) == len(data))


def write_data_or_hole(output: io.BufferedWriter, data: bytes) -> None:
    if is_zero_data(data):
        output.seek(len(data), os.SEEK_CUR)
    else:
        output.write(data)


def write_data_or_holes(output: io.BufferedWriter, data: bytes, block_size: int) -> None:
    if block_size <= 0:
        raise ValueError("hole block size must be positive")
    if len(data) <= block_size:
        write_data_or_hole(output, data)
        return

    zero_block = bytes(block_size)
    view = memoryview(data)
    run_start = 0
    run_is_zero = data.startswith(zero_block, 0, block_size)
    offset = block_size
    while offset < len(data):
        end = min(offset + block_size, len(data))
        if end - offset == block_size:
            is_zero = data.startswith(zero_block, offset, end)
        else:
            is_zero = is_zero_data(data[offset:end])
        if is_zero != run_is_zero:
            if run_is_zero:
                output.seek(offset - run_start, os.SEEK_CUR)
            else:
                output.write(view[run_start:offset])
            run_start = offset
            run_is_zero = is_zero
        offset = end

    if run_is_zero:
        output.seek(len(data) - run_start, os.SEEK_CUR)
    else:
        output.write(view[run_start:])
