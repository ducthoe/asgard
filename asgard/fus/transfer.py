# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import re
import socket
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator
from contextlib import suppress
from dataclasses import dataclass, field

import requests

from ..core.constants import (
    _AES_BLOCK_SIZE,
    _DOWNLOAD_MIN_RANGE_SIZE,
    _DOWNLOAD_RECOVERY_INTERVAL,
    _DOWNLOAD_RETRIES,
    _PROGRESS_REFRESH_S,
    _RANGE_CHUNK_SIZE,
    _RATE_LIMIT_COOLDOWN_S,
    _RETRY_BACKOFF_S,
)
from ..core.errors import FUSError, RateLimitedError, RetryableDownloadError
from .client import FUSClient
from .scheduling import AdaptiveDownloadGate

_CONTENT_RANGE_RE = re.compile(r"bytes\s+(\d+)-(\d+)/(\d+|\*)", re.IGNORECASE)


class BandwidthLimiter:
    def __init__(self, bytes_per_second: int | None):
        self.rate = int(bytes_per_second or 0)
        if self.rate < 0:
            raise ValueError("bandwidth limit cannot be negative")
        self._lock = threading.Lock()
        self._available_at = time.monotonic()

    def chunk_size(self, size: int) -> int:
        if self.rate <= 0:
            return size
        return min(size, max(_AES_BLOCK_SIZE, int(self.rate * _PROGRESS_REFRESH_S)))

    def consume(self, size: int, stop_event: threading.Event | None = None) -> None:
        if self.rate <= 0 or size <= 0:
            return
        duration = size / self.rate
        with self._lock:
            now = time.monotonic()
            start = max(now, self._available_at)
            finish = start + duration
            self._available_at = finish
        delay = finish - time.monotonic()
        if delay > 0:
            if stop_event is None:
                time.sleep(delay)
            else:
                stop_event.wait(delay)


def _validate_content_range(
    response: requests.Response,
    *,
    start: int,
    end: int,
    total_size: int,
) -> None:
    value = response.headers.get("Content-Range", "").strip()
    match = _CONTENT_RANGE_RE.fullmatch(value)
    if match is None:
        raise RetryableDownloadError(f"download server returned an invalid Content-Range: {value or 'missing'}")
    response_start, response_end = int(match.group(1)), int(match.group(2))
    response_total = match.group(3)
    if response_start != start or response_end != end:
        raise RetryableDownloadError(
            "download server returned the wrong byte range: "
            f"expected {start}-{end}, got {response_start}-{response_end}"
        )
    if response_total == "*" or int(response_total) != total_size:
        raise RetryableDownloadError(
            f"download server returned the wrong file size: expected {total_size}, got {response_total}"
        )
    content_length = response.headers.get("Content-Length")
    if content_length is not None:
        try:
            valid_length = int(content_length) == end - start + 1
        except ValueError:
            valid_length = False
        if not valid_length:
            raise RetryableDownloadError("download server returned the wrong Content-Length")


def _read_download_range(
    *,
    client: FUSClient,
    remote_path: str,
    start: int,
    end: int,
    total_size: int,
    recover_download: Callable[[], None] | None = None,
    network_progress: Callable[[int], None] | None = None,
    rate_limiter: BandwidthLimiter | None = None,
    gate: AdaptiveDownloadGate | None = None,
) -> bytes:
    expected_size = end - start + 1
    if recover_download is not None:
        client.configure_download_recovery(recover_download)
    gate = gate or AdaptiveDownloadGate(1)
    stop_event = threading.Event()
    chunks: list[bytes] = []
    received = 0
    for attempt in range(1, _DOWNLOAD_RETRIES + 2):
        response: requests.Response | None = None
        gate.acquire(stop_event)
        retry_error: Exception | None = None
        request_start = start + received
        try:
            response = client.download_file(remote_path, start=request_start, end=end)
            _validate_content_range(response, start=request_start, end=end, total_size=total_size)
            for chunk in response.iter_content(chunk_size=_RANGE_CHUNK_SIZE):
                if not chunk:
                    continue
                if network_progress is not None:
                    network_progress(len(chunk))
                if rate_limiter is not None:
                    rate_limiter.consume(len(chunk))
                if len(chunk) > expected_size - received:
                    raise RetryableDownloadError(
                        f"download server returned more data than requested for range {start}-{end}"
                    )
                chunks.append(chunk)
                received += len(chunk)
            if received != expected_size:
                raise RetryableDownloadError(
                    f"download server returned {received} bytes for range {start}-{end}, expected {expected_size}"
                )
            return b"".join(chunks)
        except (requests.RequestException, OSError, RetryableDownloadError) as exc:
            retry_error = exc
        finally:
            try:
                if response is not None:
                    response.close()
            finally:
                gate.release()
        if retry_error is not None:
            exc = retry_error
            if attempt > _DOWNLOAD_RETRIES:
                raise FUSError(f"range {start}-{end} failed after retries: {exc}") from exc
            if isinstance(exc, RateLimitedError):
                gate.throttled(exc.retry_after_s)
                continue
            if received == expected_size:
                chunks.clear()
                received = 0
            if recover_download is not None and attempt % _DOWNLOAD_RECOVERY_INTERVAL == 0:
                try:
                    recover_download()
                except Exception as recovery_exc:
                    raise FUSError(f"download recovery failed: {recovery_exc}") from recovery_exc
                time.sleep(_RATE_LIMIT_COOLDOWN_S)
            time.sleep(_RETRY_BACKOFF_S * attempt)
    raise FUSError(f"range {start}-{end} failed")


@dataclass
class _RangeBuffer:
    start: int
    end: int
    chunks: deque[bytes] = field(default_factory=deque)
    received: int = 0
    done: bool = False


class _ParallelRangeStream(Iterator[bytes]):
    def __init__(
        self,
        *,
        client: FUSClient,
        remote_path: str,
        start: int,
        end: int,
        total_size: int,
        workers: int,
        chunk_size: int,
        gate: AdaptiveDownloadGate,
        recover_download: Callable[[], None] | None,
        network_progress: Callable[[int], None] | None,
        rate_limiter: BandwidthLimiter | None,
    ):
        self._client = client
        self._remote_path = remote_path
        self._end = end
        self._total_size = total_size
        self._chunk_size = chunk_size
        self._gate = gate
        self._recover_download = recover_download
        self._network_progress = network_progress
        self._rate_limiter = rate_limiter
        self._condition = threading.Condition()
        self._stop = threading.Event()
        self._buffers: deque[_RangeBuffer] = deque()
        self._pending: deque[_RangeBuffer] = deque()
        self._responses: dict[requests.Response, socket.socket | None] = {}
        self._error: Exception | None = None
        self._next_start = start
        self._transferred = 0
        self._workers = min(workers, (end - start + _DOWNLOAD_MIN_RANGE_SIZE) // _DOWNLOAD_MIN_RANGE_SIZE)
        if recover_download is not None:
            client.configure_download_recovery(recover_download)
        self._extend_window()
        self._threads = [
            threading.Thread(target=self._worker, name=f"asgard-range-{index}", daemon=True)
            for index in range(self._workers)
        ]
        for thread in self._threads:
            thread.start()

    def _extend_window(self) -> None:
        while len(self._buffers) < self._workers and self._next_start <= self._end:
            end = min(self._end, self._next_start + _DOWNLOAD_MIN_RANGE_SIZE - 1)
            buffer = _RangeBuffer(self._next_start, end)
            self._buffers.append(buffer)
            self._pending.append(buffer)
            self._next_start = end + 1

    def __next__(self) -> bytes:
        with self._condition:
            while True:
                if self._error is not None:
                    raise self._error
                if self._stop.is_set() or not self._buffers:
                    raise StopIteration
                buffer = self._buffers[0]
                if buffer.chunks:
                    return buffer.chunks.popleft()
                if buffer.done:
                    self._buffers.popleft()
                    self._extend_window()
                    self._condition.notify_all()
                    continue
                self._condition.wait()

    def _worker(self) -> None:
        try:
            while not self._stop.is_set():
                with self._condition:
                    while not self._pending and not self._stop.is_set():
                        self._condition.wait()
                    if self._stop.is_set():
                        return
                    buffer = self._pending.popleft()
                self._download(buffer)
                with self._condition:
                    buffer.done = True
                    self._condition.notify_all()
        except Exception as exc:
            with self._condition:
                if not self._stop.is_set():
                    self._error = exc
                    self._stop.set()
                self._condition.notify_all()

    def _download(self, buffer: _RangeBuffer) -> None:
        expected = buffer.end - buffer.start + 1
        for attempt in range(1, _DOWNLOAD_RETRIES + 2):
            if not self._gate.acquire(self._stop):
                return
            response = None
            retry_error = None
            try:
                start = buffer.start + buffer.received
                response = self._client.download_file(self._remote_path, start=start, end=buffer.end)
                with self._condition:
                    if self._stop.is_set():
                        return
                    connection = getattr(response.raw, "_connection", None)
                    sock = getattr(connection, "sock", None)
                    if sock is None:
                        with suppress(AttributeError):
                            sock = response.raw._fp.fp.raw._sock
                    self._responses[response] = sock
                _validate_content_range(response, start=start, end=buffer.end, total_size=self._total_size)
                for chunk in response.iter_content(chunk_size=self._chunk_size):
                    if self._stop.is_set():
                        return
                    if not chunk:
                        continue
                    if len(chunk) > expected - buffer.received:
                        raise FUSError("download stream received more data than requested")
                    if self._network_progress is not None:
                        self._network_progress(len(chunk))
                    if self._rate_limiter is not None:
                        self._rate_limiter.consume(len(chunk), self._stop)
                    with self._condition:
                        if self._stop.is_set():
                            return
                        buffer.chunks.append(chunk)
                        buffer.received += len(chunk)
                        self._transferred += len(chunk)
                        self._gate.observe(self._transferred)
                        self._condition.notify_all()
                if buffer.received == expected:
                    return
                raise RetryableDownloadError(
                    f"download server returned {buffer.received} bytes for range "
                    f"{buffer.start}-{buffer.end}, expected {expected}"
                )
            except (requests.RequestException, OSError, RetryableDownloadError) as exc:
                retry_error = exc
                if isinstance(exc, RateLimitedError):
                    self._gate.throttled(exc.retry_after_s)
            finally:
                try:
                    if response is not None:
                        response.close()
                finally:
                    with self._condition:
                        self._responses.pop(response, None)
                    self._gate.release()
            if self._stop.is_set():
                return
            if attempt > _DOWNLOAD_RETRIES or buffer.received == expected:
                raise FUSError(f"range {buffer.start}-{buffer.end} failed: {retry_error}") from retry_error
            if isinstance(retry_error, RateLimitedError):
                continue
            if self._recover_download is not None and attempt % _DOWNLOAD_RECOVERY_INTERVAL == 0:
                self._recover_download()
                if self._stop.wait(_RATE_LIMIT_COOLDOWN_S):
                    return
            if self._stop.wait(_RETRY_BACKOFF_S * attempt):
                return

    def close(self) -> None:
        with self._condition:
            self._stop.set()
            responses = list(self._responses.items())
            self._condition.notify_all()
        for response, sock in responses:
            if sock is not None:
                with suppress(OSError):
                    sock.shutdown(socket.SHUT_RDWR)
            response.close()
        deadline = time.monotonic() + 1.0
        for thread in self._threads:
            thread.join(max(0, deadline - time.monotonic()))
        with self._condition:
            for buffer in self._buffers:
                buffer.chunks.clear()
            self._buffers.clear()
            self._pending.clear()
