# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import io
import os
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterator

import requests
from Cryptodome.Cipher import AES

from ..core.constants import (
    _AES_BLOCK_SIZE,
    _ARCHIVE_READ_CACHE_SIZE,
    _ARCHIVE_TAIL_CACHE_SIZE,
    _DOWNLOAD_RECOVERY_INTERVAL,
    _DOWNLOAD_RETRIES,
    _PROGRESS_REFRESH_S,
    _RANGE_CHUNK_SIZE,
    _RATE_LIMIT_COOLDOWN_S,
    _RETRY_BACKOFF_S,
)
from ..core.errors import FUSError, RateLimitedError, RetryableDownloadError
from .client import FUSClient
from .crypto import _pkcs7_unpad
from .scheduling import AdaptiveDownloadGate

_CONTENT_RANGE_RE = re.compile(r"bytes\s+(\d+)-(\d+)/(\d+|\*)", re.IGNORECASE)


class BandwidthLimiter:
    def __init__(self, bytes_per_second: int | None):
        self.rate = int(bytes_per_second or 0)
        if self.rate < 0:
            raise ValueError("bandwidth limit cannot be negative")
        self._lock = threading.Lock()
        self._available_at = time.monotonic()

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


class _FUSDecryptingReader(io.RawIOBase):
    def __init__(
        self,
        *,
        client: FUSClient,
        remote_path: str,
        encrypted_size: int,
        key: bytes,
        recover_download: Callable[[], None] | None = None,
        stream_chunk_size: int = _RANGE_CHUNK_SIZE,
        rate_limiter: BandwidthLimiter | None = None,
        network_progress: Callable[[int], None] | None = None,
    ):
        super().__init__()
        self._response: requests.Response | None = None
        self._stop = threading.Event()
        self._cache: OrderedDict[int, bytes] = OrderedDict()
        self._cache_bytes = 0
        self._gate = AdaptiveDownloadGate(1)
        if encrypted_size <= 0 or encrypted_size % _AES_BLOCK_SIZE:
            raise FUSError("invalid encrypted firmware size")
        stream_chunk_size = int(stream_chunk_size)
        if stream_chunk_size <= 0:
            raise ValueError("stream chunk size must be positive")
        self._client = client
        self._remote_path = remote_path
        self._encrypted_size = int(encrypted_size)
        self._key = key
        self._recover_download = recover_download
        self._stream_chunk_size = stream_chunk_size
        self._rate_limiter = rate_limiter
        self._network_progress = network_progress
        self._position = 0
        self._response_iter: Iterator[bytes] | None = None
        self._cipher: AES | None = None
        self._cipher_buffer = b""
        self._plain_buffer = b""
        self._plain_buffer_start = 0
        self._plain_buffer_offset = 0
        self._stream_next = 0
        self._response_received = 0
        self._response_expected = 0
        self._read_hint = _RANGE_CHUNK_SIZE
        self._last_read_end: int | None = None
        self._sequential_bytes = 0
        self._stream_retry = False
        self._stream_failures = 0
        self._stream_failure_position: int | None = None

        tail_start = max(0, self._encrypted_size - _ARCHIVE_TAIL_CACHE_SIZE)
        tail_start -= tail_start % _AES_BLOCK_SIZE
        encrypted_tail = _read_download_range(
            client=self._client,
            remote_path=self._remote_path,
            start=tail_start,
            end=self._encrypted_size - 1,
            total_size=self._encrypted_size,
            recover_download=self._recover_download,
            network_progress=network_progress,
            rate_limiter=rate_limiter,
            gate=self._gate,
        )
        decrypted_tail = AES.new(self._key, AES.MODE_ECB).decrypt(encrypted_tail)
        unpadded_last_block = _pkcs7_unpad(decrypted_tail[-_AES_BLOCK_SIZE:])
        padding_size = _AES_BLOCK_SIZE - len(unpadded_last_block)
        self._size = self._encrypted_size - padding_size
        self._tail_start = min(tail_start, self._size)
        self._tail = decrypted_tail[: self._size - tail_start]

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        self._checkClosed()
        return self._position

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        self._checkClosed()
        if whence == os.SEEK_SET:
            target = int(offset)
        elif whence == os.SEEK_CUR:
            target = self._position + int(offset)
        elif whence == os.SEEK_END:
            target = self._size + int(offset)
        else:
            raise ValueError(f"invalid whence: {whence}")
        if target < 0:
            raise ValueError("negative seek position")
        if target == self._position:
            return target

        buffered_end = self._plain_buffer_start + len(self._plain_buffer)
        if self._plain_buffer_start <= target <= buffered_end:
            self._plain_buffer_offset = target - self._plain_buffer_start
            self._position = target
            return target

        self._position = target
        return target

    def read(self, size: int = -1) -> bytes:
        self._checkClosed()
        if size == 0 or self._position >= self._size:
            return b""
        if size is None or size < 0:
            remaining = self._size - self._position
        else:
            remaining = min(int(size), self._size - self._position)
        if self._position != self._last_read_end:
            self._sequential_bytes = 0
        self._sequential_bytes += remaining
        self._read_hint = remaining
        chunks: list[bytes] = []

        while remaining > 0:
            if self._position >= self._tail_start:
                tail_offset = self._position - self._tail_start
                take = min(remaining, len(self._tail) - tail_offset)
                if take <= 0:
                    break
                chunks.append(self._tail[tail_offset : tail_offset + take])
                self._position += take
                remaining -= take
                continue

            buffered_end = self._plain_buffer_start + len(self._plain_buffer)
            if self._plain_buffer_start <= self._position < buffered_end:
                self._plain_buffer_offset = self._position - self._plain_buffer_start
            else:
                cached = self._cached_at(self._position)
                if cached is not None:
                    cache_start, data = cached
                    inside = self._position - cache_start
                    take = min(remaining, len(data) - inside)
                    chunks.append(data[inside : inside + take])
                    self._position += take
                    remaining -= take
                    continue
                if self._position != self._stream_next:
                    self._close_stream()
                self._plain_buffer = b""
                self._plain_buffer_offset = 0
                self._fill_stream_buffer()
            if self._plain_buffer_offset >= len(self._plain_buffer):
                raise FUSError(f"unexpected end of firmware data at byte {self._position}")
            take = min(remaining, len(self._plain_buffer) - self._plain_buffer_offset)
            end = self._plain_buffer_offset + take
            chunks.append(self._plain_buffer[self._plain_buffer_offset : end])
            self._plain_buffer_offset = end
            self._position += take
            remaining -= take

        self._last_read_end = self._position
        return b"".join(chunks)

    def readinto(self, buffer: bytearray | memoryview) -> int:
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)

    def _cached_at(self, position: int) -> tuple[int, bytes] | None:
        for start in reversed(self._cache):
            data = self._cache[start]
            if start <= position < start + len(data):
                self._cache.move_to_end(start)
                return start, data
        return None

    def _cache_buffer(self) -> None:
        start, data = self._plain_buffer_start, self._plain_buffer
        previous = self._cache.pop(start, None)
        if previous is not None:
            self._cache_bytes -= len(previous)
        self._cache[start] = data
        self._cache_bytes += len(data)
        while self._cache_bytes > _ARCHIVE_READ_CACHE_SIZE or len(self._cache) > 128:
            _, discarded = self._cache.popitem(last=False)
            self._cache_bytes -= len(discarded)

    def close(self) -> None:
        if not self.closed:
            self._stop.set()
            self._close_stream()
            self._cache.clear()
            self._cache_bytes = 0
        super().close()

    def _open_stream(self) -> None:
        small_read = self._read_hint <= _RANGE_CHUNK_SIZE and self._sequential_bytes <= _RANGE_CHUNK_SIZE
        alignment = _RANGE_CHUNK_SIZE if small_read and not self._stream_retry else _AES_BLOCK_SIZE
        request_start = self._position - (self._position % alignment)
        request_end = (
            min(self._tail_start, request_start + _RANGE_CHUNK_SIZE) - 1 if small_read else self._tail_start - 1
        )
        if not self._gate.acquire(self._stop):
            raise ValueError("read of closed firmware stream")
        try:
            response = self._client.download_file(
                self._remote_path,
                start=request_start,
                end=request_end,
            )
            try:
                _validate_content_range(
                    response,
                    start=request_start,
                    end=request_end,
                    total_size=self._encrypted_size,
                )
            except Exception:
                response.close()
                raise
        finally:
            self._gate.release()
        self._response = response
        chunk_size = self._stream_chunk_size if not small_read else _RANGE_CHUNK_SIZE
        if self._rate_limiter is not None and self._rate_limiter.rate > 0:
            chunk_size = min(chunk_size, max(_AES_BLOCK_SIZE, int(self._rate_limiter.rate * _PROGRESS_REFRESH_S)))
        self._response_iter = response.iter_content(chunk_size=chunk_size)
        self._cipher = AES.new(self._key, AES.MODE_ECB)
        self._cipher_buffer = b""
        self._stream_next = request_start
        self._response_received = 0
        self._response_expected = request_end - request_start + 1
        self._stream_retry = False

    def _close_stream(self) -> None:
        response = self._response
        self._response = None
        self._response_iter = None
        self._cipher = None
        self._cipher_buffer = b""
        self._plain_buffer = b""
        self._plain_buffer_offset = 0
        if response is not None:
            response.close()

    def _retry_stream(self, exc: Exception) -> None:
        self._close_stream()
        self._stream_retry = True
        if self._stream_failure_position == self._position:
            self._stream_failures += 1
        else:
            self._stream_failure_position = self._position
            self._stream_failures = 1
        if self._stream_failures > _DOWNLOAD_RETRIES:
            raise FUSError(f"firmware stream failed after retries at byte {self._position}: {exc}") from exc
        if isinstance(exc, RateLimitedError):
            self._gate.throttled(exc.retry_after_s)
            return
        if self._recover_download is not None and self._stream_failures % _DOWNLOAD_RECOVERY_INTERVAL == 0:
            try:
                self._recover_download()
            except Exception as recovery_exc:
                raise FUSError(f"download recovery failed: {recovery_exc}") from recovery_exc
            time.sleep(_RATE_LIMIT_COOLDOWN_S)
        time.sleep(_RETRY_BACKOFF_S * self._stream_failures)

    def _fill_stream_buffer(self) -> None:
        stream_limit = min(self._size, self._tail_start)
        while self._plain_buffer_offset >= len(self._plain_buffer) and self._position < stream_limit:
            self._plain_buffer = b""
            self._plain_buffer_offset = 0
            try:
                if self._response_iter is None:
                    self._open_stream()
                if self._response_iter is None:
                    raise RetryableDownloadError("download stream did not start")
                chunk = next(self._response_iter)
                if not chunk:
                    continue
                if self._network_progress is not None:
                    self._network_progress(len(chunk))
                if self._rate_limiter is not None:
                    self._rate_limiter.consume(len(chunk))
                if len(chunk) > self._response_expected - self._response_received:
                    raise RetryableDownloadError("download stream received more data than requested")
                self._response_received += len(chunk)
                encrypted = self._cipher_buffer + chunk if self._cipher_buffer else chunk
                block_size = (len(encrypted) // _AES_BLOCK_SIZE) * _AES_BLOCK_SIZE
                if block_size == 0:
                    self._cipher_buffer = encrypted
                    continue
                self._cipher_buffer = encrypted[block_size:]
                encrypted = encrypted[:block_size]
                if self._cipher is None:
                    raise RetryableDownloadError("download stream lost its decryptor")
                plain = self._cipher.decrypt(encrypted)
                self._plain_buffer_start = self._stream_next
                self._stream_next += len(plain)
                self._plain_buffer = plain
                self._plain_buffer_offset = max(0, self._position - self._plain_buffer_start)
                if self._plain_buffer_offset >= len(plain):
                    continue
                if self._response_received == self._response_expected:
                    if self._cipher_buffer:
                        raise RetryableDownloadError("download stream ended with a partial encrypted block")
                    for extra in self._response_iter:
                        if extra:
                            if self._network_progress is not None:
                                self._network_progress(len(extra))
                            if self._rate_limiter is not None:
                                self._rate_limiter.consume(len(extra))
                            raise RetryableDownloadError("download stream received more data than requested")
                    if self._response is not None:
                        self._response.close()
                    self._response = None
                    self._response_iter = None
                self._cache_buffer()
            except StopIteration:
                if self._cipher_buffer:
                    error = RetryableDownloadError("download stream ended with a partial encrypted block")
                else:
                    error = RetryableDownloadError("download stream ended before the requested data")
                self._retry_stream(error)
            except (requests.RequestException, OSError, RetryableDownloadError) as exc:
                self._retry_stream(exc)
