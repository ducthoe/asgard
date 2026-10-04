# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import io
import os
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterator
from contextlib import contextmanager

import requests
from Cryptodome.Cipher import AES

from ..core.constants import (
    _AES_BLOCK_SIZE,
    _ARCHIVE_READ_CACHE_SIZE,
    _ARCHIVE_TAIL_CACHE_SIZE,
    _DOWNLOAD_MIN_RANGE_SIZE,
    _DOWNLOAD_RECOVERY_INTERVAL,
    _DOWNLOAD_RETRIES,
    _RANGE_CHUNK_SIZE,
    _RATE_LIMIT_COOLDOWN_S,
    _RETRY_BACKOFF_S,
)
from ..core.errors import FUSError, RateLimitedError, RetryableDownloadError
from ..core.resources import download_worker_count
from .client import FUSClient
from .crypto import _pkcs7_unpad
from .scheduling import AdaptiveDownloadGate
from .transfer import BandwidthLimiter, _ParallelRangeStream, _read_download_range, _validate_content_range


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
        threads: int | None = None,
    ):
        super().__init__()
        self._response: requests.Response | None = None
        self._stop = threading.Event()
        self._cache: OrderedDict[int, bytes] = OrderedDict()
        self._cache_bytes = 0
        self._parallel_stream: _ParallelRangeStream | None = None
        self._workers = download_worker_count(encrypted_size) if threads is None else int(threads)
        self._gate = AdaptiveDownloadGate(self._workers)
        client.configure_download_pool(self._workers)
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
        self._streaming_reads = False
        self._stream_end: int | None = None
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

    @contextmanager
    def streaming(self, *, end: int | None = None) -> Iterator[None]:
        previous = self._streaming_reads
        previous_end = self._stream_end
        self._streaming_reads = True
        if end is not None:
            self._stream_end = end if previous_end is None else min(end, previous_end)
        try:
            yield
        finally:
            self._streaming_reads = previous
            self._stream_end = previous_end
            if not previous and self._parallel_stream is not None:
                self._close_stream()

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
        small_read = (
            not self._streaming_reads
            and self._read_hint <= _RANGE_CHUNK_SIZE
            and self._sequential_bytes <= _RANGE_CHUNK_SIZE
        )
        alignment = _RANGE_CHUNK_SIZE if small_read and not self._stream_retry else _AES_BLOCK_SIZE
        request_start = self._position - (self._position % alignment)
        stream_end = self._tail_start
        if self._stream_end is not None and self._position < self._stream_end:
            aligned_end = (self._stream_end + _AES_BLOCK_SIZE - 1) // _AES_BLOCK_SIZE * _AES_BLOCK_SIZE
            stream_end = min(stream_end, aligned_end)
        request_end = min(stream_end, request_start + _RANGE_CHUNK_SIZE) - 1 if small_read else stream_end - 1
        chunk_size = self._stream_chunk_size if not small_read else _RANGE_CHUNK_SIZE
        if self._rate_limiter is not None:
            chunk_size = self._rate_limiter.chunk_size(chunk_size)
        if self._workers > 1 and request_end - request_start + 1 > _DOWNLOAD_MIN_RANGE_SIZE:
            self._parallel_stream = _ParallelRangeStream(
                client=self._client,
                remote_path=self._remote_path,
                start=request_start,
                end=request_end,
                total_size=self._encrypted_size,
                workers=self._workers,
                chunk_size=chunk_size,
                gate=self._gate,
                recover_download=self._recover_download,
                network_progress=self._network_progress,
                rate_limiter=self._rate_limiter,
            )
            self._response_iter = self._parallel_stream
        else:
            self._open_serial_stream(request_start, request_end, chunk_size)
        self._cipher = AES.new(self._key, AES.MODE_ECB)
        self._cipher_buffer = b""
        self._stream_next = request_start
        self._response_received = 0
        self._response_expected = request_end - request_start + 1
        self._stream_retry = False

    def _open_serial_stream(self, request_start: int, request_end: int, chunk_size: int) -> None:
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
        self._response_iter = response.iter_content(chunk_size=chunk_size)

    def _close_stream(self) -> None:
        self._close_response()
        self._cipher = None
        self._cipher_buffer = b""
        self._plain_buffer = b""
        self._plain_buffer_offset = 0

    def _close_response(self) -> None:
        parallel = self._parallel_stream
        self._parallel_stream = None
        response = self._response
        self._response = None
        self._response_iter = None
        if response is not None:
            response.close()
        if parallel is not None:
            parallel.close()

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
                if self._parallel_stream is None and self._network_progress is not None:
                    self._network_progress(len(chunk))
                if self._parallel_stream is None and self._rate_limiter is not None:
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
                    self._close_response()
                self._cache_buffer()
            except StopIteration:
                if self._cipher_buffer:
                    error = RetryableDownloadError("download stream ended with a partial encrypted block")
                else:
                    error = RetryableDownloadError("download stream ended before the requested data")
                self._retry_stream(error)
            except (requests.RequestException, OSError, RetryableDownloadError) as exc:
                self._retry_stream(exc)
