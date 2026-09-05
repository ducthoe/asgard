# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import io
import os
import re
import threading
import time
from typing import Callable, Iterator

import requests
from Cryptodome.Cipher import AES

from ..core.constants import (
    _AES_BLOCK_SIZE,
    _ARCHIVE_TAIL_CACHE_SIZE,
    _DOWNLOAD_RECOVERY_INTERVAL,
    _DOWNLOAD_RETRIES,
    _RANGE_CHUNK_SIZE,
    _RATE_LIMIT_COOLDOWN_S,
    _RETRY_BACKOFF_S,
)
from ..core.errors import FUSError, RetryableDownloadError
from .client import FUSClient
from .crypto import _pkcs7_unpad

_CONTENT_RANGE_RE = re.compile(r"bytes\s+(\d+)-(\d+)/(\d+|\*)", re.IGNORECASE)


class BandwidthLimiter:
    def __init__(self, bytes_per_second: int | None):
        self.rate = int(bytes_per_second or 0)
        if self.rate < 0:
            raise ValueError("bandwidth limit cannot be negative")
        self._lock = threading.Lock()
        self._available_at = time.monotonic()

    def consume(self, size: int) -> None:
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
            time.sleep(delay)


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


def _read_download_range(
    *,
    client: FUSClient,
    remote_path: str,
    start: int,
    end: int,
    total_size: int,
    recover_download: Callable[[], None] | None = None,
) -> bytes:
    expected_size = end - start + 1
    for attempt in range(1, _DOWNLOAD_RETRIES + 2):
        response: requests.Response | None = None
        try:
            response = client.download_file(remote_path, start=start, end=end)
            _validate_content_range(response, start=start, end=end, total_size=total_size)
            chunks: list[bytes] = []
            received = 0
            for chunk in response.iter_content(chunk_size=_RANGE_CHUNK_SIZE):
                if not chunk:
                    continue
                received += len(chunk)
                if received > expected_size:
                    raise RetryableDownloadError(
                        f"download server returned more data than requested for range {start}-{end}"
                    )
                chunks.append(chunk)
            if received != expected_size:
                raise RetryableDownloadError(
                    f"download server returned {received} bytes for range {start}-{end}, expected {expected_size}"
                )
            return b"".join(chunks)
        except (requests.RequestException, OSError, RetryableDownloadError) as exc:
            if attempt > _DOWNLOAD_RETRIES:
                raise FUSError(f"range {start}-{end} failed after retries: {exc}") from exc
            if recover_download is not None and attempt % _DOWNLOAD_RECOVERY_INTERVAL == 0:
                try:
                    recover_download()
                except Exception as recovery_exc:
                    raise FUSError(f"download recovery failed: {recovery_exc}") from recovery_exc
                time.sleep(_RATE_LIMIT_COOLDOWN_S)
            time.sleep(_RETRY_BACKOFF_S * attempt)
        finally:
            if response is not None:
                response.close()
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
    ):
        super().__init__()
        self._response: requests.Response | None = None
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
        self._position = 0
        self._response_iter: Iterator[bytes] | None = None
        self._cipher: AES | None = None
        self._cipher_buffer = b""
        self._plain_buffer = b""
        self._plain_buffer_offset = 0
        self._stream_discard = 0
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

        buffered_end = self._position + len(self._plain_buffer) - self._plain_buffer_offset
        if self._position < target <= buffered_end:
            self._plain_buffer_offset += target - self._position
            self._position = target
            return target

        self._close_stream()
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
        chunks: list[bytes] = []

        while remaining > 0:
            if self._position >= self._tail_start:
                self._close_stream()
                tail_offset = self._position - self._tail_start
                take = min(remaining, len(self._tail) - tail_offset)
                if take <= 0:
                    break
                chunks.append(self._tail[tail_offset : tail_offset + take])
                self._position += take
                remaining -= take
                continue

            if self._plain_buffer_offset >= len(self._plain_buffer):
                self._fill_stream_buffer()
            if self._plain_buffer_offset >= len(self._plain_buffer):
                raise FUSError(f"unexpected end of firmware data at byte {self._position}")
            take = min(remaining, len(self._plain_buffer) - self._plain_buffer_offset)
            end = self._plain_buffer_offset + take
            chunks.append(self._plain_buffer[self._plain_buffer_offset : end])
            self._plain_buffer_offset = end
            self._position += take
            remaining -= take

        return b"".join(chunks)

    def close(self) -> None:
        if not self.closed:
            self._close_stream()
        super().close()

    def _open_stream(self) -> None:
        request_start = self._position - (self._position % _AES_BLOCK_SIZE)
        request_end = self._tail_start - 1
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
        self._response = response
        self._response_iter = response.iter_content(chunk_size=self._stream_chunk_size)
        self._cipher = AES.new(self._key, AES.MODE_ECB)
        self._cipher_buffer = b""
        self._stream_discard = self._position - request_start

    def _close_stream(self) -> None:
        response = self._response
        self._response = None
        self._response_iter = None
        self._cipher = None
        self._cipher_buffer = b""
        self._plain_buffer = b""
        self._plain_buffer_offset = 0
        self._stream_discard = 0
        if response is not None:
            response.close()

    def _retry_stream(self, exc: Exception) -> None:
        self._close_stream()
        if self._stream_failure_position == self._position:
            self._stream_failures += 1
        else:
            self._stream_failure_position = self._position
            self._stream_failures = 1
        if self._stream_failures > _DOWNLOAD_RETRIES:
            raise FUSError(f"firmware stream failed after retries at byte {self._position}: {exc}") from exc
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
                if self._rate_limiter is not None:
                    self._rate_limiter.consume(len(chunk))
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
                if self._stream_discard:
                    discarded = min(self._stream_discard, len(plain))
                    plain = plain[discarded:]
                    self._stream_discard -= discarded
                remaining = stream_limit - self._position
                if len(plain) > remaining:
                    plain = plain[:remaining]
                self._plain_buffer = plain
                self._plain_buffer_offset = 0
            except StopIteration:
                if self._cipher_buffer:
                    error = RetryableDownloadError("download stream ended with a partial encrypted block")
                else:
                    error = RetryableDownloadError("download stream ended before the requested data")
                self._retry_stream(error)
            except (requests.RequestException, OSError, RetryableDownloadError) as exc:
                self._retry_stream(exc)
