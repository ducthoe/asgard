# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import io
import os
import struct
import time
import zlib
from functools import lru_cache

from ..cli.progress import render_progress
from ..core.constants import (
    _ARCHIVE_COPY_CHUNK_SIZE,
    _MAX_SIGNED_64,
    _PROGRESS_REFRESH_S,
    _SPARSE_CHUNK_HEADER,
    _SPARSE_CRC32,
    _SPARSE_DONT_CARE,
    _SPARSE_FILL,
    _SPARSE_HEADER,
    _SPARSE_MAGIC,
    _SPARSE_RAW,
)
from ..core.errors import FUSError
from ..core.streaming import read_exact_stream, write_data_or_hole, write_data_or_holes

_CRC32_BYTE_OPERATOR = tuple(zlib.crc32(b"\0", 1 << bit) ^ zlib.crc32(b"\0") for bit in range(32))


def _crc32_matrix_times(matrix: tuple[int, ...], value: int) -> int:
    result = 0
    while value:
        bit = value & -value
        result ^= matrix[bit.bit_length() - 1]
        value ^= bit
    return result


@lru_cache(maxsize=128)
def _crc32_operator(size: int) -> tuple[int, ...]:
    if size == 0:
        return tuple(1 << bit for bit in range(32))
    if size == 1:
        return _CRC32_BYTE_OPERATOR
    half = _crc32_operator(size // 2)
    result = tuple(_crc32_matrix_times(half, column) for column in half)
    if size % 2:
        result = tuple(_crc32_matrix_times(_CRC32_BYTE_OPERATOR, column) for column in result)
    return result


def _crc32_shift(checksum: int, size: int) -> int:
    return _crc32_matrix_times(_crc32_operator(size), checksum)


@lru_cache(maxsize=128)
def _repeated_crc32(pattern: bytes, repeats: int) -> int:
    if not repeats:
        return 0
    half_size = repeats // 2
    half_crc = _repeated_crc32(pattern, half_size)
    checksum = _crc32_shift(half_crc, half_size * len(pattern)) ^ half_crc
    return zlib.crc32(pattern, checksum) if repeats % 2 else checksum


def _crc32_pattern(pattern: bytes, offset: int, size: int, checksum: int) -> int:
    rotated = pattern[offset:] + pattern[:offset]
    repeats, tail = divmod(size, len(pattern))
    block_crc = zlib.crc32(rotated[:tail], _repeated_crc32(rotated, repeats))
    return _crc32_shift(checksum, size) ^ block_crc


class _SparseRawReader:
    def __init__(self, source: io.BufferedIOBase, *, header_prefix: bytes):
        self._source = source
        header = header_prefix + read_exact_stream(
            source,
            _SPARSE_HEADER.size - len(header_prefix),
            "sparse image header",
        )
        (
            magic,
            major_version,
            _minor_version,
            self._file_header_size,
            self._chunk_header_size,
            self._block_size,
            self._total_blocks,
            self._total_chunks,
            self._image_checksum,
        ) = _SPARSE_HEADER.unpack(header)
        if magic != _SPARSE_MAGIC:
            raise FUSError("invalid sparse image magic")
        if major_version != 1:
            raise FUSError(f"unsupported sparse image version: {major_version}")
        if self._file_header_size < _SPARSE_HEADER.size:
            raise FUSError(f"invalid sparse file header size: {self._file_header_size}")
        if self._chunk_header_size < _SPARSE_CHUNK_HEADER.size:
            raise FUSError(f"invalid sparse chunk header size: {self._chunk_header_size}")
        if self._block_size <= 0 or self._block_size % 4:
            raise FUSError(f"invalid sparse block size: {self._block_size}")
        if not self._total_blocks:
            raise FUSError("sparse image contains no output blocks")
        self.raw_size = self._block_size * self._total_blocks
        if self.raw_size > _MAX_SIGNED_64:
            raise FUSError(f"sparse image is too large: {self.raw_size} bytes")
        if self._file_header_size > _SPARSE_HEADER.size:
            read_exact_stream(
                source,
                self._file_header_size - _SPARSE_HEADER.size,
                "extended sparse header",
            )

        self._position = 0
        self._blocks_seen = 0
        self._chunks_seen = 0
        self._checksum = 0
        self._chunk_type: int | None = None
        self._chunk_remaining = 0
        self._chunk_pattern = b""
        self._pattern_offset = 0
        self._finished = False

    def tell(self) -> int:
        return self._position

    def _validate_end(self) -> None:
        if self._blocks_seen != self._total_blocks:
            raise FUSError(f"incomplete sparse image: expected {self._total_blocks} blocks, got {self._blocks_seen}")
        if self._image_checksum and self._image_checksum != self._checksum:
            raise FUSError(
                f"sparse image checksum mismatch: expected {self._image_checksum:08x}, got {self._checksum:08x}"
            )
        self._finished = True

    def _load_next_chunk(self) -> bool:
        while self._chunks_seen < self._total_chunks:
            chunk_number = self._chunks_seen + 1
            raw_header = read_exact_stream(
                self._source,
                self._chunk_header_size,
                f"sparse chunk {chunk_number} header",
            )
            self._chunks_seen += 1
            chunk_type, _reserved, chunk_blocks, total_size = _SPARSE_CHUNK_HEADER.unpack_from(raw_header)
            if total_size < self._chunk_header_size:
                raise FUSError(f"invalid sparse chunk {chunk_number} size: {total_size}")
            data_size = total_size - self._chunk_header_size

            if chunk_type == _SPARSE_CRC32:
                if chunk_blocks != 0 or data_size != 4:
                    raise FUSError(f"invalid sparse CRC chunk {chunk_number}")
                expected = struct.unpack(
                    "<I",
                    read_exact_stream(self._source, 4, "sparse CRC32"),
                )[0]
                if expected != self._checksum:
                    raise FUSError(f"sparse CRC mismatch: expected {expected:08x}, got {self._checksum:08x}")
                continue

            if chunk_blocks > self._total_blocks - self._blocks_seen:
                raise FUSError(f"sparse chunk {chunk_number} exceeds the output size")
            chunk_size = chunk_blocks * self._block_size
            self._blocks_seen += chunk_blocks
            if chunk_type == _SPARSE_RAW:
                if data_size != chunk_size:
                    raise FUSError(f"invalid sparse RAW chunk {chunk_number}")
                pattern = b""
            elif chunk_type == _SPARSE_FILL:
                if data_size != 4:
                    raise FUSError(f"invalid sparse FILL chunk {chunk_number}")
                pattern = read_exact_stream(self._source, 4, "sparse fill pattern")
            elif chunk_type == _SPARSE_DONT_CARE:
                if data_size != 0:
                    raise FUSError(f"invalid sparse DONT_CARE chunk {chunk_number}")
                pattern = b"\0\0\0\0"
            else:
                raise FUSError(f"unknown sparse chunk type: 0x{chunk_type:04x}")

            if not chunk_size:
                continue
            self._chunk_type = chunk_type
            self._chunk_remaining = chunk_size
            self._chunk_pattern = pattern
            self._pattern_offset = 0
            return True

        self._validate_end()
        return False

    @staticmethod
    @lru_cache(maxsize=4)
    def _repeated_data(pattern: bytes, offset: int, size: int) -> bytes:
        repeats = (offset + size + len(pattern) - 1) // len(pattern)
        return (pattern * repeats)[offset : offset + size]

    def _consume(
        self,
        size: int,
        *,
        output: io.BufferedWriter | None = None,
        collect: bool = False,
        hole_block_size: int | None = None,
    ) -> bytes:
        if size < 0:
            raise ValueError("read size cannot be negative")
        if size > self.raw_size - self._position:
            raise FUSError("read exceeds the sparse image raw size")
        collected: list[bytes] = []
        remaining = size
        while remaining:
            if not self._chunk_remaining and not self._load_next_chunk():
                raise FUSError("unexpected end of sparse image")
            amount = min(remaining, self._chunk_remaining)
            synthetic = self._chunk_type != _SPARSE_RAW
            data = None
            if (
                synthetic
                and not collect
                and amount >= 64 * 1024
                and (output is None or self._chunk_pattern == b"\0\0\0\0")
            ):
                if output is not None:
                    output.seek(amount, os.SEEK_CUR)
            else:
                amount = min(amount, _ARCHIVE_COPY_CHUNK_SIZE)
                if synthetic:
                    data = self._repeated_data(self._chunk_pattern, self._pattern_offset, amount)
                else:
                    data = read_exact_stream(self._source, amount, "sparse RAW data")
                if output is not None:
                    if hole_block_size and not synthetic:
                        write_data_or_holes(output, data, hole_block_size)
                    else:
                        write_data_or_hole(output, data)
                if collect:
                    collected.append(data)
            if data is None or (synthetic and amount >= 64 * 1024):
                self._checksum = _crc32_pattern(self._chunk_pattern, self._pattern_offset, amount, self._checksum)
            else:
                self._checksum = zlib.crc32(data, self._checksum)
            self._position += amount
            self._chunk_remaining -= amount
            self._pattern_offset = (self._pattern_offset + amount) % 4
            remaining -= amount
        return b"".join(collected)

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            raise ValueError("a bounded read size is required")
        return self._consume(min(size, self.raw_size - self._position), collect=True)

    def skip_to(self, offset: int) -> None:
        if offset < self._position:
            raise FUSError("super image stream cannot seek backward")
        self._consume(offset - self._position)

    def copy_to(
        self,
        output: io.BufferedWriter,
        size: int,
        *,
        hole_block_size: int | None = None,
    ) -> None:
        self._consume(
            size,
            output=output,
            hole_block_size=hole_block_size or self._block_size,
        )

    def finish(self, *, require_eof: bool) -> None:
        self.skip_to(self.raw_size)
        if not self._finished:
            self._load_next_chunk()
        if require_eof and self._source.read(1):
            raise FUSError("sparse image contains trailing data")


def _copy_sparse_stream(
    source: io.BufferedIOBase,
    output: io.BufferedWriter,
    *,
    header_prefix: bytes,
    label: str,
) -> int:
    reader = _SparseRawReader(source, header_prefix=header_prefix)
    started_at = time.monotonic()
    last_render = 0.0
    remaining = reader.raw_size
    while remaining:
        amount = min(remaining, _ARCHIVE_COPY_CHUNK_SIZE)
        reader.copy_to(output, amount)
        remaining -= amount
        now = time.monotonic()
        if now - last_render >= _PROGRESS_REFRESH_S and reader.tell() < reader.raw_size:
            render_progress(label, reader.tell(), reader.raw_size, started_at)
            last_render = now
    reader.finish(require_eof=True)
    output.truncate(reader.raw_size)
    render_progress(label, reader.raw_size, reader.raw_size, started_at, complete=True)
    return reader.raw_size
