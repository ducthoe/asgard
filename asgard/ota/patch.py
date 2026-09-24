# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import bz2
import hashlib
import os
from contextlib import ExitStack
from pathlib import Path
from typing import BinaryIO

from ..core.errors import FUSError

_BSDIFF40 = b"BSDIFF40"
_BSDF2 = b"BSDF2"
_PATCH_IO_SIZE = 1024 * 1024


def normalize_source_signature(
    source: bytes | bytearray, expected: bytes, *, offset: int = 0, algorithm: str = "sha256"
) -> bytes | bytearray:
    if source[offset + 768 : offset + 779] != b"SignerVer02":
        return source
    view = memoryview(source)
    digest = hashlib.new(algorithm)
    digest.update(view[:offset])
    digest.update(bytes(256))
    digest.update(view[offset + 256 :])
    if digest.digest() != expected:
        return source
    return source[:offset] + bytes(256) + source[offset + 256 :]


def _signed_int64(raw: bytes) -> int:
    if len(raw) != 8:
        raise FUSError("truncated bsdiff integer")
    value = int.from_bytes(raw, "little") & ((1 << 63) - 1)
    return -value if raw[7] & 0x80 else value


def _decompress(kind: int, raw: bytes) -> bytes:
    try:
        if kind == 0:
            return raw
        if kind == 1:
            return bz2.decompress(raw)
        if kind == 2:
            import brotli

            return brotli.decompress(raw)
    except (OSError, EOFError) as exc:
        raise FUSError(f"invalid compressed bsdiff stream: {exc}") from exc
    except Exception as exc:
        raise FUSError(f"could not decompress bsdiff stream: {exc}") from exc
    raise FUSError(f"unsupported bsdiff compressor: {kind}")


def _decode_patch(patch: bytes) -> tuple[int, list[tuple[int, int, int]], bytes, bytes]:
    if len(patch) < 32:
        raise FUSError("truncated bsdiff patch")
    if patch.startswith(_BSDIFF40):
        compressors = (1, 1, 1)
    elif patch.startswith(_BSDF2):
        compressors = tuple(patch[5:8])
    else:
        raise FUSError("unsupported patch format")
    control_size = _signed_int64(patch[8:16])
    diff_size = _signed_int64(patch[16:24])
    target_size = _signed_int64(patch[24:32])
    if min(control_size, diff_size, target_size) < 0 or 32 + control_size + diff_size > len(patch):
        raise FUSError("invalid bsdiff patch lengths")
    control_end = 32 + control_size
    diff_end = control_end + diff_size
    control = _decompress(compressors[0], patch[32:control_end])
    diff = _decompress(compressors[1], patch[control_end:diff_end])
    extra = _decompress(compressors[2], patch[diff_end:])
    if len(control) % 24:
        raise FUSError("invalid bsdiff control stream")
    triples = [
        (
            _signed_int64(control[offset : offset + 8]),
            _signed_int64(control[offset + 8 : offset + 16]),
            _signed_int64(control[offset + 16 : offset + 24]),
        )
        for offset in range(0, len(control), 24)
    ]
    if any(diff_length < 0 or extra_length < 0 for diff_length, extra_length, _seek in triples):
        raise FUSError("invalid bsdiff control entry")
    diff_total = sum(item[0] for item in triples)
    extra_total = sum(item[1] for item in triples)
    if diff_total + extra_total != target_size or diff_total != len(diff) or extra_total != len(extra):
        raise FUSError("bsdiff streams do not match the declared target size")
    return target_size, triples, diff, extra


def apply_bsdiff(source: bytes | bytearray, patch: bytes, *, expected_size: int | None = None) -> bytes:
    target_size, controls, diff, extra = _decode_patch(patch)
    if expected_size is not None and target_size != expected_size:
        raise FUSError(f"patch target size mismatch: expected {expected_size}, got {target_size}")
    try:
        from bsdiff4 import core

        result = core.patch(bytes(source), target_size, controls, diff, extra)
    except Exception as exc:
        raise FUSError(f"could not apply bsdiff patch: {exc}") from exc
    if len(result) != target_size:
        raise FUSError(f"patched output size mismatch: expected {target_size}, got {len(result)}")
    return result


class _LimitedReader:
    def __init__(self, source: BinaryIO, size: int):
        self.source = source
        self.remaining = size

    def read(self, size: int = -1) -> bytes:
        if not self.remaining or size == 0:
            return b""
        amount = self.remaining if size < 0 else min(size, self.remaining)
        data = self.source.read(amount)
        if not data:
            raise FUSError("truncated bsdiff patch stream")
        self.remaining -= len(data)
        return data


class _BrotliReader:
    def __init__(self, source: _LimitedReader):
        import brotli

        self.source = source
        self.decoder = brotli.Decompressor()
        self.buffer = b""
        self.offset = 0

    def read(self, size: int) -> bytes:
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            if self.offset < len(self.buffer):
                part = self.buffer[self.offset : self.offset + remaining]
                chunks.append(part)
                self.offset += len(part)
                remaining -= len(part)
                continue
            compressed = self.source.read(4096)
            if not compressed:
                if not self.decoder.is_finished():
                    raise FUSError("truncated Brotli bsdiff stream")
                break
            try:
                self.buffer = self.decoder.process(compressed)
            except Exception as exc:
                raise FUSError(f"invalid Brotli bsdiff stream: {exc}") from exc
            self.offset = 0
        return b"".join(chunks)


def _read_decoded(source, size: int, *, allow_eof: bool = False) -> bytes | None:
    chunks = []
    remaining = size
    while remaining:
        try:
            chunk = source.read(remaining)
        except (EOFError, OSError) as exc:
            raise FUSError(f"invalid compressed bsdiff stream: {exc}") from exc
        if not chunk:
            if allow_eof and remaining == size:
                return None
            raise FUSError("truncated bsdiff patch stream")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _write_chunk(output: BinaryIO, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = output.write(view)
        if written is None or written <= 0:
            raise FUSError("could not write patched image data")
        view = view[written:]


def _patch_segment(stack: ExitStack, source: BinaryIO, start: int, size: int, compressor: int):
    source.seek(start)
    limited = _LimitedReader(source, size)
    if compressor == 0:
        return limited
    if compressor == 1:
        return stack.enter_context(bz2.BZ2File(limited))
    if compressor == 2:
        return _BrotliReader(limited)
    raise FUSError(f"unsupported bsdiff compressor: {compressor}")


def _source_chunk(file_descriptor: int, source_size: int, offset: int, size: int) -> bytes:
    start = max(0, offset)
    end = min(source_size, offset + size)
    if start >= end:
        return bytes(size)
    chunks = []
    position = start
    while position < end:
        chunk = os.pread(file_descriptor, end - position, position)
        if not chunk:
            raise FUSError("base image ended during bsdiff patch")
        chunks.append(chunk)
        position += len(chunk)
    return bytes(start - offset) + b"".join(chunks) + bytes(offset + size - end)


def apply_bsdiff_to_file(
    source_path: Path,
    patch_streams: tuple[BinaryIO, BinaryIO, BinaryIO],
    patch_size: int,
    output: BinaryIO,
    *,
    expected_size: int | None = None,
) -> tuple[str, str]:
    header = _read_decoded(patch_streams[0], 32)
    if header.startswith(_BSDIFF40):
        compressors = (1, 1, 1)
    elif header.startswith(_BSDF2):
        compressors = tuple(header[5:8])
    else:
        raise FUSError("unsupported patch format")
    control_size = _signed_int64(header[8:16])
    diff_size = _signed_int64(header[16:24])
    target_size = _signed_int64(header[24:32])
    if min(control_size, diff_size, target_size) < 0 or 32 + control_size + diff_size > patch_size:
        raise FUSError("invalid bsdiff patch lengths")
    if expected_size is not None and target_size != expected_size:
        raise FUSError(f"patch target size mismatch: expected {expected_size}, got {target_size}")

    from bsdiff4 import core

    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with ExitStack() as stack:
        control = _patch_segment(stack, patch_streams[0], 32, control_size, compressors[0])
        diff = _patch_segment(stack, patch_streams[1], 32 + control_size, diff_size, compressors[1])
        extra = _patch_segment(
            stack,
            patch_streams[2],
            32 + control_size + diff_size,
            patch_size - 32 - control_size - diff_size,
            compressors[2],
        )
        source = stack.enter_context(source_path.open("rb", buffering=0))
        source_size = os.fstat(source.fileno()).st_size
        old_position = 0
        new_position = 0
        while triple := _read_decoded(control, 24, allow_eof=True):
            diff_length, extra_length, seek = (_signed_int64(triple[index : index + 8]) for index in (0, 8, 16))
            if min(diff_length, extra_length) < 0 or new_position + diff_length + extra_length > target_size:
                raise FUSError("invalid bsdiff control entry")
            remaining = diff_length
            while remaining:
                amount = min(remaining, _PATCH_IO_SIZE)
                delta = _read_decoded(diff, amount)
                original = _source_chunk(source.fileno(), source_size, old_position, amount)
                try:
                    result = core.patch(original, amount, [(amount, 0, 0)], delta, b"")
                except Exception as exc:
                    raise FUSError(f"could not apply bsdiff patch: {exc}") from exc
                _write_chunk(output, result)
                sha1.update(result)
                sha256.update(result)
                remaining -= amount
                old_position += amount
                new_position += amount
            remaining = extra_length
            while remaining:
                amount = min(remaining, _PATCH_IO_SIZE)
                result = _read_decoded(extra, amount)
                _write_chunk(output, result)
                sha1.update(result)
                sha256.update(result)
                remaining -= amount
                new_position += amount
            old_position += seek
        if new_position != target_size or diff.read(1) or extra.read(1):
            raise FUSError("bsdiff streams do not match the declared target size")
    return sha1.hexdigest(), sha256.hexdigest()
