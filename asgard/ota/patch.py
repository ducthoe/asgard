# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import bz2
import hashlib

from ..core.errors import FUSError

_BSDIFF40 = b"BSDIFF40"
_BSDF2 = b"BSDF2"


def normalize_source_signature(source: bytes, expected: bytes, *, offset: int = 0, algorithm: str = "sha256") -> bytes:
    if source[offset + 768 : offset + 779] != b"SignerVer02":
        return source
    normalized = source[:offset] + bytes(256) + source[offset + 256 :]
    if hashlib.new(algorithm, normalized).digest() == expected:
        return normalized
    return source


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


def apply_bsdiff(source: bytes, patch: bytes, *, expected_size: int | None = None) -> bytes:
    target_size, controls, diff, extra = _decode_patch(patch)
    if expected_size is not None and target_size != expected_size:
        raise FUSError(f"patch target size mismatch: expected {expected_size}, got {target_size}")
    try:
        from bsdiff4 import core

        result = core.patch(source, target_size, controls, diff, extra)
    except Exception as exc:
        raise FUSError(f"could not apply bsdiff patch: {exc}") from exc
    if len(result) != target_size:
        raise FUSError(f"patched output size mismatch: expected {target_size}, got {len(result)}")
    return result
