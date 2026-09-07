# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path

from ..core.errors import FUSError

try:
    _fallocate = ctypes.CDLL(None, use_errno=True).fallocate
    _fallocate.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_longlong, ctypes.c_longlong)
    _fallocate.restype = ctypes.c_int
except (AttributeError, OSError):
    _fallocate = None


def write_all(output, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = output.write(view)
        if written is None or written <= 0:
            raise FUSError("could not write OTA image data")
        view = view[written:]


def zero_range(output, offset: int, size: int) -> None:
    output.flush()
    if _fallocate is not None and _fallocate(output.fileno(), 3, offset, size) == 0:
        return
    output.seek(offset)
    zeros = bytes(min(size, 1024 * 1024))
    while size:
        amount = min(size, len(zeros))
        write_all(output, zeros[:amount])
        size -= amount


def prepare_image(source: Path, destination: Path, *, consume: bool) -> None:
    if source.resolve() == destination.resolve():
        raise FUSError("base image aliases the merge output")
    if consume:
        try:
            source.rename(destination)
            return
        except OSError as exc:
            if exc.errno != errno.EXDEV:
                raise
    with source.open("rb") as incoming, destination.open("xb") as outgoing:
        size = os.fstat(incoming.fileno()).st_size
        position = 0
        while position < size:
            try:
                start = os.lseek(incoming.fileno(), position, os.SEEK_DATA)
                end = min(os.lseek(incoming.fileno(), start, os.SEEK_HOLE), size)
            except (OSError, AttributeError) as exc:
                if isinstance(exc, OSError) and exc.errno == errno.ENXIO:
                    break
                if isinstance(exc, OSError) and exc.errno not in {errno.EINVAL, errno.ENOTSUP}:
                    raise
                start, end = position, size
            incoming.seek(start)
            outgoing.seek(start)
            while start < end:
                chunk = incoming.read(min(4 * 1024 * 1024, end - start))
                if not chunk:
                    raise FUSError(f"truncated base image: {source}")
                if chunk.count(0) == len(chunk):
                    outgoing.seek(len(chunk), os.SEEK_CUR)
                else:
                    outgoing.write(chunk)
                start += len(chunk)
            position = end
        outgoing.truncate(size)
    if consume:
        source.unlink()
