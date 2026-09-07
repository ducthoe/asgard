# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import BinaryIO


class SourceBuffers:
    def __init__(self, work_dir: Path | None = None, *, memory_limit: int = 32 * 1024 * 1024):
        self.work_dir = work_dir
        self.memory_limit = memory_limit
        self.memory_used = 0
        self._values: dict[str | int, bytes | BinaryIO] = {}

    def __contains__(self, key: str | int) -> bool:
        return key in self._values

    def __setitem__(self, key: str | int, data: bytes) -> None:
        self.discard(key)
        if self.memory_used + len(data) <= self.memory_limit:
            self._values[key] = data
            self.memory_used += len(data)
        else:
            temporary = tempfile.TemporaryFile(dir=self.work_dir)
            try:
                temporary.write(data)
            except BaseException:
                temporary.close()
                raise
            self._values[key] = temporary

    def __getitem__(self, key: str | int) -> bytes:
        value = self._values[key]
        if isinstance(value, bytes):
            return value
        value.seek(0)
        return value.read()

    def pop(self, key: str | int) -> bytes | None:
        if key not in self._values:
            return None
        result = self[key]
        self.discard(key)
        return result

    def discard(self, key: str | int) -> None:
        value = self._values.pop(key, None)
        if isinstance(value, bytes):
            self.memory_used -= len(value)
        elif value is not None:
            value.close()

    def __enter__(self) -> SourceBuffers:
        return self

    def __exit__(self, *_exc: object) -> None:
        for key in tuple(self._values):
            self.discard(key)
