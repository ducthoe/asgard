# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import os
import re
from collections.abc import Callable
from pathlib import Path, PurePosixPath

from ..core.errors import FUSError
from .erofs import EROFS
from .ext4 import Ext4
from .f2fs import F2FS
from .random_access import ReadableImage


def _safe_path(path: str) -> str:
    if not path.startswith("/") or "\\" in path or "\0" in path:
        raise FUSError(f"invalid path inside partition: {path!r}")
    parts = path[1:].split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise FUSError(f"invalid path inside partition: {path!r}")
    return "/".join(parts)


def group_partition_paths(paths: tuple[str, ...], partition: str | None = None) -> dict[str, list[str]]:
    """Validate full device paths and group them by partition."""
    if not paths:
        raise FUSError("at least one --path is required")
    requested: dict[str, list[str]] = {}
    for path in paths:
        name, separator, relative = _safe_path(path).partition("/")
        if not separator or not relative or not re.fullmatch(r"[A-Za-z0-9_]+", name):
            raise FUSError(f"--path must be a full device path such as /system/build.prop: {path!r}")
        if partition is not None and name != partition:
            raise FUSError(f"--path {path!r} does not belong to {partition!r}")
        requested.setdefault(name, []).append(path)
    return requested


def _open_filesystem(image: ReadableImage, partition: str) -> EROFS | F2FS | Ext4:
    magic = image.read_at(1024, 4)
    if magic == b"\xe2\xe1\xf5\xe0":
        return EROFS(image)
    if magic == b"\x10\x20\xf5\xf2":
        return F2FS(image)
    if image.read_at(1080, 2) == b"\x53\xef":
        return Ext4(image)
    raise FUSError(f"unknown filesystem in {partition}; expected EROFS, F2FS, or ext4")


def extract_files(
    image: ReadableImage,
    partition: str,
    paths: tuple[str, ...],
    output: str | os.PathLike[str],
    on_progress: Callable[[int, int], None] | None = None,
) -> tuple[Path, ...]:
    group_partition_paths(paths, partition)
    fs = _open_filesystem(image, partition)
    root = Path(output).expanduser()
    if root.exists() and not root.is_dir():
        raise FUSError(f"file extraction output must be a directory: {root}")
    selected = []
    for requested in paths:
        path = requested[len(partition) + 2 :]
        try:
            inode = fs.find(path)
        except FUSError as first_error:
            if "file not found" not in str(first_error):
                raise
            # System-as-root images keep /system inside the filesystem itself.
            try:
                inode = fs.find(f"{partition}/{path}")
            except FUSError:
                raise first_error from None
        selected.append((path, inode))
    root.mkdir(parents=True, exist_ok=True)
    root = root.resolve()
    total = sum(inode.size for _, inode in selected)
    done = 0
    last_report = 0
    if on_progress is not None:
        on_progress(0, total)
    destinations = []
    for path, inode in selected:
        destination = root / partition / path
        directory = root
        for component in (partition, *PurePosixPath(path).parts[:-1]):
            directory = directory / component
            if directory.is_symlink():
                raise FUSError(f"output path contains a symbolic link: {directory}")
            directory.mkdir(exist_ok=True)
        temporary = destination.with_name(destination.name + ".asgard.part")
        try:
            with temporary.open("wb") as result:
                for chunk in fs.iter_file(inode):
                    result.write(chunk)
                    done += len(chunk)
                    if on_progress is not None and (done - last_report >= 1024 * 1024 or done >= total):
                        on_progress(done, total)
                        last_report = done
            temporary.replace(destination)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        destinations.append(destination)
    if on_progress is not None and done != last_report:
        on_progress(done, total)
    return tuple(destinations)
