# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import hashlib
import io
import os
import tarfile
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from pathlib import Path
from typing import BinaryIO

from ..core.constants import (
    _HASH_CHUNK_SIZE,
    _HASH_PARALLEL_MIN_SIZE,
    _SPARSE_CHUNK_HEADER,
    _SPARSE_CRC32,
    _SPARSE_DONT_CARE,
    _SPARSE_FILL,
    _SPARSE_HEADER,
    _SPARSE_MAGIC,
    _SPARSE_RAW,
)
from ..core.errors import FUSError


def _hash_file(path: Path) -> tuple[str, str]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)
    with path.open("rb") as source:
        prefix = source.read(io.DEFAULT_BUFFER_SIZE)
        sha256.update(prefix)
        md5.update(prefix)
        if len(prefix) < io.DEFAULT_BUFFER_SIZE:
            return sha256.hexdigest(), md5.hexdigest()
        size = os.fstat(source.fileno()).st_size
        buffer = bytearray(min(_HASH_CHUNK_SIZE, max(1, size)))
        view = memoryview(buffer)
        pool = ThreadPoolExecutor(max_workers=1) if size >= _HASH_PARALLEL_MIN_SIZE else nullcontext()
        with pool as executor:
            while size := source.readinto(buffer):
                chunk = view[:size]
                if executor is None:
                    sha256.update(chunk)
                    md5.update(chunk)
                else:
                    pending = executor.submit(sha256.update, chunk)
                    md5.update(chunk)
                    pending.result()
    return sha256.hexdigest(), md5.hexdigest()


def _skip_exact(source: BinaryIO, size: int, description: str, *, file_size: int) -> None:
    if size < 0 or size > file_size - source.tell():
        raise FUSError(f"unexpected end of {description}")
    source.seek(size, os.SEEK_CUR)


def _verify_sparse(path: Path) -> dict[str, object] | None:
    with path.open("rb") as source:
        file_size = os.fstat(source.fileno()).st_size
        prefix = source.read(_SPARSE_HEADER.size)
        if len(prefix) < 4 or int.from_bytes(prefix[:4], "little") != _SPARSE_MAGIC:
            return None
        if len(prefix) != _SPARSE_HEADER.size:
            raise FUSError("truncated Android sparse header")
        magic, major, minor, file_header_size, chunk_header_size, block_size, total_blocks, total_chunks, checksum = (
            _SPARSE_HEADER.unpack(prefix)
        )
        if (
            magic != _SPARSE_MAGIC
            or major != 1
            or file_header_size < _SPARSE_HEADER.size
            or chunk_header_size < _SPARSE_CHUNK_HEADER.size
            or block_size <= 0
        ):
            raise FUSError("invalid Android sparse header")
        _skip_exact(source, file_header_size - _SPARSE_HEADER.size, "sparse file header", file_size=file_size)
        produced_blocks = 0
        for index in range(total_chunks):
            raw = source.read(chunk_header_size)
            if len(raw) != chunk_header_size:
                raise FUSError(f"truncated sparse chunk {index + 1}")
            chunk_type, _reserved, chunk_blocks, total_size = _SPARSE_CHUNK_HEADER.unpack_from(raw)
            payload_size = total_size - chunk_header_size
            expected = {
                _SPARSE_RAW: chunk_blocks * block_size,
                _SPARSE_FILL: 4,
                _SPARSE_DONT_CARE: 0,
                _SPARSE_CRC32: 4,
            }.get(chunk_type)
            if expected is None or payload_size != expected:
                raise FUSError(f"invalid sparse chunk {index + 1}")
            _skip_exact(source, payload_size, f"sparse chunk {index + 1}", file_size=file_size)
            if chunk_type != _SPARSE_CRC32:
                produced_blocks += chunk_blocks
        if produced_blocks != total_blocks or source.read(1):
            raise FUSError("sparse image size or trailing data is invalid")
        return {
            "format": "android-sparse",
            "version": f"{major}.{minor}",
            "block_size": block_size,
            "blocks": total_blocks,
            "raw_size": total_blocks * block_size,
            "chunks": total_chunks,
            "checksum": checksum,
        }


def verify_file(path_value: str | Path, *, include_entries: bool = True) -> dict[str, object]:
    path = Path(path_value).expanduser()
    if not path.is_file():
        raise FileNotFoundError(path)
    result: dict[str, object] = {
        "path": str(path.resolve()),
        "size": path.stat().st_size,
        "valid": True,
    }
    sha256, md5 = _hash_file(path)
    result.update({"sha256": sha256, "md5": md5})

    sparse = _verify_sparse(path)
    if sparse is not None:
        result.update(sparse)
        return result

    if zipfile.is_zipfile(path):
        result["format"] = "zip"
        try:
            with zipfile.ZipFile(path) as archive:
                bad = archive.testzip()
                if bad is not None:
                    raise FUSError(f"ZIP CRC failed for {bad!r}")
                members = [item for item in archive.infolist() if not item.is_dir()]
                result["entry_count"] = len(members)
                if include_entries:
                    result["entries"] = [
                        {
                            "name": item.filename,
                            "size": item.file_size,
                            "compressed_size": item.compress_size,
                            "crc32": f"{item.CRC:08x}",
                        }
                        for item in members
                    ]
        except zipfile.BadZipFile as exc:
            raise FUSError(f"invalid ZIP: {exc}") from exc
        return result

    try:
        is_tar = tarfile.is_tarfile(path)
    except OSError:
        is_tar = False
    if is_tar:
        result["format"] = "tar"
        try:
            with tarfile.open(path, "r:*") as archive:
                members = [item for item in archive if item.isfile()]
                result["entry_count"] = len(members)
                if include_entries:
                    result["entries"] = [{"name": item.name, "size": item.size} for item in members]
        except tarfile.TarError as exc:
            raise FUSError(f"invalid TAR: {exc}") from exc
        return result

    suffix = path.suffix.lower()
    if suffix in {".enc2", ".enc4"}:
        if path.stat().st_size <= 0 or path.stat().st_size % 16:
            raise FUSError("encrypted FUS package size is not AES-block aligned")
        result["format"] = suffix[1:]
        result["encrypted"] = True
    else:
        result["format"] = "binary"
    return result


def write_manifest(
    path_value: str | Path,
    output: str | Path | None = None,
    *,
    metadata: dict[str, object] | None = None,
) -> tuple[Path, dict[str, object]]:
    import json

    source = Path(path_value).expanduser()
    manifest = verify_file(source, include_entries=True)
    manifest["manifest_version"] = 1
    if metadata:
        manifest.update(metadata)
    basename = source.name.casefold()
    if basename in {"super.img", "super.img.lz4"}:
        from .images import list_super_partitions

        with source.open("rb") as image_source:
            partitions = list_super_partitions(image_source, source.name, source.stat().st_size)
        manifest["partitions"] = [{"name": partition.name, "size": partition.size} for partition in partitions]
    output_path = Path(output).expanduser() if output else source.with_name(f"{source.name}.manifest.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(f"{output_path.name}.tmp")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output_path)
    return output_path, manifest
