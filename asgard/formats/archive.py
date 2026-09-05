# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import fnmatch
import hashlib
import io
import json
import os
import secrets
import struct
import tarfile
import zipfile
import zlib
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Iterator, TypeVar

from .. import fus as _fus
from ..cli.progress import format_bytes, print_info
from ..core.constants import (
    _ARCHIVE_COPY_CHUNK_SIZE,
    _TAR_INDEX_MEMBER_BUFFER_SIZE,
    _TAR_INDEX_SCAN_BUFFER_SIZE,
    _TAR_INDEX_SPACING,
    _TAR_INDEX_VERSION,
)
from ..core.errors import FUSError, StreamSourceError
from ..core.streaming import copy_stream_with_progress, open_prefetched_stream
from .images import (
    FirmwareSuperPartition,
    copy_image_stream,
    copy_lz4_stream,
    extract_super_partitions,
    list_super_partitions,
)

__all__ = [
    "FirmwareArchiveEntry",
    "FirmwareArchiveListing",
    "FirmwareSuperPartition",
    "FirmwareTarEntry",
    "download_firmware_entries",
    "download_firmware_super_partitions",
    "download_firmware_tar_member",
    "iter_firmware_super_partitions",
    "iter_firmware_tar_entries",
    "list_firmware_entries",
]

_ZIP_LOCAL_FILE_HEADER = struct.Struct("<I5H3I2H")
_ZIP_LOCAL_FILE_HEADER_SIGNATURE = 0x04034B50
_GZIP_HEADER = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff"
_T = TypeVar("_T")


@dataclass(frozen=True)
class FirmwareArchiveEntry:
    name: str
    size: int
    compressed_size: int


@dataclass(frozen=True)
class FirmwareArchiveListing:
    firmware_version: str
    filename: str
    size: int
    entries: tuple[FirmwareArchiveEntry, ...]


@dataclass(frozen=True)
class FirmwareTarEntry:
    name: str
    size: int


@dataclass(frozen=True)
class _IndexedTarMember:
    name: str
    size: int
    offset_data: int


@dataclass(frozen=True)
class _TarIndexCache:
    complete: bool
    members: tuple[_IndexedTarMember, ...]
    index_path: Path


class _FileWithoutFileno:
    def __init__(self, source: io.BufferedIOBase):
        self._source = source

    def fileno(self) -> int:
        raise io.UnsupportedOperation("fileno")

    def __getattr__(self, name: str) -> object:
        return getattr(self._source, name)


@dataclass
class _RemoteFirmwareArchive:
    model: str
    region: str
    info: _fus.BinaryInfo
    firmware_version: str
    reader: _fus._FUSDecryptingReader
    archive: zipfile.ZipFile


@contextmanager
def _open_remote_firmware_archive(
    *,
    model: str,
    region: str,
    firmware_version: str | None = None,
    timeout_s: int = 30,
    rate_limit: int | None = None,
) -> Iterator[_RemoteFirmwareArchive]:
    model_u, region_u = _fus._device_codes(model, region)
    client = _fus.FUSClient(timeout_s=timeout_s)
    try:
        info = _fus._resolve_versioned_info(client, model_u, region_u, firmware_version)
        firmware = info.binary_version or ""
        if not firmware:
            raise FUSError("FUS did not return a firmware version")

        _fus.initialize_download(client, info, region_u)
        remote_path = f"{info.model_path}{info.filename}"

        def recover_download() -> None:
            client.refresh_auth()
            _fus.initialize_download(client, info, region_u)

        reader = _fus._FUSDecryptingReader(
            client=client,
            remote_path=remote_path,
            encrypted_size=info.size,
            key=_fus._decryption_key_from_info(info, model_u, region_u),
            recover_download=recover_download,
            stream_chunk_size=_ARCHIVE_COPY_CHUNK_SIZE,
            rate_limiter=_fus.BandwidthLimiter(rate_limit),
        )
    except Exception:
        client.session.close()
        raise
    try:
        archive = zipfile.ZipFile(reader)
    except zipfile.BadZipFile as exc:
        reader.close()
        client.session.close()
        raise FUSError(f"decrypted firmware is not a valid ZIP archive: {exc}") from exc
    except Exception:
        reader.close()
        client.session.close()
        raise

    try:
        yield _RemoteFirmwareArchive(
            model=model_u,
            region=region_u,
            info=info,
            firmware_version=firmware,
            reader=reader,
            archive=archive,
        )
    finally:
        try:
            archive.close()
        finally:
            try:
                reader.close()
            finally:
                client.session.close()


def list_firmware_entries(
    *,
    model: str,
    region: str,
    firmware_version: str | None = None,
    timeout_s: int = 30,
    rate_limit: int | None = None,
) -> FirmwareArchiveListing:
    with _open_remote_firmware_archive(
        model=model,
        region=region,
        firmware_version=firmware_version,
        timeout_s=timeout_s,
        rate_limit=rate_limit,
    ) as remote:
        entries = tuple(
            FirmwareArchiveEntry(
                name=entry.filename,
                size=entry.file_size,
                compressed_size=entry.compress_size,
            )
            for entry in remote.archive.infolist()
            if not entry.is_dir()
        )
        return FirmwareArchiveListing(
            firmware_version=remote.firmware_version,
            filename=remote.info.filename,
            size=remote.info.size,
            entries=entries,
        )


def _entry_matches_selector(entry: zipfile.ZipInfo, selector: str) -> bool:
    normalized_selector = str(selector or "").strip().replace("\\", "/")
    if not normalized_selector:
        raise ValueError("entry selector cannot be empty")
    name = entry.filename.replace("\\", "/")
    basename = PurePosixPath(name).name
    selector_lower = normalized_selector.casefold()
    name_lower = name.casefold()
    basename_lower = basename.casefold()
    if name_lower == selector_lower or basename_lower == selector_lower:
        return True
    if any(character in normalized_selector for character in "*?["):
        return fnmatch.fnmatchcase(name_lower, selector_lower) or fnmatch.fnmatchcase(basename_lower, selector_lower)
    return name_lower.startswith(f"{selector_lower}_") or basename_lower.startswith(f"{selector_lower}_")


def _select_firmware_entries(
    entries: list[zipfile.ZipInfo],
    selectors: tuple[str, ...],
) -> list[zipfile.ZipInfo]:
    files = [entry for entry in entries if not entry.is_dir()]
    selected_offsets: set[int] = set()
    selected: list[zipfile.ZipInfo] = []
    unmatched: list[str] = []
    for selector in selectors:
        matches = [entry for entry in files if _entry_matches_selector(entry, selector)]
        if not matches:
            unmatched.append(selector)
            continue
        for entry in matches:
            if entry.header_offset in selected_offsets:
                continue
            selected_offsets.add(entry.header_offset)
            selected.append(entry)
    if unmatched:
        available = ", ".join(entry.filename for entry in files)
        raise FUSError(
            f"no archive entry matched {', '.join(repr(selector) for selector in unmatched)}"
            + (f"; available entries: {available}" if available else "")
        )
    return selected


def _select_single_firmware_entry(entries: list[zipfile.ZipInfo], selector: str) -> zipfile.ZipInfo:
    selected = _select_firmware_entries(entries, (selector,))
    if len(selected) != 1:
        names = ", ".join(entry.filename for entry in selected)
        raise FUSError(f"archive selector {selector!r} matched multiple entries: {names}")
    return selected[0]


class _VirtualGzipReader(io.RawIOBase):
    def __init__(
        self,
        source: _fus._FUSDecryptingReader,
        *,
        data_offset: int,
        compressed_size: int,
        crc: int,
        uncompressed_size: int,
    ):
        super().__init__()
        self._source = source
        self._data_offset = data_offset
        self._compressed_size = compressed_size
        self._footer = struct.pack("<II", crc, uncompressed_size & 0xFFFFFFFF)
        self._size = len(_GZIP_HEADER) + compressed_size + len(self._footer)
        self._position = 0

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
        self._position = min(target, self._size)
        return self._position

    def read(self, size: int = -1) -> bytes:
        self._checkClosed()
        if self._position >= self._size or size == 0:
            return b""
        remaining = self._size - self._position
        amount = remaining if size is None or size < 0 else min(int(size), remaining)
        chunks: list[bytes] = []

        header_end = len(_GZIP_HEADER)
        data_end = header_end + self._compressed_size
        while amount:
            if self._position < header_end:
                take = min(amount, header_end - self._position)
                chunks.append(_GZIP_HEADER[self._position : self._position + take])
            elif self._position < data_end:
                take = min(amount, data_end - self._position)
                source_offset = self._data_offset + self._position - header_end
                self._source.seek(source_offset)
                chunk = self._source.read(take)
                if len(chunk) != take:
                    raise FUSError("unexpected end of compressed firmware entry")
                chunks.append(chunk)
            else:
                footer_offset = self._position - data_end
                take = min(amount, len(self._footer) - footer_offset)
                chunks.append(self._footer[footer_offset : footer_offset + take])
            self._position += take
            amount -= take

        return b"".join(chunks)


class _BoundedReader(io.RawIOBase):
    def __init__(self, source: io.BufferedIOBase, size: int):
        super().__init__()
        self._source = source
        self._remaining = size

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: bytearray | memoryview) -> int:
        self._checkClosed()
        if self._remaining <= 0:
            return 0
        view = memoryview(buffer)
        amount = min(len(view), self._remaining)
        if not amount:
            return 0
        try:
            received = self._source.readinto(view[:amount])
        except Exception as exc:
            if exc.__class__.__module__.partition(".")[0] == "indexed_gzip" or isinstance(
                exc,
                (EOFError, ValueError, zlib.error),
            ):
                raise StreamSourceError from exc
            raise
        if not isinstance(received, int) or not 0 < received <= amount:
            raise StreamSourceError
        self._remaining -= received
        return received


def _zip_entry_data_offset(remote: _RemoteFirmwareArchive, entry: zipfile.ZipInfo) -> int:
    remote.reader.seek(entry.header_offset)
    header = remote.reader.read(_ZIP_LOCAL_FILE_HEADER.size)
    if len(header) != _ZIP_LOCAL_FILE_HEADER.size:
        raise FUSError(f"could not read ZIP header for {entry.filename!r}")
    (
        signature,
        _extract_version,
        flags,
        compression,
        _modified_time,
        _modified_date,
        _crc,
        _compressed_size,
        _uncompressed_size,
        filename_size,
        extra_size,
    ) = _ZIP_LOCAL_FILE_HEADER.unpack(header)
    if signature != _ZIP_LOCAL_FILE_HEADER_SIGNATURE:
        raise FUSError(f"invalid ZIP header for {entry.filename!r}")
    if flags & 1:
        raise FUSError(f"encrypted ZIP entry is not supported: {entry.filename!r}")
    if compression != entry.compress_type:
        raise FUSError(f"ZIP compression metadata does not match for {entry.filename!r}")
    return entry.header_offset + _ZIP_LOCAL_FILE_HEADER.size + filename_size + extra_size


def _tar_index_identity(
    remote: _RemoteFirmwareArchive,
    outer_entry: zipfile.ZipInfo,
) -> dict[str, int | str]:
    return {
        "firmware": remote.firmware_version,
        "firmware_file": remote.info.filename,
        "entry": outer_entry.filename,
        "header_offset": outer_entry.header_offset,
        "crc": outer_entry.CRC,
        "compressed_size": outer_entry.compress_size,
        "size": outer_entry.file_size,
    }


def _tar_index_paths(
    remote: _RemoteFirmwareArchive,
    outer_entry: zipfile.ZipInfo,
) -> tuple[Path, Path, dict[str, int | str]]:
    identity = _tar_index_identity(remote, outer_entry)
    cache_key = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    cache_home = os.environ.get("XDG_CACHE_HOME")
    cache_root = Path(cache_home).expanduser() if cache_home else Path.home() / ".cache"
    cache_dir = cache_root / "asgard" / "tar-index"
    return cache_dir / f"{cache_key}.json", cache_dir / f"{cache_key}.gzidx", identity


def _load_tar_index(
    remote: _RemoteFirmwareArchive,
    outer_entry: zipfile.ZipInfo,
) -> _TarIndexCache | None:
    metadata_path, index_path, identity = _tar_index_paths(remote, outer_entry)
    if not metadata_path.is_file() or not index_path.is_file():
        return None
    try:
        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
        if (
            payload.get("version") != _TAR_INDEX_VERSION
            or payload.get("identity") != identity
            or not isinstance(payload.get("complete"), bool)
            or not isinstance(payload.get("members"), list)
            or index_path.stat().st_size <= 0
        ):
            return None
        members: list[_IndexedTarMember] = []
        for raw_member in payload["members"]:
            if not isinstance(raw_member, dict):
                return None
            name = raw_member.get("name")
            size = raw_member.get("size")
            offset_data = raw_member.get("offset_data")
            if (
                not isinstance(name, str)
                or not name
                or not isinstance(size, int)
                or size < 0
                or not isinstance(offset_data, int)
                or offset_data < 0
                or offset_data + size > outer_entry.file_size
            ):
                return None
            members.append(_IndexedTarMember(name=name, size=size, offset_data=offset_data))
        return _TarIndexCache(
            complete=payload["complete"],
            members=tuple(members),
            index_path=index_path,
        )
    except (OSError, TypeError, ValueError):
        return None


def _indexed_progress(members: tuple[_IndexedTarMember, ...] | list[_IndexedTarMember]) -> int:
    return max((member.offset_data + member.size for member in members), default=0)


def _prefer_indexed_member(member: _IndexedTarMember) -> bool:
    buffer_size = min(
        _TAR_INDEX_MEMBER_BUFFER_SIZE,
        max(_ARCHIVE_COPY_CHUNK_SIZE, member.size),
    )
    buffer_count = max(1, (member.size + buffer_size - 1) // buffer_size)
    return member.offset_data > buffer_count * _TAR_INDEX_SPACING


def _discard_tar_index(remote: _RemoteFirmwareArchive, outer_entry: zipfile.ZipInfo) -> None:
    metadata_path, index_path, _identity = _tar_index_paths(remote, outer_entry)
    for path in (metadata_path, index_path):
        with suppress(OSError):
            path.unlink(missing_ok=True)


def _save_tar_index(
    remote: _RemoteFirmwareArchive,
    outer_entry: zipfile.ZipInfo,
    indexed_source: object,
    members: list[_IndexedTarMember],
    *,
    complete: bool,
) -> None:
    if not complete and not members:
        return
    metadata_path, index_path, identity = _tar_index_paths(remote, outer_entry)
    existing = _load_tar_index(remote, outer_entry)
    if existing is not None and (
        existing.complete or (not complete and _indexed_progress(existing.members) >= _indexed_progress(members))
    ):
        return

    suffix = f".{secrets.token_hex(8)}.tmp"
    metadata_tmp = metadata_path.with_name(f"{metadata_path.name}{suffix}")
    index_tmp = index_path.with_name(f"{index_path.name}{suffix}")
    try:
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": _TAR_INDEX_VERSION,
            "identity": identity,
            "complete": complete,
            "members": [
                {
                    "name": member.name,
                    "size": member.size,
                    "offset_data": member.offset_data,
                }
                for member in members
            ],
        }
        serialized_metadata = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        with index_tmp.open("wb") as index_output, metadata_tmp.open("w", encoding="utf-8") as metadata_output:
            indexed_source.export_index(fileobj=_FileWithoutFileno(index_output))
            metadata_output.write(serialized_metadata)
        index_tmp.replace(index_path)
        metadata_tmp.replace(metadata_path)
    except Exception:
        pass
    finally:
        for path in (metadata_tmp, index_tmp):
            with suppress(OSError):
                path.unlink(missing_ok=True)


@contextmanager
def _open_indexed_firmware_entry(
    remote: _RemoteFirmwareArchive,
    outer_entry: zipfile.ZipInfo,
    *,
    index_path: Path | None = None,
    buffer_size: int | None = None,
) -> Iterator[io.BufferedIOBase]:
    try:
        import indexed_gzip
    except ImportError as exc:
        raise FUSError("indexed DEFLATE support is not installed; reinstall asgard") from exc

    virtual_source = _VirtualGzipReader(
        remote.reader,
        data_offset=_zip_entry_data_offset(remote, outer_entry),
        compressed_size=outer_entry.compress_size,
        crc=outer_entry.CRC,
        uncompressed_size=outer_entry.file_size,
    )
    indexed_source = indexed_gzip.IndexedGzipFile(
        fileobj=virtual_source,
        spacing=_TAR_INDEX_SPACING,
        readbuf_size=_ARCHIVE_COPY_CHUNK_SIZE,
        readall_buf_size=_ARCHIVE_COPY_CHUNK_SIZE,
        buffer_size=buffer_size or _TAR_INDEX_SCAN_BUFFER_SIZE,
    )
    try:
        if index_path is not None:
            try:
                with index_path.open("rb") as index_input:
                    indexed_source.import_index(fileobj=_FileWithoutFileno(index_input))
            except Exception as exc:
                raise StreamSourceError from exc
        yield indexed_source
    finally:
        indexed_source.close()
        virtual_source.close()


@contextmanager
def _open_cached_tar_member(
    remote: _RemoteFirmwareArchive,
    outer_entry: zipfile.ZipInfo,
    cached_member: _IndexedTarMember,
    index_path: Path,
) -> Iterator[io.BufferedReader]:
    buffer_size = min(
        _TAR_INDEX_MEMBER_BUFFER_SIZE,
        max(_ARCHIVE_COPY_CHUNK_SIZE, cached_member.size),
    )
    with _open_indexed_firmware_entry(
        remote,
        outer_entry,
        index_path=index_path,
        buffer_size=buffer_size,
    ) as indexed_source:
        try:
            header_offset = cached_member.offset_data - tarfile.BLOCKSIZE
            if header_offset < 0 or cached_member.offset_data % tarfile.BLOCKSIZE:
                raise StreamSourceError
            indexed_source.seek(header_offset)
            header = indexed_source.read(tarfile.BLOCKSIZE)
            if len(header) != tarfile.BLOCKSIZE:
                raise StreamSourceError
            tar_info = tarfile.TarInfo.frombuf(header, encoding="utf-8", errors="surrogateescape")
            if tar_info.name != cached_member.name or tar_info.size != cached_member.size or not tar_info.isfile():
                raise StreamSourceError
        except StreamSourceError:
            raise
        except Exception as exc:
            raise StreamSourceError from exc
        bounded = _BoundedReader(indexed_source, cached_member.size)
        source = io.BufferedReader(bounded, buffer_size=64 * 1024)
        try:
            yield source
        finally:
            source.close()


@contextmanager
def _open_firmware_tar(
    remote: _RemoteFirmwareArchive,
    outer_entry: zipfile.ZipInfo,
) -> Iterator[tarfile.TarFile]:
    with remote.archive.open(outer_entry, "r") as source:
        mode = "r:" if outer_entry.compress_type == zipfile.ZIP_STORED else "r|"
        try:
            archive = tarfile.open(fileobj=source, mode=mode)
        except tarfile.TarError as exc:
            raise FUSError(f"archive entry {outer_entry.filename!r} is not a readable TAR: {exc}") from exc
        try:
            yield archive
        finally:
            archive.close()


def iter_firmware_tar_entries(
    *,
    model: str,
    region: str,
    outer_selector: str,
    firmware_version: str | None = None,
    timeout_s: int = 30,
    rate_limit: int | None = None,
) -> Iterator[FirmwareTarEntry]:
    with _open_remote_firmware_archive(
        model=model,
        region=region,
        firmware_version=firmware_version,
        timeout_s=timeout_s,
        rate_limit=rate_limit,
    ) as remote:
        outer_entry = _select_single_firmware_entry(remote.archive.infolist(), outer_selector)
        if outer_entry.compress_type == zipfile.ZIP_DEFLATED:
            cached = _load_tar_index(remote, outer_entry)
            if cached is not None and cached.complete:
                for member in cached.members:
                    yield FirmwareTarEntry(name=member.name, size=member.size)
                return

            small_archive = outer_entry.file_size <= _TAR_INDEX_MEMBER_BUFFER_SIZE
            scan_buffer_size = (
                max(_ARCHIVE_COPY_CHUNK_SIZE, outer_entry.file_size) if small_archive else _TAR_INDEX_SCAN_BUFFER_SIZE
            )
            cache_attempt = cached
            while True:
                indexed_members: list[_IndexedTarMember] = []
                scan_complete = False
                try:
                    with _open_indexed_firmware_entry(
                        remote,
                        outer_entry,
                        index_path=cache_attempt.index_path if cache_attempt is not None else None,
                        buffer_size=scan_buffer_size,
                    ) as indexed_source:
                        tar_mode = "r|" if small_archive and cache_attempt is None else "r:"
                        try:
                            archive = tarfile.open(fileobj=indexed_source, mode=tar_mode)
                        except tarfile.TarError as exc:
                            if cache_attempt is not None:
                                raise StreamSourceError from exc
                            raise FUSError(
                                f"archive entry {outer_entry.filename!r} is not a readable TAR: {exc}"
                            ) from exc
                        try:
                            for member in archive:
                                if not member.isfile():
                                    continue
                                indexed_member = _IndexedTarMember(
                                    name=member.name,
                                    size=member.size,
                                    offset_data=member.offset_data,
                                )
                                indexed_members.append(indexed_member)
                                yield FirmwareTarEntry(name=member.name, size=member.size)
                            while indexed_source.read(_ARCHIVE_COPY_CHUNK_SIZE):
                                pass
                            scan_complete = True
                        finally:
                            archive.close()
                            _save_tar_index(
                                remote,
                                outer_entry,
                                indexed_source,
                                indexed_members,
                                complete=scan_complete,
                            )
                    return
                except StreamSourceError:
                    if cache_attempt is None:
                        raise FUSError(f"cached TAR index for {outer_entry.filename!r} could not be read")
                    _discard_tar_index(remote, outer_entry)
                    cache_attempt = None
                except FUSError:
                    raise
                except Exception as exc:
                    raise FUSError(f"could not read TAR entry {outer_entry.filename!r}: {exc}") from exc

        try:
            with _open_firmware_tar(remote, outer_entry) as archive:
                for member in archive:
                    if member.isfile():
                        yield FirmwareTarEntry(name=member.name, size=member.size)
        except FUSError:
            raise
        except Exception as exc:
            raise FUSError(f"could not read TAR entry {outer_entry.filename!r}: {exc}") from exc


def _entry_output_path(output_dir: Path, entry_name: str) -> Path:
    filename = PurePosixPath(str(entry_name or "").replace("\\", "/")).name
    if not filename or filename in {".", ".."}:
        raise FUSError(f"invalid archive entry name: {entry_name!r}")
    return output_dir / filename


def _discard_stream(source: io.BufferedIOBase, size: int, description: str) -> None:
    remaining = size
    while remaining:
        chunk = source.read(min(remaining, _ARCHIVE_COPY_CHUNK_SIZE))
        if not chunk:
            raise FUSError(f"unexpected end while resuming {description}")
        remaining -= len(chunk)


def _copy_resumable_source(
    source: io.BufferedIOBase,
    part_path: Path,
    *,
    total_size: int,
    label: str,
) -> None:
    initial_size = part_path.stat().st_size if part_path.is_file() else 0
    if initial_size > total_size:
        raise FUSError(f"resume source is larger than expected: {part_path}")
    if initial_size == total_size:
        return
    if initial_size:
        _discard_stream(source, initial_size, label)
    mode = "ab" if initial_size else "xb"
    with part_path.open(mode) as output:
        done = copy_stream_with_progress(
            source,
            output,
            label=label,
            total_size=total_size,
            initial_done=initial_size,
        )
    if done != total_size:
        raise FUSError(f"incomplete {label.lower()}: expected {total_size} bytes, got {done}")


def _write_firmware_tar_member(
    source: io.BufferedIOBase,
    part_path: Path,
    *,
    requested_name: str,
    output_name: str,
    member_size: int,
    keep_sparse: bool,
) -> None:
    with part_path.open("xb") as output:
        label = f"Extracting {PurePosixPath(output_name).name}"
        if requested_name.lower().endswith(".lz4"):
            copy_lz4_stream(source, output, label=label, keep_sparse=keep_sparse)
        else:
            with open_prefetched_stream(source) as prefetched:
                copy_image_stream(
                    prefetched,
                    output,
                    label=label,
                    total_size=member_size,
                    keep_sparse=keep_sparse,
                )


def download_firmware_tar_member(
    *,
    model: str,
    region: str,
    outer_selector: str,
    member_name: str,
    out_dir: str | os.PathLike[str],
    firmware_version: str | None = None,
    keep_sparse: bool = False,
    resume: bool = False,
    timeout_s: int = 30,
    rate_limit: int | None = None,
) -> Path:
    requested_name = str(member_name or "").strip().replace("\\", "/")
    if not requested_name:
        raise ValueError("TAR member name is required")
    output_name = requested_name[:-4] if requested_name.lower().endswith(".lz4") else requested_name
    output_dir = Path(out_dir).expanduser()
    if output_dir.exists() and not output_dir.is_dir():
        raise FUSError(f"member output must be a directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = _entry_output_path(output_dir.resolve(), output_name)
    part_path = _fus._partial_output_path(destination)
    source_part_path: Path | None = None
    if destination.exists() and resume:
        return destination
    if destination.exists():
        raise FUSError(f"{destination} already exists")
    if part_path.exists() and not resume:
        raise FUSError(f"{part_path} already exists")

    with _open_remote_firmware_archive(
        model=model,
        region=region,
        firmware_version=firmware_version,
        timeout_s=timeout_s,
        rate_limit=rate_limit,
    ) as remote:
        outer_entry = _select_single_firmware_entry(remote.archive.infolist(), outer_selector)
        print_info(f"model: {remote.model}")
        print_info(f"region: {remote.region}")
        print_info(f"firmware: {remote.firmware_version}")
        print_info(f"archive: {outer_entry.filename}")
        print_info(f"member: {requested_name}")
        print_info(f"output: {destination}")

        output_complete = False
        try:

            def write_member(member_source: io.BufferedIOBase, member_size: int) -> None:
                nonlocal source_part_path
                if not resume:
                    _write_firmware_tar_member(
                        member_source,
                        part_path,
                        requested_name=requested_name,
                        output_name=output_name,
                        member_size=member_size,
                        keep_sparse=keep_sparse,
                    )
                    return
                source_part_path = destination.with_name(f".{destination.name}.{member_size}.asgard-source.part")
                _copy_resumable_source(
                    member_source,
                    source_part_path,
                    total_size=member_size,
                    label=f"Caching {PurePosixPath(requested_name).name}",
                )
                part_path.unlink(missing_ok=True)
                with source_part_path.open("rb") as local_source:
                    _write_firmware_tar_member(
                        local_source,
                        part_path,
                        requested_name=requested_name,
                        output_name=output_name,
                        member_size=member_size,
                        keep_sparse=keep_sparse,
                    )

            member_copied = False
            cached: _TarIndexCache | None = None
            cached_member: _IndexedTarMember | None = None
            if outer_entry.compress_type == zipfile.ZIP_DEFLATED:
                cached = _load_tar_index(remote, outer_entry)
                cached_member = (
                    next(
                        (member for member in cached.members if member.name == requested_name),
                        None,
                    )
                    if cached is not None
                    else None
                )
                if cached_member is not None and _prefer_indexed_member(cached_member):
                    try:
                        with _open_cached_tar_member(
                            remote,
                            outer_entry,
                            cached_member,
                            cached.index_path,
                        ) as member_source:
                            write_member(member_source, cached_member.size)
                        member_copied = True
                    except StreamSourceError:
                        part_path.unlink(missing_ok=True)
                        _discard_tar_index(remote, outer_entry)

            if not member_copied:
                if cached is not None and cached.complete and cached_member is None:
                    raise FUSError(f"TAR member not found: {requested_name}")

                with _open_firmware_tar(remote, outer_entry) as archive:
                    for member in archive:
                        if member.name != requested_name:
                            continue
                        if not member.isfile():
                            raise FUSError(f"TAR member is not a regular file: {requested_name}")
                        member_source = archive.extractfile(member)
                        if member_source is None:
                            raise FUSError(f"could not open TAR member: {requested_name}")
                        with member_source:
                            write_member(member_source, member.size)
                        member_copied = True
                        break

            if not member_copied:
                raise FUSError(f"TAR member not found: {requested_name}")
            if destination.exists():
                raise FUSError(f"{destination} already exists")
            part_path.replace(destination)
            if source_part_path is not None:
                source_part_path.unlink(missing_ok=True)
            output_complete = True
            return destination
        except FUSError:
            raise
        except Exception as exc:
            raise FUSError(f"could not extract TAR member {requested_name!r}: {exc}") from exc
        finally:
            if not output_complete:
                part_path.unlink(missing_ok=True)


def _super_member_rank(name: str) -> int | None:
    basename = PurePosixPath(name.replace("\\", "/")).name.casefold()
    if basename == "super.img.lz4":
        return 0
    if basename == "super.img":
        return 1
    return None


def _select_cached_super_member(members: tuple[_IndexedTarMember, ...]) -> _IndexedTarMember | None:
    matches = [(rank, member) for member in members if (rank := _super_member_rank(member.name)) is not None]
    if not matches:
        return None
    best_rank = min(rank for rank, _member in matches)
    best = [member for rank, member in matches if rank == best_rank]
    if len(best) != 1:
        raise FUSError("selected archive contains multiple super images: " + ", ".join(m.name for m in best))
    return best[0]


def _run_super_member_operation(
    remote: _RemoteFirmwareArchive,
    outer_entry: zipfile.ZipInfo,
    operation: Callable[[io.BufferedIOBase, str, int], _T],
    *,
    prefer_cached: bool,
) -> _T:
    cached: _TarIndexCache | None = None
    cached_member: _IndexedTarMember | None = None
    if outer_entry.compress_type == zipfile.ZIP_DEFLATED:
        cached = _load_tar_index(remote, outer_entry)
        cached_member = _select_cached_super_member(cached.members) if cached is not None else None
        if cached_member is not None and (prefer_cached or _prefer_indexed_member(cached_member)):
            try:
                with _open_cached_tar_member(
                    remote,
                    outer_entry,
                    cached_member,
                    cached.index_path,
                ) as source:
                    return operation(source, cached_member.name, cached_member.size)
            except StreamSourceError:
                _discard_tar_index(remote, outer_entry)
                cached = None
        if cached is not None and cached.complete and cached_member is None:
            available = ", ".join(member.name for member in cached.members)
            raise FUSError(
                "selected archive does not contain super.img or super.img.lz4"
                + (f"; available files: {available}" if available else "")
            )

    available: list[str] = []
    try:
        with _open_firmware_tar(remote, outer_entry) as archive:
            for member in archive:
                if not member.isfile():
                    continue
                available.append(member.name)
                if _super_member_rank(member.name) is None:
                    continue
                source = archive.extractfile(member)
                if source is None:
                    raise FUSError(f"could not open TAR member: {member.name}")
                with source:
                    return operation(source, member.name, member.size)
    except FUSError:
        raise
    except Exception as exc:
        raise FUSError(f"could not read TAR entry {outer_entry.filename!r}: {exc}") from exc
    raise FUSError(
        "selected archive does not contain super.img or super.img.lz4"
        + (f"; available files: {', '.join(available)}" if available else "")
    )


def _run_firmware_super_operation(
    *,
    model: str,
    region: str,
    outer_selector: str,
    firmware_version: str | None,
    operation: Callable[[io.BufferedIOBase, str, int], _T],
    prefer_cached: bool,
    timeout_s: int = 30,
    rate_limit: int | None = None,
) -> _T:
    with _open_remote_firmware_archive(
        model=model,
        region=region,
        firmware_version=firmware_version,
        timeout_s=timeout_s,
        rate_limit=rate_limit,
    ) as remote:
        outer_entry = _select_single_firmware_entry(remote.archive.infolist(), outer_selector)
        print_info(f"model: {remote.model}")
        print_info(f"region: {remote.region}")
        print_info(f"firmware: {remote.firmware_version}")
        print_info(f"archive: {outer_entry.filename}")
        return _run_super_member_operation(
            remote,
            outer_entry,
            operation,
            prefer_cached=prefer_cached,
        )


def iter_firmware_super_partitions(
    *,
    model: str,
    region: str,
    outer_selector: str,
    firmware_version: str | None = None,
    timeout_s: int = 30,
    rate_limit: int | None = None,
) -> Iterator[FirmwareSuperPartition]:
    partitions = _run_firmware_super_operation(
        model=model,
        region=region,
        outer_selector=outer_selector,
        firmware_version=firmware_version,
        operation=list_super_partitions,
        prefer_cached=True,
        timeout_s=timeout_s,
        rate_limit=rate_limit,
    )
    yield from partitions


def download_firmware_super_partitions(
    *,
    model: str,
    region: str,
    outer_selector: str,
    partitions: tuple[str, ...] | list[str] | None,
    output: str | os.PathLike[str],
    firmware_version: str | None = None,
    resume: bool = False,
    timeout_s: int = 30,
    rate_limit: int | None = None,
) -> tuple[Path, ...]:
    requested = None if partitions is None else tuple(partitions)
    output_dir = Path(output).expanduser()
    if output_dir.exists() and not output_dir.is_dir():
        raise FUSError(f"partition output must be a directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_dir = output_dir.resolve()

    def extract_operation(source: io.BufferedIOBase, name: str, size: int) -> tuple[Path, ...]:
        if not resume:
            return extract_super_partitions(
                source,
                name,
                size,
                requested=requested,
                output_dir=output_dir,
            )
        stage_name = PurePosixPath(name.replace("\\", "/")).name
        source_part = output_dir / f".{stage_name}.{size}.asgard-source.part"
        _copy_resumable_source(
            source,
            source_part,
            total_size=size,
            label=f"Caching {stage_name}",
        )
        with source_part.open("rb") as local_source:
            available = list_super_partitions(local_source, name, size)
        selected_names = tuple(partition.name for partition in available) if requested is None else tuple(requested)
        destinations = tuple(output_dir / f"{partition_name}.img" for partition_name in selected_names)
        existing = tuple(path.exists() for path in destinations)
        if destinations and all(existing):
            source_part.unlink(missing_ok=True)
            return destinations
        if any(existing):
            raise FUSError("only some requested partition outputs exist; move them away before resuming")
        with source_part.open("rb") as local_source:
            paths = extract_super_partitions(
                local_source,
                name,
                size,
                requested=requested,
                output_dir=output_dir,
            )
        source_part.unlink(missing_ok=True)
        return paths

    return _run_firmware_super_operation(
        model=model,
        region=region,
        outer_selector=outer_selector,
        firmware_version=firmware_version,
        operation=extract_operation,
        prefer_cached=False,
        timeout_s=timeout_s,
        rate_limit=rate_limit,
    )


def download_firmware_entries(
    *,
    model: str,
    region: str,
    selectors: tuple[str, ...] | list[str],
    out_dir: str | os.PathLike[str],
    firmware_version: str | None = None,
    resume: bool = False,
    timeout_s: int = 30,
    rate_limit: int | None = None,
) -> tuple[Path, ...]:
    selector_values = tuple(str(selector) for selector in selectors)
    if not selector_values:
        raise ValueError("at least one entry selector is required")
    output_dir = Path(out_dir).expanduser()
    if output_dir.exists() and not output_dir.is_dir():
        raise FUSError(f"entry output must be a directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_root = output_dir.resolve()

    with _open_remote_firmware_archive(
        model=model,
        region=region,
        firmware_version=firmware_version,
        timeout_s=timeout_s,
        rate_limit=rate_limit,
    ) as remote:
        selected = _select_firmware_entries(remote.archive.infolist(), selector_values)
        destinations: list[tuple[zipfile.ZipInfo, Path]] = []
        already_complete: set[Path] = set()
        destination_keys: set[str] = set()
        for entry in selected:
            destination = _entry_output_path(output_root, entry.filename)
            destination_key = os.path.normcase(str(destination))
            if destination_key in destination_keys:
                raise FUSError(f"multiple archive entries map to the same output path: {destination}")
            destination_keys.add(destination_key)
            if destination.exists() and resume and destination.stat().st_size == entry.file_size:
                already_complete.add(destination)
            elif destination.exists():
                raise FUSError(f"{destination} already exists")
            destinations.append((entry, destination))

        print_info(f"model: {remote.model}")
        print_info(f"region: {remote.region}")
        print_info(f"firmware: {remote.firmware_version}")
        print_info(f"filename: {remote.info.filename}")
        print_info(f"size: {format_bytes(remote.info.size)}")
        print_info(f"entries: {len(destinations)}")
        print_info(f"output: {output_dir}")

        for entry, destination in sorted(destinations, key=lambda item: item[0].header_offset):
            if destination in already_complete:
                continue
            complete = False
            part_path = _fus._partial_output_path(destination)
            try:
                initial_size = part_path.stat().st_size if resume and part_path.is_file() else 0
                if initial_size > entry.file_size:
                    raise FUSError(f"partial archive entry is larger than expected: {part_path}")
                if initial_size == entry.file_size:
                    done = initial_size
                else:
                    with remote.archive.open(entry, "r") as source:
                        if initial_size:
                            _discard_stream(source, initial_size, entry.filename)
                        with (
                            part_path.open("ab" if initial_size else "xb") as output,
                            open_prefetched_stream(source) as prefetched,
                        ):
                            done = copy_stream_with_progress(
                                prefetched,
                                output,
                                label=f"Downloading {PurePosixPath(entry.filename).name}",
                                total_size=entry.file_size,
                                initial_done=initial_size,
                            )
                if done != entry.file_size:
                    raise FUSError(
                        f"incomplete archive entry {entry.filename!r}: expected {entry.file_size} bytes, got {done}"
                    )
                if destination.exists():
                    raise FUSError(f"{destination} already exists")
                part_path.replace(destination)
                complete = True
            except FUSError:
                raise
            except Exception as exc:
                raise FUSError(f"could not extract archive entry {entry.filename!r}: {exc}") from exc
            finally:
                if not complete and not resume:
                    part_path.unlink(missing_ok=True)

        return tuple(destination for _entry, destination in destinations)
