# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import hashlib
import io
import struct
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path

from .constants import (
    _ARCHIVE_COPY_CHUNK_SIZE,
    _LP_BLOCK_DEVICE,
    _LP_EXTENT,
    _LP_GEOMETRY,
    _LP_GEOMETRY_MAGIC,
    _LP_GEOMETRY_SIZE,
    _LP_GROUP,
    _LP_HEADER_MAGIC,
    _LP_HEADER_PREFIX,
    _LP_HEADER_V1_0_SIZE,
    _LP_HEADER_V1_2_SIZE,
    _LP_MAJOR_VERSION,
    _LP_MAX_MINOR_VERSION,
    _LP_MAX_TABLES_SIZE,
    _LP_NAME_RE,
    _LP_PARTITION,
    _LP_PARTITION_ATTRIBUTES_V0,
    _LP_PARTITION_ATTRIBUTES_V1,
    _LP_PARTITION_SLOT_SUFFIXED,
    _LP_RESERVED_BYTES,
    _LP_SECTOR_SIZE,
    _LP_TABLE_DESCRIPTOR,
    _LP_TARGET_LINEAR,
    _LP_TARGET_ZERO,
    _MAX_SIGNED_64,
    _PROGRESS_REFRESH_S,
    _SPARSE_MAGIC,
)
from .errors import FUSError, StreamSourceError
from .progress import render_progress
from .sparse_format import _copy_sparse_stream, _SparseRawReader
from .streaming import (
    copy_stream_with_progress,
    open_prefetched_stream,
    read_exact_stream,
    write_data_or_hole,
    write_data_or_holes,
)


@dataclass(frozen=True, slots=True)
class FirmwareSuperPartition:
    name: str
    size: int


@dataclass(frozen=True, slots=True)
class _LpGeometry:
    metadata_max_size: int
    metadata_slot_count: int
    logical_block_size: int


@dataclass(frozen=True, slots=True)
class _LpPartition:
    name: str
    first_extent_index: int
    num_extents: int


@dataclass(frozen=True, slots=True)
class _LpExtent:
    num_sectors: int
    target_type: int
    target_data: int
    target_source: int


@dataclass(frozen=True, slots=True)
class _LpBlockDevice:
    first_logical_sector: int
    size: int


@dataclass(frozen=True, slots=True)
class _LpMetadata:
    logical_block_size: int
    partitions: tuple[_LpPartition, ...]
    extents: tuple[_LpExtent, ...]


@dataclass(frozen=True, slots=True)
class _SuperCopySpan:
    source_offset: int
    size: int
    partition_name: str
    destination_offset: int


class _RawForwardReader:
    def __init__(
        self,
        source: io.BufferedIOBase,
        *,
        prefix: bytes,
        raw_size: int | None,
    ):
        self._source = source
        self._prefix = prefix
        self._prefix_offset = 0
        self._position = 0
        self.raw_size = raw_size if raw_size and raw_size >= len(prefix) else None

    def tell(self) -> int:
        return self._position

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            raise ValueError("a bounded read size is required")
        if size == 0:
            return b""
        if self.raw_size is not None:
            size = min(size, self.raw_size - self._position)
        chunks: list[bytes] = []
        remaining = size
        if self._prefix_offset < len(self._prefix):
            amount = min(remaining, len(self._prefix) - self._prefix_offset)
            chunks.append(self._prefix[self._prefix_offset : self._prefix_offset + amount])
            self._prefix_offset += amount
            remaining -= amount
        while remaining:
            data = self._source.read(remaining)
            if not data:
                break
            chunks.append(data)
            remaining -= len(data)
        result = b"".join(chunks)
        self._position += len(result)
        return result

    def skip_to(self, offset: int) -> None:
        if offset < self._position:
            raise FUSError("super image stream cannot seek backward")
        if self.raw_size is not None and offset > self.raw_size:
            raise FUSError(f"super image offset {offset} exceeds its raw size")
        remaining = offset - self._position
        while remaining:
            amount = min(remaining, _ARCHIVE_COPY_CHUNK_SIZE)
            data = self.read(amount)
            if len(data) != amount:
                raise FUSError("unexpected end of raw super image")
            remaining -= amount

    def copy_to(
        self,
        output: io.BufferedWriter,
        size: int,
        *,
        hole_block_size: int | None = None,
    ) -> None:
        if size < 0:
            raise ValueError("copy size cannot be negative")
        remaining = size
        while remaining:
            amount = min(remaining, _ARCHIVE_COPY_CHUNK_SIZE)
            data = self.read(amount)
            if len(data) != amount:
                raise FUSError("unexpected end of raw super image")
            if hole_block_size:
                write_data_or_holes(output, data, hole_block_size)
            else:
                write_data_or_hole(output, data)
            remaining -= amount

    def finish(self, *, require_eof: bool) -> None:
        if self.raw_size is not None and self._position != self.raw_size:
            raise FUSError("raw image stream did not reach its declared size")
        if require_eof and self._source.read(1):
            raise FUSError("raw image contains trailing data")


def copy_image_stream(
    source: io.BufferedIOBase,
    output: io.BufferedWriter,
    *,
    label: str,
    total_size: int,
    keep_sparse: bool = False,
) -> int:
    prefix = source.read(4)
    if prefix == struct.pack("<I", _SPARSE_MAGIC) and not keep_sparse:
        return _copy_sparse_stream(source, output, header_prefix=prefix, label=label)
    done = copy_stream_with_progress(
        source,
        output,
        label=label,
        total_size=total_size,
        initial=prefix,
    )
    if total_size and done != total_size:
        raise FUSError(f"incomplete output: expected {total_size} bytes, got {done}")
    return done


def copy_lz4_stream(
    source: io.BufferedIOBase,
    output: io.BufferedWriter,
    *,
    label: str,
    keep_sparse: bool = False,
) -> int:
    try:
        from lz4 import frame as lz4_frame
    except ImportError as exc:
        raise FUSError("LZ4 support is not installed; reinstall asgard") from exc

    try:
        frame_info = lz4_frame.get_frame_info(source.peek(19)[:19])
        total_size = int(frame_info.get("content_size") or 0)
        with (
            lz4_frame.LZ4FrameFile(source, mode="rb") as decoded,
            open_prefetched_stream(decoded) as prefetched,
        ):
            done = copy_image_stream(
                prefetched,
                output,
                label=label,
                total_size=total_size,
                keep_sparse=keep_sparse,
            )
    except (StreamSourceError, FUSError, OSError):
        raise
    except Exception as exc:
        raise FUSError(f"could not decompress LZ4 member: {exc}") from exc
    return done


def _forward_image_reader(
    source: io.BufferedIOBase,
    *,
    raw_size: int | None,
) -> _RawForwardReader | _SparseRawReader:
    prefix = read_exact_stream(source, 4, "super image")
    if prefix == struct.pack("<I", _SPARSE_MAGIC):
        return _SparseRawReader(source, header_prefix=prefix)
    return _RawForwardReader(source, prefix=prefix, raw_size=raw_size)


@contextmanager
def _open_super_image_reader(
    source: io.BufferedIOBase,
    *,
    member_name: str,
    member_size: int,
) -> Iterator[_RawForwardReader | _SparseRawReader]:
    try:
        if member_name.casefold().endswith(".lz4"):
            try:
                from lz4 import frame as lz4_frame
            except ImportError as exc:
                raise FUSError("LZ4 support is not installed; reinstall asgard") from exc

            raw_size = 0
            with suppress(AttributeError, BufferError, EOFError, RuntimeError, ValueError):
                frame_info = lz4_frame.get_frame_info(source.peek(19)[:19])
                raw_size = int(frame_info.get("content_size") or 0)
            with (
                lz4_frame.LZ4FrameFile(source, mode="rb") as decoded,
                open_prefetched_stream(decoded) as prefetched,
            ):
                yield _forward_image_reader(prefetched, raw_size=raw_size or None)
        else:
            with open_prefetched_stream(source) as prefetched:
                yield _forward_image_reader(prefetched, raw_size=member_size)
    except (StreamSourceError, FUSError, OSError):
        raise
    except Exception as exc:
        raise FUSError(f"could not decode super image {member_name!r}: {exc}") from exc


def _parse_lp_geometry(raw_block: bytes) -> _LpGeometry:
    if len(raw_block) != _LP_GEOMETRY_SIZE:
        raise FUSError("truncated logical partition geometry")
    magic, struct_size, checksum, metadata_max_size, slot_count, block_size = _LP_GEOMETRY.unpack_from(raw_block)
    if magic != _LP_GEOMETRY_MAGIC:
        raise FUSError("invalid logical partition geometry magic")
    if struct_size != _LP_GEOMETRY.size:
        raise FUSError(f"unsupported logical partition geometry size: {struct_size}")
    checksum_input = bytearray(raw_block[:struct_size])
    checksum_input[8:40] = bytes(32)
    if hashlib.sha256(checksum_input).digest() != checksum:
        raise FUSError("logical partition geometry checksum mismatch")
    if not metadata_max_size or metadata_max_size % _LP_SECTOR_SIZE:
        raise FUSError(f"invalid logical partition metadata size: {metadata_max_size}")
    if not slot_count:
        raise FUSError("logical partition geometry has no metadata slots")
    if not block_size or block_size % _LP_SECTOR_SIZE:
        raise FUSError(f"invalid logical partition block size: {block_size}")
    return _LpGeometry(
        metadata_max_size=metadata_max_size,
        metadata_slot_count=slot_count,
        logical_block_size=block_size,
    )


def _lp_partition_name(raw_name: bytes) -> str:
    nul = raw_name.find(b"\0")
    encoded = raw_name if nul < 0 else raw_name[:nul]
    if nul >= 0 and any(raw_name[nul:]):
        raise FUSError("invalid partition name padding")
    try:
        name = encoded.decode("ascii")
    except UnicodeDecodeError as exc:
        raise FUSError("invalid partition name: name is not ASCII") from exc
    if not name or _LP_NAME_RE.fullmatch(name) is None:
        raise FUSError(f"invalid partition name: {name!r}")
    return name


def _iter_lp_table_records(
    tables: bytes,
    descriptor: tuple[int, int, int],
    record: struct.Struct,
    description: str,
) -> Iterator[tuple[object, ...]]:
    offset, count, entry_size = descriptor
    if entry_size != record.size:
        raise FUSError(f"invalid {description} table entry size: {entry_size}")
    table_size = count * entry_size
    if table_size > 0x7FFFFFFF or offset > len(tables) or table_size > len(tables) - offset:
        raise FUSError(f"invalid {description} table bounds")
    for index in range(count):
        yield record.unpack_from(tables, offset + index * entry_size)


def _parse_lp_metadata_copy(
    reader: _RawForwardReader | _SparseRawReader,
    *,
    offset: int,
    geometry: _LpGeometry,
) -> _LpMetadata:
    reader.skip_to(offset)
    base_header = read_exact_stream(reader, _LP_HEADER_V1_0_SIZE, "logical partition metadata header")
    (
        magic,
        major_version,
        minor_version,
        header_size,
        header_checksum,
        tables_size,
        tables_checksum,
    ) = _LP_HEADER_PREFIX.unpack_from(base_header)
    if magic != _LP_HEADER_MAGIC:
        raise FUSError("invalid logical partition metadata magic")
    if major_version != _LP_MAJOR_VERSION or not 0 <= minor_version <= _LP_MAX_MINOR_VERSION:
        raise FUSError(f"unsupported logical partition metadata version: {major_version}.{minor_version}")
    expected_header_size = _LP_HEADER_V1_2_SIZE if minor_version >= 2 else _LP_HEADER_V1_0_SIZE
    if header_size != expected_header_size:
        raise FUSError(f"invalid logical partition metadata header size: {header_size}")
    if header_size > geometry.metadata_max_size:
        raise FUSError("logical partition metadata header exceeds its slot")
    if tables_size > geometry.metadata_max_size - header_size:
        raise FUSError("logical partition tables exceed their metadata slot")
    if tables_size > _LP_MAX_TABLES_SIZE:
        raise FUSError(f"logical partition tables are too large: {tables_size} bytes")

    header = base_header
    if header_size > len(header):
        header += read_exact_stream(
            reader,
            header_size - len(header),
            "expanded logical partition metadata header",
        )
    checksum_input = bytearray(header)
    checksum_input[12:44] = bytes(32)
    if hashlib.sha256(checksum_input).digest() != header_checksum:
        raise FUSError("logical partition metadata header checksum mismatch")
    tables = read_exact_stream(reader, tables_size, "logical partition metadata tables")
    if hashlib.sha256(tables).digest() != tables_checksum:
        raise FUSError("logical partition metadata table checksum mismatch")

    descriptors = tuple(_LP_TABLE_DESCRIPTOR.unpack_from(header, 80 + index * 12) for index in range(4))
    group_count = descriptors[2][1]
    for _row in _iter_lp_table_records(
        tables,
        descriptors[2],
        _LP_GROUP,
        "group",
    ):
        pass

    block_devices = tuple(
        _LpBlockDevice(
            first_logical_sector=int(first_sector),
            size=int(size),
        )
        for first_sector, _alignment, _alignment_offset, size, _raw_name, _flags in _iter_lp_table_records(
            tables,
            descriptors[3],
            _LP_BLOCK_DEVICE,
            "block device",
        )
    )
    if not block_devices:
        raise FUSError("logical partition metadata has no block devices")
    for device_index, device in enumerate(block_devices):
        if not device.size or device.size > _MAX_SIGNED_64 or device.size % _LP_SECTOR_SIZE:
            raise FUSError(f"invalid block device {device_index} size: {device.size}")
        if device.first_logical_sector * _LP_SECTOR_SIZE > device.size:
            raise FUSError(f"invalid first logical sector for block device {device_index}")

    valid_attributes = _LP_PARTITION_ATTRIBUTES_V0
    if minor_version >= 1:
        valid_attributes |= _LP_PARTITION_ATTRIBUTES_V1
    partitions: list[_LpPartition] = []
    names: set[str] = set()
    extent_count_total = descriptors[1][1]
    for raw_name, attributes, first_extent, extent_count, group_index in _iter_lp_table_records(
        tables,
        descriptors[0],
        _LP_PARTITION,
        "partition",
    ):
        attributes = int(attributes)
        if attributes & ~valid_attributes:
            raise FUSError("logical partition metadata has unsupported partition attributes")
        name = _lp_partition_name(raw_name)
        if attributes & _LP_PARTITION_SLOT_SUFFIXED:
            name += "_a"
        if len(name.encode("ascii")) > 36 or name in names:
            raise FUSError(f"duplicate or oversized logical partition name: {name!r}")
        names.add(name)
        first_extent = int(first_extent)
        extent_count = int(extent_count)
        group_index = int(group_index)
        if first_extent > extent_count_total or extent_count > extent_count_total - first_extent:
            raise FUSError(f"invalid extent range for logical partition {name!r}")
        if group_index >= group_count:
            raise FUSError(f"invalid group index for logical partition {name!r}")
        partitions.append(
            _LpPartition(
                name=name,
                first_extent_index=first_extent,
                num_extents=extent_count,
            )
        )

    extents = tuple(
        _LpExtent(
            num_sectors=int(num_sectors),
            target_type=int(target_type),
            target_data=int(target_data),
            target_source=int(target_source),
        )
        for num_sectors, target_type, target_data, target_source in _iter_lp_table_records(
            tables,
            descriptors[1],
            _LP_EXTENT,
            "extent",
        )
    )
    for extent in extents:
        extent_size = extent.num_sectors * _LP_SECTOR_SIZE
        if extent_size > _MAX_SIGNED_64 or extent_size % geometry.logical_block_size:
            raise FUSError("logical partition extent is not block-aligned")
        if extent.target_type == _LP_TARGET_ZERO:
            if extent.target_data or extent.target_source:
                raise FUSError("logical partition ZERO extent has invalid target fields")
            continue
        if extent.target_type != _LP_TARGET_LINEAR:
            raise FUSError(f"unsupported logical partition extent type: {extent.target_type}")
        if extent.target_source >= len(block_devices):
            raise FUSError(f"invalid logical partition extent source: {extent.target_source}")
        device = block_devices[extent.target_source]
        start = extent.target_data * _LP_SECTOR_SIZE
        if start % geometry.logical_block_size:
            raise FUSError("logical partition extent is not physically block-aligned")
        if start < device.first_logical_sector * _LP_SECTOR_SIZE or extent_size > device.size - start:
            raise FUSError("logical partition extent is outside its block device")

    metadata_end = (
        _LP_RESERVED_BYTES + 2 * _LP_GEOMETRY_SIZE + (2 * geometry.metadata_max_size * geometry.metadata_slot_count)
    )
    if metadata_end > _MAX_SIGNED_64:
        raise FUSError("logical partition metadata offsets are too large")
    if metadata_end > block_devices[0].first_logical_sector * _LP_SECTOR_SIZE:
        raise FUSError("logical partition metadata overlaps partition data")
    if reader.raw_size is not None and block_devices[0].size > reader.raw_size:
        raise FUSError("super image is smaller than its logical block device metadata")
    return _LpMetadata(
        logical_block_size=geometry.logical_block_size,
        partitions=tuple(partitions),
        extents=extents,
    )


def _read_lp_metadata(reader: _RawForwardReader | _SparseRawReader) -> _LpMetadata:
    reader.skip_to(_LP_RESERVED_BYTES)
    primary_geometry = read_exact_stream(reader, _LP_GEOMETRY_SIZE, "primary logical partition geometry")
    backup_geometry = read_exact_stream(reader, _LP_GEOMETRY_SIZE, "backup logical partition geometry")
    geometry_errors: list[str] = []
    geometry: _LpGeometry | None = None
    for label, raw_geometry in (("primary", primary_geometry), ("backup", backup_geometry)):
        try:
            geometry = _parse_lp_geometry(raw_geometry)
            break
        except FUSError as exc:
            geometry_errors.append(f"{label}: {exc}")
    if geometry is None:
        raise FUSError("both logical partition geometry copies are invalid (" + "; ".join(geometry_errors) + ")")
    metadata_end = (
        _LP_RESERVED_BYTES + 2 * _LP_GEOMETRY_SIZE + (2 * geometry.metadata_max_size * geometry.metadata_slot_count)
    )
    if metadata_end > _MAX_SIGNED_64:
        raise FUSError("logical partition metadata offsets are too large")
    if reader.raw_size is not None and metadata_end > reader.raw_size:
        raise FUSError("super image is smaller than its logical partition metadata region")

    primary_offset = _LP_RESERVED_BYTES + 2 * _LP_GEOMETRY_SIZE
    backup_offset = (
        _LP_RESERVED_BYTES + 2 * _LP_GEOMETRY_SIZE + geometry.metadata_max_size * geometry.metadata_slot_count
    )
    metadata_errors: list[str] = []
    for label, metadata_offset in (("primary", primary_offset), ("backup", backup_offset)):
        try:
            return _parse_lp_metadata_copy(
                reader,
                offset=metadata_offset,
                geometry=geometry,
            )
        except FUSError as exc:
            metadata_errors.append(f"{label}: {exc}")
    raise FUSError("both logical partition metadata copies are invalid (" + "; ".join(metadata_errors) + ")")


def _lp_partition_size(metadata: _LpMetadata, partition: _LpPartition) -> int:
    total = 0
    end = partition.first_extent_index + partition.num_extents
    for extent in metadata.extents[partition.first_extent_index : end]:
        extent_size = extent.num_sectors * _LP_SECTOR_SIZE
        if extent_size > _MAX_SIGNED_64 - total:
            raise FUSError(f"logical partition {partition.name!r} is too large")
        total += extent_size
    return total


def list_super_partitions(
    source: io.BufferedIOBase,
    member_name: str,
    member_size: int,
) -> tuple[FirmwareSuperPartition, ...]:
    with _open_super_image_reader(
        source,
        member_name=member_name,
        member_size=member_size,
    ) as reader:
        metadata = _read_lp_metadata(reader)
        return tuple(
            FirmwareSuperPartition(name=partition.name, size=_lp_partition_size(metadata, partition))
            for partition in metadata.partitions
        )


def _select_lp_partitions(
    metadata: _LpMetadata,
    requested: tuple[str, ...] | None,
) -> tuple[_LpPartition, ...]:
    if requested is None:
        return metadata.partitions
    requested_names = tuple(str(name or "").strip() for name in requested)
    if not requested_names or any(not name for name in requested_names):
        raise ValueError("at least one non-empty partition name is required")
    requested_set = set(requested_names)
    selected = tuple(partition for partition in metadata.partitions if partition.name in requested_set)
    found = {partition.name for partition in selected}
    missing = tuple(dict.fromkeys(name for name in requested_names if name not in found))
    if missing:
        available = ", ".join(partition.name for partition in metadata.partitions)
        raise FUSError(
            f"super partition not found: {', '.join(missing)}"
            + (f"; available partitions: {available}" if available else "")
        )
    return selected


def _build_super_copy_plan(
    metadata: _LpMetadata,
    selected: tuple[_LpPartition, ...],
    reader: _RawForwardReader | _SparseRawReader,
) -> tuple[tuple[_SuperCopySpan, ...], dict[str, int]]:
    spans: list[_SuperCopySpan] = []
    sizes: dict[str, int] = {}
    for partition in selected:
        destination_offset = 0
        extent_end = partition.first_extent_index + partition.num_extents
        for extent in metadata.extents[partition.first_extent_index : extent_end]:
            extent_size = extent.num_sectors * _LP_SECTOR_SIZE
            if extent_size > _MAX_SIGNED_64 - destination_offset:
                raise FUSError(f"logical partition {partition.name!r} is too large")
            if extent.target_type == _LP_TARGET_LINEAR:
                if extent.target_source != 0:
                    raise FUSError(
                        f"partition {partition.name!r} uses split super source {extent.target_source}; "
                        "this super image stream only supplies source 0"
                    )
                source_offset = extent.target_data * _LP_SECTOR_SIZE
                if reader.raw_size is not None and extent_size > reader.raw_size - source_offset:
                    raise FUSError(f"partition {partition.name!r} extends beyond the super image")
                spans.append(
                    _SuperCopySpan(
                        source_offset=source_offset,
                        size=extent_size,
                        partition_name=partition.name,
                        destination_offset=destination_offset,
                    )
                )
            destination_offset += extent_size
        sizes[partition.name] = destination_offset

    spans.sort(key=lambda span: span.source_offset)
    previous_end = 0
    for span in spans:
        if span.source_offset < previous_end:
            raise FUSError("selected logical partitions contain overlapping physical extents")
        previous_end = span.source_offset + span.size
    return tuple(spans), sizes


def extract_super_partitions(
    source: io.BufferedIOBase,
    member_name: str,
    member_size: int,
    *,
    requested: tuple[str, ...] | None,
    output_dir: Path,
) -> tuple[Path, ...]:
    with _open_super_image_reader(
        source,
        member_name=member_name,
        member_size=member_size,
    ) as reader:
        metadata = _read_lp_metadata(reader)
        selected = _select_lp_partitions(metadata, requested)
        spans, sizes = _build_super_copy_plan(metadata, selected, reader)
        progress_start = reader.tell()
        progress_end = spans[-1].source_offset + spans[-1].size if spans else progress_start
        progress_total = progress_end - progress_start
        if len(selected) == 1:
            progress_label = f"Streaming super for {selected[0].name}"
        else:
            progress_label = f"Streaming super for {len(selected)} partitions"
        progress_started_at = time.monotonic()
        progress_last_render = progress_started_at - _PROGRESS_REFRESH_S

        def update_progress(*, complete: bool = False) -> None:
            nonlocal progress_last_render
            if not progress_total:
                return
            now = time.monotonic()
            done = min(progress_total, max(0, reader.tell() - progress_start))
            if not complete and (done >= progress_total or now - progress_last_render < _PROGRESS_REFRESH_S):
                return
            render_progress(
                progress_label,
                done,
                progress_total,
                progress_started_at,
                complete=complete,
            )
            progress_last_render = now

        paths: dict[str, tuple[Path, Path]] = {}
        for partition in selected:
            destination = output_dir / f"{partition.name}.img"
            paths[partition.name] = destination, destination.with_name(f"{destination.name}.part")
        for destination, part_path in paths.values():
            if destination.exists():
                raise FUSError(f"{destination} already exists")
            if part_path.exists():
                raise FUSError(f"{part_path} already exists")

        renamed: list[Path] = []
        complete = False
        try:
            for _destination, part_path in paths.values():
                with part_path.open("xb"):
                    pass
            for span in spans:
                while reader.tell() < span.source_offset:
                    reader.skip_to(min(span.source_offset, reader.tell() + _ARCHIVE_COPY_CHUNK_SIZE))
                    update_progress()
                with paths[span.partition_name][1].open("r+b") as output:
                    output.seek(span.destination_offset)
                    remaining = span.size
                    while remaining:
                        amount = min(remaining, _ARCHIVE_COPY_CHUNK_SIZE)
                        reader.copy_to(
                            output,
                            amount,
                            hole_block_size=metadata.logical_block_size,
                        )
                        remaining -= amount
                        update_progress()
            if reader.raw_size is not None and reader.tell() == reader.raw_size:
                reader.finish(require_eof=True)
            update_progress(complete=True)
            for name, (_destination, part_path) in paths.items():
                with part_path.open("r+b") as output:
                    output.truncate(sizes[name])
            for partition in selected:
                destination, part_path = paths[partition.name]
                if destination.exists():
                    raise FUSError(f"{destination} already exists")
                part_path.replace(destination)
                renamed.append(destination)
            complete = True
            return tuple(paths[partition.name][0] for partition in selected)
        finally:
            if not complete:
                for _destination, part_path in paths.values():
                    part_path.unlink(missing_ok=True)
                for destination in renamed:
                    destination.unlink(missing_ok=True)
