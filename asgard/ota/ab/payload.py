# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import base64
import bz2
import hashlib
import lzma
import os
import struct
import zipfile
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack
from dataclasses import dataclass
from itertools import chain, pairwise
from pathlib import Path

from ...cli.progress import print_info
from ...core.errors import FUSError
from ...core.resources import ota_operation_max_bytes, ota_worker_count
from ..inplace import prepare_image, write_all, zero_range
from ..models import OtaPartition
from ..patch import apply_bsdiff, normalize_source_signature
from ..state import save_outputs
from .scheduler import operation_order

_PAYLOAD_HEADER = struct.Struct(">4sQQI")
_ZIP_LOCAL_HEADER = struct.Struct("<I5H3I2H")
_ZIP_LOCAL_MAGIC = 0x04034B50
_SPARSE_HOLE = (1 << 64) - 1
_OPERATION_NAMES = {
    0: "REPLACE",
    1: "REPLACE_BZ",
    2: "MOVE",
    3: "BSDIFF",
    4: "SOURCE_COPY",
    5: "SOURCE_BSDIFF",
    6: "ZERO",
    7: "DISCARD",
    8: "REPLACE_XZ",
    9: "PUFFDIFF",
    10: "BROTLI_BSDIFF",
    11: "ZUCCHINI",
    12: "LZ4DIFF_BSDIFF",
    13: "LZ4DIFF_PUFFDIFF",
}
_SUPPORTED_OPERATIONS = {0, 1, 4, 5, 6, 7, 8, 10}
_PREADV = getattr(os, "preadv", None)
_EXTENT_IO_SIZE = 1024 * 1024


@dataclass(frozen=True)
class _Extent:
    start: int
    blocks: int


@dataclass(frozen=True)
class _PartitionInfo:
    size: int
    digest: bytes


@dataclass(frozen=True)
class _Operation:
    kind: int
    data_offset: int
    data_length: int
    source_extents: tuple[_Extent, ...]
    target_extents: tuple[_Extent, ...]
    data_digest: bytes
    source_digest: bytes


@dataclass(frozen=True)
class _Partition:
    name: str
    old: _PartitionInfo | None
    new: _PartitionInfo
    operations: tuple[_Operation, ...]
    needs_verity: bool


@dataclass(frozen=True)
class _Manifest:
    block_size: int
    minor_version: int
    partitions: tuple[_Partition, ...]


@dataclass
class PayloadArchive:
    path: Path
    file_descriptor: int
    blob_offset: int
    manifest: _Manifest

    def close(self) -> None:
        if self.file_descriptor >= 0:
            os.close(self.file_descriptor)
            self.file_descriptor = -1

    def read_blob(self, operation: _Operation) -> bytes:
        return _pread_exact(
            self.file_descriptor,
            operation.data_length,
            self.blob_offset + operation.data_offset,
        )

    def __enter__(self) -> PayloadArchive:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


def _varint(raw: memoryview, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(raw) and shift < 70:
        byte = raw[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
    raise FUSError("invalid protobuf varint in payload manifest")


def _fields(raw_value: bytes | memoryview):
    raw = memoryview(raw_value)
    offset = 0
    while offset < len(raw):
        key, offset = _varint(raw, offset)
        number, wire = key >> 3, key & 7
        if not number:
            raise FUSError("invalid protobuf field in payload manifest")
        if wire == 0:
            value, offset = _varint(raw, offset)
        elif wire == 1:
            end = offset + 8
            if end > len(raw):
                raise FUSError("truncated protobuf field in payload manifest")
            value, offset = raw[offset:end], end
        elif wire == 2:
            size, offset = _varint(raw, offset)
            end = offset + size
            if end > len(raw):
                raise FUSError("truncated protobuf field in payload manifest")
            value, offset = raw[offset:end], end
        elif wire == 5:
            end = offset + 4
            if end > len(raw):
                raise FUSError("truncated protobuf field in payload manifest")
            value, offset = raw[offset:end], end
        else:
            raise FUSError(f"unsupported protobuf wire type in payload manifest: {wire}")
        yield number, wire, value


def _parse_extent(raw: memoryview) -> _Extent:
    start = 0
    blocks = 0
    for number, wire, value in _fields(raw):
        if wire != 0:
            continue
        if number == 1:
            start = int(value)
        elif number == 2:
            blocks = int(value)
    if blocks <= 0:
        raise FUSError("payload extent has no blocks")
    return _Extent(start, blocks)


def _parse_info(raw: memoryview) -> _PartitionInfo:
    size = 0
    digest = b""
    for number, wire, value in _fields(raw):
        if number == 1 and wire == 0:
            size = int(value)
        elif number == 2 and wire == 2:
            digest = bytes(value)
    return _PartitionInfo(size, digest)


def _parse_operation(raw: memoryview) -> _Operation:
    kind = -1
    data_offset = 0
    data_length = 0
    source_extents: list[_Extent] = []
    target_extents: list[_Extent] = []
    data_digest = b""
    source_digest = b""
    for number, wire, value in _fields(raw):
        if number == 1 and wire == 0:
            kind = int(value)
        elif number == 2 and wire == 0:
            data_offset = int(value)
        elif number == 3 and wire == 0:
            data_length = int(value)
        elif number == 4 and wire == 2:
            source_extents.append(_parse_extent(value))
        elif number == 6 and wire == 2:
            target_extents.append(_parse_extent(value))
        elif number == 8 and wire == 2:
            data_digest = bytes(value)
        elif number == 9 and wire == 2:
            source_digest = bytes(value)
    if kind < 0 or not target_extents:
        raise FUSError("invalid operation in payload manifest")
    return _Operation(
        kind=kind,
        data_offset=data_offset,
        data_length=data_length,
        source_extents=tuple(source_extents),
        target_extents=tuple(target_extents),
        data_digest=data_digest,
        source_digest=source_digest,
    )


def _parse_partition(raw: memoryview) -> _Partition:
    name = ""
    old = None
    new = None
    operations: list[_Operation] = []
    needs_verity = False
    for number, wire, value in _fields(raw):
        if number == 1 and wire == 2:
            name = bytes(value).decode("utf-8")
        elif number == 6 and wire == 2:
            old = _parse_info(value)
        elif number == 7 and wire == 2:
            new = _parse_info(value)
        elif number == 8 and wire == 2:
            operations.append(_parse_operation(value))
        elif number in {11, 15} and wire == 2:
            extent = _parse_extent(value)
            needs_verity = needs_verity or extent.blocks > 0
    if (
        not name
        or new is None
        or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in name)
    ):
        raise FUSError("invalid partition in payload manifest")
    return _Partition(name, old, new, tuple(operations), needs_verity)


def _parse_manifest(raw: bytes) -> _Manifest:
    block_size = 4096
    minor_version = 0
    partitions: list[_Partition] = []
    for number, wire, value in _fields(raw):
        if number == 3 and wire == 0:
            block_size = int(value)
        elif number == 12 and wire == 0:
            minor_version = int(value)
        elif number == 13 and wire == 2:
            partitions.append(_parse_partition(value))
    if block_size <= 0 or not partitions:
        raise FUSError("payload manifest contains no partitions")
    if len({partition.name for partition in partitions}) != len(partitions):
        raise FUSError("duplicate partition names in payload manifest")
    return _Manifest(block_size, minor_version, tuple(partitions))


def _pread_exact(file_descriptor: int, size: int, offset: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.pread(file_descriptor, remaining, offset)
        if not chunk:
            raise FUSError("unexpected end of OTA payload")
        chunks.append(chunk)
        remaining -= len(chunk)
        offset += len(chunk)
    return b"".join(chunks)


def _zip_entry_offset(file_descriptor: int, info: zipfile.ZipInfo) -> int:
    raw = _pread_exact(file_descriptor, _ZIP_LOCAL_HEADER.size, info.header_offset)
    values = _ZIP_LOCAL_HEADER.unpack(raw)
    if values[0] != _ZIP_LOCAL_MAGIC:
        raise FUSError("invalid payload ZIP entry header")
    return info.header_offset + _ZIP_LOCAL_HEADER.size + values[-2] + values[-1]


def open_payload(path_value: str | Path, *, verify: bool = True) -> PayloadArchive:
    path = Path(path_value).expanduser().resolve()
    try:
        with zipfile.ZipFile(path) as archive:
            info = archive.getinfo("payload.bin")
            properties = {}
            if "payload_properties.txt" in archive.namelist():
                for line in archive.read("payload_properties.txt").decode("ascii", "replace").splitlines():
                    if "=" in line:
                        key, value = line.split("=", 1)
                        properties[key] = value.strip()
    except (KeyError, zipfile.BadZipFile) as exc:
        raise FUSError(f"invalid A/B OTA: {path}") from exc
    if info.compress_type != zipfile.ZIP_STORED:
        raise FUSError("payload.bin must be stored without ZIP compression")
    if properties.get("FILE_SIZE") and int(properties["FILE_SIZE"]) != info.file_size:
        raise FUSError("payload size does not match payload_properties.txt")
    file_descriptor = os.open(path, os.O_RDONLY)
    try:
        entry_offset = _zip_entry_offset(file_descriptor, info)
        header = _pread_exact(file_descriptor, _PAYLOAD_HEADER.size, entry_offset)
        magic, major_version, manifest_size, signature_size = _PAYLOAD_HEADER.unpack(header)
        if magic != b"CrAU" or major_version != 2:
            raise FUSError(f"unsupported payload format: magic={magic!r}, version={major_version}")
        if _PAYLOAD_HEADER.size + manifest_size + signature_size > info.file_size:
            raise FUSError("payload metadata exceeds the ZIP entry size")
        manifest_raw = _pread_exact(file_descriptor, manifest_size, entry_offset + _PAYLOAD_HEADER.size)
        metadata_size = _PAYLOAD_HEADER.size + manifest_size
        if properties.get("METADATA_SIZE") and int(properties["METADATA_SIZE"]) != metadata_size:
            raise FUSError("payload metadata size does not match payload_properties.txt")
        if verify and properties.get("METADATA_HASH"):
            actual = hashlib.sha256(header + manifest_raw).digest()
            expected = base64.b64decode(properties["METADATA_HASH"], validate=True)
            if actual != expected:
                raise FUSError("payload metadata hash mismatch")
        manifest = _parse_manifest(manifest_raw)
        blob_offset = entry_offset + metadata_size + signature_size
        blob_size = info.file_size - metadata_size - signature_size
        if any(op.data_offset + op.data_length > blob_size for part in manifest.partitions for op in part.operations):
            raise FUSError("payload operation data exceeds the ZIP entry size")
        return PayloadArchive(path, file_descriptor, blob_offset, manifest)
    except Exception:
        os.close(file_descriptor)
        raise


def payload_partitions(path_value: str | Path, *, verify: bool = True) -> tuple[OtaPartition, ...]:
    with open_payload(path_value, verify=verify) as payload:
        return tuple(
            OtaPartition(
                name=partition.name,
                size=partition.new.size,
                source_required=any(op.source_extents for op in partition.operations),
                operations=dict(Counter(_OPERATION_NAMES.get(op.kind, str(op.kind)) for op in partition.operations)),
            )
            for partition in payload.manifest.partitions
        )


def validate_payload_targets(path_value: str | Path, selected: tuple[str, ...], *, verify: bool) -> None:
    with open_payload(path_value, verify=verify) as payload:
        for partition in payload.manifest.partitions:
            if partition.name not in selected:
                continue
            _validate_partition(partition, payload.manifest.block_size)


def _validate_partition(partition: _Partition, block_size: int) -> None:
    if partition.needs_verity:
        raise FUSError(f"payload verity/FEC generation is not supported for {partition.name}")
    unsupported = sorted({op.kind for op in partition.operations} - _SUPPORTED_OPERATIONS)
    if unsupported:
        names = ", ".join(_OPERATION_NAMES.get(kind, str(kind)) for kind in unsupported)
        raise FUSError(f"unsupported payload operations for {partition.name}: {names}")
    for info in (partition.old, partition.new):
        if info is not None and (info.size < 0 or (info.digest and len(info.digest) != 32)):
            raise FUSError(f"invalid image metadata for {partition.name}")
    targets = []
    for op in partition.operations:
        for digest in (op.data_digest, op.source_digest):
            if digest and len(digest) != 32:
                raise FUSError(f"invalid operation hash for {partition.name}")
        if op.source_extents and op.kind not in {4, 5, 10}:
            raise FUSError(f"invalid operation source for {partition.name}")
        if op.kind in {4, 6, 7} and op.data_length:
            raise FUSError(f"unexpected operation data for {partition.name}")
        if not op.target_extents:
            raise FUSError(f"missing target extents for {partition.name}")
        for extent in op.target_extents:
            if (
                extent.start < 0
                or extent.blocks <= 0
                or (extent.start + extent.blocks) * block_size > partition.new.size
            ):
                raise FUSError(f"invalid target extent for {partition.name}")
            targets.append((extent.start, extent.start + extent.blocks))
        for extent in op.source_extents:
            if (
                partition.old is None
                or extent.start < 0
                or extent.blocks <= 0
                or (extent.start != _SPARSE_HOLE and (extent.start + extent.blocks) * block_size > partition.old.size)
            ):
                raise FUSError(f"invalid source extent for {partition.name}")
        if op.kind == 4 and _extent_size(op.source_extents, block_size) != _extent_size(op.target_extents, block_size):
            raise FUSError(f"source-copy size mismatch for {partition.name}")
    targets.sort()
    if any(right[0] < left[1] for left, right in pairwise(targets)):
        raise FUSError(f"overlapping payload target extents for {partition.name}")


def _extent_size(extents: tuple[_Extent, ...], block_size: int) -> int:
    return sum(extent.blocks for extent in extents) * block_size


def _read_extents(file_descriptor: int, extents: tuple[_Extent, ...], block_size: int) -> bytearray:
    total = _extent_size(extents, block_size)
    output = bytearray(total)
    view = memoryview(output)
    position = 0
    for extent in extents:
        size = extent.blocks * block_size
        if extent.start != _SPARSE_HOLE:
            source_offset = extent.start * block_size
            end = position + size
            while position < end:
                target = view[position : min(end, position + _EXTENT_IO_SIZE)]
                if _PREADV is not None:
                    received = _PREADV(file_descriptor, [target], source_offset)
                else:
                    chunk = os.pread(file_descriptor, len(target), source_offset)
                    received = len(chunk)
                    target[:received] = chunk
                if not received:
                    raise FUSError("unexpected end of OTA payload")
                position += received
                source_offset += received
        else:
            position += size
    return output


def _write_extents(output, extents: tuple[_Extent, ...], block_size: int, data: bytes | bytearray) -> None:
    capacity = _extent_size(extents, block_size)
    if len(data) > capacity:
        raise FUSError(f"operation output exceeds its target extents: {len(data)} > {capacity}")
    position = 0
    view = memoryview(data)
    for extent in extents:
        size = min(extent.blocks * block_size, len(data) - position)
        if size <= 0:
            break
        if extent.start != _SPARSE_HOLE:
            output.seek(extent.start * block_size)
            write_all(output, view[position : position + size])
        position += size


def _pwrite_extents(
    file_descriptor: int, extents: tuple[_Extent, ...], block_size: int, data: bytes | bytearray
) -> None:
    capacity = _extent_size(extents, block_size)
    if len(data) != capacity:
        raise FUSError(f"operation output size mismatch: expected {capacity}, got {len(data)}")
    position = 0
    view = memoryview(data)
    for extent in extents:
        size = extent.blocks * block_size
        if extent.start != _SPARSE_HOLE:
            offset = extent.start * block_size
            end = position + size
            while position < end:
                written = os.pwrite(file_descriptor, view[position:end], offset)
                if written <= 0:
                    raise FUSError("could not write OTA image data")
                position += written
                offset += written
        else:
            position += size


def _source_chunks(file_descriptor: int, extents: tuple[_Extent, ...], block_size: int):
    for extent in extents:
        remaining = extent.blocks * block_size
        offset = extent.start * block_size
        while remaining:
            amount = min(remaining, _EXTENT_IO_SIZE)
            yield bytes(amount) if extent.start == _SPARSE_HOLE else _pread_exact(file_descriptor, amount, offset)
            remaining -= amount
            offset += amount


def _normalized_chunk(chunk: bytes, position: int, signature_position: int) -> bytes:
    start = max(0, signature_position - position)
    end = min(len(chunk), signature_position + 256 - position)
    if start >= end:
        return chunk
    return chunk[:start] + bytes(end - start) + chunk[end:]


def _stream_source_copy(
    source_fd: int,
    output_fd: int,
    operation: _Operation,
    block_size: int,
    *,
    verify: bool,
    partition_name: str,
    index: int,
) -> None:
    if verify and operation.data_digest and hashlib.sha256(b"").digest() != operation.data_digest:
        raise FUSError(f"payload data hash mismatch for {partition_name}")
    signature_position = None
    if operation.source_digest:
        position = 0
        for extent in operation.source_extents:
            if extent.start == 0:
                signature_position = position
                break
            position += extent.blocks * block_size

    normalize = False
    if operation.source_digest and (verify or signature_position is not None):
        raw_digest = hashlib.sha256() if verify else None
        normalized_digest = hashlib.sha256() if signature_position is not None else None
        signature = bytearray()
        position = 0
        for chunk in _source_chunks(source_fd, operation.source_extents, block_size):
            if raw_digest is not None:
                raw_digest.update(chunk)
            if normalized_digest is not None and signature_position is not None:
                marker_start = max(0, signature_position + 768 - position)
                marker_end = min(len(chunk), signature_position + 779 - position)
                if marker_start < marker_end:
                    signature.extend(chunk[marker_start:marker_end])
                normalized_digest.update(_normalized_chunk(chunk, position, signature_position))
            position += len(chunk)
        if raw_digest is not None and raw_digest.digest() == operation.source_digest:
            normalize = False
        elif (
            normalized_digest is not None
            and signature == b"SignerVer02"
            and normalized_digest.digest() == operation.source_digest
        ):
            normalize = True
        elif verify:
            raise FUSError(f"base extent hash mismatch for {partition_name}, operation {index}")

    target_index = 0
    target_offset = 0
    position = 0
    for chunk in _source_chunks(source_fd, operation.source_extents, block_size):
        if normalize and signature_position is not None:
            chunk = _normalized_chunk(chunk, position, signature_position)
        position += len(chunk)
        view = memoryview(chunk)
        while view:
            extent = operation.target_extents[target_index]
            extent_size = extent.blocks * block_size
            amount = min(len(view), extent_size - target_offset)
            offset = extent.start * block_size + target_offset
            part = view[:amount]
            while part:
                written = os.pwrite(output_fd, part, offset)
                if written <= 0:
                    raise FUSError("could not write OTA image data")
                part = part[written:]
                offset += written
            view = view[amount:]
            target_offset += amount
            if target_offset == extent_size:
                target_index += 1
                target_offset = 0


def _can_stream_in_place(operation: _Operation) -> bool:
    if operation.source_extents == operation.target_extents:
        return True
    sources = sorted(
        (extent.start, extent.start + extent.blocks)
        for extent in operation.source_extents
        if extent.start != _SPARSE_HOLE
    )
    targets = sorted((extent.start, extent.start + extent.blocks) for extent in operation.target_extents)
    source_index = target_index = 0
    while source_index < len(sources) and target_index < len(targets):
        source_start, source_end = sources[source_index]
        target_start, target_end = targets[target_index]
        if source_start < target_end and target_start < source_end:
            return False
        if source_end <= target_start:
            source_index += 1
        else:
            target_index += 1
    return True


def _operation_target(
    payload: PayloadArchive,
    partition: _Partition,
    operation: _Operation,
    index: int,
    source: bytes | bytearray,
    *,
    block_size: int,
    verify: bool,
) -> tuple[bytes | bytearray | None, bool]:
    blob = payload.read_blob(operation) if operation.data_length else b""
    if verify and operation.data_digest and hashlib.sha256(blob).digest() != operation.data_digest:
        raise FUSError(f"payload data hash mismatch for {partition.name}")
    normalized_source = False
    if (
        operation.source_extents
        and operation.source_digest
        and (not verify or hashlib.sha256(source).digest() != operation.source_digest)
    ):
        position = 0
        for extent in operation.source_extents:
            if extent.start == 0:
                normalized = normalize_source_signature(source, operation.source_digest, offset=position)
                normalized_source = normalized is not source
                source = normalized
                break
            position += extent.blocks * block_size
        if verify and not normalized_source:
            raise FUSError(f"base extent hash mismatch for {partition.name}, operation {index}")
    if operation.kind == 0:
        target = blob
    elif operation.kind == 1:
        target = bz2.decompress(blob)
    elif operation.kind == 8:
        target = lzma.decompress(blob)
    elif operation.kind in {6, 7}:
        return None, normalized_source
    elif operation.kind == 4:
        target = source
    else:
        target = apply_bsdiff(source, blob, expected_size=_extent_size(operation.target_extents, block_size))
    if len(target) != _extent_size(operation.target_extents, block_size):
        raise FUSError(f"operation output size mismatch for {partition.name}")
    return target, normalized_source


def _hash_file(path: Path, size: int) -> bytes:
    digest = hashlib.sha256()
    remaining = size
    buffer = bytearray(min(4 * 1024 * 1024, max(1, size)))
    view = memoryview(buffer)
    with path.open("rb") as source:
        while remaining:
            received = source.readinto(view[: min(len(view), remaining)])
            if not received:
                raise FUSError(f"unexpected end of image: {path}")
            digest.update(view[:received])
            remaining -= received
    return digest.digest()


def _apply_partition(
    payload: PayloadArchive,
    partition: _Partition,
    source_path: Path | None,
    output_dir: Path,
    *,
    verify: bool,
    resume: bool,
    force: bool,
    consume_source: bool = False,
    operation_workers: int = 1,
    operation_limit_bytes: int | None = None,
) -> tuple[Path, bool]:
    _validate_partition(partition, payload.manifest.block_size)
    destination = output_dir / f"{partition.name}.img"
    if destination.exists():
        valid = destination.stat().st_size == partition.new.size
        if valid and verify and partition.new.digest:
            valid = _hash_file(destination, partition.new.size) == partition.new.digest
        if resume and valid:
            return destination, True
        if not force:
            raise FUSError(f"OTA output already exists: {destination}")
    needs_source = any(op.source_extents for op in partition.operations)
    if needs_source:
        if partition.old is None:
            raise FUSError(f"payload source metadata is missing for {partition.name}")
        if source_path is None or not source_path.is_file():
            raise FUSError(f"base image is required for {partition.name}")
        if source_path.stat().st_size != partition.old.size:
            raise FUSError(
                f"base {partition.name} size mismatch: expected {partition.old.size}, got {source_path.stat().st_size}"
            )
        needs_full_hash = any(op.source_extents and not op.source_digest for op in partition.operations)
        if (
            verify
            and needs_full_hash
            and (not partition.old.digest or _hash_file(source_path, partition.old.size) != partition.old.digest)
        ):
            raise FUSError(f"base image hash mismatch for {partition.name}")
    block_size = payload.manifest.block_size
    in_place = consume_source and needs_source
    if operation_limit_bytes is None:
        operation_limit_bytes = ota_operation_max_bytes(operation_workers)
    part_path = destination.with_name(f"{destination.name}.part")
    part_path.unlink(missing_ok=True)
    print_info(f"Merging OTA partition: {partition.name}")
    try:
        if in_place:
            prepare_image(source_path, part_path, consume=True)
            source_path = part_path
        with ExitStack() as stack:
            output = stack.enter_context(part_path.open("r+b" if in_place else "x+b", buffering=0))
            source_fd = stack.enter_context(source_path.open("rb", buffering=0)).fileno() if needs_source else None
            output.truncate(max(partition.new.size, partition.old.size if in_place else 0))
            if in_place:
                cached: dict[int, bytearray] = {}
                for save, index in operation_order(partition.operations, block_size):
                    operation = partition.operations[index]
                    if save:
                        cached[index] = _read_extents(source_fd, operation.source_extents, block_size)
                        continue
                    if operation.kind == 4 and index not in cached and _can_stream_in_place(operation):
                        _stream_source_copy(
                            source_fd,
                            output.fileno(),
                            operation,
                            block_size,
                            verify=verify,
                            partition_name=partition.name,
                            index=index,
                        )
                        continue
                    source = b""
                    if operation.source_extents:
                        saved = cached.pop(index, None)
                        source = (
                            saved
                            if saved is not None
                            else _read_extents(source_fd, operation.source_extents, block_size)
                        )
                    target, normalized_source = _operation_target(
                        payload, partition, operation, index, source, block_size=block_size, verify=verify
                    )
                    if target is None:
                        for extent in operation.target_extents:
                            zero_range(output, extent.start * block_size, extent.blocks * block_size)
                    elif not (
                        not normalized_source
                        and operation.kind == 4
                        and operation.source_extents == operation.target_extents
                    ):
                        _write_extents(output, operation.target_extents, block_size, target)
                    del source, target
            else:
                output_fd = output.fileno()

                def apply_independent(index: int) -> None:
                    operation = partition.operations[index]
                    if operation.kind == 4:
                        _stream_source_copy(
                            source_fd,
                            output_fd,
                            operation,
                            block_size,
                            verify=verify,
                            partition_name=partition.name,
                            index=index,
                        )
                        return
                    source = (
                        _read_extents(source_fd, operation.source_extents, block_size)
                        if operation.source_extents
                        else b""
                    )
                    target, _normalized = _operation_target(
                        payload, partition, operation, index, source, block_size=block_size, verify=verify
                    )
                    if target is not None:
                        _pwrite_extents(output_fd, operation.target_extents, block_size, target)

                if operation_workers > 1:
                    with ThreadPoolExecutor(max_workers=operation_workers) as executor:
                        pending = deque()
                        try:
                            for index, operation in enumerate(partition.operations):
                                operation_size = (
                                    operation.data_length
                                    + _extent_size(operation.source_extents, block_size)
                                    + _extent_size(operation.target_extents, block_size)
                                )
                                parallel = operation.kind in {0, 1, 4, 8} and operation_size <= operation_limit_bytes
                                if parallel:
                                    pending.append(executor.submit(apply_independent, index))
                                    if len(pending) >= operation_workers * 2:
                                        pending.popleft().result()
                                else:
                                    while pending:
                                        pending.popleft().result()
                                    apply_independent(index)
                            while pending:
                                pending.popleft().result()
                        except BaseException:
                            for future in pending:
                                future.cancel()
                            raise
                else:
                    for index in range(len(partition.operations)):
                        apply_independent(index)
            if in_place:
                end = 0
                for start, stop in chain(
                    sorted(
                        (extent.start * block_size, (extent.start + extent.blocks) * block_size)
                        for operation in partition.operations
                        for extent in operation.target_extents
                    ),
                    ((partition.new.size, partition.new.size),),
                ):
                    if end < start:
                        zero_range(output, end, start - end)
                    end = stop
            output.truncate(partition.new.size)
            output.flush()
            os.fsync(output.fileno())
        if part_path.stat().st_size != partition.new.size:
            raise FUSError(f"target size mismatch for {partition.name}")
        verified_digest = None
        if verify and partition.new.digest:
            verified_digest = _hash_file(part_path, partition.new.size)
            if verified_digest != partition.new.digest:
                raise FUSError(f"target hash mismatch for {partition.name}")
        part_path.replace(destination)
        save_outputs(
            payload.path,
            output_dir,
            (destination,),
            verify=verify,
            precomputed_hashes={destination.name: verified_digest.hex()} if verified_digest is not None else None,
        )
        return destination, False
    except BaseException as exc:
        part_path.unlink(missing_ok=True)
        if isinstance(exc, MemoryError):
            raise FUSError(
                "not enough RAM for OTA source buffers; select fewer partitions or reduce --ota-jobs"
            ) from exc
        if isinstance(exc, (OSError, EOFError, lzma.LZMAError)):
            raise FUSError(f"could not merge OTA partition {partition.name}: {exc}") from exc
        raise


def apply_payload(
    ota_path: str | Path,
    base_images: dict[str, Path],
    output_dir: Path,
    *,
    partitions: tuple[str, ...] | None = None,
    jobs: int | None = None,
    verify: bool = True,
    resume: bool = False,
    force: bool = False,
    consume_base: frozenset[str] = frozenset(),
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    with open_payload(ota_path, verify=verify) as payload:
        available = {partition.name: partition for partition in payload.manifest.partitions}
        selected_names = tuple(available) if partitions is None else tuple(dict.fromkeys(partitions))
        missing = sorted(set(selected_names) - set(available))
        if missing:
            raise FUSError(f"partitions not found in payload: {', '.join(missing)}")
        selected = [available[name] for name in selected_names]
        for partition in selected:
            _validate_partition(partition, payload.manifest.block_size)
        completed: dict[str, tuple[Path, bool]] = {}
        worker_budget = ota_worker_count() if jobs is None else max(1, int(jobs))
        partition_workers = min(worker_budget, len(selected) or 1)
        operation_workers, extra_workers = divmod(worker_budget, partition_workers)
        operation_limit_bytes = ota_operation_max_bytes(worker_budget)
        with ThreadPoolExecutor(max_workers=partition_workers) as executor:
            futures = {
                executor.submit(
                    _apply_partition,
                    payload,
                    partition,
                    base_images.get(partition.name),
                    output_dir,
                    verify=verify,
                    resume=resume,
                    force=force,
                    consume_source=partition.name in consume_base,
                    operation_workers=operation_workers + (index < extra_workers),
                    operation_limit_bytes=operation_limit_bytes,
                ): partition.name
                for index, partition in enumerate(selected)
            }
            try:
                for future in as_completed(futures):
                    completed[futures[future]] = future.result()
            except Exception:
                for future in futures:
                    future.cancel()
                raise
        ordered = tuple(completed[name][0] for name in selected_names)
        skipped = tuple(completed[name][0] for name in selected_names if completed[name][1])
        return ordered, skipped
