# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import hashlib
import os
import re
import shutil
import struct
import zipfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

from ...cli.progress import print_info
from ...core.errors import FUSError
from ..buffers import SourceBuffers
from ..inplace import prepare_image, zero_range
from ..models import OtaFile, OtaPartition
from ..patch import apply_bsdiff
from ..state import save_outputs

_BLOCK_SIZE = 4096
_COPY_SIZE = 4 * 1024 * 1024
_ZIP_LOCAL_HEADER = struct.Struct("<I5H3I2H")
_ZIP_LOCAL_MAGIC = 0x04034B50
_TRANSFER_SUFFIX = ".transfer.list"
_DIRECT_SUFFIXES = (".img", ".bin")
_PATCH_CALL_RE = re.compile(r'patch_partition\((.*?package_extract_file\("([^"\n]+\.p)"\)\s*\))', re.S)
_PATCH_DESCRIPTOR_RE = re.compile(r":(\d+):([0-9a-fA-F]{40})")
_PARTITION_NAME_RE = re.compile(r"/by-name/([A-Za-z0-9_-]+)")
_COMMAND_MIN_TOKENS = {"new": 2, "zero": 2, "erase": 2, "move": 5, "bsdiff": 8, "imgdiff": 8, "stash": 3, "free": 2}
_COMMAND_TARGET_INDEX = {"new": 1, "zero": 1, "erase": 1, "move": 2, "bsdiff": 5, "imgdiff": 5}


@dataclass(frozen=True)
class _Ranges:
    values: tuple[tuple[int, int], ...]

    @property
    def blocks(self) -> int:
        return sum(end - start for start, end in self.values)


@dataclass(frozen=True)
class _StashUse:
    name: str
    locations: _Ranges


@dataclass(frozen=True)
class _SourceSpec:
    digest: str
    blocks: int
    ranges: _Ranges
    locations: _Ranges | None
    stashes: tuple[_StashUse, ...]


@dataclass(frozen=True)
class _PatchSpec:
    name: str
    source_member: str
    patch_entry: str
    size: int
    source_digest: str
    target_digest: str
    source_size: int


@dataclass(frozen=True)
class _Transfer:
    name: str
    target_blocks: int
    commands: tuple[str, ...]


def _parse_ranges(value: str) -> _Ranges:
    try:
        numbers = [int(item) for item in value.split(",")]
    except ValueError as exc:
        raise FUSError(f"invalid OTA range set: {value}") from exc
    if not numbers or numbers[0] != len(numbers) - 1 or numbers[0] % 2:
        raise FUSError(f"invalid OTA range set: {value}")
    pairs = tuple(zip(numbers[1::2], numbers[2::2], strict=True))
    if any(start < 0 or end <= start for start, end in pairs):
        raise FUSError(f"invalid OTA range set: {value}")
    ordered = sorted(pairs)
    if any(right[0] < left[1] for left, right in zip(ordered, ordered[1:])):
        raise FUSError(f"overlapping OTA range set: {value}")
    return _Ranges(pairs)


def _parse_transfer(name: str, raw: bytes) -> _Transfer:
    if not re.fullmatch(r"[A-Za-z0-9_-]+\.transfer\.list", name):
        raise FUSError(f"invalid transfer list name: {name}")
    try:
        lines = tuple(line.strip() for line in raw.decode("ascii").splitlines() if line.strip())
    except UnicodeError as exc:
        raise FUSError(f"invalid transfer list encoding: {name}") from exc
    if len(lines) < 4:
        raise FUSError(f"truncated transfer list: {name}")
    try:
        version = int(lines[0])
        target_blocks = int(lines[1])
        int(lines[2])
        int(lines[3])
    except ValueError as exc:
        raise FUSError(f"invalid transfer list header: {name}") from exc
    if version not in {3, 4} or target_blocks <= 0:
        raise FUSError(f"unsupported transfer list {name}: version {version}")
    maximum = 0
    for line in lines[4:]:
        tokens = line.split()
        minimum = _COMMAND_MIN_TOKENS.get(tokens[0])
        if minimum is not None and (
            len(tokens) < minimum or (tokens[0] in {"new", "zero", "erase", "stash", "free"} and len(tokens) != minimum)
        ):
            raise FUSError(f"invalid {tokens[0]} command in {name}")
        index = _COMMAND_TARGET_INDEX.get(tokens[0])
        if index is not None:
            ranges = _parse_ranges(tokens[index])
            maximum = max(maximum, max((end for _, end in ranges.values), default=0))
    return _Transfer(name.removesuffix(_TRANSFER_SUFFIX), maximum, lines[4:])


def _target_size(archive: zipfile.ZipFile, transfer: _Transfer, base_size: int = 0) -> int:
    if "dynamic_partitions_op_list" in archive.namelist():
        for line in archive.read("dynamic_partitions_op_list").decode("ascii").splitlines():
            tokens = line.split()
            if len(tokens) == 3 and tokens[:2] == ["resize", transfer.name]:
                size = int(tokens[2])
                if size < transfer.target_blocks * _BLOCK_SIZE:
                    raise FUSError(f"OTA writes outside resized {transfer.name}")
                return size
    if "META-INF/com/google/android/updater-script" in archive.namelist():
        script = archive.read("META-INF/com/google/android/updater-script").decode("utf-8", "replace")
        match = re.search(r"range_scan\([^\n]*?/by-name/" + re.escape(transfer.name) + r'",\s*"2,0,(\d+)"', script)
        if match:
            return max(int(match[1]) * _BLOCK_SIZE, transfer.target_blocks * _BLOCK_SIZE)
    return max(base_size, transfer.target_blocks * _BLOCK_SIZE)


def _direct_entries(archive: zipfile.ZipFile) -> tuple[str, ...]:
    return tuple(
        info.filename
        for info in archive.infolist()
        if "/" not in info.filename
        and info.filename.lower().endswith(_DIRECT_SUFFIXES)
        and not info.filename.lower().endswith((".img.p", ".bin.p"))
    )


def _patch_specs(archive: zipfile.ZipFile) -> tuple[_PatchSpec, ...]:
    patch_entries = {name for name in archive.namelist() if name.endswith((".img.p", ".bin.p"))}
    try:
        script = archive.read("META-INF/com/google/android/updater-script").decode("utf-8", "replace")
    except KeyError:
        if patch_entries:
            raise FUSError("OTA partition patches require updater-script source and target declarations")
        return ()
    specs: list[_PatchSpec] = []
    for match in _PATCH_CALL_RE.finditer(script):
        descriptors = _PATCH_DESCRIPTOR_RE.findall(match.group(1))
        names = _PARTITION_NAME_RE.findall(match.group(1))
        if len(descriptors) < 2 or not names:
            continue
        source_size, source_digest = descriptors[0]
        target_size, target_digest = descriptors[1]
        filename = Path(match.group(2)).name.removesuffix(".p")
        name, member = Path(filename).stem, filename + ".lz4"
        specs.append(
            _PatchSpec(
                name=name,
                source_member=member,
                patch_entry=match.group(2),
                size=int(target_size),
                source_digest=source_digest.lower(),
                target_digest=target_digest.lower(),
                source_size=int(source_size),
            )
        )
    missing = patch_entries - {spec.patch_entry for spec in specs}
    if missing:
        raise FUSError(f"unsupported OTA partition patch declarations: {', '.join(sorted(missing))}")
    return tuple(specs)


def block_partitions(path_value: str | Path) -> tuple[OtaPartition, ...]:
    path = Path(path_value)
    try:
        with zipfile.ZipFile(path) as archive:
            transfers = tuple(
                _parse_transfer(info.filename, archive.read(info))
                for info in archive.infolist()
                if "/" not in info.filename and info.filename.endswith(_TRANSFER_SUFFIX)
            )
            patches = _patch_specs(archive)
            sizes = {transfer.name: _target_size(archive, transfer) for transfer in transfers}
    except zipfile.BadZipFile as exc:
        raise FUSError(f"invalid block OTA: {path}") from exc
    partitions = [
        OtaPartition(
            transfer.name,
            sizes[transfer.name],
            any(command.split(" ", 1)[0] in {"move", "bsdiff", "imgdiff", "stash"} for command in transfer.commands),
            dict(Counter(command.split(" ", 1)[0].upper() for command in transfer.commands)),
        )
        for transfer in transfers
    ]
    partitions.extend(
        OtaPartition(spec.name, spec.size, True, {"BSDIFF": 1}, Path(spec.patch_entry).name.removesuffix(".p"))
        for spec in patches
    )
    return tuple(partitions)


def block_direct_files(path_value: str | Path) -> tuple[OtaFile, ...]:
    with zipfile.ZipFile(path_value) as archive:
        return tuple(OtaFile(name, archive.getinfo(name).file_size) for name in _direct_entries(archive))


def block_source_members(path_value: str | Path) -> dict[str, str]:
    with zipfile.ZipFile(path_value) as archive:
        result = {
            transfer.name: f"{transfer.name}.img.lz4"
            for transfer in (
                _parse_transfer(info.filename, archive.read(info))
                for info in archive.infolist()
                if "/" not in info.filename and info.filename.endswith(_TRANSFER_SUFFIX)
            )
            if any(command.split(" ", 1)[0] in {"move", "bsdiff", "imgdiff", "stash"} for command in transfer.commands)
        }
        result.update({spec.name: spec.source_member for spec in _patch_specs(archive)})
        return result


def _read_ranges(source, ranges: _Ranges) -> bytes:
    output = bytearray(ranges.blocks * _BLOCK_SIZE)
    position = 0
    for start, end in ranges.values:
        size = (end - start) * _BLOCK_SIZE
        source.seek(start * _BLOCK_SIZE)
        chunk = source.read(size)
        if len(chunk) != size:
            raise FUSError("base image is shorter than an OTA source range")
        output[position : position + size] = chunk
        position += size
    return bytes(output)


def _write_ranges(output, ranges: _Ranges, data: bytes) -> None:
    size = ranges.blocks * _BLOCK_SIZE
    if len(data) != size:
        raise FUSError(f"OTA command output size mismatch: expected {size}, got {len(data)}")
    position = 0
    for start, end in ranges.values:
        amount = (end - start) * _BLOCK_SIZE
        output.seek(start * _BLOCK_SIZE)
        output.write(data[position : position + amount])
        position += amount


def _copy_stream_to_ranges(source, output, ranges: _Ranges) -> None:
    for start, end in ranges.values:
        output.seek(start * _BLOCK_SIZE)
        remaining = (end - start) * _BLOCK_SIZE
        while remaining:
            chunk = source.read(min(_COPY_SIZE, remaining))
            if not chunk:
                raise FUSError("new-data stream ended before all target ranges were written")
            output.write(chunk)
            remaining -= len(chunk)


def _zero_ranges(output, ranges: _Ranges) -> None:
    for start, end in ranges.values:
        zero_range(output, start * _BLOCK_SIZE, (end - start) * _BLOCK_SIZE)


def _place_ranges(target: bytearray, locations: _Ranges, source: bytes) -> None:
    if len(source) != locations.blocks * _BLOCK_SIZE:
        raise FUSError("OTA stash location size mismatch")
    if any(end * _BLOCK_SIZE > len(target) for _, end in locations.values):
        raise FUSError("OTA source location exceeds its buffer")
    position = 0
    for start, end in locations.values:
        amount = (end - start) * _BLOCK_SIZE
        target[start * _BLOCK_SIZE : end * _BLOCK_SIZE] = source[position : position + amount]
        position += amount


def _source_spec(tokens: list[str], digest: str) -> tuple[_Ranges, _SourceSpec]:
    if len(tokens) < 3:
        raise FUSError("invalid OTA source command")
    target = _parse_ranges(tokens[0])
    try:
        blocks = int(tokens[1])
    except ValueError as exc:
        raise FUSError("invalid OTA source block count") from exc
    position = 2
    ranges = _Ranges(())
    locations = None
    if tokens[position] == "-":
        position += 1
    else:
        ranges = _parse_ranges(tokens[position])
        position += 1
        if position < len(tokens):
            locations = _parse_ranges(tokens[position])
            position += 1
    stashes: list[_StashUse] = []
    for token in tokens[position:]:
        name, separator, raw_locations = token.partition(":")
        if not separator:
            raise FUSError("invalid OTA stash reference")
        stashes.append(_StashUse(name, _parse_ranges(raw_locations)))
    represented = ranges.blocks + sum(stash.locations.blocks for stash in stashes)
    if blocks < 0:
        raise FUSError("invalid OTA source block count")
    if represented != blocks:
        raise FUSError(f"OTA source block count mismatch: expected {blocks}, got {represented}")
    if locations is not None and locations.blocks != ranges.blocks:
        raise FUSError("OTA source location block count mismatch")
    placements = list(locations.values if locations is not None else ((0, ranges.blocks),) if ranges.blocks else ())
    placements.extend(pair for stash in stashes for pair in stash.locations.values)
    end = 0
    for start, stop in sorted(placements):
        if start != end or stop > blocks:
            raise FUSError("OTA source locations overlap or leave gaps")
        end = stop
    if end != blocks:
        raise FUSError("OTA source locations do not fill the buffer")
    return target, _SourceSpec(digest.lower(), blocks, ranges, locations, tuple(stashes))


def _load_source(output, source: _SourceSpec, stashes: SourceBuffers, *, verify: bool) -> bytes:
    result = bytearray(source.blocks * _BLOCK_SIZE)
    if source.ranges.blocks:
        raw = _read_ranges(output, source.ranges)
        if source.locations is None:
            result[: len(raw)] = raw
        else:
            _place_ranges(result, source.locations, raw)
    for stash in source.stashes:
        try:
            raw = stashes[stash.name]
        except KeyError as exc:
            raise FUSError(f"OTA stash is unavailable: {stash.name}") from exc
        _place_ranges(result, stash.locations, raw)
    data = bytes(result)
    if verify and source.digest and hashlib.sha1(data).hexdigest() != source.digest:
        raise FUSError("OTA source range hash mismatch")
    return data


def _validate_transfer(archive: zipfile.ZipFile, transfer: _Transfer) -> None:
    entries = set(archive.namelist())
    new_size = 0
    stashes: dict[str, int] = {}
    for line in transfer.commands:
        tokens = line.split()
        command = tokens[0]
        if command not in {"bsdiff", "erase", "free", "move", "new", "stash", "zero"}:
            raise FUSError(f"unsupported block OTA command for {transfer.name}: {command}")
        if command == "new":
            new_size += _parse_ranges(tokens[1]).blocks * _BLOCK_SIZE
        elif command == "stash":
            if not re.fullmatch(r"[0-9a-fA-F]{40}", tokens[1]):
                raise FUSError(f"invalid stash hash for {transfer.name}")
            blocks = _parse_ranges(tokens[2]).blocks
            if stashes.setdefault(tokens[1], blocks) != blocks:
                raise FUSError(f"inconsistent OTA stash size for {transfer.name}")
        elif command == "free":
            stashes.pop(tokens[1], None)
        elif command in {"move", "bsdiff"}:
            digest_tokens = tokens[1:2] if command == "move" else tokens[3:5]
            if any(not re.fullmatch(r"[0-9a-fA-F]{40}", digest) for digest in digest_tokens):
                raise FUSError(f"invalid source/target hash for {transfer.name}")
            target, source = (
                _source_spec(tokens[2:], tokens[1]) if command == "move" else _source_spec(tokens[5:], tokens[3])
            )
            if command == "move" and target.blocks != source.blocks:
                raise FUSError(f"OTA move size mismatch for {transfer.name}")
            for stash in source.stashes:
                if stashes.get(stash.name) != stash.locations.blocks:
                    raise FUSError(f"missing or incorrectly sized OTA stash: {stash.name}")
            if command == "bsdiff":
                entry = f"{transfer.name}.patch.dat"
                if entry not in entries:
                    raise FUSError(f"patch-data stream is missing for {transfer.name}")
                info = archive.getinfo(entry)
                if info.compress_type != zipfile.ZIP_STORED:
                    raise FUSError(f"OTA patch data must be stored without compression: {entry}")
                try:
                    offset, size = int(tokens[1]), int(tokens[2])
                except ValueError as exc:
                    raise FUSError(f"invalid OTA patch offset for {transfer.name}") from exc
                if offset < 0 or size <= 0 or offset + size > info.file_size:
                    raise FUSError(f"OTA patch range exceeds {entry}")
    entry = f"{transfer.name}.new.dat"
    if new_size and entry not in entries:
        raise FUSError(f"new-data stream is missing for {transfer.name}")
    if entry in entries and archive.getinfo(entry).file_size != new_size:
        raise FUSError(f"new-data size mismatch for {transfer.name}")


def validate_block_targets(path_value: str | Path, selected: tuple[str, ...]) -> None:
    with zipfile.ZipFile(path_value) as archive:
        for name in selected:
            entry = f"{name}{_TRANSFER_SUFFIX}"
            if entry in archive.namelist():
                _validate_transfer(archive, _parse_transfer(entry, archive.read(entry)))
        for spec in _patch_specs(archive):
            if spec.name in selected and spec.patch_entry not in archive.namelist():
                raise FUSError(f"OTA partition patch is missing: {spec.patch_entry}")


def _stored_entry_offset(path: Path, info: zipfile.ZipInfo) -> tuple[int, int]:
    if info.compress_type != zipfile.ZIP_STORED:
        raise FUSError(f"OTA patch data must be stored without compression: {info.filename}")
    file_descriptor = os.open(path, os.O_RDONLY)
    try:
        raw = os.pread(file_descriptor, _ZIP_LOCAL_HEADER.size, info.header_offset)
        if len(raw) != _ZIP_LOCAL_HEADER.size:
            raise FUSError("truncated OTA ZIP header")
        values = _ZIP_LOCAL_HEADER.unpack(raw)
        if values[0] != _ZIP_LOCAL_MAGIC:
            raise FUSError("invalid OTA ZIP header")
        offset = info.header_offset + _ZIP_LOCAL_HEADER.size + values[-2] + values[-1]
        return file_descriptor, offset
    except BaseException:
        os.close(file_descriptor)
        raise


def _apply_transfer(
    ota_path: Path,
    transfer: _Transfer,
    source_path: Path | None,
    output_dir: Path,
    *,
    verify: bool,
    resume: bool,
    force: bool,
    consume_source: bool = False,
    work_dir: Path | None = None,
) -> tuple[Path, bool]:
    destination = output_dir / f"{transfer.name}.img"
    with zipfile.ZipFile(ota_path) as archive:
        _validate_transfer(archive, transfer)
        expected_size = _target_size(archive, transfer, source_path.stat().st_size if source_path else 0)
    if destination.exists():
        if not force:
            raise FUSError(f"OTA output already exists: {destination}")
    if source_path is not None and not source_path.is_file():
        raise FUSError(f"base image is required for {transfer.name}")
    part_path = destination.with_name(f"{destination.name}.part")
    part_path.unlink(missing_ok=True)
    print_info(f"Merging OTA partition: {transfer.name}")
    patch_fd = -1
    try:
        if source_path is not None:
            prepare_image(source_path, part_path, consume=consume_source)
        else:
            with part_path.open("xb") as empty:
                empty.truncate(expected_size)
        with zipfile.ZipFile(ota_path) as archive, ExitStack() as stack:
            new_entry = f"{transfer.name}.new.dat"
            patch_entry = f"{transfer.name}.patch.dat"
            new_stream = stack.enter_context(archive.open(new_entry)) if new_entry in archive.namelist() else None
            if patch_entry in archive.namelist():
                patch_fd, patch_offset = _stored_entry_offset(ota_path, archive.getinfo(patch_entry))
            else:
                patch_offset = 0
            stashes = stack.enter_context(SourceBuffers(work_dir))
            with part_path.open("r+b") as output:
                output.truncate(max(output.seek(0, os.SEEK_END), expected_size))
                for raw_command in transfer.commands:
                    tokens = raw_command.split()
                    command = tokens.pop(0)
                    if command == "new":
                        if new_stream is None:
                            raise FUSError(f"new-data stream is missing for {transfer.name}")
                        _copy_stream_to_ranges(new_stream, output, _parse_ranges(tokens[0]))
                    elif command in {"zero", "erase"}:
                        _zero_ranges(output, _parse_ranges(tokens[0]))
                    elif command == "stash":
                        if tokens[0] in stashes:
                            continue
                        raw = _read_ranges(output, _parse_ranges(tokens[1]))
                        if verify and hashlib.sha1(raw).hexdigest() != tokens[0].lower():
                            raise FUSError(f"OTA stash hash mismatch for {transfer.name}")
                        stashes[tokens[0]] = raw
                        del raw
                    elif command == "free":
                        stashes.discard(tokens[0])
                    elif command == "move":
                        target, source = _source_spec(tokens[1:], tokens[0])
                        result = _load_source(output, source, stashes, verify=verify)
                        _write_ranges(output, target, result)
                        if verify and hashlib.sha1(result).hexdigest() != tokens[0].lower():
                            raise FUSError(f"OTA move target hash mismatch for {transfer.name}")
                    else:
                        if patch_fd < 0:
                            raise FUSError(f"patch-data stream is missing for {transfer.name}")
                        try:
                            offset, size = int(tokens[0]), int(tokens[1])
                        except ValueError as exc:
                            raise FUSError("invalid OTA patch offset") from exc
                        target, source = _source_spec(tokens[4:], tokens[2])
                        source_data = _load_source(output, source, stashes, verify=verify)
                        patch = os.pread(patch_fd, size, patch_offset + offset)
                        if len(patch) != size:
                            raise FUSError(f"truncated patch data for {transfer.name}")
                        result = apply_bsdiff(source_data, patch, expected_size=target.blocks * _BLOCK_SIZE)
                        if verify and hashlib.sha1(result).hexdigest() != tokens[3].lower():
                            raise FUSError(f"OTA patch target hash mismatch for {transfer.name}")
                        _write_ranges(output, target, result)
                if new_stream is not None:
                    if new_stream.read(1):
                        raise FUSError(f"unused new-data bytes for {transfer.name}")
                output.truncate(expected_size)
                output.flush()
                os.fsync(output.fileno())
        if patch_fd >= 0:
            os.close(patch_fd)
            patch_fd = -1
        part_path.replace(destination)
        save_outputs(ota_path, output_dir, (destination,), verify=verify)
        return destination, False
    except BaseException as exc:
        if patch_fd >= 0:
            os.close(patch_fd)
        part_path.unlink(missing_ok=True)
        if isinstance(exc, (OSError, EOFError, zipfile.BadZipFile)):
            raise FUSError(f"could not merge OTA partition {transfer.name}: {exc}") from exc
        raise


def _sha1_file(path: Path) -> str:
    digest = hashlib.sha1()
    with path.open("rb") as source:
        while chunk := source.read(_COPY_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _apply_partition_patch(
    ota_path: Path,
    spec: _PatchSpec,
    source_path: Path,
    output_dir: Path,
    *,
    verify: bool,
    resume: bool,
    force: bool,
    consume_source: bool = False,
) -> tuple[Path, bool]:
    destination = output_dir / Path(spec.patch_entry).name.removesuffix(".p")
    if destination.exists():
        valid = destination.stat().st_size == spec.size
        if valid and verify:
            valid = _sha1_file(destination) == spec.target_digest
        if resume and valid:
            return destination, True
        if not force:
            raise FUSError(f"OTA output already exists: {destination}")
    if source_path.stat().st_size != spec.source_size:
        raise FUSError(f"base {spec.name} size mismatch")
    if verify and _sha1_file(source_path) != spec.source_digest:
        raise FUSError(f"base {spec.name} hash mismatch")
    print_info(f"Merging OTA partition: {spec.name}")
    with zipfile.ZipFile(ota_path) as archive:
        patch = archive.read(spec.patch_entry)
    result = apply_bsdiff(source_path.read_bytes(), patch, expected_size=spec.size)
    if verify and hashlib.sha1(result).hexdigest() != spec.target_digest:
        raise FUSError(f"target {spec.name} hash mismatch")
    part_path = destination.with_name(f"{destination.name}.part")
    part_path.unlink(missing_ok=True)
    try:
        if consume_source:
            prepare_image(source_path, part_path, consume=True)
        with part_path.open("wb") as output:
            output.write(result)
            output.flush()
            os.fsync(output.fileno())
        part_path.replace(destination)
        save_outputs(ota_path, output_dir, (destination,), verify=verify)
    except Exception:
        part_path.unlink(missing_ok=True)
        raise
    return destination, False


def _copy_direct_entry(
    ota_path: Path,
    entry: str,
    output_dir: Path,
    *,
    resume: bool,
    force: bool,
    verify: bool = True,
) -> tuple[Path, bool]:
    destination = output_dir / Path(entry).name
    with zipfile.ZipFile(ota_path) as archive:
        size = archive.getinfo(entry).file_size
        if destination.exists():
            if resume and destination.stat().st_size == size:
                import zlib

                crc = 0
                with destination.open("rb") as existing:
                    while chunk := existing.read(_COPY_SIZE):
                        crc = zlib.crc32(chunk, crc)
                if crc == archive.getinfo(entry).CRC:
                    return destination, True
            if not force:
                raise FUSError(f"OTA output already exists: {destination}")
        print_info(f"Extracting OTA target: {entry}")
        part_path = destination.with_name(f"{destination.name}.part")
        part_path.unlink(missing_ok=True)
        try:
            with archive.open(entry) as source, part_path.open("xb") as output:
                shutil.copyfileobj(source, output, _COPY_SIZE)
                output.flush()
                os.fsync(output.fileno())
            if part_path.stat().st_size != size:
                raise FUSError(f"OTA entry size mismatch: {entry}")
            part_path.replace(destination)
            save_outputs(ota_path, output_dir, (destination,), verify=verify)
        except Exception:
            part_path.unlink(missing_ok=True)
            raise
    return destination, False


def apply_block_ota(
    ota_path_value: str | Path,
    base_images: dict[str, Path],
    output_dir: Path,
    *,
    partitions: tuple[str, ...] | None = None,
    files: tuple[str, ...] | None = None,
    jobs: int = 4,
    verify: bool = True,
    resume: bool = False,
    force: bool = False,
    consume_base: frozenset[str] = frozenset(),
    work_dir: Path | None = None,
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    ota_path = Path(ota_path_value).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(ota_path) as archive:
        transfers = tuple(
            _parse_transfer(info.filename, archive.read(info))
            for info in archive.infolist()
            if "/" not in info.filename and info.filename.endswith(_TRANSFER_SUFFIX)
        )
        patches = _patch_specs(archive)
        direct = _direct_entries(archive)
    available = {item.name for item in transfers} | {item.name for item in patches}
    selected = available if partitions is None else set(partitions)
    missing = sorted(selected - available)
    if missing:
        raise FUSError(f"partitions not found in block OTA: {', '.join(missing)}")
    available_files = set(direct)
    selected_files = available_files if files is None else set(files)
    missing_files = sorted(selected_files - available_files)
    if missing_files:
        raise FUSError(f"files not found in block OTA: {', '.join(missing_files)}")
    validate_block_targets(ota_path, tuple(selected))
    output_names = [f"{item.name}.img" for item in transfers if item.name in selected]
    output_names.extend(Path(item.patch_entry).name.removesuffix(".p") for item in patches if item.name in selected)
    output_names.extend(item for item in direct if item in selected_files)
    if len(set(output_names)) != len(output_names):
        raise FUSError("OTA targets have conflicting output filenames")
    tasks = []
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as executor:
        for transfer in transfers:
            if transfer.name in selected:
                source = base_images.get(transfer.name)
                if source is None and any(
                    line.split()[0] in {"move", "bsdiff", "imgdiff", "stash"} for line in transfer.commands
                ):
                    raise FUSError(f"base image is required for {transfer.name}")
                tasks.append(
                    (
                        f"{transfer.name}.img",
                        executor.submit(
                            _apply_transfer,
                            ota_path,
                            transfer,
                            source,
                            output_dir,
                            verify=verify,
                            resume=resume,
                            force=force,
                            consume_source=transfer.name in consume_base,
                            work_dir=work_dir,
                        ),
                    )
                )
        for spec in patches:
            if spec.name in selected:
                source = base_images.get(spec.name)
                if source is None:
                    raise FUSError(f"base image is required for {spec.name}")
                tasks.append(
                    (
                        Path(spec.patch_entry).name.removesuffix(".p"),
                        executor.submit(
                            _apply_partition_patch,
                            ota_path,
                            spec,
                            source,
                            output_dir,
                            verify=verify,
                            resume=resume,
                            force=force,
                            consume_source=spec.name in consume_base,
                        ),
                    )
                )
        for entry in direct:
            if entry in selected_files:
                tasks.append(
                    (
                        entry,
                        executor.submit(
                            _copy_direct_entry,
                            ota_path,
                            entry,
                            output_dir,
                            resume=resume,
                            force=force,
                            verify=verify,
                        ),
                    )
                )
        completed: dict[str, tuple[Path, bool]] = {}
        try:
            for name, future in tasks:
                completed[name] = future.result()
        except Exception:
            for _name, future in tasks:
                future.cancel()
            raise
    paths = tuple(completed[name][0] for name in output_names)
    skipped = tuple(completed[name][0] for name in output_names if completed[name][1])
    return paths, skipped
