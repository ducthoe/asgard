# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import tarfile
import time
import zipfile
from pathlib import Path, PurePosixPath

from ..cli.progress import print_info, render_progress
from ..core.constants import _ARCHIVE_COPY_CHUNK_SIZE, _PROGRESS_REFRESH_S
from ..core.errors import FUSError
from ..formats.images import copy_image_stream, copy_lz4_stream, extract_super_partitions
from .source_cache import load_locations, save_locations, source_identity


class _ArchiveScanReader:
    def __init__(self, source, name: str, size: int):
        self.source = source
        self.label = f"Scanning {name}"
        self.size = size
        self.enabled = False
        self.resume()

    def tell(self) -> int:
        return self.source.tell()

    def read(self, size: int = -1) -> bytes:
        data = self.source.read(size)
        self.update()
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        position = self.source.seek(offset, whence)
        self.update()
        return position

    def update(self, *, complete: bool = False) -> None:
        now = time.monotonic()
        if self.enabled and (complete or now - self.last_render >= _PROGRESS_REFRESH_S):
            done = min(self.size, self.tell())
            render_progress(
                self.label, done, self.size, self.started_at, speed_done=max(0, done - self.initial), complete=complete
            )
            self.last_render = now

    def pause(self) -> None:
        self.update(complete=True)
        self.enabled = False

    def resume(self) -> None:
        self.started_at = time.monotonic()
        self.initial = self.tell()
        self.last_render = 0.0
        self.enabled = True
        self.update()


def _candidate_paths(base_dir: Path, name: str, member: str) -> tuple[Path, ...]:
    plain_member = member.removesuffix(".lz4")
    return tuple(
        dict.fromkeys(
            (
                base_dir / plain_member,
                base_dir / member,
                base_dir / f"{name}.img",
                base_dir / f"{name}.bin",
                base_dir / f"{name}.img.lz4",
                base_dir / f"{name}.bin.lz4",
            )
        )
    )


def _materialize_image(source: Path, name: str, staging: Path, *, resume: bool) -> Path:
    with source.open("rb") as stream:
        prefix = stream.read(4)
    compressed = prefix == b"\x04\x22\x4d\x18"
    sparse = prefix == b":\xff&\xed"
    if not compressed and not sparse:
        return source.resolve()
    suffix = ".bin" if Path(source.name.removesuffix(".lz4")).suffix.lower() == ".bin" else ".img"
    destination = staging / f"{name}{suffix}"
    if destination.exists() and resume:
        return destination
    if destination.exists():
        raise FUSError(f"base staging output already exists: {destination}")
    part_path = destination.with_name(f"{destination.name}.part")
    part_path.unlink(missing_ok=True)
    try:
        with source.open("rb") as input_stream, part_path.open("xb") as output:
            if compressed:
                copy_lz4_stream(input_stream, output, label=f"Preparing base {name}")
            else:
                copy_image_stream(
                    input_stream, output, label=f"Preparing base {name}", total_size=source.stat().st_size
                )
        part_path.replace(destination)
    except Exception:
        part_path.unlink(missing_ok=True)
        raise
    return destination


def _local_sources(
    source_members: dict[str, str],
    base_dir: Path | None,
    overrides: dict[str, Path],
    staging: Path,
    *,
    resume: bool,
) -> dict[str, Path]:
    sources: dict[str, Path] = {}
    for name, path in overrides.items():
        if name not in source_members:
            raise FUSError(f"base image override is not required by this OTA: {name}")
        if not path.is_file():
            raise FileNotFoundError(path)
        sources[name] = _materialize_image(path, name, staging, resume=resume)
    if base_dir is not None:
        if not base_dir.is_dir():
            raise FUSError(f"OTA base path must be a directory: {base_dir}")
        for name, member in source_members.items():
            if name in sources:
                continue
            matches = [path for path in _candidate_paths(base_dir, name, member) if path.is_file()]
            if not matches:
                for suffix in ("_a", "_b"):
                    matches = [
                        path
                        for path in _candidate_paths(base_dir, name + suffix, name + suffix + ".img.lz4")
                        if path.is_file() and path.stat().st_size > 0
                    ]
                    if matches:
                        break
            if len(matches) > 1:
                raise FUSError(f"multiple local base images for {name}; select one with --ota-base-image")
            if matches:
                sources[name] = _materialize_image(matches[0], name, staging, resume=resume)
        missing = tuple(name for name in source_members if name not in sources)
        if missing:
            super_image = next(
                (base_dir / name for name in ("super.img", "super.img.lz4") if (base_dir / name).is_file()),
                None,
            )
            if super_image is not None:
                with super_image.open("rb") as stream:
                    extracted = extract_super_partitions(
                        stream,
                        super_image.name,
                        super_image.stat().st_size,
                        requested=missing,
                        output_dir=staging,
                        slot_fallback=True,
                        allow_missing=True,
                    )
                sources.update({path.stem: path for path in extracted})
    return sources


def _download_sources(
    source_members: dict[str, str],
    sources: dict[str, Path],
    staging: Path,
    *,
    model: str,
    region: str,
    firmware_version: str,
    resume: bool,
    timeout_s: int,
    rate_limit: int | None,
    preferred_archives: tuple[str, ...] = (),
    source_cache: Path | None = None,
) -> dict[str, Path]:
    from ..formats import archive

    common = dict(
        model=model, region=region, firmware_version=firmware_version, timeout_s=timeout_s, rate_limit=rate_limit
    )
    pending = {
        name: {path.name for path in _candidate_paths(Path("."), name, member)}
        for name, member in source_members.items()
        if name not in sources
    }
    if not pending:
        return sources
    print_info("Connecting to FUS for OTA base images...")
    with archive._open_remote_firmware_archive(**common) as remote:
        entries = [
            entry
            for entry in remote.archive.infolist()
            if not entry.is_dir() and entry.filename.lower().endswith((".tar", ".tar.md5"))
        ]
        identity = source_identity(model, region, firmware_version, entries)
        entry_names = {entry.filename for entry in entries}
        locations = {
            name: entry for name, entry in load_locations(source_cache, identity).items() if entry in entry_names
        }
        declared_entries = {
            entry.filename
            for entry in entries
            if PurePosixPath(entry.filename.replace("\\", "/")).name in preferred_archives
        }
        while entries and pending:
            known_entries = {locations[name] for name in pending if name in locations}
            fully_located = all(name in locations for name in pending)
            entry = min(
                entries,
                key=lambda item: (
                    fully_located and item.filename not in known_entries,
                    item.filename not in declared_entries,
                    item.file_size,
                    preferred_archives.index(item.filename)
                    if item.filename in preferred_archives
                    else len(preferred_archives),
                    item.filename,
                ),
            )
            entries.remove(entry)
            with remote.archive.open(entry) as stream:
                scan = _ArchiveScanReader(stream, entry.filename, entry.file_size)
                mode = "r:" if entry.compress_type == zipfile.ZIP_STORED else "r|"
                try:
                    with tarfile.open(fileobj=scan, mode=mode, bufsize=_ARCHIVE_COPY_CHUNK_SIZE) as members:
                        for member in members:
                            if not member.isfile():
                                continue
                            basename = PurePosixPath(member.name.replace("\\", "/")).name
                            is_super = basename.lower() in {"super.img", "super.img.lz4"}
                            matches = [name for name, candidates in pending.items() if basename in candidates]
                            if len(matches) > 1:
                                raise FUSError(f"ambiguous OTA source member: {member.name}")
                            if not is_super and not matches:
                                continue
                            scan.pause()
                            source = members.extractfile(member)
                            if source is None:
                                raise FUSError(f"could not open OTA base member: {member.name}")
                            with source:
                                if is_super:
                                    print_info("Reading super metadata and streaming matching OTA bases...")
                                    extracted = extract_super_partitions(
                                        source,
                                        member.name,
                                        member.size,
                                        requested=tuple(pending),
                                        output_dir=staging,
                                        slot_fallback=True,
                                        allow_missing=True,
                                    )
                                    for path in extracted:
                                        sources[path.stem] = path
                                        pending.pop(path.stem)
                                        locations[path.stem] = entry.filename
                                else:
                                    name = matches[0]
                                    suffix = Path(basename.removesuffix(".lz4")).suffix
                                    destination = staging / f"{name}{suffix}"
                                    part_path = destination.with_name(f"{destination.name}.part")
                                    if destination.exists() or part_path.exists():
                                        raise FUSError(f"OTA base staging output already exists: {destination}")
                                    try:
                                        archive._write_firmware_tar_member(
                                            source,
                                            part_path,
                                            requested_name=basename,
                                            output_name=destination.name,
                                            member_size=member.size,
                                            keep_sparse=False,
                                        )
                                        part_path.replace(destination)
                                    except BaseException:
                                        part_path.unlink(missing_ok=True)
                                        raise
                                    sources[name] = destination
                                    pending.pop(name)
                                    locations[name] = entry.filename
                            save_locations(source_cache, identity, locations)
                            if not pending or all(
                                name in locations and locations[name] != entry.filename for name in pending
                            ):
                                break
                            scan.resume()
                except tarfile.TarError as exc:
                    raise FUSError(f"could not read OTA base archive {entry.filename}: {exc}") from exc
                finally:
                    scan.pause()
            for name in pending:
                if locations.get(name) == entry.filename:
                    locations.pop(name)
            save_locations(source_cache, identity, locations)
    missing = sorted(pending)
    if missing:
        raise FUSError(f"base firmware contains no images for: {', '.join(missing)}")
    return sources
