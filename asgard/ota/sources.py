# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

from pathlib import Path

from ..core.errors import FUSError
from ..formats.images import copy_image_stream, copy_lz4_stream, extract_super_partitions, list_super_partitions


def _super_matches(available, requested) -> tuple[str, ...]:
    names = {item.name for item in available if item.size > 0}
    return tuple(
        name for name in requested if any(candidate in names for candidate in (name, name + "_a", name + "_b"))
    )


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
        missing_dynamic = tuple(name for name in source_members if name not in sources)
        if missing_dynamic:
            super_image = next(
                (base_dir / name for name in ("super.img", "super.img.lz4") if (base_dir / name).is_file()),
                None,
            )
            if super_image is not None:
                with super_image.open("rb") as stream:
                    available = list_super_partitions(stream, super_image.name, super_image.stat().st_size)
                missing_dynamic = _super_matches(available, missing_dynamic)
            if super_image is not None and missing_dynamic:
                with super_image.open("rb") as stream:
                    extracted = extract_super_partitions(
                        stream,
                        super_image.name,
                        super_image.stat().st_size,
                        requested=missing_dynamic,
                        output_dir=staging,
                        slot_fallback=True,
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
) -> dict[str, Path]:
    from ..formats import archive

    common = dict(
        model=model, region=region, firmware_version=firmware_version, timeout_s=timeout_s, rate_limit=rate_limit
    )
    listing = archive.list_firmware_entries(**common)
    entries = [entry.name for entry in listing.entries if entry.name.lower().endswith((".tar", ".tar.md5"))]
    entries.sort(
        key=lambda name: (
            preferred_archives.index(name) if name in preferred_archives else len(preferred_archives),
            name,
        )
    )
    found = set(sources)
    direct = {}
    supers = []
    for entry in entries:
        if all(name in found for name in source_members):
            break
        members = archive.iter_firmware_tar_entries(outer_selector=entry, **common)
        try:
            for member in members:
                pending = tuple(name for name in source_members if name not in found)
                if not pending:
                    break
                if Path(member.name).name.lower() in {"super.img", "super.img.lz4"}:
                    available = tuple(archive.iter_firmware_super_partitions(outer_selector=entry, **common))
                    selected = _super_matches(available, pending)
                    if selected:
                        supers.append((entry, selected))
                        found.update(selected)
                    if all(name in found for name in source_members):
                        break
                    continue
                matches = [
                    name
                    for name in pending
                    if Path(member.name).name
                    in {path.name for path in _candidate_paths(Path("."), name, source_members[name])}
                ]
                if len(matches) > 1:
                    raise FUSError(f"ambiguous OTA source member: {member.name}")
                if matches:
                    direct[matches[0]] = (entry, member.name)
                    found.add(matches[0])
                    if all(name in found for name in source_members):
                        break
        finally:
            members.close()
    missing = sorted(set(source_members) - found)
    if missing:
        raise FUSError(f"base firmware contains no images for: {', '.join(missing)}")
    for entry, selected in supers:
        extracted = archive.download_firmware_super_partitions(
            outer_selector=entry, partitions=selected, output=staging, slot_fallback=True, **common
        )
        sources.update({path.stem: path for path in extracted})
    for name, (entry, member) in direct.items():
        sources[name] = archive.download_firmware_tar_member(
            outer_selector=entry, member_name=member, out_dir=staging, **common
        )
    return sources
