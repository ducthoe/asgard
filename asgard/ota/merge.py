# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import fnmatch
import shutil
import tempfile
from dataclasses import replace
from pathlib import Path

from ..cli.progress import print_info
from ..core.errors import FUSError
from .a_only import apply_block_ota, block_direct_files, block_partitions, block_source_members, validate_block_targets
from .ab import apply_payload, payload_partitions, validate_payload_targets
from .metadata import read_ota_metadata, resolve_base_firmware
from .models import OtaMergeResult, OtaPlan
from .sources import _download_sources, _local_sources
from .state import completed_outputs


def inspect_ota(
    path_value: str | Path,
    *,
    forced_type: str = "auto",
    verify: bool = True,
) -> OtaPlan:
    metadata = read_ota_metadata(path_value, forced_type=forced_type)
    if metadata.ota_type == "ab":
        partitions = payload_partitions(metadata.path, verify=verify)
        files = ()
    else:
        partitions = block_partitions(metadata.path)
        files = block_direct_files(metadata.path)
    if len({part.name for part in partitions}) != len(partitions):
        raise FUSError("duplicate OTA partition names")
    for name in [part.output_name for part in partitions] + [file.name for file in files]:
        if Path(name).name != name or "\\" in name:
            raise FUSError(f"invalid OTA output filename: {name}")
    return OtaPlan(metadata, partitions, files)


def _selectors(values: tuple[str, ...], available: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    selected: list[str] = []
    for raw_selector in values:
        for raw_pattern in raw_selector.split(","):
            pattern = raw_pattern.strip().casefold()
            if not pattern:
                continue
            matches = [
                name
                for name in available
                if fnmatch.fnmatchcase(name.casefold(), pattern)
                or fnmatch.fnmatchcase(Path(name).stem.casefold(), pattern)
            ]
            if not matches:
                raise FUSError(f"OTA {label} selector matched nothing: {raw_pattern.strip()}")
            selected.extend(matches)
    if values and not selected:
        raise FUSError(f"OTA {label} selectors cannot be empty")
    return tuple(dict.fromkeys(selected))


def select_ota_targets(
    plan: OtaPlan,
    partition_selectors: tuple[str, ...] | None,
    file_selectors: tuple[str, ...] | None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    available_partitions = tuple(partition.name for partition in plan.partitions)
    available_files = tuple(file.name for file in plan.files)
    if partition_selectors is None and file_selectors is None:
        return available_partitions, available_files
    partitions = (
        () if partition_selectors is None else _selectors(partition_selectors, available_partitions, label="partition")
    )
    files = () if file_selectors is None else _selectors(file_selectors, available_files, label="file")
    return partitions, files


def _source_members(plan: OtaPlan, selected: tuple[str, ...]) -> dict[str, str]:
    selected_set = set(selected)
    if plan.metadata.ota_type == "block":
        return {
            name: member for name, member in block_source_members(plan.metadata.path).items() if name in selected_set
        }
    return {
        partition.name: f"{partition.name}.img.lz4"
        for partition in plan.partitions
        if partition.source_required and partition.name in selected_set
    }


def _validate_targets(plan: OtaPlan, selected: tuple[str, ...], *, verify: bool) -> None:
    if plan.metadata.ota_type == "ab":
        validate_payload_targets(plan.metadata.path, selected, verify=verify)
    else:
        validate_block_targets(plan.metadata.path, selected)


def _target_names(plan: OtaPlan, selected: tuple[str, ...], files: tuple[str, ...]) -> tuple[str, ...]:
    names = {part.name: part.output_name for part in plan.partitions}
    outputs = tuple(names[name] for name in selected) + files
    if len(set(outputs)) != len(outputs):
        raise FUSError("OTA targets have conflicting output filenames")
    return outputs


def _check_existing_outputs(output: Path, names: tuple[str, ...], completed: dict[str, Path], *, force: bool) -> None:
    if not force:
        for name in names:
            if (output / name).exists() and name not in completed:
                raise FUSError(
                    f"OTA output exists without a matching completion record: {output / name}; use --ota-force to replace it"
                )


def _validate_model_and_base(
    plan: OtaPlan,
    model: str,
    firmware_version: str,
    *,
    force: bool,
) -> None:
    model_code = model.upper().removeprefix("SM-")
    source_ap = plan.metadata.base_ap
    if source_ap and not source_ap.startswith(model_code) and not force:
        raise FUSError(f"OTA base {source_ap} does not belong to {model}")
    supplied_ap = firmware_version.split("/", 1)[0].upper()
    if source_ap and supplied_ap and supplied_ap != source_ap and not force:
        raise FUSError(f"OTA requires base AP {source_ap}; {firmware_version} needs --ota-force")
    supplied_parts = firmware_version.upper().split("/")
    if plan.metadata.base_csc and len(supplied_parts) > 1 and supplied_parts[1] != plan.metadata.base_csc and not force:
        raise FUSError(f"OTA requires base CSC {plan.metadata.base_csc}; {firmware_version} needs --ota-force")


def merge_ota(
    ota_path: str | Path,
    output: str | Path,
    base_images: dict[str, Path],
    *,
    partitions: tuple[str, ...] | None = None,
    files: tuple[str, ...] | None = None,
    jobs: int = 4,
    forced_type: str = "auto",
    verify: bool = True,
    resume: bool = False,
    force: bool = False,
    consume_base: frozenset[str] = frozenset(),
) -> OtaMergeResult:
    plan = inspect_ota(ota_path, forced_type=forced_type, verify=verify)
    selected, selected_files = select_ota_targets(plan, partitions, files)
    _validate_targets(plan, selected, verify=verify)
    output_dir = Path(output).expanduser().resolve()
    if output_dir.exists() and not output_dir.is_dir():
        raise FUSError(f"OTA output must be a directory: {output_dir}")
    normalized = {name: Path(path).expanduser().resolve() for name, path in base_images.items()}
    output_names = {part.name: part.output_name for part in plan.partitions}
    expected_names = _target_names(plan, selected, selected_files)
    completed = completed_outputs(plan.metadata.path, output_dir, verify=verify, names=expected_names) if resume else {}
    _check_existing_outputs(output_dir, expected_names, completed, force=force)
    target_paths = {(output_dir / (name + suffix)).resolve() for name in expected_names for suffix in ("", ".part")}
    if any(path in target_paths for path in normalized.values()):
        raise FUSError("local base images must be separate from OTA output paths")
    prior = tuple(completed.values())
    selected = tuple(name for name in selected if output_names[name] not in completed)
    selected_files = tuple(name for name in selected_files if name not in completed)
    if plan.metadata.ota_type == "ab":
        paths, skipped = apply_payload(
            plan.metadata.path,
            normalized,
            output_dir,
            partitions=selected,
            jobs=jobs,
            verify=verify,
            resume=resume,
            force=force,
            consume_base=consume_base,
        )
    else:
        paths, skipped = apply_block_ota(
            plan.metadata.path,
            normalized,
            output_dir,
            partitions=selected,
            files=selected_files,
            jobs=jobs,
            verify=verify,
            resume=resume,
            force=force,
            consume_base=consume_base,
        )
    outputs = {path.name: path for path in prior + paths}
    paths = tuple(outputs[name] for name in expected_names)
    skipped_names = {path.name for path in prior + skipped}
    skipped = tuple(path for path in paths if path.name in skipped_names)
    return OtaMergeResult(plan.metadata, plan.metadata.base_firmware, paths, skipped)


def download_and_merge_ota(
    *,
    ota_path: str | Path,
    model: str,
    region: str,
    output: str | Path,
    firmware_version: str | None = None,
    base_dir: str | Path | None = None,
    base_images: dict[str, Path] | None = None,
    partitions: tuple[str, ...] | None = None,
    files: tuple[str, ...] | None = None,
    jobs: int = 4,
    forced_type: str = "auto",
    verify: bool = True,
    resume: bool = False,
    keep_base: bool = False,
    force: bool = False,
    timeout_s: int = 30,
    rate_limit: int | None = None,
) -> OtaMergeResult:
    plan = inspect_ota(ota_path, forced_type=forced_type, verify=verify)
    selected, selected_files = select_ota_targets(plan, partitions, files)
    _validate_targets(plan, selected, verify=verify)
    source_members = _source_members(plan, selected)
    output_names = {part.name: part.output_name for part in plan.partitions}
    base_version = firmware_version or ""
    _validate_model_and_base(plan, model, base_version, force=force)
    output_dir = Path(output).expanduser().resolve()
    if output_dir.exists() and not output_dir.is_dir():
        raise FUSError(f"OTA output must be a directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    expected_names = _target_names(plan, selected, selected_files)
    completed = completed_outputs(plan.metadata.path, output_dir, verify=verify, names=expected_names) if resume else {}
    source_members = {name: member for name, member in source_members.items() if output_names[name] not in completed}
    _check_existing_outputs(output_dir, expected_names, completed, force=force)
    staging = Path(tempfile.mkdtemp(prefix=".asgard-ota-", dir=output_dir))
    override_paths = {name: Path(path).expanduser().resolve() for name, path in (base_images or {}).items()}
    local_dir = Path(base_dir).expanduser().resolve() if base_dir is not None else None
    override_paths = {
        name: path
        for name, path in override_paths.items()
        if name not in output_names or output_names[name] not in completed
    }
    try:
        sources = _local_sources(source_members, local_dir, override_paths, staging, resume=resume)
        if len(sources) != len(source_members):
            base_version = resolve_base_firmware(
                plan.metadata, model, region, firmware_version=firmware_version, timeout_s=timeout_s
            )
            _validate_model_and_base(plan, model, base_version, force=force)
            print_info(f"base firmware: {base_version}")
            sources = _download_sources(
                source_members,
                sources,
                staging,
                model=model,
                region=region,
                firmware_version=base_version,
                resume=resume,
                timeout_s=timeout_s,
                rate_limit=rate_limit,
                preferred_archives=(plan.metadata.source_csc_name, plan.metadata.source_ap_name),
            )
        result = merge_ota(
            plan.metadata.path,
            output_dir,
            sources,
            partitions=selected,
            files=selected_files,
            jobs=jobs,
            forced_type=forced_type,
            verify=verify,
            resume=resume,
            force=force,
            consume_base=frozenset(name for name, path in sources.items() if path.is_relative_to(staging))
            if not keep_base
            else frozenset(),
        )
    finally:
        if not keep_base:
            shutil.rmtree(staging)
    return OtaMergeResult(
        replace(result.metadata, base_firmware=base_version),
        base_version,
        result.paths,
        result.skipped,
        staging if keep_base else None,
    )
