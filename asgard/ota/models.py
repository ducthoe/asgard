# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class OtaMetadata:
    path: Path
    ota_type: str
    pre_build: str
    post_build: str
    pre_incremental: str
    post_incremental: str
    source_ap_name: str
    source_csc_name: str
    base_firmware: str
    properties: Mapping[str, str]
    base_ap: str = ""
    base_csc: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "type": self.ota_type,
            "pre_build": self.pre_build,
            "post_build": self.post_build,
            "pre_incremental": self.pre_incremental,
            "post_incremental": self.post_incremental,
            "source_ap_name": self.source_ap_name,
            "source_csc_name": self.source_csc_name,
            "base_firmware": self.base_firmware,
            "base_ap": self.base_ap,
            "base_csc": self.base_csc,
        }


@dataclass(frozen=True)
class OtaPartition:
    name: str
    size: int
    source_required: bool
    operations: Mapping[str, int]
    filename: str = ""

    @property
    def output_name(self) -> str:
        return self.filename or f"{self.name}.img"

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "size": self.size,
            "source_required": self.source_required,
            "operations": dict(self.operations),
            "filename": self.output_name,
        }


@dataclass(frozen=True)
class OtaFile:
    name: str
    size: int

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "size": self.size}


@dataclass(frozen=True)
class OtaPlan:
    metadata: OtaMetadata
    partitions: tuple[OtaPartition, ...]
    files: tuple[OtaFile, ...]

    @property
    def source_partitions(self) -> tuple[str, ...]:
        return tuple(partition.name for partition in self.partitions if partition.source_required)

    def to_dict(self) -> dict[str, object]:
        return {
            "metadata": self.metadata.to_dict(),
            "partitions": [partition.to_dict() for partition in self.partitions],
            "files": [file.to_dict() for file in self.files],
        }


@dataclass(frozen=True)
class OtaMergeResult:
    metadata: OtaMetadata
    base_firmware: str
    paths: tuple[Path, ...]
    skipped: tuple[Path, ...]
    base_path: Path | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "metadata": self.metadata.to_dict(),
            "base_firmware": self.base_firmware,
            "paths": [str(path) for path in self.paths],
            "skipped": [str(path) for path in self.skipped],
            "base_path": str(self.base_path) if self.base_path else None,
        }
