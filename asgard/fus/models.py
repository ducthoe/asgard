# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class BinaryInfo:
    model_path: str
    filename: str
    size: int
    latest_version: str | None = None
    logic_value_factory: str | None = None
    logic_value_home: str | None = None
    firmware_version: str | None = None
    model_type: str | None = None

    @property
    def logic_value(self) -> str | None:
        return self.logic_value_factory or self.logic_value_home

    @property
    def binary_version(self) -> str | None:
        return self.firmware_version or self.latest_version


@dataclass(frozen=True)
class DownloadResult:
    encrypted_path: Path
    decrypted_path: Path | None
    firmware_version: str
    filename: str
    size: int


@dataclass(frozen=True)
class FirmwareHistoryEntry:
    firmware_version: str
    index: str
    sequence: str
    natures: tuple[str, ...]
    open_date: str
    android_version: str = ""
    os_name: str = ""
    display_version: str = ""
    sw_display_version: str = ""
    model_name: str = ""
    display_name: str = ""
    local_code: str = ""
    fields: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "firmware_version": self.firmware_version,
            "index": self.index,
            "sequence": self.sequence,
            "natures": list(self.natures),
            "open_date": self.open_date,
            "android_version": self.android_version,
            "os_name": self.os_name,
            "display_version": self.display_version,
            "sw_display_version": self.sw_display_version,
            "model_name": self.model_name,
            "display_name": self.display_name,
            "local_code": self.local_code,
            "fields": {tag: list(values) for tag, values in self.fields.items()},
        }
