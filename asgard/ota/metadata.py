# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import re
import zipfile
from pathlib import Path

from ..core.errors import FUSError
from .models import OtaMetadata

_METADATA_PATH = "META-INF/com/android/metadata"
_SOURCE_AP_RE = re.compile(r"^AP_([^_]+)_")
_SOURCE_CSC_RE = re.compile(r"^(?:HOME_)?CSC_[^_]+_([^_]+)_")
_UI_PRINT_RE = re.compile(r'\bui_print\s*\(\s*"((?:[^"\\]|\\.)*)"\s*\)', re.S)
_SOURCE_QB_RE = re.compile(r"^\s*(?:\[[^\]\n]*\]\s*)?source binary QB info\b", re.I)


def source_archive_hints(metadata: OtaMetadata) -> tuple[str, ...]:
    names = [
        value.strip()
        for key, value in metadata.properties.items()
        if key.startswith("source-") and key.endswith("-name")
    ]
    with zipfile.ZipFile(metadata.path) as archive:
        try:
            script = archive.read("META-INF/com/google/android/updater-script").decode("utf-8", "replace")
        except KeyError:
            script = ""
    for match in _UI_PRINT_RE.finditer(script):
        message = match[1].replace("\\n", "\n")
        if _SOURCE_QB_RE.match(message):
            names.extend(line.strip() for line in message.splitlines()[1:])
    return tuple(dict.fromkeys(name for name in names if re.fullmatch(r"[^\s/\\\x00]+\.tar(?:\.md5)?", name, re.I)))


def _read_properties(raw: bytes) -> dict[str, str]:
    properties: dict[str, str] = {}
    for raw_line in raw.decode("utf-8", "replace").splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        properties[key.strip()] = value.strip()
    return properties


def _source_version(name: str, pattern: re.Pattern[str]) -> str:
    match = pattern.match(name)
    return match.group(1).upper() if match else ""


def read_ota_metadata(path_value: str | Path, *, forced_type: str = "auto") -> OtaMetadata:
    path = Path(path_value).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            if len(names) != len(archive.infolist()):
                raise FUSError("OTA ZIP contains duplicate entry names")
            try:
                properties = _read_properties(archive.read(_METADATA_PATH))
            except KeyError as exc:
                raise FUSError(f"OTA metadata is missing: {_METADATA_PATH}") from exc
    except zipfile.BadZipFile as exc:
        raise FUSError(f"invalid OTA ZIP: {path}") from exc
    detected = (
        "ab" if "payload.bin" in names else "block" if any(name.endswith(".transfer.list") for name in names) else ""
    )
    requested = forced_type.strip().lower()
    if requested not in {"auto", "ab", "block"}:
        raise ValueError(f"unknown OTA format: {forced_type}")
    if not detected:
        raise FUSError("OTA ZIP contains neither payload.bin nor block transfer lists")
    if requested != "auto" and requested != detected:
        raise FUSError(f"OTA is {detected}, not the requested {requested} format")
    declared = properties.get("ota-type", "").strip().lower()
    if declared and declared != detected:
        raise FUSError(f"OTA metadata declares {declared}, but its contents are {detected}")
    source_ap_name = properties.get("source-ap-name", "")
    source_csc_name = properties.get("source-csc-name", "")
    ap_version = _source_version(source_ap_name, _SOURCE_AP_RE) or properties.get("pre-build-incremental", "").upper()
    csc_version = _source_version(source_csc_name, _SOURCE_CSC_RE)
    return OtaMetadata(
        path=path,
        ota_type=detected,
        pre_build=properties.get("pre-build", ""),
        post_build=properties.get("post-build", ""),
        pre_incremental=properties.get("pre-build-incremental", ""),
        post_incremental=properties.get("post-build-incremental", ""),
        source_ap_name=source_ap_name,
        source_csc_name=source_csc_name,
        base_firmware="",
        base_ap=ap_version,
        base_csc=csc_version,
        properties=properties,
    )


def resolve_base_firmware(
    metadata: OtaMetadata, model: str, region: str, *, firmware_version: str | None = None, timeout_s: int = 30
) -> str:
    from ..fus import get_firmware_history

    supplied = tuple(part.strip().upper() for part in firmware_version.split("/")) if firmware_version else ()
    if supplied and len(supplied) not in {3, 4}:
        raise FUSError("OTA base firmware must have three or four version components")
    if len(supplied) == 4 and all(supplied):
        return "/".join(supplied)
    ap = supplied[0] if supplied else metadata.base_ap
    csc = supplied[1] if supplied else metadata.base_csc
    if not ap:
        raise FUSError("OTA does not identify its base AP version; pass --firmware")
    matches = set()
    for row in get_firmware_history(model, region, timeout_s=timeout_s):
        parts = tuple(part.strip().upper() for part in row.firmware_version.split("/"))
        if len(parts) != 4 or not all(parts):
            continue
        if parts[0] != ap or (csc and parts[1] != csc):
            continue
        if supplied and any(value and parts[index] != value for index, value in enumerate(supplied)):
            continue
        matches.add("/".join(parts))
    if len(matches) != 1:
        reason = "no complete matching version" if not matches else "multiple matching versions"
        raise FUSError(
            f"firmware history for {model}/{region} has {reason} for {ap}/{csc}; pass an explicit four-part --firmware"
        )
    return matches.pop()
