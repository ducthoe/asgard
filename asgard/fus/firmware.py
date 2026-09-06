# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from ..core.constants import _LATEST_HISTORY_IGNORED_INDEXES
from ..core.errors import FUSError
from .client import FUSClient
from .models import BinaryInfo, FirmwareHistoryEntry
from .protocol import (
    _device_codes,
    _first_xml_text,
    _parse_xml_response,
    _xml_text,
    build_binaryinform_request,
    build_binaryinit_request,
    build_smart_history_request,
)


def _parse_binary_info(response_text: str) -> BinaryInfo:
    root = _parse_xml_response(response_text, "DownloadBinaryInform")
    status = _xml_text(root, "./FUSBody/Results/Status")
    if status not in {"200", "S00"}:
        raise FUSError(f"DownloadBinaryInform returned {status or 'unknown'}")
    filename = _first_xml_text(root, "./FUSBody/Put/BINARY_NAME/Data", "./FUSBody/Put/BINARY_FILE_NAME/Data")
    size_text = _xml_text(root, "./FUSBody/Put/BINARY_BYTE_SIZE/Data")
    model_path = _xml_text(root, "./FUSBody/Put/MODEL_PATH/Data")
    if not filename or not size_text or model_path is None:
        raise FUSError("FUS response did not include a downloadable firmware bundle")
    try:
        size = int(size_text)
    except ValueError as exc:
        raise FUSError(f"FUS returned an invalid firmware size: {size_text}") from exc
    return BinaryInfo(
        model_path=model_path,
        filename=filename,
        size=size,
        latest_version=_first_xml_text(
            root, "./FUSBody/Results/LATEST_FW_VERSION/Data", "./FUSBody/Results/BINARY_SW_VERSION/Data"
        ),
        logic_value_factory=_xml_text(root, "./FUSBody/Put/LOGIC_VALUE_FACTORY/Data"),
        logic_value_home=_xml_text(root, "./FUSBody/Put/LOGIC_VALUE_HOME/Data"),
        firmware_version=_xml_text(root, "./FUSBody/Put/BINARY_SW_VERSION/Data"),
        model_type=_xml_text(root, "./FUSBody/Put/DEVICE_MODEL_TYPE/Data"),
    )


def _element_data_text(element: ET.Element) -> str:
    data_node = element.find("Data")
    if data_node is not None and data_node.text is not None:
        return data_node.text.strip()
    return "".join(element.itertext()).strip()


def _add_history_field(fields: dict[str, list[str]], tag: str, value: str) -> None:
    values = fields.setdefault(tag, [])
    if value not in values:
        values.append(value)


@dataclass
class _HistoryRow:
    firmware_version: str
    index: str
    sequence: str
    open_date: str
    natures: set[str] = field(default_factory=set)
    fields: dict[str, list[str]] = field(default_factory=dict)

    def merge(self, fields: dict[str, list[str]], *, natures: set[str], open_date: str) -> None:
        self.natures.update(natures)
        if open_date > self.open_date:
            self.open_date = open_date
        for tag, values in fields.items():
            for value in values:
                _add_history_field(self.fields, tag, value)


def _first_history_field(fields: dict[str, tuple[str, ...]], *tags: str) -> str:
    for tag in tags:
        for value in fields.get(tag, ()):
            if value:
                return value
    return ""


def _android_version_from_text(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    open_idx = text.find("(")
    close_idx = text.find(")", open_idx + 1)
    if open_idx >= 0 and close_idx > open_idx:
        inner = text[open_idx + 1 : close_idx].strip()
        if inner:
            return inner
    if text.lower().startswith("android"):
        return text
    if text.isdecimal():
        return f"Android {text}"
    return ""


def _history_android_version(fields: dict[str, tuple[str, ...]], os_name: str) -> str:
    for tag in ("BINARY_ANDROID_VERSION", "ANDROID_VERSION", "BINARY_OS_VERSION", "OS_VERSION"):
        for value in fields.get(tag, ()):
            android_version = _android_version_from_text(value)
            if android_version:
                return android_version
    return _android_version_from_text(os_name)


def _freeze_history_fields(fields: dict[str, list[str]]) -> dict[str, tuple[str, ...]]:
    return {tag: tuple(values) for tag, values in fields.items()}


def _history_fields(binary_info: ET.Element) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for field_node in binary_info:
        _add_history_field(fields, field_node.tag, _element_data_text(field_node))
    return fields


def _history_row_from_fields(fields: dict[str, list[str]]) -> _HistoryRow | None:
    frozen_fields = _freeze_history_fields(fields)
    firmware_version = _first_history_field(frozen_fields, "BINARY_SW_VERSION")
    if not firmware_version:
        return None
    return _HistoryRow(
        firmware_version=firmware_version,
        index=_first_history_field(frozen_fields, "BINARY_INDEX"),
        sequence=_first_history_field(frozen_fields, "BINARY_SEQUENCE"),
        open_date=_first_history_field(frozen_fields, "BINARY_OPEN_DATE"),
        natures=set(value for value in frozen_fields.get("BINARY_NATURE", ()) if value),
        fields=fields,
    )


def _history_entry_from_row(row: _HistoryRow) -> FirmwareHistoryEntry:
    fields = _freeze_history_fields(row.fields)
    os_name = _first_history_field(fields, "BINARY_OS_NAME", "OS_NAME", "BINARY_OS_VERSION", "OS_VERSION")
    return FirmwareHistoryEntry(
        firmware_version=row.firmware_version,
        index=row.index,
        sequence=row.sequence,
        natures=tuple(sorted(row.natures)),
        open_date=row.open_date,
        android_version=_history_android_version(fields, os_name),
        os_name=os_name,
        display_version=_first_history_field(fields, "BINARY_DISPLAY_VERSION", "DISPLAY_VERSION"),
        sw_display_version=_first_history_field(fields, "BINARY_SW_DISPLAYVERSION", "SW_DISPLAYVERSION"),
        model_name=_first_history_field(fields, "BINARY_MODEL_NAME", "DEVICE_MODEL_NAME", "MODEL_NAME"),
        display_name=_first_history_field(
            fields,
            "BINARY_MODEL_DISPLAYNAME",
            "BINARY_DISPLAY_NAME",
            "DEVICE_DISPLAY_NAME",
            "DISPLAY_NAME",
        ),
        local_code=_first_history_field(fields, "BINARY_LOCAL_CODE", "DEVICE_LOCAL_CODE", "LOCAL_CODE"),
        fields=fields,
    )


def _sequence_sort_value(entry: FirmwareHistoryEntry) -> tuple[int, str]:
    try:
        return int(entry.sequence), entry.open_date
    except ValueError:
        return -1, entry.open_date


def _latest_history_candidates(rows: list[FirmwareHistoryEntry]) -> list[FirmwareHistoryEntry]:
    return [row for row in rows if str(row.index).strip() not in _LATEST_HISTORY_IGNORED_INDEXES]


def _parse_smart_history(response_text: str) -> list[FirmwareHistoryEntry]:
    root = _parse_xml_response(response_text, "SmartHistory")
    merged: dict[tuple[str, str, str], _HistoryRow] = {}
    for binary_info in root.iter("BINARY_INFO"):
        row = _history_row_from_fields(_history_fields(binary_info))
        if row is None:
            continue
        key = (row.firmware_version, row.index, row.sequence)
        if key in merged:
            merged[key].merge(row.fields, natures=row.natures, open_date=row.open_date)
        else:
            merged[key] = row

    rows = [_history_entry_from_row(row) for row in merged.values()]
    rows.sort(key=_sequence_sort_value)
    return rows


def get_firmware_history_with_client(client: FUSClient, model: str, region: str) -> list[FirmwareHistoryEntry]:
    model_u, region_u = _device_codes(model, region)
    response_text = client.make_signed_request(
        FUSClient.SMART_HISTORY_PATH,
        build_smart_history_request(model_u, region_u),
        signature=model_u,
    )
    return _parse_smart_history(response_text)


def get_firmware_history(model: str, region: str, *, timeout_s: int = 15) -> list[FirmwareHistoryEntry]:
    client = FUSClient(timeout_s=timeout_s)
    return get_firmware_history_with_client(client, model, region)


def get_latest_history_version(client: FUSClient, model: str, region: str) -> str:
    rows = get_firmware_history_with_client(client, model, region)
    if not rows:
        raise FUSError("SmartHistory did not return firmware history")
    latest_candidates = _latest_history_candidates(rows)
    if not latest_candidates:
        raise FUSError("SmartHistory did not return non-index-90 firmware history")
    return latest_candidates[-1].firmware_version


def get_latest_version(model: str, region: str, *, timeout_s: int = 15) -> str:
    client = FUSClient(timeout_s=timeout_s)
    return get_latest_history_version(client, model, region)


def get_binary_info_for_version(client: FUSClient, model: str, region: str, firmware_version: str) -> BinaryInfo:
    client.ensure_auth()
    response_text = client.make_request(
        FUSClient.BINARY_INFORM_PATH,
        build_binaryinform_request(model, region, firmware_version=firmware_version, nonce=client.nonce),
    )
    return _parse_binary_info(response_text)


def _resolve_versioned_info(client: FUSClient, model: str, region: str, firmware_version: str | None) -> BinaryInfo:
    if str(firmware_version or "").strip():
        return get_binary_info_for_version(client, model, region, str(firmware_version))
    resolved_version = get_latest_history_version(client, model, region)
    return get_binary_info_for_version(client, model, region, resolved_version)


def initialize_download(client: FUSClient, info: BinaryInfo, region: str) -> None:
    client.make_request(
        FUSClient.BINARY_INIT_PATH,
        build_binaryinit_request(
            info.filename,
            client.nonce,
            firmware_version=info.binary_version,
            model_type=info.model_type,
            region=region,
        ),
    )
