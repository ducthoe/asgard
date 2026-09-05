# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import xml.etree.ElementTree as ET

from ..constants import (
    _AES_BLOCK_SIZE,
    _FUS_PLACEHOLDER,
)
from ..errors import FUSError
from .auth import get_logic_check


def _upper_code(value: str) -> str:
    return str(value or "").strip().upper()


def _device_codes(model: str, region: str) -> tuple[str, str]:
    model_code = _upper_code(model)
    region_code = _upper_code(region)
    if not model_code or not region_code:
        raise ValueError("model and region are required")
    return model_code, region_code


def normalize_version_code(version_code: str) -> str:
    parts = [part.strip() for part in str(version_code or "").split("/")]
    if len(parts) == 3:
        parts.append(parts[0])
    if len(parts) >= 3 and not parts[2]:
        parts[2] = parts[0]
    return "/".join(parts)


def _xml_text(root: ET.Element, path: str) -> str | None:
    node = root.find(path)
    if node is None or node.text is None:
        return None
    text = node.text.strip()
    return text or None


def _first_xml_text(root: ET.Element, *paths: str) -> str | None:
    for path in paths:
        text = _xml_text(root, path)
        if text is not None:
            return text
    return None


def _parse_xml_response(response_text: str, source: str) -> ET.Element:
    try:
        return ET.fromstring(response_text)
    except ET.ParseError as exc:
        raise FUSError(f"{source} returned invalid XML") from exc


def _build_xml_request(*, proto_ver: str = "1") -> tuple[ET.Element, ET.Element]:
    fus_msg = ET.Element("FUSMsg")
    fus_hdr = ET.SubElement(fus_msg, "FUSHdr")
    ET.SubElement(fus_hdr, "ProtoVer").text = proto_ver
    ET.SubElement(fus_hdr, "SessionID").text = "0"
    ET.SubElement(fus_hdr, "MsgID").text = "1"
    fus_body = ET.SubElement(fus_msg, "FUSBody")
    put = ET.SubElement(fus_body, "Put")
    return fus_msg, put


def _append_data_node(parent: ET.Element, tag: str, value: str | int) -> None:
    elem = ET.SubElement(parent, tag)
    ET.SubElement(elem, "Data").text = str(value)


def build_binaryinform_request(
    model: str,
    region: str,
    *,
    firmware_version: str | None = None,
    nonce: str | None = None,
) -> bytes:
    version = normalize_version_code(firmware_version) if str(firmware_version or "").strip() else _FUS_PLACEHOLDER
    logic_check = get_logic_check(version, nonce or "") if firmware_version and nonce else _FUS_PLACEHOLDER
    fus_msg, put = _build_xml_request(proto_ver="1")
    fus_body = fus_msg.find("./FUSBody")
    ET.SubElement(put, "CmdID").text = "1"
    for tag, value in (
        ("ACCESS_MODE", "1"),
        ("BINARY_NATURE", "1"),
        ("REQUEST_TYPE", "2"),
        ("LOGIC_CHECK", logic_check),
        ("BINARY_SW_VERSION", version),
        ("DEVICE_SN_NUMBER", ""),
        ("BINARY_LOCAL_CODE", _upper_code(region)),
        ("BINARY_MODEL_NAME", _upper_code(model)),
    ):
        _append_data_node(put, tag, value)
    get = ET.SubElement(fus_body, "Get")
    ET.SubElement(get, "CmdID").text = "2"
    ET.SubElement(get, "BINARY_SW_VERSION")
    return ET.tostring(fus_msg, encoding="utf-8")


def build_smart_history_request(model: str, region: str) -> bytes:
    fus_msg, put = _build_xml_request(proto_ver="1")
    ET.SubElement(put, "CmdID").text = "1"
    for tag, value in (
        ("ACCESS_MODE", "1"),
        ("BINARY_LOCAL_CODE", _upper_code(region)),
        ("BINARY_MODEL_NAME", _upper_code(model)),
    ):
        _append_data_node(put, tag, value)
    return ET.tostring(fus_msg, encoding="utf-8")


def _binary_init_logic_input(filename: str) -> str:
    name = str(filename or "")
    if len(name) >= 25:
        return name[-25:-9]
    return name.split(".")[0][-_AES_BLOCK_SIZE:]


def build_binaryinit_request(
    filename: str,
    nonce: str,
    *,
    firmware_version: str | None = None,
    model_type: str | None = None,
    region: str | None = None,
) -> bytes:
    fus_msg, put = _build_xml_request(proto_ver="1")
    _append_data_node(put, "BINARY_NAME", filename)
    if firmware_version:
        _append_data_node(put, "BINARY_SW_VERSION", normalize_version_code(firmware_version))
    if region:
        _append_data_node(put, "DEVICE_LOCAL_CODE", _upper_code(region))
    if model_type:
        _append_data_node(put, "DEVICE_MODEL_TYPE", model_type)
    _append_data_node(put, "LOGIC_CHECK", get_logic_check(_binary_init_logic_input(filename), nonce))
    return ET.tostring(fus_msg, encoding="utf-8")
