# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

from importlib import import_module

_EXPORTS = {
    "BandwidthLimiter": (".streaming", "BandwidthLimiter"),
    "BinaryInfo": (".models", "BinaryInfo"),
    "DownloadResult": (".models", "DownloadResult"),
    "FUSError": ("..core.errors", "FUSError"),
    "FUSClient": (".client", "FUSClient"),
    "FirmwareHistoryEntry": (".models", "FirmwareHistoryEntry"),
    "RetryableDownloadError": ("..core.errors", "RetryableDownloadError"),
    "_FUSDecryptingReader": (".streaming", "_FUSDecryptingReader"),
    "_decryption_key_from_info": (".crypto", "_decryption_key_from_info"),
    "_device_codes": (".protocol", "_device_codes"),
    "_partial_output_path": (".resume", "_partial_output_path"),
    "_resolve_versioned_info": (".firmware", "_resolve_versioned_info"),
    "build_binaryinform_request": (".protocol", "build_binaryinform_request"),
    "build_binaryinit_request": (".protocol", "build_binaryinit_request"),
    "build_smart_history_request": (".protocol", "build_smart_history_request"),
    "decrypt_firmware": (".crypto", "decrypt_firmware"),
    "decrypt_nonce": (".auth", "decrypt_nonce"),
    "decrypted_output_path": (".crypto", "decrypted_output_path"),
    "download_firmware": (".download", "download_firmware"),
    "get_binary_info_for_version": (".firmware", "get_binary_info_for_version"),
    "get_firmware_history": (".firmware", "get_firmware_history"),
    "get_firmware_history_with_client": (".firmware", "get_firmware_history_with_client"),
    "get_latest_history_version": (".firmware", "get_latest_history_version"),
    "get_latest_version": (".firmware", "get_latest_version"),
    "get_logic_check": (".auth", "get_logic_check"),
    "get_v2_key": (".crypto", "get_v2_key"),
    "get_v4_key": (".crypto", "get_v4_key"),
    "initialize_download": (".firmware", "initialize_download"),
    "normalize_version_code": (".protocol", "normalize_version_code"),
}

__all__ = tuple(name for name in _EXPORTS if not name.startswith("_"))


def __getattr__(name: str) -> object:
    try:
        module_name, attribute = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    value = getattr(import_module(module_name, __name__), attribute)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | _EXPORTS.keys())
