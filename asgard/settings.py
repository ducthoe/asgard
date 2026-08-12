# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

from .errors import FUSError


def config_dir() -> Path:
    configured = os.environ.get("XDG_CONFIG_HOME")
    root = Path(configured).expanduser() if configured else Path.home() / ".config"
    return root / "asgard"


def _profiles_path() -> Path:
    return config_dir() / "profiles.json"


def load_profiles() -> dict[str, dict[str, str]]:
    path = _profiles_path()
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FUSError(f"could not read profiles from {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise FUSError(f"invalid profile file: {path}")
    profiles: dict[str, dict[str, str]] = {}
    for name, value in raw.items():
        if not isinstance(name, str) or not isinstance(value, dict):
            continue
        model = str(value.get("model", "")).strip().upper()
        region = str(value.get("region", "")).strip().upper()
        if name.strip() and model and region:
            profiles[name.strip()] = {"model": model, "region": region}
    return profiles


def _save_profiles(profiles: dict[str, dict[str, str]]) -> None:
    path = _profiles_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.{secrets.token_hex(6)}.tmp")
    try:
        temporary.write_text(json.dumps(profiles, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def add_profile(name: str, model: str, region: str, *, replace: bool = False) -> dict[str, str]:
    profile_name = str(name or "").strip()
    model_code = str(model or "").strip().upper()
    region_code = str(region or "").strip().upper()
    if not profile_name or not model_code or not region_code:
        raise ValueError("profile name, model, and region are required")
    profiles = load_profiles()
    if profile_name in profiles and not replace:
        raise FUSError(f"profile {profile_name!r} already exists; use --replace to update it")
    profiles[profile_name] = {"model": model_code, "region": region_code}
    _save_profiles(profiles)
    return profiles[profile_name]


def remove_profile(name: str) -> dict[str, str]:
    profiles = load_profiles()
    try:
        removed = profiles.pop(name)
    except KeyError as exc:
        raise FUSError(f"profile not found: {name}") from exc
    _save_profiles(profiles)
    return removed


def resolve_device(model_or_profile: str, region: str | None) -> tuple[str, str]:
    if region is not None and str(region).strip():
        return str(model_or_profile).strip().upper(), str(region).strip().upper()
    name = str(model_or_profile or "").strip()
    profile = load_profiles().get(name)
    if profile is None:
        raise ValueError(f"region is required unless {name!r} is a saved profile")
    return profile["model"], profile["region"]
