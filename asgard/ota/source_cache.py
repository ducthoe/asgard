# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path


def source_identity(model: str, region: str, firmware: str, entries) -> str:
    inventory = sorted((entry.filename, entry.CRC, entry.file_size, entry.compress_size) for entry in entries)
    data = [model.upper(), region.upper(), firmware, inventory]
    return hashlib.sha256(json.dumps(data, separators=(",", ":")).encode()).hexdigest()


def load_locations(path: Path | None, identity: str) -> dict[str, str]:
    if path is None:
        return {}
    try:
        state = json.loads(path.read_text())
        locations = state["locations"]
        if state["identity"] != identity or not isinstance(locations, dict):
            return {}
        return {name: entry for name, entry in locations.items() if isinstance(name, str) and isinstance(entry, str)}
    except (OSError, ValueError, KeyError, TypeError):
        return {}


def save_locations(path: Path | None, identity: str, locations: dict[str, str]) -> None:
    if path is None:
        return
    temporary = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".ota-locations-", dir=path.parent)
        with os.fdopen(descriptor, "w") as stream:
            json.dump({"identity": identity, "locations": locations}, stream)
        Path(temporary).replace(path)
    except OSError:
        pass
    finally:
        if temporary is not None:
            try:
                Path(temporary).unlink(missing_ok=True)
            except OSError:
                pass
