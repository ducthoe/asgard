# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import zipfile
from pathlib import Path

_STATE_LOCK = threading.Lock()


def image_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(4 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def ota_identity(path: Path) -> str:
    with zipfile.ZipFile(path) as archive:
        entries = [(info.filename, info.file_size, info.CRC) for info in archive.infolist()]
    return hashlib.sha256(json.dumps(entries).encode()).hexdigest()


def completed_outputs(
    ota: Path, output: Path, *, verify: bool = True, names: tuple[str, ...] | None = None
) -> dict[str, Path]:
    selected = set(names) if names is not None else None
    try:
        state = json.loads((output / ".asgard-ota.json").read_text())
        if state["ota"] != ota_identity(ota):
            return {}
        if verify and not state.get("verified", False):
            return {}
        return {
            name: output / name
            for name, digest in state["outputs"].items()
            if (selected is None or name in selected)
            and Path(name).name == name
            and (output / name).is_file()
            and image_hash(output / name) == digest
        }
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {}


def save_outputs(ota: Path, output: Path, paths: tuple[Path, ...], *, verify: bool = True) -> None:
    hashes = {path.name: image_hash(path) for path in paths}
    identity = ota_identity(ota)
    with _STATE_LOCK:
        try:
            state = json.loads((output / ".asgard-ota.json").read_text())
            existing = state["outputs"] if state["ota"] == identity and state.get("verified") == verify else {}
            if not isinstance(existing, dict):
                existing = {}
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            existing = {}
        existing.update(hashes)
        _write_state(output, {"ota": identity, "verified": verify, "outputs": existing})


def _write_state(output: Path, state: dict) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".ota-state-", dir=output)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(state, stream)
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary).replace(output / ".asgard-ota.json")
    finally:
        Path(temporary).unlink(missing_ok=True)
