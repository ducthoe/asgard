# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import hashlib
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from Cryptodome.Cipher import AES

from ..cli.progress import render_progress as _render_progress
from ..core.constants import _AES_BLOCK_SIZE, _PROGRESS_REFRESH_S
from ..core.errors import FUSError
from .auth import get_logic_check
from .client import FUSClient
from .firmware import _resolve_versioned_info
from .models import BinaryInfo
from .protocol import _upper_code, normalize_version_code
from .resume import _partial_output_path, _prepare_range_resume_state, _resume_done_bytes, _save_range_resume_state


def _available_worker_count() -> int:
    try:
        affinity = os.sched_getaffinity(0)
    except (AttributeError, OSError):
        affinity = None
    if affinity:
        return max(1, len(affinity))
    return max(1, os.cpu_count() or 1)


_DECRYPT_THREADS = _available_worker_count()


def _md5_digest(text: str) -> bytes:
    return hashlib.md5(text.encode("utf-8"), usedforsecurity=False).digest()


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise FUSError("invalid PKCS#7 payload")
    pad_len = data[-1]
    if pad_len <= 0 or pad_len > _AES_BLOCK_SIZE or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise FUSError("invalid PKCS#7 padding")
    return data[:-pad_len]


def decrypted_output_path(path: str | os.PathLike[str]) -> Path:
    in_path = Path(path).expanduser()
    if in_path.suffix.lower() in {".enc2", ".enc4"}:
        return in_path.with_suffix("")
    return in_path.with_name(f"{in_path.name}.dec")


def get_v4_key(
    model: str,
    region: str,
    *,
    firmware_version: str | None = None,
    timeout_s: int = 30,
) -> bytes:
    client = FUSClient(timeout_s=timeout_s)
    info = _resolve_versioned_info(client, model, region, firmware_version)
    binary_version = info.binary_version
    logic_value = info.logic_value
    if not binary_version or not logic_value:
        raise FUSError("FUS did not return the logic value required for v4 decryption")
    return _md5_digest(get_logic_check(binary_version, logic_value))


def get_v2_key(version: str, model: str, region: str) -> bytes:
    deckey = f"{_upper_code(region)}:{_upper_code(model)}:{normalize_version_code(version)}"
    return _md5_digest(deckey)


def _decryption_key_from_info(info: BinaryInfo, model: str, region: str) -> bytes:
    firmware = info.binary_version
    if not firmware:
        raise FUSError("FUS did not return a firmware version")
    if info.filename.lower().endswith(".enc2"):
        return get_v2_key(firmware, model, region)
    if not info.logic_value:
        raise FUSError("FUS did not return the logic value required for v4 decryption")
    return _md5_digest(get_logic_check(firmware, info.logic_value))


def _decrypt_range(
    in_path: Path,
    out_path: Path,
    key: bytes,
    start: int,
    end: int,
    progress: Callable[[int], None] | None = None,
) -> None:
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = bytearray(1024 * 1024)
    decrypted = bytearray(len(encrypted))
    encrypted_view = memoryview(encrypted)
    decrypted_view = memoryview(decrypted)
    with in_path.open("rb") as inf, out_path.open("r+b") as outf:
        inf.seek(start)
        outf.seek(start)
        remaining = end - start + 1
        while remaining > 0:
            chunk_size = min(len(encrypted), remaining)
            chunk_size -= chunk_size % _AES_BLOCK_SIZE
            if chunk_size == 0:
                chunk_size = remaining
            data = encrypted_view[:chunk_size]
            if inf.readinto(data) != chunk_size:
                raise FUSError("unexpected end of encrypted input")
            plain = decrypted_view[:chunk_size]
            cipher.decrypt(data, output=plain)
            outf.write(plain)
            remaining -= chunk_size
            if progress is not None:
                progress(chunk_size)


def _finalize_decrypted_file(path: Path) -> None:
    with path.open("r+b") as fh:
        if fh.seek(0, os.SEEK_END) <= 0:
            raise FUSError("decrypted file is empty")
        fh.seek(-_AES_BLOCK_SIZE, os.SEEK_END)
        tail = fh.read(_AES_BLOCK_SIZE)
        final_size = fh.tell() - len(tail) + len(_pkcs7_unpad(tail))
        fh.truncate(final_size)


def decrypt_firmware(
    *,
    version: str | None,
    model: str,
    region: str,
    in_file: str | os.PathLike[str],
    out_file: str | os.PathLike[str],
    enc_ver: int = 4,
    resume: bool = False,
    threads: int | None = None,
    timeout_s: int = 30,
) -> Path:
    in_path = Path(in_file).expanduser()
    out_path = Path(out_file).expanduser()
    if not in_path.is_file():
        raise FileNotFoundError(in_path)
    length = in_path.stat().st_size
    if length % _AES_BLOCK_SIZE != 0:
        raise FUSError("invalid encrypted input size")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        raise FUSError(f"{out_path} already exists")
    worker_count = _DECRYPT_THREADS if threads is None else int(threads)
    if worker_count <= 0:
        raise ValueError("threads must be positive")
    if int(enc_ver) == 4:
        key = get_v4_key(model, region, firmware_version=version, timeout_s=timeout_s)
    else:
        if not str(version or "").strip():
            raise ValueError("firmware version is required for enc2 decrypt")
        key = get_v2_key(str(version), model, region)

    part_path = _partial_output_path(out_path)
    ranges, meta_path = _prepare_range_resume_state(
        part_path,
        length,
        resume,
        part_count=worker_count,
        alignment=_AES_BLOCK_SIZE,
    )

    done = _resume_done_bytes(ranges)
    done_lock = threading.Lock()
    started_at = time.monotonic()

    def worker(item: dict[str, int]) -> None:
        def update_progress(size: int) -> None:
            nonlocal done
            with done_lock:
                done += size
                item["offset"] = int(item["offset"]) + size

        start = int(item["offset"])
        end = int(item["end"])
        if start <= end:
            _decrypt_range(in_path, part_path, key, start, end, progress=update_progress)
            with done_lock:
                item["offset"] = end + 1

    with ThreadPoolExecutor(max_workers=min(worker_count, len(ranges)) or 1) as executor:
        futures = [executor.submit(worker, item) for item in ranges]
        last_saved = -1
        while True:
            completed = all(future.done() for future in futures)
            with done_lock:
                current_done = done
                snapshot = [dict(item) for item in ranges]
            _render_progress(
                "Decrypting", current_done, length, started_at, complete=completed and current_done >= length
            )
            if current_done != last_saved:
                _save_range_resume_state(meta_path, length, snapshot)
                last_saved = current_done
            if completed:
                for future in futures:
                    future.result()
                break
            time.sleep(_PROGRESS_REFRESH_S)

    _finalize_decrypted_file(part_path)
    part_path.replace(out_path)
    meta_path.unlink(missing_ok=True)
    return out_path
