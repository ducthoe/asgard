# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable

import requests
from Cryptodome.Cipher import AES

from ..constants import (
    _AES_BLOCK_SIZE,
    _DOWNLOAD_CHUNK_SIZE,
    _DOWNLOAD_RECOVERY_INTERVAL,
    _DOWNLOAD_RETRIES,
    _PROGRESS_REFRESH_S,
    _RATE_LIMIT_COOLDOWN_S,
    _RESUME_META_SAVE_INTERVAL_S,
    _RETRY_BACKOFF_S,
)
from ..errors import FUSError, RetryableDownloadError
from ..progress import format_bytes as _format_bytes
from ..progress import print_info as _print_info
from ..progress import render_progress as _render_progress
from ..scheduling import split_download_ranges
from .client import FUSClient
from .crypto import _decryption_key_from_info, _pkcs7_unpad, decrypted_output_path
from .firmware import _resolve_versioned_info, initialize_download
from .models import DownloadResult
from .protocol import _device_codes
from .resume import (
    _DOWNLOAD_THREADS,
    _partial_output_path,
    _prepare_range_resume_state,
    _resume_done_bytes,
    _resume_state_path,
    _save_range_resume_state,
)
from .streaming import BandwidthLimiter, _validate_content_range


def _download_output_path(
    *,
    filename: str,
    out_dir: str | os.PathLike[str] | None,
    out_file: str | os.PathLike[str] | None,
    auto_decrypt: bool,
) -> Path:
    if out_file:
        path = Path(out_file).expanduser()
    else:
        path = Path(out_dir or ".").expanduser() / filename
    return decrypted_output_path(path) if auto_decrypt else path


def _encrypted_target_path(
    *,
    filename: str,
    out_dir: str | os.PathLike[str] | None,
    out_file: str | os.PathLike[str] | None,
) -> Path:
    if out_file:
        out_path = Path(out_file).expanduser()
        if out_path.suffix.lower() in {".enc2", ".enc4"}:
            return out_path
        return out_path.with_name(f"{out_path.name}.enc4")
    return Path(out_dir or ".").expanduser() / filename


def _finalize_stream_decrypted_file(part_path: Path, final_path: Path) -> Path:
    if not part_path.is_file():
        raise FileNotFoundError(part_path)
    with part_path.open("r+b") as fh:
        if fh.seek(0, os.SEEK_END) <= 0:
            raise FUSError(f"partial file is empty: {part_path}")
        fh.seek(-_AES_BLOCK_SIZE, os.SEEK_END)
        tail = fh.read(_AES_BLOCK_SIZE)
        final_size = fh.tell() - len(tail) + len(_pkcs7_unpad(tail))
        fh.truncate(final_size)
    if final_path.exists():
        final_path.unlink()
    part_path.replace(final_path)
    return final_path


def _download_ranges_parallel(
    *,
    client: FUSClient,
    remote_path: str,
    out_path: Path,
    total_size: int,
    ranges: list[dict[str, int]],
    decrypt_key: bytes | None = None,
    recover_download: Callable[[], None] | None = None,
    rate_limiter: BandwidthLimiter | None = None,
    workers: int | None = None,
) -> None:
    if workers is not None and workers <= 0:
        raise ValueError("threads must be positive")
    workers = _DOWNLOAD_THREADS if workers is None else workers
    ranges[:] = split_download_ranges(ranges, workers=workers)
    state_lock = threading.Lock()
    stop_event = threading.Event()
    errors: list[Exception] = []
    started_at = time.monotonic()
    last_meta_save = 0.0
    last_saved_offsets: tuple[int, ...] | None = None
    meta_path = _resume_state_path(out_path)
    initial_done = _resume_done_bytes(ranges)
    recovery_lock = threading.Lock()
    worker_finished = threading.Event()
    pending_ranges = deque(idx for idx, item in enumerate(ranges) if item["offset"] <= item["end"])
    worker_limit = min(workers, len(pending_ranges))
    chunk_size = _DOWNLOAD_CHUNK_SIZE
    if rate_limiter is not None and rate_limiter.rate > 0:
        chunk_size = min(chunk_size, max(_AES_BLOCK_SIZE, int(rate_limiter.rate * _PROGRESS_REFRESH_S)))

    def worker(range_idx: int) -> None:
        segment = ranges[range_idx]
        seg_end = int(segment["end"])
        cipher = AES.new(decrypt_key, AES.MODE_ECB) if decrypt_key is not None else None
        decrypted = bytearray(chunk_size + _AES_BLOCK_SIZE) if cipher is not None else None
        decrypted_view = memoryview(decrypted) if decrypted is not None else None
        pending = b""
        attempts = 0
        with out_path.open("r+b", buffering=0) as fh:
            while not stop_event.is_set():
                with state_lock:
                    write_offset = int(segment["offset"])
                request_start = write_offset + len(pending)
                if request_start > seg_end:
                    if pending:
                        stop_event.set()
                        with state_lock:
                            errors.append(FUSError(f"range {range_idx + 1} ended with a partial encrypted block"))
                    return
                response: requests.Response | None = None
                try:
                    response = client.download_file(remote_path, start=request_start, end=seg_end)
                    _validate_content_range(
                        response,
                        start=request_start,
                        end=seg_end,
                        total_size=total_size,
                    )
                    expected_response_size = seg_end - request_start + 1
                    response_received = 0
                    fh.seek(write_offset)
                    for chunk in response.iter_content(chunk_size=chunk_size):
                        if stop_event.is_set():
                            return
                        if not chunk:
                            continue
                        if rate_limiter is not None:
                            rate_limiter.consume(len(chunk))
                        if len(chunk) > expected_response_size - response_received:
                            raise RetryableDownloadError(f"range {range_idx + 1} received more data than requested")
                        response_received += len(chunk)
                        remaining = seg_end + 1 - write_offset
                        if cipher is None:
                            if len(chunk) > remaining:
                                raise RetryableDownloadError(f"range {range_idx + 1} received more data than requested")
                            fh.write(chunk)
                            write_offset += len(chunk)
                        else:
                            pending = pending + chunk if pending else chunk
                            block_size = (len(pending) // _AES_BLOCK_SIZE) * _AES_BLOCK_SIZE
                            if block_size:
                                if block_size > remaining:
                                    raise RetryableDownloadError(
                                        f"range {range_idx + 1} received more data than requested"
                                    )
                                block = memoryview(pending)[:block_size]
                                pending = pending[block_size:]
                                plain = decrypted_view[:block_size]
                                cipher.decrypt(block, output=plain)
                                fh.write(plain)
                                write_offset += len(plain)
                        with state_lock:
                            segment["offset"] = write_offset
                    if response_received != expected_response_size:
                        raise RetryableDownloadError(
                            f"range {range_idx + 1} received {response_received} bytes, "
                            f"expected {expected_response_size}"
                        )
                    if pending:
                        raise RetryableDownloadError(f"range {range_idx + 1} ended with a partial encrypted block")
                    if write_offset != seg_end + 1:
                        raise RetryableDownloadError(
                            f"range {range_idx + 1} incomplete: expected {seg_end + 1}, got {write_offset}"
                        )
                    return
                except (requests.RequestException, OSError, RetryableDownloadError) as exc:
                    attempts += 1
                    if attempts > _DOWNLOAD_RETRIES:
                        stop_event.set()
                        with state_lock:
                            errors.append(FUSError(f"range {range_idx + 1} failed after retries: {exc}"))
                        return
                    if recover_download is not None and attempts % _DOWNLOAD_RECOVERY_INTERVAL == 0:
                        try:
                            with recovery_lock:
                                recover_download()
                        except Exception as recovery_exc:
                            stop_event.set()
                            with state_lock:
                                errors.append(FUSError(f"download recovery failed: {recovery_exc}"))
                            return
                        if stop_event.wait(_RATE_LIMIT_COOLDOWN_S):
                            return
                    if stop_event.wait(_RETRY_BACKOFF_S * attempts):
                        return
                except Exception as exc:
                    stop_event.set()
                    with state_lock:
                        errors.append(exc)
                    return
                finally:
                    if response is not None:
                        response.close()

    def run_worker() -> None:
        try:
            while not stop_event.is_set():
                with state_lock:
                    if stop_event.is_set() or not pending_ranges:
                        return
                    range_idx = pending_ranges.popleft()
                worker(range_idx)
                worker_finished.set()
        except Exception as exc:
            with state_lock:
                errors.append(exc)
                stop_event.set()
        finally:
            worker_finished.set()

    threads: list[threading.Thread] = []
    try:
        _save_range_resume_state(meta_path, total_size, ranges)
        for _ in range(worker_limit):
            thread = threading.Thread(target=run_worker, daemon=True)
            thread.start()
            threads.append(thread)
        while any(thread.is_alive() for thread in threads):
            worker_finished.clear()
            now = time.monotonic()
            with state_lock:
                done = _resume_done_bytes(ranges)
                err = errors[0] if errors else None
                snapshot = [dict(item) for item in ranges]
            _render_progress(
                "Downloading",
                done,
                total_size,
                started_at,
                speed_done=max(0, done - initial_done),
                complete=False,
            )
            if now - last_meta_save >= _RESUME_META_SAVE_INTERVAL_S:
                offsets = tuple(int(item["offset"]) for item in snapshot)
                if offsets != last_saved_offsets:
                    _save_range_resume_state(meta_path, total_size, snapshot)
                    last_saved_offsets = offsets
                last_meta_save = now
            if err is not None:
                break
            if any(thread.is_alive() for thread in threads):
                worker_finished.wait(_PROGRESS_REFRESH_S)
    finally:
        stop_event.set()
        for thread in threads:
            thread.join()
        with state_lock:
            snapshot = [dict(item) for item in ranges]
        _save_range_resume_state(meta_path, total_size, snapshot)

    with state_lock:
        done = _resume_done_bytes(ranges)
        err = errors[0] if errors else None
    _render_progress(
        "Downloading",
        done,
        total_size,
        started_at,
        speed_done=max(0, done - initial_done),
        complete=err is None and done >= total_size,
    )
    if err is not None:
        raise err
    if done != total_size:
        raise FUSError(f"incomplete download: expected {total_size} bytes, received {done}")


def download_firmware(
    *,
    model: str,
    region: str,
    firmware_version: str | None = None,
    out_dir: str | os.PathLike[str] | None = None,
    out_file: str | os.PathLike[str] | None = None,
    resume: bool = False,
    auto_decrypt: bool = False,
    threads: int | None = None,
    timeout_s: int = 30,
    rate_limit: int | None = None,
) -> DownloadResult:
    model_u, region_u = _device_codes(model, region)

    worker_count = _DOWNLOAD_THREADS if threads is None else int(threads)
    if worker_count <= 0:
        raise ValueError("threads must be positive")
    client = FUSClient(timeout_s=timeout_s)
    info = _resolve_versioned_info(client, model_u, region_u, firmware_version)
    firmware = info.binary_version or ""
    if not firmware:
        raise FUSError("FUS did not return a firmware version")

    final_path = _download_output_path(
        filename=info.filename,
        out_dir=out_dir,
        out_file=out_file,
        auto_decrypt=auto_decrypt,
    )
    encrypted_path = _encrypted_target_path(filename=info.filename, out_dir=out_dir, out_file=out_file)
    temp_path = _partial_output_path(final_path) if auto_decrypt else encrypted_path
    final_path.parent.mkdir(parents=True, exist_ok=True)

    if final_path.exists() and auto_decrypt:
        raise FUSError(f"{final_path} already exists")
    if encrypted_path.exists() and not auto_decrypt and not resume:
        raise FUSError(f"{encrypted_path} already exists, use --resume or choose another output")

    ranges, meta_path = _prepare_range_resume_state(
        temp_path,
        info.size,
        resume,
        part_count=1,
        alignment=_AES_BLOCK_SIZE if auto_decrypt else 1,
    )
    done_before = _resume_done_bytes(ranges)

    initialize_download(client, info, region_u)
    remote_path = f"{info.model_path}{info.filename}"

    def recover_download() -> None:
        client.refresh_auth()
        initialize_download(client, info, region_u)

    _print_info(f"model: {model_u}")
    _print_info(f"region: {region_u}")
    _print_info(f"firmware: {firmware}")
    _print_info(f"filename: {info.filename}")
    _print_info(f"size: {_format_bytes(info.size)}")
    _print_info(f"output: {final_path if auto_decrypt else temp_path}")
    if done_before:
        _print_info(f"resume: {_format_bytes(done_before)}")
    limiter = BandwidthLimiter(rate_limit)

    if not auto_decrypt:
        if done_before < info.size:
            _download_ranges_parallel(
                client=client,
                remote_path=remote_path,
                out_path=temp_path,
                total_size=info.size,
                ranges=ranges,
                recover_download=recover_download,
                rate_limiter=limiter,
                workers=worker_count if threads is not None else None,
            )
        meta_path.unlink(missing_ok=True)
        return DownloadResult(temp_path, None, firmware, info.filename, info.size)

    decrypt_key = _decryption_key_from_info(info, model_u, region_u)
    if done_before < info.size:
        _download_ranges_parallel(
            client=client,
            remote_path=remote_path,
            out_path=temp_path,
            total_size=info.size,
            ranges=ranges,
            decrypt_key=decrypt_key,
            recover_download=recover_download,
            rate_limiter=limiter,
            workers=worker_count if threads is not None else None,
        )
    meta_path.unlink(missing_ok=True)
    final_stream_path = _finalize_stream_decrypted_file(temp_path, final_path)
    return DownloadResult(encrypted_path, final_stream_path, firmware, info.filename, info.size)
