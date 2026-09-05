# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import secrets
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from typing import Callable, Iterator

import requests
from Cryptodome.Cipher import AES

from .constants import (
    _AES_BLOCK_SIZE,
    _ARCHIVE_TAIL_CACHE_SIZE,
    _AUTH_AES_KEY,
    _AUTH_NONCE_COUNT,
    _AUTH_SIGNATURE_ALPHABET,
    _DOWNLOAD_CHUNK_SIZE,
    _DOWNLOAD_RECOVERY_INTERVAL,
    _DOWNLOAD_RETRIES,
    _FUS_BASE_URL,
    _FUS_DOWNLOAD_URL,
    _FUS_PLACEHOLDER,
    _FUS_USER_AGENT,
    _LATEST_HISTORY_IGNORED_INDEXES,
    _PROGRESS_REFRESH_S,
    _RANGE_CHUNK_SIZE,
    _RATE_LIMIT_COOLDOWN_S,
    _RESUME_META_SAVE_INTERVAL_S,
    _RETRY_BACKOFF_S,
    _THREAD_STAGGER_S,
)
from .errors import FUSError, RetryableDownloadError
from .progress import format_bytes as _format_bytes
from .progress import print_info as _print_info
from .progress import render_progress as _render_progress


def _available_worker_count() -> int:
    try:
        affinity = os.sched_getaffinity(0)
    except (AttributeError, OSError):
        affinity = None
    if affinity:
        return max(1, len(affinity))
    return max(1, os.cpu_count() or 1)


_DOWNLOAD_THREADS = _available_worker_count()
_DECRYPT_THREADS = _available_worker_count()
_CONTENT_RANGE_RE = re.compile(r"bytes\s+(\d+)-(\d+)/(\d+|\*)", re.IGNORECASE)


class BandwidthLimiter:
    def __init__(self, bytes_per_second: int | None):
        self.rate = int(bytes_per_second or 0)
        if self.rate < 0:
            raise ValueError("bandwidth limit cannot be negative")
        self._lock = threading.Lock()
        self._available_at = time.monotonic()

    def consume(self, size: int) -> None:
        if self.rate <= 0 or size <= 0:
            return
        duration = size / self.rate
        with self._lock:
            now = time.monotonic()
            start = max(now, self._available_at)
            finish = start + duration
            self._available_at = finish
        delay = finish - time.monotonic()
        if delay > 0:
            time.sleep(delay)


def _md5_digest(text: str) -> bytes:
    return hashlib.md5(text.encode("utf-8"), usedforsecurity=False).digest()


def _md5_hexdigest(text: str) -> str:
    return hashlib.md5(text.encode("utf-8"), usedforsecurity=False).hexdigest()


def _upper_code(value: str) -> str:
    return str(value or "").strip().upper()


def _device_codes(model: str, region: str) -> tuple[str, str]:
    model_code = _upper_code(model)
    region_code = _upper_code(region)
    if not model_code or not region_code:
        raise ValueError("model and region are required")
    return model_code, region_code


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


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise FUSError("invalid PKCS#7 payload")
    pad_len = data[-1]
    if pad_len <= 0 or pad_len > _AES_BLOCK_SIZE or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise FUSError("invalid PKCS#7 padding")
    return data[:-pad_len]


def _authenticate_block(in_block: bytes) -> bytes:
    if len(in_block) != _AES_BLOCK_SIZE:
        raise FUSError("nonce block is too short")
    return AES.new(_AUTH_AES_KEY, AES.MODE_ECB).encrypt(in_block)


def decrypt_nonce(enc_nonce: str) -> str:
    seed = enc_nonce[:_AES_BLOCK_SIZE].ljust(_AES_BLOCK_SIZE, "0").encode("utf-8")
    return _authenticate_block(seed).hex()


def normalize_version_code(version_code: str) -> str:
    parts = [part.strip() for part in str(version_code or "").split("/")]
    if len(parts) == 3:
        parts.append(parts[0])
    if len(parts) >= 3 and not parts[2]:
        parts[2] = parts[0]
    return "/".join(parts)


def get_logic_check(value: str, nonce: str) -> str:
    if len(value) < _AES_BLOCK_SIZE:
        raise FUSError("logic check input too short")
    return "".join(value[ord(ch) & 0xF] for ch in nonce)


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


def decrypted_output_path(path: str | os.PathLike[str]) -> Path:
    in_path = Path(path).expanduser()
    if in_path.suffix.lower() in {".enc2", ".enc4"}:
        return in_path.with_suffix("")
    return in_path.with_name(f"{in_path.name}.dec")


def _partial_output_path(path: Path) -> Path:
    return path.with_name(f"{path.name}.part")


def _resume_state_path(path: Path) -> Path:
    return path.with_name(f"{path.name}.resume.json")


def _build_range_parts(total_size: int, part_count: int = _DOWNLOAD_THREADS) -> list[dict[str, int]]:
    if total_size <= 0:
        return []
    block_size = _AES_BLOCK_SIZE
    max_parts = max(1, total_size // block_size)
    parts = max(1, min(int(part_count), max_parts))
    ranges: list[dict[str, int]] = []
    start = 0
    for idx in range(parts):
        if idx == parts - 1:
            end = total_size - 1
        else:
            remaining_parts = parts - idx
            remaining_bytes = total_size - start
            seg_len = max(block_size, (remaining_bytes // remaining_parts) // block_size * block_size)
            max_len = remaining_bytes - (remaining_parts - 1) * block_size
            seg_len = min(seg_len, max_len)
            end = start + seg_len - 1
        ranges.append({"start": start, "end": end, "offset": start})
        start = end + 1
    return ranges


def _save_range_resume_state(meta_path: Path, total_size: int, ranges: list[dict[str, int]]) -> None:
    tmp_path = meta_path.with_name(f"{meta_path.name}.tmp")
    tmp_path.write_text(json.dumps({"size": total_size, "ranges": ranges}), encoding="utf-8")
    tmp_path.replace(meta_path)


def _resume_done_bytes(ranges: list[dict[str, int]]) -> int:
    return sum(max(0, int(item["offset"]) - int(item["start"])) for item in ranges)


def _prepare_range_resume_state(
    data_path: Path,
    total_size: int,
    resume: bool,
    *,
    part_count: int = _DOWNLOAD_THREADS,
) -> tuple[list[dict[str, int]], Path]:
    meta_path = _resume_state_path(data_path)
    default_ranges = _build_range_parts(total_size, part_count=part_count)
    ranges = default_ranges
    if resume and meta_path.is_file():
        try:
            payload = json.loads(meta_path.read_text(encoding="utf-8"))
            raw_ranges = payload.get("ranges")
            if (
                isinstance(raw_ranges, list)
                and int(payload.get("size", -1)) == total_size
                and len(raw_ranges) == len(default_ranges)
            ):
                loaded: list[dict[str, int]] = []
                valid = True
                for raw, default in zip(raw_ranges, default_ranges):
                    start = int(raw.get("start", -1))
                    end = int(raw.get("end", -1))
                    offset = int(raw.get("offset", start))
                    if start != default["start"] or end != default["end"]:
                        valid = False
                        break
                    loaded.append({"start": start, "end": end, "offset": max(start, min(end + 1, offset))})
                if valid:
                    ranges = loaded
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            ranges = default_ranges

    data_path.parent.mkdir(parents=True, exist_ok=True)
    if resume and data_path.exists():
        with data_path.open("r+b") as fh:
            fh.truncate(total_size)
    else:
        with data_path.open("wb") as fh:
            fh.truncate(total_size)
    return (ranges if resume else default_ranges), meta_path


class FUSClient:
    GENERATE_NONCE_PATH = "NF_SmartDownloadGenerateNonce.do"
    SMART_HISTORY_PATH = "SmartHistory.do"
    BINARY_INFORM_PATH = "NF_SmartDownloadBinaryInform.do"
    BINARY_INIT_PATH = "NF_SmartDownloadBinaryInitForMass.do"

    def __init__(self, *, timeout_s: int = 30, session: requests.Session | None = None):
        self.timeout_s = int(timeout_s)
        self.session = session or requests.Session()
        self.auth = ""
        self.server_cookies: dict[str, str] = {}
        self.encnonce = ""
        self.nonce = ""
        self._auth_lock = threading.RLock()
        self._refresh_lock = threading.Lock()
        self.make_request(self.GENERATE_NONCE_PATH)

    def _make_interface_signature_hash(self, nonce: str, signature: str) -> str:
        auth_hash = _md5_hexdigest(f"auth:{nonce}:{_AUTH_NONCE_COUNT}")
        interface_hash = _md5_hexdigest(f"interface:{signature}")
        return _md5_hexdigest(f"{auth_hash}:FUS:{interface_hash}")

    def _build_auth_header_unlocked(self, *, cloud: bool = False) -> str:
        header_nonce = self.encnonce if cloud else ""
        auth = self.auth
        return f'FUS nonce="{header_nonce}", signature="{auth}", nc="", type="", realm=""'

    def _cookie_header_unlocked(self) -> str | None:
        if not self.server_cookies:
            return None
        cookies = tuple(self.server_cookies.items())
        return "; ".join(f"{name}={value}" for name, value in cookies)

    def _headers_unlocked(self, authorization: str, *, no_cache: bool = False) -> dict[str, str]:
        headers = {"Authorization": authorization, "User-Agent": _FUS_USER_AGENT}
        if no_cache:
            headers["Cache-Control"] = "no-cache"
        cookie = self._cookie_header_unlocked()
        if cookie:
            headers["Cookie"] = cookie
        return headers

    def _has_nonce(self) -> bool:
        with self._auth_lock:
            return bool(self.nonce)

    def _headers(self, authorization: str, *, no_cache: bool = False) -> dict[str, str]:
        with self._auth_lock:
            return self._headers_unlocked(authorization, no_cache=no_cache)

    def _post_headers(self) -> dict[str, str]:
        with self._auth_lock:
            return self._headers_unlocked(self._build_auth_header_unlocked(cloud=False))

    def _signed_post_headers(self, signature: str) -> dict[str, str]:
        nonce = "".join(secrets.choice(_AUTH_SIGNATURE_ALPHABET) for _ in range(_AES_BLOCK_SIZE))
        authorization = (
            f'FUS nonce="{nonce}", signature="{self._make_interface_signature_hash(nonce, signature)}", '
            f'nc="{_AUTH_NONCE_COUNT}", type="auth", realm="interface"'
        )
        return self._headers(authorization, no_cache=True)

    def _download_headers(self) -> dict[str, str]:
        with self._auth_lock:
            headers = self._headers_unlocked(self._build_auth_header_unlocked(cloud=True), no_cache=True)
            headers["Accept-Encoding"] = "identity"
            return headers

    def _response_is_401(self, response: requests.Response, body: str) -> bool:
        if response.status_code == 401:
            return True
        try:
            root = ET.fromstring(body)
        except ET.ParseError:
            return False
        return _xml_text(root, "./FUSBody/Results/Status") == "401"

    def _response_cookies(self, response: requests.Response) -> dict[str, str]:
        parsed_cookies: dict[str, str] = {}
        for cookie_value in self._set_cookie_headers(response):
            cookies = SimpleCookie()
            try:
                cookies.load(cookie_value)
            except CookieError:
                continue
            for name, morsel in cookies.items():
                if morsel.value:
                    parsed_cookies[name] = morsel.value
        for name, value in response.cookies.items():
            if value:
                parsed_cookies.setdefault(name, value)
        return parsed_cookies

    def _set_cookie_headers(self, response: requests.Response) -> list[str]:
        set_cookie_values: list[str] = []
        raw_headers = getattr(getattr(response, "raw", None), "headers", None)
        if raw_headers is not None and hasattr(raw_headers, "get_all"):
            try:
                set_cookie_values = list(raw_headers.get_all("Set-Cookie") or [])
            except (AttributeError, TypeError, ValueError):
                set_cookie_values = []
        if not set_cookie_values:
            header = response.headers.get("Set-Cookie")
            if header:
                set_cookie_values = [header]
        return set_cookie_values

    def _update_identity_state(self, response: requests.Response) -> None:
        enc_nonce = response.headers.get("NONCE") or response.headers.get("nonce")
        auth = None
        if enc_nonce:
            try:
                auth = decrypt_nonce(enc_nonce)
            except FUSError:
                auth = ""
        parsed_cookies = self._response_cookies(response)
        with self._auth_lock:
            if enc_nonce:
                self.encnonce = enc_nonce
                self.nonce = enc_nonce
                self.auth = auth or ""
            if parsed_cookies:
                self.server_cookies.update(parsed_cookies)

    def refresh_auth(self) -> str:
        with self._refresh_lock:
            response = self.session.post(
                f"{_FUS_BASE_URL}{self.GENERATE_NONCE_PATH}",
                data=b"",
                headers=self._post_headers(),
                timeout=self.timeout_s,
            )
            body = response.text
            response.raise_for_status()
            self._update_identity_state(response)
            return body

    def make_request(self, path: str, data: bytes | str = b"") -> str:
        if path == self.GENERATE_NONCE_PATH:
            return self.refresh_auth()
        for attempt in range(2):
            if not self._has_nonce():
                self.refresh_auth()
            response = self.session.post(
                f"{_FUS_BASE_URL}{path}",
                data=data,
                headers=self._post_headers(),
                timeout=self.timeout_s,
            )
            body = response.text
            if self._response_is_401(response, body) and attempt == 0:
                self.refresh_auth()
                continue
            response.raise_for_status()
            self._update_identity_state(response)
            return body
        raise FUSError("FUS authorization failed after nonce refresh")

    def make_signed_request(self, path: str, data: bytes | str = b"", *, signature: str) -> str:
        response = self.session.post(
            f"{_FUS_BASE_URL}{path}",
            data=data,
            headers=self._signed_post_headers(signature),
            timeout=self.timeout_s,
        )
        response.raise_for_status()
        self._update_identity_state(response)
        return response.text

    def download_file(
        self,
        remote_path: str,
        *,
        start: int = 0,
        end: int | None = None,
    ) -> requests.Response:
        url = f"{_FUS_DOWNLOAD_URL}?file={remote_path}"
        for attempt in range(2):
            headers = self._download_headers()
            if end is not None:
                headers["Range"] = f"bytes={start}-{end}"
            elif start > 0:
                headers["Range"] = f"bytes={start}-"
            response = self.session.get(url, headers=headers, stream=True, timeout=self.timeout_s)
            if response.status_code == 401 and attempt == 0:
                response.close()
                self.refresh_auth()
                time.sleep(_RETRY_BACKOFF_S)
                continue
            if "Range" in headers and response.status_code != requests.codes.partial_content:
                status = response.status_code
                response.close()
                raise RetryableDownloadError(
                    f"download server ignored requested byte range ({status}): {headers['Range']}"
                )
            response.raise_for_status()
            self._update_identity_state(response)
            return response
        raise FUSError("FUS download authorization failed after nonce refresh")


def _validate_content_range(
    response: requests.Response,
    *,
    start: int,
    end: int,
    total_size: int,
) -> None:
    value = response.headers.get("Content-Range", "").strip()
    match = _CONTENT_RANGE_RE.fullmatch(value)
    if match is None:
        raise RetryableDownloadError(f"download server returned an invalid Content-Range: {value or 'missing'}")
    response_start, response_end = int(match.group(1)), int(match.group(2))
    response_total = match.group(3)
    if response_start != start or response_end != end:
        raise RetryableDownloadError(
            "download server returned the wrong byte range: "
            f"expected {start}-{end}, got {response_start}-{response_end}"
        )
    if response_total == "*" or int(response_total) != total_size:
        raise RetryableDownloadError(
            f"download server returned the wrong file size: expected {total_size}, got {response_total}"
        )


def _read_download_range(
    *,
    client: FUSClient,
    remote_path: str,
    start: int,
    end: int,
    total_size: int,
    recover_download: Callable[[], None] | None = None,
) -> bytes:
    expected_size = end - start + 1
    for attempt in range(1, _DOWNLOAD_RETRIES + 2):
        response: requests.Response | None = None
        try:
            response = client.download_file(remote_path, start=start, end=end)
            _validate_content_range(response, start=start, end=end, total_size=total_size)
            chunks: list[bytes] = []
            received = 0
            for chunk in response.iter_content(chunk_size=_RANGE_CHUNK_SIZE):
                if not chunk:
                    continue
                received += len(chunk)
                if received > expected_size:
                    raise RetryableDownloadError(
                        f"download server returned more data than requested for range {start}-{end}"
                    )
                chunks.append(chunk)
            if received != expected_size:
                raise RetryableDownloadError(
                    f"download server returned {received} bytes for range {start}-{end}, expected {expected_size}"
                )
            return b"".join(chunks)
        except (requests.RequestException, OSError, RetryableDownloadError) as exc:
            if attempt > _DOWNLOAD_RETRIES:
                raise FUSError(f"range {start}-{end} failed after retries: {exc}") from exc
            if recover_download is not None and attempt % _DOWNLOAD_RECOVERY_INTERVAL == 0:
                try:
                    recover_download()
                except Exception as recovery_exc:
                    raise FUSError(f"download recovery failed: {recovery_exc}") from recovery_exc
                time.sleep(_RATE_LIMIT_COOLDOWN_S)
            time.sleep(_RETRY_BACKOFF_S * attempt)
        finally:
            if response is not None:
                response.close()
    raise FUSError(f"range {start}-{end} failed")


class _FUSDecryptingReader(io.RawIOBase):
    def __init__(
        self,
        *,
        client: FUSClient,
        remote_path: str,
        encrypted_size: int,
        key: bytes,
        recover_download: Callable[[], None] | None = None,
        stream_chunk_size: int = _RANGE_CHUNK_SIZE,
        rate_limiter: BandwidthLimiter | None = None,
    ):
        super().__init__()
        self._response: requests.Response | None = None
        if encrypted_size <= 0 or encrypted_size % _AES_BLOCK_SIZE:
            raise FUSError("invalid encrypted firmware size")
        stream_chunk_size = int(stream_chunk_size)
        if stream_chunk_size <= 0:
            raise ValueError("stream chunk size must be positive")
        self._client = client
        self._remote_path = remote_path
        self._encrypted_size = int(encrypted_size)
        self._key = key
        self._recover_download = recover_download
        self._stream_chunk_size = stream_chunk_size
        self._rate_limiter = rate_limiter
        self._position = 0
        self._response_iter: Iterator[bytes] | None = None
        self._cipher: AES | None = None
        self._cipher_buffer = b""
        self._plain_buffer = b""
        self._plain_buffer_offset = 0
        self._stream_discard = 0
        self._stream_failures = 0
        self._stream_failure_position: int | None = None

        tail_start = max(0, self._encrypted_size - _ARCHIVE_TAIL_CACHE_SIZE)
        tail_start -= tail_start % _AES_BLOCK_SIZE
        encrypted_tail = _read_download_range(
            client=self._client,
            remote_path=self._remote_path,
            start=tail_start,
            end=self._encrypted_size - 1,
            total_size=self._encrypted_size,
            recover_download=self._recover_download,
        )
        decrypted_tail = AES.new(self._key, AES.MODE_ECB).decrypt(encrypted_tail)
        unpadded_last_block = _pkcs7_unpad(decrypted_tail[-_AES_BLOCK_SIZE:])
        padding_size = _AES_BLOCK_SIZE - len(unpadded_last_block)
        self._size = self._encrypted_size - padding_size
        self._tail_start = min(tail_start, self._size)
        self._tail = decrypted_tail[: self._size - tail_start]

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        self._checkClosed()
        return self._position

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        self._checkClosed()
        if whence == os.SEEK_SET:
            target = int(offset)
        elif whence == os.SEEK_CUR:
            target = self._position + int(offset)
        elif whence == os.SEEK_END:
            target = self._size + int(offset)
        else:
            raise ValueError(f"invalid whence: {whence}")
        if target < 0:
            raise ValueError("negative seek position")
        if target == self._position:
            return target

        buffered_end = self._position + len(self._plain_buffer) - self._plain_buffer_offset
        if self._position < target <= buffered_end:
            self._plain_buffer_offset += target - self._position
            self._position = target
            return target

        self._close_stream()
        self._position = target
        return target

    def read(self, size: int = -1) -> bytes:
        self._checkClosed()
        if size == 0 or self._position >= self._size:
            return b""
        if size is None or size < 0:
            remaining = self._size - self._position
        else:
            remaining = min(int(size), self._size - self._position)
        chunks: list[bytes] = []

        while remaining > 0:
            if self._position >= self._tail_start:
                self._close_stream()
                tail_offset = self._position - self._tail_start
                take = min(remaining, len(self._tail) - tail_offset)
                if take <= 0:
                    break
                chunks.append(self._tail[tail_offset : tail_offset + take])
                self._position += take
                remaining -= take
                continue

            if self._plain_buffer_offset >= len(self._plain_buffer):
                self._fill_stream_buffer()
            if self._plain_buffer_offset >= len(self._plain_buffer):
                raise FUSError(f"unexpected end of firmware data at byte {self._position}")
            take = min(remaining, len(self._plain_buffer) - self._plain_buffer_offset)
            end = self._plain_buffer_offset + take
            chunks.append(self._plain_buffer[self._plain_buffer_offset : end])
            self._plain_buffer_offset = end
            self._position += take
            remaining -= take

        return b"".join(chunks)

    def close(self) -> None:
        if not self.closed:
            self._close_stream()
        super().close()

    def _open_stream(self) -> None:
        request_start = self._position - (self._position % _AES_BLOCK_SIZE)
        request_end = self._tail_start - 1
        response = self._client.download_file(
            self._remote_path,
            start=request_start,
            end=request_end,
        )
        try:
            _validate_content_range(
                response,
                start=request_start,
                end=request_end,
                total_size=self._encrypted_size,
            )
        except Exception:
            response.close()
            raise
        self._response = response
        self._response_iter = response.iter_content(chunk_size=self._stream_chunk_size)
        self._cipher = AES.new(self._key, AES.MODE_ECB)
        self._cipher_buffer = b""
        self._stream_discard = self._position - request_start

    def _close_stream(self) -> None:
        response = self._response
        self._response = None
        self._response_iter = None
        self._cipher = None
        self._cipher_buffer = b""
        self._plain_buffer = b""
        self._plain_buffer_offset = 0
        self._stream_discard = 0
        if response is not None:
            response.close()

    def _retry_stream(self, exc: Exception) -> None:
        self._close_stream()
        if self._stream_failure_position == self._position:
            self._stream_failures += 1
        else:
            self._stream_failure_position = self._position
            self._stream_failures = 1
        if self._stream_failures > _DOWNLOAD_RETRIES:
            raise FUSError(f"firmware stream failed after retries at byte {self._position}: {exc}") from exc
        if self._recover_download is not None and self._stream_failures % _DOWNLOAD_RECOVERY_INTERVAL == 0:
            try:
                self._recover_download()
            except Exception as recovery_exc:
                raise FUSError(f"download recovery failed: {recovery_exc}") from recovery_exc
            time.sleep(_RATE_LIMIT_COOLDOWN_S)
        time.sleep(_RETRY_BACKOFF_S * self._stream_failures)

    def _fill_stream_buffer(self) -> None:
        stream_limit = min(self._size, self._tail_start)
        while self._plain_buffer_offset >= len(self._plain_buffer) and self._position < stream_limit:
            self._plain_buffer = b""
            self._plain_buffer_offset = 0
            try:
                if self._response_iter is None:
                    self._open_stream()
                if self._response_iter is None:
                    raise RetryableDownloadError("download stream did not start")
                chunk = next(self._response_iter)
                if not chunk:
                    continue
                if self._rate_limiter is not None:
                    self._rate_limiter.consume(len(chunk))
                encrypted = self._cipher_buffer + chunk if self._cipher_buffer else chunk
                block_size = (len(encrypted) // _AES_BLOCK_SIZE) * _AES_BLOCK_SIZE
                if block_size == 0:
                    self._cipher_buffer = encrypted
                    continue
                self._cipher_buffer = encrypted[block_size:]
                encrypted = encrypted[:block_size]
                if self._cipher is None:
                    raise RetryableDownloadError("download stream lost its decryptor")
                plain = self._cipher.decrypt(encrypted)
                if self._stream_discard:
                    discarded = min(self._stream_discard, len(plain))
                    plain = plain[discarded:]
                    self._stream_discard -= discarded
                remaining = stream_limit - self._position
                if len(plain) > remaining:
                    plain = plain[:remaining]
                self._plain_buffer = plain
                self._plain_buffer_offset = 0
            except StopIteration:
                if self._cipher_buffer:
                    error = RetryableDownloadError("download stream ended with a partial encrypted block")
                else:
                    error = RetryableDownloadError("download stream ended before the requested data")
                self._retry_stream(error)
            except (requests.RequestException, OSError, RetryableDownloadError) as exc:
                self._retry_stream(exc)


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

    with ThreadPoolExecutor(max_workers=len(ranges) or 1) as executor:
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
) -> None:
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
                        time.sleep(_RATE_LIMIT_COOLDOWN_S)
                    time.sleep(_RETRY_BACKOFF_S * attempts)
                except Exception as exc:
                    stop_event.set()
                    with state_lock:
                        errors.append(exc)
                    return
                finally:
                    if response is not None:
                        response.close()

    def run_worker(range_idx: int) -> None:
        try:
            worker(range_idx)
        except Exception as exc:
            with state_lock:
                errors.append(exc)
            stop_event.set()
        finally:
            worker_finished.set()

    threads = [
        threading.Thread(target=run_worker, args=(idx,), daemon=True)
        for idx, segment in enumerate(ranges)
        if int(segment["offset"]) <= int(segment["end"])
    ]
    for index, thread in enumerate(threads):
        thread.start()
        if index + 1 < len(threads):
            time.sleep(_THREAD_STAGGER_S)

    try:
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
        done = _resume_done_bytes(ranges)
        err = errors[0] if errors else None
        snapshot = [dict(item) for item in ranges]
    _save_range_resume_state(meta_path, total_size, snapshot)
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
        part_count=worker_count,
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
        )
    meta_path.unlink(missing_ok=True)
    final_stream_path = _finalize_stream_decrypted_file(temp_path, final_path)
    return DownloadResult(encrypted_path, final_stream_path, firmware, info.filename, info.size)
