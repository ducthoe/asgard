# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import threading
import time
import xml.etree.ElementTree as ET

import requests

from ..core.constants import _FUS_BASE_URL, _FUS_DOWNLOAD_URL, _RETRY_BACKOFF_S
from ..core.errors import FUSError, RetryableDownloadError
from .auth import FUSAuth
from .protocol import _xml_text


class FUSClient(FUSAuth):
    GENERATE_NONCE_PATH = "NF_SmartDownloadGenerateNonce.do"
    SMART_HISTORY_PATH = "SmartHistory.do"
    BINARY_INFORM_PATH = "NF_SmartDownloadBinaryInform.do"
    BINARY_INIT_PATH = "NF_SmartDownloadBinaryInitForMass.do"

    def __init__(self, *, timeout_s: int = 30, session: requests.Session | None = None):
        self.timeout_s = int(timeout_s)
        self.session = session or requests.Session()
        super().__init__()
        self._refresh_lock = threading.Lock()
        self.make_request(self.GENERATE_NONCE_PATH)

    def _response_is_401(self, response: requests.Response, body: str) -> bool:
        if response.status_code == 401:
            return True
        try:
            root = ET.fromstring(body)
        except ET.ParseError:
            return False
        return _xml_text(root, "./FUSBody/Results/Status") == "401"

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
