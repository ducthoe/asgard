# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import hashlib
import secrets
import threading
from http.cookies import CookieError, SimpleCookie

import requests

from ..core.constants import (
    _AES_BLOCK_SIZE,
    _AUTH_AES_KEY,
    _AUTH_NONCE_COUNT,
    _AUTH_SIGNATURE_ALPHABET,
    _FUS_USER_AGENT,
)
from ..core.errors import FUSError


def _md5_hexdigest(text: str) -> str:
    return hashlib.md5(text.encode("utf-8"), usedforsecurity=False).hexdigest()


def _authenticate_block(in_block: bytes) -> bytes:
    if len(in_block) != _AES_BLOCK_SIZE:
        raise FUSError("nonce block is too short")
    from Cryptodome.Cipher import AES

    return AES.new(_AUTH_AES_KEY, AES.MODE_ECB).encrypt(in_block)


def decrypt_nonce(enc_nonce: str) -> str:
    seed = enc_nonce[:_AES_BLOCK_SIZE].ljust(_AES_BLOCK_SIZE, "0").encode("utf-8")
    return _authenticate_block(seed).hex()


def get_logic_check(value: str, nonce: str) -> str:
    if len(value) < _AES_BLOCK_SIZE:
        raise FUSError("logic check input too short")
    return "".join(value[ord(ch) & 0xF] for ch in nonce)


class FUSAuth:
    def __init__(self):
        self.auth = ""
        self.server_cookies: dict[str, str] = {}
        self.encnonce = ""
        self.nonce = ""
        self._auth_lock = threading.RLock()

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
