# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import socket
import threading
from contextlib import suppress
from contextvars import ContextVar

import requests
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

from ..core.errors import DownloadCancelledError

DOWNLOAD_STOP: ContextVar[threading.Event | None] = ContextVar("asgard_download_stop", default=None)


class _ConnectionGuard:
    _asgard_stop: threading.Event | None = None

    def _check_cancelled(self):
        if self._asgard_stop is not None and self._asgard_stop.is_set():
            self.close()
            raise DownloadCancelledError("download cancelled")

    def connect(self):
        self._check_cancelled()
        super().connect()
        self._check_cancelled()

    def request(self, *args, **kwargs):
        self._check_cancelled()
        return super().request(*args, **kwargs)


class _HTTPConnection(_ConnectionGuard, HTTPConnection):
    pass


class _HTTPSConnection(_ConnectionGuard, HTTPSConnection):
    pass


class DownloadHTTPAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self._lock = threading.Lock()
        self._connections = {}
        super().__init__(*args, **kwargs)

    def _pool_type(self, base, connection_type):
        adapter = self

        class Pool(base):
            ConnectionCls = connection_type

            def _get_conn(self, timeout=None):
                connection = super()._get_conn(timeout)
                stop = DOWNLOAD_STOP.get()
                connection._asgard_stop = stop
                with adapter._lock:
                    adapter._connections[connection] = stop
                return connection

            def _put_conn(self, connection):
                with adapter._lock:
                    adapter._connections.pop(connection, None)
                return super()._put_conn(connection)

        return Pool

    def _configure_pools(self, manager):
        manager.pool_classes_by_scheme = {
            "http": self._pool_type(HTTPConnectionPool, _HTTPConnection),
            "https": self._pool_type(HTTPSConnectionPool, _HTTPSConnection),
        }

    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self._configure_pools(self.poolmanager)

    def proxy_manager_for(self, *args, **kwargs):
        manager = super().proxy_manager_for(*args, **kwargs)
        self._configure_pools(manager)
        return manager

    def cancel(self, stop):
        with self._lock:
            connections = [connection for connection, event in self._connections.items() if event is stop]
        for connection in connections:
            sock = connection.sock
            if sock is not None:
                with suppress(OSError):
                    sock.shutdown(socket.SHUT_RDWR)
            connection.close()
