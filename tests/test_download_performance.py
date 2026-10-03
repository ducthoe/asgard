from __future__ import annotations

import io
import random
import re
import socket
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests
from Cryptodome.Cipher import AES

from asgard.core.errors import FUSError
from asgard.fus import client as client_module
from asgard.fus import download, scheduling, streaming
from asgard.fus.client import FUSClient
from asgard.fus.models import BinaryInfo
from asgard.fus.resume import _prepare_range_resume_state, _resume_done_bytes
from asgard.fus.scheduling import AdaptiveDownloadGate, load_resume_ranges, split_download_ranges
from asgard.fus.streaming import BandwidthLimiter, _FUSDecryptingReader, _read_download_range

KEY = bytes(range(16))


def encrypt(data):
    padding = 16 - len(data) % 16
    return AES.new(KEY, AES.MODE_ECB).encrypt(data + bytes([padding]) * padding)


@pytest.fixture
def server(monkeypatch):
    state = SimpleNamespace(
        data=b"", requests=[], connections=set(), drops=0, throttles=0, throttle_status=429, bad_range=False
    )

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def handle(self):
            try:
                super().handle()
            except ConnectionResetError:
                pass

        def log_message(self, *args):
            pass

        def do_GET(self):
            start, end = map(int, re.fullmatch(r"bytes=(\d+)-(\d+)", self.headers["Range"]).groups())
            state.requests.append((start, end, time.monotonic()))
            state.connections.add(self.client_address)
            if state.throttles:
                state.throttles -= 1
                self.send_response(state.throttle_status)
                self.send_header("Retry-After", "0.08")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(206)
            range_start = start + 1 if state.bad_range else start
            self.send_header("Content-Range", f"bytes {range_start}-{end}/{len(state.data)}")
            self.send_header("Content-Length", str(end - start + 1))
            self.end_headers()
            if state.drops:
                state.drops -= 1
                self.wfile.write(state.data[start : min(end + 1, start + 100000)])
                self.wfile.flush()
                self.connection.shutdown(socket.SHUT_RDWR)
                self.close_connection = True
                return
            try:
                self.wfile.write(memoryview(state.data)[start : end + 1])
            except (BrokenPipeError, ConnectionResetError):
                pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(client_module, "_FUS_DOWNLOAD_URL", f"http://127.0.0.1:{httpd.server_port}/download")
    monkeypatch.setattr(scheduling, "_DOWNLOAD_REQUEST_INTERVAL_S", 0)
    monkeypatch.setattr(scheduling, "_RATE_LIMIT_COOLDOWN_S", 0.02)
    monkeypatch.setattr(streaming, "_RETRY_BACKOFF_S", 0)
    monkeypatch.setattr(download, "_RETRY_BACKOFF_S", 0)
    monkeypatch.setattr(download, "_render_progress", lambda *args, **kwargs: None)
    try:
        yield state
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


def test_small_reads_reuse_cached_pages_and_connections(server):
    plain = random.Random(1).randbytes(3 * 1024 * 1024)
    server.data = encrypt(plain)
    received = []
    with (
        FUSClient() as client,
        _FUSDecryptingReader(
            client=client,
            remote_path="test",
            encrypted_size=len(server.data),
            key=KEY,
            stream_chunk_size=1024 * 1024,
            network_progress=received.append,
        ) as reader,
    ):
        for _ in range(10):
            for offset in (123, 100123, 200123):
                reader.seek(offset)
                assert reader.read(97) == plain[offset : offset + 97]
        assert len(server.requests) == 4
        assert sum(received) == 128 * 1024 + 3 * 65536
        assert len(server.connections) == 1


def test_random_seeks_sequential_reads_and_readinto(server):
    plain = random.Random(2).randbytes(3 * 1024 * 1024 + 113)
    server.data = encrypt(plain)
    with (
        FUSClient() as client,
        _FUSDecryptingReader(
            client=client,
            remote_path="test",
            encrypted_size=len(server.data),
            key=KEY,
            stream_chunk_size=1024 * 1024,
        ) as reader,
    ):
        expected = io.BytesIO(plain)
        rng = random.Random(3)
        for _ in range(100):
            offset = rng.randrange(len(plain) + 100)
            size = rng.choice((0, 1, 17, 65537, 1024 * 1024))
            reader.seek(offset)
            expected.seek(offset)
            assert reader.read(size) == expected.read(size)
        reader.seek(0)
        assert reader.read() == plain
        reader.seek(-150, io.SEEK_END)
        buffer = bytearray(100)
        assert reader.readinto(buffer) == 100
        assert buffer == plain[-150:-50]


def test_cache_has_bounded_memory(server, monkeypatch):
    monkeypatch.setattr(streaming, "_ARCHIVE_READ_CACHE_SIZE", 128 * 1024)
    plain = random.Random(4).randbytes(2 * 1024 * 1024)
    server.data = encrypt(plain)
    with (
        FUSClient() as client,
        _FUSDecryptingReader(
            client=client,
            remote_path="test",
            encrypted_size=len(server.data),
            key=KEY,
        ) as reader,
    ):
        for offset in range(0, 1024 * 1024, 65536):
            reader.seek(offset)
            assert reader.read(32) == plain[offset : offset + 32]
        count = len(server.requests)
        reader.seek(0)
        assert reader.read(32) == plain[:32]
        assert len(server.requests) == count + 1
        assert reader._cache_bytes <= 128 * 1024


def test_remote_zip_entries_remain_valid(server):
    output = io.BytesIO()
    plain = random.Random(5).randbytes(1024 * 1024)
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("stored.img", plain, compress_type=zipfile.ZIP_STORED)
        archive.writestr("compressed.img", plain, compress_type=zipfile.ZIP_DEFLATED)
    server.data = encrypt(output.getvalue())
    with (
        FUSClient() as client,
        _FUSDecryptingReader(
            client=client,
            remote_path="test",
            encrypted_size=len(server.data),
            key=KEY,
            stream_chunk_size=1024 * 1024,
        ) as reader,
        zipfile.ZipFile(reader) as archive,
    ):
        assert archive.read("stored.img") == plain
        assert archive.read("compressed.img") == plain
        assert archive.testzip() is None


def test_small_sequential_reads_use_a_long_stream(server):
    plain = random.Random(12).randbytes(2 * 1024 * 1024)
    server.data = encrypt(plain)
    with (
        FUSClient() as client,
        _FUSDecryptingReader(
            client=client,
            remote_path="test",
            encrypted_size=len(server.data),
            key=KEY,
        ) as reader,
    ):
        chunks = []
        while chunk := reader.read(4096):
            chunks.append(chunk)
        assert b"".join(chunks) == plain
        assert len(server.requests) == 3


def test_tail_reads_and_cache_hits_respect_the_bandwidth_limit(server):
    plain = random.Random(13).randbytes(1024 * 1024)
    server.data = encrypt(plain)
    limited = []
    limiter = BandwidthLimiter(None)
    limiter.consume = limited.append
    with (
        FUSClient() as client,
        _FUSDecryptingReader(
            client=client,
            remote_path="test",
            encrypted_size=len(server.data),
            key=KEY,
            rate_limiter=limiter,
        ) as reader,
    ):
        assert sum(limited) == 128 * 1024
        reader.read(97)
        total = sum(limited)
        reader.seek(0)
        reader.read(97)
        assert sum(limited) == total


@pytest.mark.parametrize("decrypt", [False, True])
def test_full_download_api(server, tmp_path, monkeypatch, decrypt):
    plain = random.Random(14).randbytes(1024 * 1024)
    server.data = encrypt(plain)
    info = BinaryInfo("/test/", "test.zip.enc4", len(server.data), firmware_version="A/B/C/D")
    monkeypatch.setattr(download, "_resolve_versioned_info", lambda *args: info)
    monkeypatch.setattr(download, "initialize_download", lambda *args: None)
    monkeypatch.setattr(download, "_decryption_key_from_info", lambda *args: KEY)
    monkeypatch.setattr(download, "_print_info", lambda *args: None)
    result = download.download_firmware(model="SM-TEST", region="EUX", out_dir=tmp_path, auto_decrypt=decrypt)
    path = result.decrypted_path if decrypt else result.encrypted_path
    assert path.read_bytes() == (plain if decrypt else server.data)
    assert not list(tmp_path.glob("*.resume.json"))


def test_metadata_retry_preserves_received_bytes(server):
    server.data = random.Random(6).randbytes(300000)
    server.drops = 1
    with FUSClient() as client:
        data = _read_download_range(
            client=client, remote_path="test", start=0, end=len(server.data) - 1, total_size=len(server.data)
        )
    assert data == server.data
    assert [item[0] for item in server.requests] == [0, 65536]


@pytest.mark.parametrize("decrypt", [False, True])
@pytest.mark.parametrize("workers", [1, 4])
def test_interrupted_download_and_resume(server, tmp_path, monkeypatch, decrypt, workers):
    plain = random.Random(7).randbytes(2 * 1024 * 1024)
    server.data = encrypt(plain)
    server.drops = 1
    monkeypatch.setattr(download, "_DOWNLOAD_CHUNK_SIZE", 32769)
    monkeypatch.setattr(scheduling, "_DOWNLOAD_MIN_RANGE_SIZE", 256 * 1024)
    path = tmp_path / "download.part"
    ranges, meta_path = _prepare_range_resume_state(path, len(server.data), False, part_count=1)
    with FUSClient() as client:
        client.configure_download_pool(workers)
        download._download_ranges_parallel(
            client=client,
            remote_path="test",
            out_path=path,
            total_size=len(server.data),
            ranges=ranges,
            workers=workers,
            decrypt_key=KEY if decrypt else None,
        )
        expected = plain + bytes([16]) * 16 if decrypt else server.data
        assert path.read_bytes() == expected
        assert _resume_done_bytes(ranges) == len(server.data)
        loaded = load_resume_ranges(
            {"size": len(server.data), "ranges": ranges},
            len(server.data),
            path.stat().st_size,
            alignment=16 if decrypt else 1,
        )
        count = len(server.requests)
        download._download_ranges_parallel(
            client=client,
            remote_path="test",
            out_path=path,
            total_size=len(server.data),
            ranges=loaded,
            workers=workers,
        )
        assert len(server.requests) == count
    assert meta_path.is_file()
    assert any(item[0] % 16 for item in server.requests)


@pytest.mark.parametrize("status", [429, 503])
def test_retry_after_is_respected(server, tmp_path, status):
    server.data = bytes(1024 * 1024)
    server.throttles = 2
    server.throttle_status = status
    path = tmp_path / "download.part"
    ranges, _ = _prepare_range_resume_state(path, len(server.data), False, part_count=1)
    with FUSClient() as client:
        download._download_ranges_parallel(
            client=client, remote_path="test", out_path=path, total_size=len(server.data), ranges=ranges, workers=4
        )
    assert path.read_bytes() == server.data
    starts = [item[2] for item in server.requests]
    assert len(starts) == 3
    assert all(after - before >= 0.075 for before, after in zip(starts, starts[1:]))


def test_wrong_ranges_are_rejected(server, monkeypatch):
    server.data = bytes(65536)
    server.bad_range = True
    monkeypatch.setattr(streaming, "_DOWNLOAD_RETRIES", 0)
    with FUSClient() as client, pytest.raises(FUSError, match="wrong byte range"):
        _read_download_range(client=client, remote_path="test", start=0, end=65535, total_size=65536)


def test_concurrent_unauthorized_requests_refresh_once(monkeypatch):
    barrier = threading.Barrier(4)
    refreshes = []

    class Session:
        def get(self, url, *, headers, **kwargs):
            response = requests.Response()
            response._content = b""
            response._content_consumed = True
            response.status_code = 206
            if "old" in headers["Authorization"]:
                barrier.wait(timeout=2)
                response.status_code = 401
            return response

        def post(self, *args, **kwargs):
            refreshes.append(1)
            response = requests.Response()
            response.status_code = 200
            response._content = b""
            response._content_consumed = True
            response.headers["NONCE"] = "new"
            return response

    monkeypatch.setattr(client_module, "_RETRY_BACKOFF_S", 0)
    client = FUSClient(session=Session())
    client.encnonce = "old"
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: client.download_file("test", start=0, end=15), range(4)))
    assert all(response.status_code == 206 for response in results)
    assert len(refreshes) == 1


def test_concurrency_probe_rejects_no_throughput_gain(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(scheduling.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(scheduling, "_DOWNLOAD_REQUEST_INTERVAL_S", 0)
    gate = AdaptiveDownloadGate(4)
    stop = threading.Event()
    assert gate.acquire(stop)
    assert gate.limit == 1
    acquired = threading.Event()

    def waiting_worker():
        if gate.acquire(stop):
            acquired.set()
            stop.wait()
            gate.release()

    thread = threading.Thread(target=waiting_worker)
    thread.start()
    try:
        with gate._condition:
            assert gate._condition.wait_for(lambda: gate._waiting == 1, timeout=1)
        gate.observe(0)
        clock[0] += 2.1
        gate.observe(2100)
        assert acquired.wait(1)
        gate.observe(2100)
        clock[0] += 2.1
        gate.observe(4200)
        assert gate.limit == 1
        assert gate.active == 2
    finally:
        stop.set()
        gate.release()
        thread.join(timeout=2)


def test_concurrency_grows_when_more_streams_improve_speed(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(scheduling.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(scheduling, "_DOWNLOAD_REQUEST_INTERVAL_S", 0)
    gate = AdaptiveDownloadGate(4)
    stop = threading.Event()
    assert gate.acquire(stop)
    acquired = [threading.Event(), threading.Event()]

    def waiting_worker(event):
        if gate.acquire(stop):
            event.set()
            stop.wait()
            gate.release()

    threads = [threading.Thread(target=waiting_worker, args=(event,)) for event in acquired]
    for thread in threads:
        thread.start()
    try:
        with gate._condition:
            assert gate._condition.wait_for(lambda: gate._waiting == 2, timeout=1)
        gate.observe(0)
        clock[0] += 2.1
        gate.observe(2100)
        assert any(event.wait(0.5) for event in acquired)
        assert gate.active == 2
        gate.observe(2100)
        clock[0] += 2.1
        gate.observe(6300)
        assert all(event.wait(1) for event in acquired)
        assert gate.limit == 3
        assert gate.active == 3
    finally:
        stop.set()
        gate.release()
        for thread in threads:
            thread.join(timeout=2)


def test_request_starts_are_spaced_apart():
    gate = AdaptiveDownloadGate(1)
    stop = threading.Event()
    starts = []
    for _ in range(3):
        assert gate.acquire(stop)
        starts.append(time.monotonic())
        gate.release()
    assert all(after - before >= 0.045 for before, after in zip(starts, starts[1:]))


def test_disk_errors_do_not_retry_network_requests(server, tmp_path, monkeypatch):
    plain = random.Random(15).randbytes(1024 * 1024)
    server.data = encrypt(plain)
    path = tmp_path / "download.part"
    ranges, _ = _prepare_range_resume_state(path, len(server.data), False, part_count=1)
    real_open = Path.open

    class FaultyFile:
        def __init__(self, file):
            self.file = file
            self.writes = 0

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.file.close()

        def seek(self, *args):
            return self.file.seek(*args)

        def write(self, data):
            self.writes += 1
            if self.writes == 1:
                return self.file.write(data[:7])
            raise OSError("disk full")

    def failing_open(target, mode="r", *args, **kwargs):
        file = real_open(target, mode, *args, **kwargs)
        return FaultyFile(file) if target == path and mode == "r+b" else file

    monkeypatch.setattr(Path, "open", failing_open)
    with FUSClient() as client, pytest.raises(FUSError, match="disk full"):
        download._download_ranges_parallel(
            client=client,
            remote_path="test",
            out_path=path,
            total_size=len(server.data),
            ranges=ranges,
            workers=1,
            decrypt_key=KEY,
        )
    assert len(server.requests) == 1
    assert _resume_done_bytes(ranges) == 0
    monkeypatch.setattr(Path, "open", real_open)
    with FUSClient() as client:
        download._download_ranges_parallel(
            client=client,
            remote_path="test",
            out_path=path,
            total_size=len(server.data),
            ranges=ranges,
            workers=1,
            decrypt_key=KEY,
        )
    assert path.read_bytes() == plain + bytes([16]) * 16


def test_range_scheduling_reduces_requests_and_preserves_resume():
    total = 12 * 1024**3
    parts = split_download_ranges([{"start": 0, "end": total - 1, "offset": 0}], workers=4)
    assert len(parts) == 24
    parts[0]["offset"] = 64 * 1024**2
    parts[3]["offset"] = parts[3]["end"] + 1
    done = _resume_done_bytes(parts)
    resumed = split_download_ranges(parts, workers=2)
    assert _resume_done_bytes(resumed) == done
    assert load_resume_ranges({"size": total, "ranges": resumed}, total, total, alignment=16) == resumed


def test_bandwidth_wait_can_be_cancelled():
    limiter = BandwidthLimiter(1)
    stop = threading.Event()
    thread = threading.Thread(target=limiter.consume, args=(1000000, stop))
    thread.start()
    stop.set()
    thread.join(timeout=1)
    assert not thread.is_alive()
