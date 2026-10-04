from __future__ import annotations

import hashlib
import io
import random
import re
import socket
import struct
import tarfile
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
from lz4 import frame as lz4_frame

from asgard import fus
from asgard.cli.app import _build_parser, _handle_download
from asgard.core.errors import FUSError
from asgard.formats import archive as archive_module
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


def super_image(plain):
    data_offset = 5 * 4096
    geometry = bytearray(4096)
    struct.pack_into("<II32sIII", geometry, 0, 0x616C4467, 52, bytes(32), 4096, 1, 4096)
    geometry[8:40] = hashlib.sha256(geometry[:52]).digest()
    records = (
        struct.pack("<36sIIII", b"vendor_a", 0, 0, 1, 0),
        struct.pack("<QIQI", len(plain) // 512, 0, data_offset // 512, 0),
        struct.pack("<36sIQ", b"default", 0, 0),
        struct.pack("<QIIQ36sI", data_offset // 512, 4096, 0, data_offset + len(plain), b"super", 0),
    )
    tables = b"".join(records)
    header = bytearray(128)
    struct.pack_into(
        "<IHHI32sI32s", header, 0, 0x414C5030, 10, 0, 128, bytes(32), len(tables), hashlib.sha256(tables).digest()
    )
    offset = 0
    for index, record in enumerate(records):
        struct.pack_into("<III", header, 80 + index * 12, offset, 1, len(record))
        offset += len(record)
    header[12:44] = hashlib.sha256(header).digest()
    metadata = (header + tables).ljust(4096, b"\0")
    return bytes(4096) + bytes(geometry) * 2 + bytes(metadata) * 2 + plain


@pytest.fixture
def server(monkeypatch):
    state = SimpleNamespace(
        data=b"",
        requests=[],
        connections=set(),
        drops=0,
        throttles=0,
        throttle_status=429,
        bad_range=False,
        auth_required=False,
        authorized=False,
        permanent_401=False,
        nonce_requests=0,
        init_requests=0,
        lock=threading.Lock(),
        active=0,
        max_active=0,
        completed=[],
        chunk_delay=0,
        first_range_delay=0,
        stall=None,
        stalled=threading.Event(),
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
            if state.auth_required and not state.authorized:
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
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
                with state.lock:
                    state.active += 1
                    state.max_active = max(state.max_active, state.active)
                if start == 0:
                    time.sleep(state.first_range_delay)
                if state.stall is not None and end - start + 1 > 128 * 1024:
                    state.stalled.set()
                    state.stall.wait(5)
                if state.chunk_delay:
                    for offset in range(start, end + 1, 65536):
                        time.sleep(state.chunk_delay)
                        self.wfile.write(memoryview(state.data)[offset : min(end + 1, offset + 65536)])
                        self.wfile.flush()
                else:
                    self.wfile.write(memoryview(state.data)[start : end + 1])
                state.completed.append(start)
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                with state.lock:
                    state.active -= 1

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.send_response(200)
            if self.path.endswith(FUSClient.GENERATE_NONCE_PATH):
                state.nonce_requests += 1
                self.send_header("NONCE", "0123456789ABCDEF")
            elif self.path.endswith(FUSClient.BINARY_INIT_PATH):
                state.init_requests += 1
                state.authorized = bool(state.nonce_requests) and not state.permanent_401
            self.send_header("Content-Length", "0")
            self.end_headers()

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(client_module, "_FUS_DOWNLOAD_URL", f"http://127.0.0.1:{httpd.server_port}/download")
    monkeypatch.setattr(client_module, "_FUS_BASE_URL", f"http://127.0.0.1:{httpd.server_port}/")
    monkeypatch.setattr(client_module, "_RETRY_BACKOFF_S", 0)
    monkeypatch.setattr(scheduling, "_DOWNLOAD_REQUEST_INTERVAL_S", 0)
    monkeypatch.setattr(scheduling, "_RATE_LIMIT_COOLDOWN_S", 0.02)
    monkeypatch.setattr(streaming, "_RETRY_BACKOFF_S", 0)
    monkeypatch.setattr(download, "_RETRY_BACKOFF_S", 0)
    monkeypatch.setattr(download, "_render_progress", lambda *args, **kwargs: None)
    try:
        yield state
    finally:
        if state.stall is not None:
            state.stall.set()
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


@pytest.mark.parametrize("threads", [None, 1, 2, 6])
def test_parallel_stream_delivers_out_of_order_ranges_in_order(server, monkeypatch, threads):
    monkeypatch.setattr(streaming, "_DOWNLOAD_MIN_RANGE_SIZE", 256 * 1024)
    plain = random.Random(30).randbytes(3 * 1024 * 1024 + 113)
    server.data = encrypt(plain)
    server.chunk_delay = 0.005
    server.first_range_delay = 0.08
    received = []
    limited = []
    limiter = BandwidthLimiter(None)
    limiter.consume = lambda size, stop_event=None: limited.append(size)
    with (
        FUSClient() as client,
        _FUSDecryptingReader(
            client=client,
            remote_path="test",
            encrypted_size=len(server.data),
            key=KEY,
            threads=threads,
            stream_chunk_size=65537,
            network_progress=received.append,
            rate_limiter=limiter,
        ) as reader,
    ):
        with reader.streaming():
            assert reader.read() == plain
        assert sum(received) == len(server.data)
        assert sum(limited) == len(server.data)
        expected_workers = 6 if threads is None else threads
        assert server.max_active == expected_workers
        if expected_workers > 1:
            assert server.completed.index(256 * 1024) < server.completed.index(0)
        reader.seek(123)
        assert reader.read(117) == plain[123:240]
        reader.seek(-113, io.SEEK_END)
        assert reader.read() == plain[-113:]
        assert reader._gate.active == 0
        assert not any(thread.name.startswith("asgard-range-") for thread in threading.enumerate())


def test_parallel_stream_bounds_read_ahead_when_consumer_pauses(server, monkeypatch):
    range_size = 256 * 1024
    monkeypatch.setattr(streaming, "_DOWNLOAD_MIN_RANGE_SIZE", range_size)
    plain = random.Random(31).randbytes(4 * 1024 * 1024)
    server.data = encrypt(plain)
    received = []
    with (
        FUSClient() as client,
        _FUSDecryptingReader(
            client=client,
            remote_path="test",
            encrypted_size=len(server.data),
            key=KEY,
            stream_chunk_size=65536,
            network_progress=received.append,
        ) as reader,
    ):
        with reader.streaming():
            assert reader.read(16) == plain[:16]
            deadline = time.monotonic() + 2
            while sum(received) < 6 * range_size + 128 * 1024 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert sum(received) == 6 * range_size + 128 * 1024
            count = len(server.requests)
            time.sleep(0.1)
            assert len(server.requests) == count == 7
            reader.seek(2 * 1024 * 1024 + 13)
            assert reader.read(16) == plain[2 * 1024 * 1024 + 13 : 2 * 1024 * 1024 + 29]
        assert not any(thread.name.startswith("asgard-range-") for thread in threading.enumerate())


def test_parallel_stream_resumes_partial_ranges_without_refetching(server, monkeypatch):
    monkeypatch.setattr(streaming, "_DOWNLOAD_MIN_RANGE_SIZE", 256 * 1024)
    plain = random.Random(32).randbytes(2 * 1024 * 1024)
    server.data = encrypt(plain)
    received = []
    with (
        FUSClient() as client,
        _FUSDecryptingReader(
            client=client,
            remote_path="test",
            encrypted_size=len(server.data),
            key=KEY,
            stream_chunk_size=65537,
            network_progress=received.append,
        ) as reader,
    ):
        server.drops = 1
        with reader.streaming():
            assert reader.read() == plain
        starts = [start for start, _, _ in server.requests]
        assert any(start % (256 * 1024) == 65537 for start in starts)
        assert sum(received) == len(server.data)


def test_parallel_stream_cancels_stalled_connections(server, monkeypatch):
    monkeypatch.setattr(streaming, "_DOWNLOAD_MIN_RANGE_SIZE", 256 * 1024)
    server.data = encrypt(random.Random(33).randbytes(2 * 1024 * 1024))
    with FUSClient() as client:
        reader = _FUSDecryptingReader(client=client, remote_path="test", encrypted_size=len(server.data), key=KEY)
        server.stall = threading.Event()
        reader._streaming_reads = True
        reader._open_stream()
        assert server.stalled.wait(2)
        deadline = time.monotonic() + 2
        while len(server.requests) < 7 and time.monotonic() < deadline:
            time.sleep(0.01)
        started = time.monotonic()
        reader.close()
        assert time.monotonic() - started < 1.5
        assert reader._gate.active == 0
        assert not any(thread.name.startswith("asgard-range-") for thread in threading.enumerate())


@pytest.mark.parametrize("status", [429, 503])
def test_parallel_stream_honors_shared_throttle_cooldown(server, monkeypatch, status):
    monkeypatch.setattr(streaming, "_DOWNLOAD_MIN_RANGE_SIZE", 256 * 1024)
    monkeypatch.setattr(scheduling, "_DOWNLOAD_REQUEST_INTERVAL_S", 0.025)
    plain = random.Random(34).randbytes(2 * 1024 * 1024)
    server.data = encrypt(plain)
    with (
        FUSClient() as client,
        _FUSDecryptingReader(client=client, remote_path="test", encrypted_size=len(server.data), key=KEY) as reader,
    ):
        server.throttles = 1
        server.throttle_status = status
        with reader.streaming():
            assert reader.read() == plain
        assert server.requests[2][2] - server.requests[1][2] >= 0.07
        assert reader._gate.limit == 3


def test_default_gate_allows_six_concurrent_connections(server):
    gate = AdaptiveDownloadGate(6)
    stop = threading.Event()
    for _ in range(6):
        assert gate.acquire(stop)
    assert gate.active == gate.limit == 6
    gate.throttled(0.08)
    assert gate.limit == 3
    for _ in range(6):
        gate.release()


@pytest.mark.parametrize("compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
@pytest.mark.parametrize("mode", ["archive", "file", "partition"])
@pytest.mark.parametrize("threads", [None, 2])
def test_archive_extraction_api_uses_requested_connections(server, tmp_path, monkeypatch, compression, mode, threads):
    monkeypatch.setattr(streaming, "_DOWNLOAD_MIN_RANGE_SIZE", 256 * 1024)
    plain = random.Random(35).randbytes(3 * 1024 * 1024)
    member_name = "super.img.lz4" if mode == "partition" else "boot.img.lz4"
    compressed = lz4_frame.compress(super_image(plain) if mode == "partition" else plain, content_checksum=True)
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
        entry = tarfile.TarInfo(member_name)
        entry.size = len(compressed)
        tar.addfile(entry, io.BytesIO(compressed))
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as archive:
        archive.writestr("AP_test.tar.md5", tar_buffer.getvalue(), compress_type=compression)
    server.data = encrypt(zip_buffer.getvalue())
    server.chunk_delay = 0.005
    info = BinaryInfo("", "test.zip.enc4", len(server.data), firmware_version="A/B/C/D")
    monkeypatch.setattr(fus, "_resolve_versioned_info", lambda *args: info)
    monkeypatch.setattr(fus, "initialize_download", lambda *args: None)
    monkeypatch.setattr(fus, "_decryption_key_from_info", lambda *args: KEY)
    monkeypatch.setattr(archive_module, "_load_tar_index", lambda *args: None)
    if mode == "archive":
        paths = archive_module.download_firmware_entries(
            model="SM-TEST", region="EUX", selectors=("AP",), out_dir=tmp_path, threads=threads
        )
        assert paths[0].read_bytes() == tar_buffer.getvalue()
    elif mode == "file":
        path = archive_module.download_firmware_tar_member(
            model="SM-TEST",
            region="EUX",
            outer_selector="AP",
            member_name="boot.img.lz4",
            out_dir=tmp_path,
            threads=threads,
        )
        assert path.read_bytes() == plain
    else:
        paths = archive_module.download_firmware_super_partitions(
            model="SM-TEST",
            region="EUX",
            outer_selector="AP",
            partitions=("vendor_a",),
            output=tmp_path,
            threads=threads,
        )
        assert paths[0].read_bytes() == plain
    assert server.max_active == (6 if threads is None else threads)
    assert not list(tmp_path.glob("*.part"))
    assert not any(thread.name.startswith("asgard-range-") for thread in threading.enumerate())


def test_parallel_extraction_recovers_expired_auth_once(server, monkeypatch):
    monkeypatch.setattr(streaming, "_DOWNLOAD_MIN_RANGE_SIZE", 256 * 1024)
    plain = random.Random(36).randbytes(2 * 1024 * 1024)
    server.data = encrypt(plain)
    with FUSClient() as client:

        def recover():
            client.refresh_auth()
            client.make_request(FUSClient.BINARY_INIT_PATH, b"init")

        with _FUSDecryptingReader(
            client=client, remote_path="test", encrypted_size=len(server.data), key=KEY, recover_download=recover
        ) as reader:
            server.auth_required = True
            with reader.streaming():
                assert reader.read() == plain
    assert server.nonce_requests == server.init_requests == 1


def test_small_archive_extraction_does_not_prefetch_the_following_archive(server, tmp_path, monkeypatch):
    monkeypatch.setattr(streaming, "_DOWNLOAD_MIN_RANGE_SIZE", 256 * 1024)
    plain = random.Random(38).randbytes(65536)
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as archive:
        archive.writestr("BL_test.tar.md5", plain)
        archive.writestr("AP_test.tar.md5", random.Random(39).randbytes(3 * 1024 * 1024))
    server.data = encrypt(zip_buffer.getvalue())
    info = BinaryInfo("", "test.zip.enc4", len(server.data), firmware_version="A/B/C/D")
    monkeypatch.setattr(fus, "_resolve_versioned_info", lambda *args: info)
    monkeypatch.setattr(fus, "initialize_download", lambda *args: None)
    monkeypatch.setattr(fus, "_decryption_key_from_info", lambda *args: KEY)
    paths = archive_module.download_firmware_entries(model="SM-TEST", region="EUX", selectors=("BL",), out_dir=tmp_path)
    assert paths[0].read_bytes() == plain
    assert sum(end - start + 1 for start, end, _ in server.requests) <= 128 * 1024 + len(plain) + 132 * 1024


def test_parallel_extraction_rejects_wrong_ranges_and_closes_connections(server, monkeypatch):
    monkeypatch.setattr(streaming, "_DOWNLOAD_MIN_RANGE_SIZE", 256 * 1024)
    monkeypatch.setattr(streaming, "_DOWNLOAD_RETRIES", 1)
    server.data = encrypt(random.Random(37).randbytes(2 * 1024 * 1024))
    with (
        FUSClient() as client,
        _FUSDecryptingReader(client=client, remote_path="test", encrypted_size=len(server.data), key=KEY) as reader,
    ):
        server.bad_range = True
        with pytest.raises(FUSError, match="wrong byte range"), reader.streaming():
            reader.read()
        assert reader._gate.active == 0
        assert not any(thread.name.startswith("asgard-range-") for thread in threading.enumerate())


@pytest.mark.parametrize(
    ("options", "function", "single_output"),
    [
        ([], "download_firmware_entries", False),
        (["--file", "boot.img.lz4"], "download_firmware_tar_member", True),
        (["--partition", "vendor_a"], "download_firmware_super_partitions", False),
        (["--partition", "vendor_a", "--path", "/vendor_a/etc/build.prop"], "download_firmware_partition_files", False),
        (["--list-entries"], "iter_firmware_tar_entries", False),
        (["--list-partitions"], "iter_firmware_super_partitions", False),
    ],
)
def test_cli_thread_override_reaches_extraction(tmp_path, monkeypatch, options, function, single_output):
    captured = {}
    destination = tmp_path / "result.img"

    def extract(**kwargs):
        captured.update(kwargs)
        if single_output:
            return destination
        return () if options and options[0].startswith("--list") else (destination,)

    monkeypatch.setattr(archive_module, function, extract)
    parser = _build_parser()
    output_options = [] if options and options[0].startswith("--list") else ["-o", str(tmp_path)]
    args = parser.parse_args(
        ["download", "SM-TEST", "EUX", "--archive", "AP", "--threads", "3", "--json"] + output_options + options
    )
    assert _handle_download(args, parser) == 0
    assert captured["threads"] == 3


@pytest.mark.parametrize("compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_large_tar_extraction_keeps_one_stream_without_refetching(server, compression):
    members = {
        "boot.img": b"boot" * 1024,
        "super.img.lz4": random.Random(21).randbytes(12 * 1024 * 1024),
        "vbmeta.img": b"meta" * 1024,
    }
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
        for name, content in members.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(content)
            tar.addfile(entry, io.BytesIO(content))
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as archive:
        archive.writestr("AP.tar.md5", tar_buffer.getvalue(), compress_type=compression)
    server.data = encrypt(zip_buffer.getvalue())
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
        zipfile.ZipFile(reader) as archive,
    ):
        remote = archive_module._RemoteFirmwareArchive(
            "SM-TEST",
            "EUX",
            BinaryInfo("", "test.zip.enc4", len(server.data), firmware_version="A/B/C/D"),
            "A/B/C/D",
            reader,
            archive,
        )
        with archive_module._open_firmware_tar(remote, archive.getinfo("AP.tar.md5")) as tar:
            for entry in tar:
                with tar.extractfile(entry) as source:
                    assert source.read() == members[entry.name]
        assert len(server.requests) == 2
        assert sum(received) == len(server.data)
        reader.seek(512)
        assert reader.read(32) == zip_buffer.getvalue()[512:544]
        assert len(server.requests) == 3
        assert sum(received) == len(server.data) + 65536


@pytest.mark.parametrize("compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
@pytest.mark.parametrize("corrupt", [False, True])
def test_streamed_lz4_tar_member_preserves_data_and_validates_checksum(server, compression, corrupt):
    plain = random.Random(22).randbytes(2 * 1024 * 1024) + bytes(1024 * 1024)
    packed = lz4_frame.compress(plain, content_checksum=True)
    if corrupt:
        packed = packed[:-1] + bytes([packed[-1] ^ 1])
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
        entry = tarfile.TarInfo("super.img.lz4")
        entry.size = len(packed)
        tar.addfile(entry, io.BytesIO(packed))
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as archive:
        archive.writestr("AP.tar.md5", tar_buffer.getvalue(), compress_type=compression)
    server.data = encrypt(zip_buffer.getvalue())
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
        zipfile.ZipFile(reader) as archive,
    ):
        remote = archive_module._RemoteFirmwareArchive(
            "SM-TEST",
            "EUX",
            BinaryInfo("", "test.zip.enc4", len(server.data), firmware_version="A/B/C/D"),
            "A/B/C/D",
            reader,
            archive,
        )
        with archive_module._open_firmware_tar(remote, archive.getinfo("AP.tar.md5")) as tar:
            with tar.extractfile(next(iter(tar))) as source:
                output = io.BytesIO()
                if corrupt:
                    with pytest.raises(FUSError, match="could not decompress LZ4"):
                        archive_module.copy_lz4_stream(source, output, label="test", keep_sparse=True)
                else:
                    archive_module.copy_lz4_stream(source, output, label="test", keep_sparse=True)
                    assert output.getvalue() == plain
                    assert len(server.requests) == 2
                    assert sum(received) == len(server.data)


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
    monkeypatch.setattr(scheduling, "_DOWNLOAD_MIN_RANGE_SIZE", 256 * 1024)
    monkeypatch.setattr(download, "_DOWNLOAD_CHUNK_SIZE", 65536)
    plain = random.Random(14).randbytes(3 * 1024 * 1024)
    server.data = encrypt(plain)
    server.chunk_delay = 0.005
    info = BinaryInfo("/test/", "test.zip.enc4", len(server.data), firmware_version="A/B/C/D")
    monkeypatch.setattr(download, "_resolve_versioned_info", lambda *args: info)
    monkeypatch.setattr(download, "initialize_download", lambda *args: None)
    monkeypatch.setattr(download, "_decryption_key_from_info", lambda *args: KEY)
    monkeypatch.setattr(download, "_print_info", lambda *args: None)
    result = download.download_firmware(model="SM-TEST", region="EUX", out_dir=tmp_path, auto_decrypt=decrypt)
    path = result.decrypted_path if decrypt else result.encrypted_path
    assert path.read_bytes() == (plain if decrypt else server.data)
    assert not list(tmp_path.glob("*.resume.json"))
    assert server.max_active == 6


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


@pytest.mark.parametrize("mode", ["metadata", "stream", "parallel"])
def test_expired_authorization_reinitializes_before_retry(server, tmp_path, mode):
    plain = random.Random(16).randbytes(1024 * 1024)
    server.data = encrypt(plain)
    server.auth_required = True
    with FUSClient() as client:

        def recover():
            client.refresh_auth()
            client.make_request(FUSClient.BINARY_INIT_PATH, b"init")

        if mode == "metadata":
            result = _read_download_range(
                client=client,
                remote_path="test",
                start=0,
                end=len(server.data) - 1,
                total_size=len(server.data),
                recover_download=recover,
            )
            assert result == server.data
        elif mode == "stream":
            with _FUSDecryptingReader(
                client=client, remote_path="test", encrypted_size=len(server.data), key=KEY, recover_download=recover
            ) as reader:
                assert reader.read() == plain
        else:
            path = tmp_path / "expired.part"
            ranges, _ = _prepare_range_resume_state(path, len(server.data), False, part_count=1)
            download._download_ranges_parallel(
                client=client,
                remote_path="test",
                out_path=path,
                total_size=len(server.data),
                ranges=ranges,
                workers=4,
                recover_download=recover,
            )
            assert path.read_bytes() == server.data
    assert server.nonce_requests == 1
    assert server.init_requests == 1
    assert sum(item[0] == server.requests[0][0] for item in server.requests) == 2


def test_persistent_unauthorized_response_stops_without_transfer_retries(server):
    server.data = bytes(65536)
    server.auth_required = True
    server.permanent_401 = True
    with FUSClient() as client:

        def recover():
            client.refresh_auth()
            client.make_request(FUSClient.BINARY_INIT_PATH, b"init")

        with pytest.raises(FUSError, match="authorization failed after session recovery.*401"):
            _read_download_range(
                client=client, remote_path="test", start=0, end=65535, total_size=65536, recover_download=recover
            )
    assert len(server.requests) == 2
    assert server.nonce_requests == 1
    assert server.init_requests == 1


def test_workers_share_nonce_refresh_and_download_initialization(monkeypatch):
    barrier = threading.Barrier(4)
    posts = []
    initialized = threading.Event()

    class Session:
        def get(self, url, *, headers, **kwargs):
            response = requests.Response()
            response._content = b""
            response._content_consumed = True
            if "old" in headers["Authorization"]:
                barrier.wait(timeout=2)
                response.status_code = 401
            else:
                response.status_code = 206 if initialized.is_set() else 401
            return response

        def post(self, url, **kwargs):
            posts.append(url.rsplit("/", 1)[-1])
            response = requests.Response()
            response.status_code = 200
            response._content = b""
            response._content_consumed = True
            if url.endswith(FUSClient.GENERATE_NONCE_PATH):
                response.headers["NONCE"] = "new"
            elif url.endswith(FUSClient.BINARY_INIT_PATH):
                initialized.set()
            return response

    monkeypatch.setattr(client_module, "_RETRY_BACKOFF_S", 0)
    client = FUSClient(session=Session())
    client.encnonce = "old"

    def recover():
        client.refresh_auth()
        client.make_request(FUSClient.BINARY_INIT_PATH, b"init")

    client.configure_download_recovery(recover)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: client.download_file("test", start=0, end=15), range(4)))
    assert all(response.status_code == 206 for response in results)
    assert posts == [FUSClient.GENERATE_NONCE_PATH, FUSClient.BINARY_INIT_PATH]


def test_concurrency_probe_rejects_no_throughput_gain(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(scheduling.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(scheduling, "_DOWNLOAD_REQUEST_INTERVAL_S", 0)
    gate = AdaptiveDownloadGate(4, initial_workers=1)
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
    gate = AdaptiveDownloadGate(4, initial_workers=1)
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
