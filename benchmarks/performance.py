from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from Cryptodome.Cipher import AES

from asgard.formats.ext4 import Ext4, _Inode
from asgard.fus import client as client_module
from asgard.fus.client import FUSClient
from asgard.fus.scheduling import split_download_ranges
from asgard.fus.streaming import _FUSDecryptingReader


def load_baseline(path, reference, constants=None):
    repo = Path(__file__).resolve().parents[1]
    source = subprocess.run(
        ["git", "show", f"{reference}:{path}"], cwd=repo, check=True, capture_output=True, text=True
    ).stdout
    name = path.removesuffix(".py").replace("/", ".") + "_baseline"
    module = types.ModuleType(name)
    module.__package__ = name.rsplit(".", 1)[0]
    sys.modules[name] = module
    exec(compile(source, path, "exec"), vars(module))
    if constants is not None:
        for key, value in vars(constants).items():
            if key.startswith("_") and not key.startswith("__") and hasattr(module, key):
                setattr(module, key, value)
    return module


def metadata_benchmark(old_reader, latency):
    key = bytes(range(16))
    plain = random.Random(11).randbytes(4 * 1024 * 1024)
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(plain + bytes([16]) * 16)
    requests = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self):
            super().setup()
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        def log_message(self, *args):
            pass

        def handle(self):
            try:
                super().handle()
            except ConnectionResetError:
                pass

        def do_GET(self):
            start, end = map(int, re.fullmatch(r"bytes=(\d+)-(\d+)", self.headers["Range"]).groups())
            requests.append((start, end))
            time.sleep(latency)
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {start}-{end}/{len(encrypted)}")
            self.send_header("Content-Length", str(end - start + 1))
            self.end_headers()
            try:
                self.wfile.write(memoryview(encrypted)[start : end + 1])
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    original_url = client_module._FUS_DOWNLOAD_URL
    client_module._FUS_DOWNLOAD_URL = f"http://127.0.0.1:{server.server_port}/download"
    results = {}
    try:
        for label, reader_type in (("before", old_reader), ("after", _FUSDecryptingReader)):
            requests.clear()
            received = []
            started = time.perf_counter()
            with (
                FUSClient() as client,
                reader_type(
                    client=client,
                    remote_path="benchmark",
                    encrypted_size=len(encrypted),
                    key=key,
                    stream_chunk_size=1024 * 1024,
                    network_progress=received.append,
                ) as reader,
            ):
                for _ in range(10):
                    for offset in (123, 1024 * 1024 + 100123, 2 * 1024 * 1024 + 200123):
                        reader.seek(offset)
                        assert reader.read(97) == plain[offset : offset + 97]
            results[label] = {
                "seconds": round(time.perf_counter() - started, 3),
                "requests": len(requests),
                "received_bytes": sum(received),
            }
    finally:
        client_module._FUS_DOWNLOAD_URL = original_url
        server.shutdown()
        server.server_close()
        thread.join()
    return results


def image_benchmark():
    block_size = 4096
    blocks = 8192
    raw = bytearray(b"F" * ((blocks + 16) * block_size))
    struct.pack_into("<HHHHI", raw, block_size, 0xF30A, 1, 340, 0, 0)
    struct.pack_into("<IHHI", raw, block_size + 12, 0, blocks, 0, 16)
    root = bytearray(60)
    struct.pack_into("<HHHHI", root, 0, 0xF30A, 1, 4, 1, 0)
    struct.pack_into("<IIHH", root, 12, 0, 1, 0, 0)
    inode = _Inode(stat.S_IFREG | 0o644, blocks * block_size, 0x80000, bytes(root))

    class Image:
        reads = 0

        def read_at(self, offset, size):
            self.reads += 1
            return raw[offset : offset + size]

    filesystem = object.__new__(Ext4)
    filesystem.block_size = block_size
    results = {}
    digests = []
    for label, read_file in (("before", filesystem._data), ("after", filesystem.iter_file)):
        filesystem.image = Image()
        digest = hashlib.sha256()
        started = time.perf_counter()
        for chunk in read_file(inode):
            digest.update(chunk)
        results[label] = {"seconds": round(time.perf_counter() - started, 3), "reads": filesystem.image.reads}
        digests.append(digest.digest())
    assert digests[0] == digests[1]
    return results


def parallel_stream_benchmark(size_mib=96, mib_per_second=16):
    key = bytes(range(16))
    plain = random.Random(31).randbytes(size_mib * 1024 * 1024)
    expected_digest = hashlib.sha256(plain).hexdigest()
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(plain + bytes([16]) * 16)
    lock = threading.Lock()
    active = 0
    max_active = 0

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def handle(self):
            try:
                super().handle()
            except ConnectionResetError:
                pass

        def do_GET(self):
            nonlocal active, max_active
            start, end = map(int, re.fullmatch(r"bytes=(\d+)-(\d+)", self.headers["Range"]).groups())
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {start}-{end}/{len(encrypted)}")
            self.send_header("Content-Length", str(end - start + 1))
            self.end_headers()
            with lock:
                active += 1
                max_active = max(max_active, active)
            try:
                deadline = time.perf_counter()
                for offset in range(start, end + 1, 65536):
                    chunk = memoryview(encrypted)[offset : min(end + 1, offset + 65536)]
                    deadline += len(chunk) / (mib_per_second * 1024 * 1024)
                    time.sleep(max(0, deadline - time.perf_counter()))
                    self.wfile.write(chunk)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                with lock:
                    active -= 1

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    original_url = client_module._FUS_DOWNLOAD_URL
    client_module._FUS_DOWNLOAD_URL = f"http://127.0.0.1:{server.server_port}/download"
    results = {"source": "local HTTP server", "per_connection_mib_s": mib_per_second, "size_mib": size_mib}
    try:
        for workers in (1, 6):
            max_active = 0
            digest = hashlib.sha256()
            started = time.perf_counter()
            with (
                FUSClient() as client,
                _FUSDecryptingReader(
                    client=client,
                    remote_path="benchmark",
                    encrypted_size=len(encrypted),
                    key=key,
                    stream_chunk_size=1024 * 1024,
                    threads=workers,
                ) as reader,
                reader.streaming(),
            ):
                while chunk := reader.read(1024 * 1024):
                    digest.update(chunk)
            elapsed = time.perf_counter() - started
            assert digest.hexdigest() == expected_digest
            results[f"{workers}_connections"] = {
                "seconds": round(elapsed, 3),
                "ordered_mib_s": round(size_mib / elapsed, 2),
                "max_active": max_active,
                "sha256": digest.hexdigest(),
            }
    finally:
        client_module._FUS_DOWNLOAD_URL = original_url
        server.shutdown()
        server.server_close()
        thread.join()
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", default="HEAD")
    parser.add_argument("--latency-ms", default=50.0, type=float)
    parser.add_argument("--parallel-stream-only", action="store_true")
    args = parser.parse_args()
    if args.parallel_stream_only:
        print(json.dumps(parallel_stream_benchmark(), indent=2))
        return
    constants = load_baseline("asgard/core/constants.py", args.baseline)
    old_streaming = load_baseline("asgard/fus/streaming.py", args.baseline, constants)
    old_scheduling = load_baseline("asgard/fus/scheduling.py", args.baseline, constants)
    ranges = [{"start": 0, "end": 12 * 1024**3 - 1, "offset": 0}]
    results = {
        "remote_metadata": metadata_benchmark(old_streaming._FUSDecryptingReader, args.latency_ms / 1000),
        "ext4_extraction": image_benchmark(),
        "ordered_parallel_stream": parallel_stream_benchmark(),
        "12_gib_download_requests": {
            "before": len(old_scheduling.split_download_ranges(ranges, workers=4)),
            "after": len(split_download_ranges(ranges, workers=4)),
        },
    }
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
