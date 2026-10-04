from __future__ import annotations

import bz2
import hashlib
import io
import random
import struct
import zipfile

import brotli
import bsdiff4
import pytest

from asgard.core.errors import FUSError
from asgard.ota.merge import inspect_ota, merge_ota
from asgard.ota.patch import apply_bsdiff, apply_bsdiff_to_file


def integer(value):
    raw = bytearray(abs(value).to_bytes(8, "little"))
    if value < 0:
        raw[7] |= 0x80
    return bytes(raw)


def convert_patch(patch, compressors):
    control_size = int.from_bytes(patch[8:16], "little")
    diff_size = int.from_bytes(patch[16:24], "little")
    streams = (
        patch[32 : 32 + control_size],
        patch[32 + control_size : 32 + control_size + diff_size],
        patch[32 + control_size + diff_size :],
    )
    encoders = (lambda value: value, bz2.compress, brotli.compress)
    encoded = tuple(encoders[kind](bz2.decompress(raw)) for kind, raw in zip(compressors, streams, strict=True))
    return (
        b"BSDF2"
        + bytes(compressors)
        + integer(len(encoded[0]))
        + integer(len(encoded[1]))
        + patch[24:32]
        + b"".join(encoded)
    )


class ShortReads(io.BytesIO):
    def read(self, size=-1):
        return super().read(min(17, size) if size >= 0 else 17)


class ShortWrites(io.BytesIO):
    def write(self, data):
        return super().write(data[:23])


@pytest.mark.parametrize("compressors", [None, (0, 0, 0), (2, 2, 2), (0, 1, 2)])
def test_bsdiff_memory_and_streamed_patch_match_independent_output(tmp_path, compressors):
    source = random.Random(42).randbytes(2 * 1024 * 1024 + 113)
    target = b"new prefix" + source[123:-129] + b"changed suffix" * 73
    patch = bsdiff4.diff(source, target)
    assert bsdiff4.patch(source, patch) == target
    if compressors is not None:
        patch = convert_patch(patch, compressors)
    assert apply_bsdiff(source, patch, expected_size=len(target)) == target
    path = tmp_path / "base.img"
    path.write_bytes(source)
    output = ShortWrites()
    hashes = apply_bsdiff_to_file(
        path, tuple(ShortReads(patch) for _ in range(3)), len(patch), output, expected_size=len(target)
    )
    assert output.getvalue() == target
    assert hashes == (hashlib.sha1(target).hexdigest(), hashlib.sha256(target).hexdigest())


def test_bsdiff_negative_source_seek_pads_outside_source(tmp_path):
    source = b"abcdefgh"
    control = b"".join(integer(value) for value in (2, 0, -4, 4, 3, 0))
    diff = b"\xe0\xe0\x01\x02\x02\x02"
    extra = b"END"
    target = b"AB\x01\x02cdEND"
    patch = b"BSDF2\0\0\0" + integer(len(control)) + integer(len(diff)) + integer(len(target)) + control + diff + extra
    assert apply_bsdiff(source, patch) == target
    path = tmp_path / "base.img"
    path.write_bytes(source)
    output = io.BytesIO()
    apply_bsdiff_to_file(path, tuple(io.BytesIO(patch) for _ in range(3)), len(patch), output)
    assert output.getvalue() == target


@pytest.mark.parametrize("mutation", ["header", "negative", "control", "truncated", "target", "compressor"])
def test_invalid_bsdiff_is_rejected_by_memory_and_streaming_paths(tmp_path, mutation):
    source, target = b"base bytes" * 100, b"patched bytes" * 101
    patch = convert_patch(bsdiff4.diff(source, target), (0, 0, 0))
    if mutation == "header":
        patch = b"invalid!" + patch[8:]
    elif mutation == "negative":
        patch = patch[:8] + integer(-1) + patch[16:]
    elif mutation == "control":
        patch = patch[:32] + integer(-1) + patch[40:]
    elif mutation == "truncated":
        patch = patch[:-1]
    elif mutation == "target":
        patch = patch[:24] + integer(len(target) + 1) + patch[32:]
    else:
        patch = b"BSDF2\x03\x03\x03" + patch[8:]
    with pytest.raises(FUSError):
        apply_bsdiff(source, patch)
    path = tmp_path / "base.img"
    path.write_bytes(source)
    with pytest.raises(FUSError):
        apply_bsdiff_to_file(path, tuple(io.BytesIO(patch) for _ in range(3)), len(patch), io.BytesIO())


def varint(value):
    output = bytearray()
    while value > 127:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return bytes(output)


def field(number, value):
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    return varint((number << 3) | 2) + varint(len(value)) + value


def make_payload(data, *, bad_hash=False):
    digest = bytes(32) if bad_hash else hashlib.sha256(data).digest()
    extent = field(1, 0) + field(2, 1)
    operation = field(1, 0) + field(2, 0) + field(3, len(data)) + field(6, extent) + field(8, digest)
    info = field(1, len(data)) + field(2, hashlib.sha256(data).digest())
    partition = field(1, b"vendor") + field(7, info) + field(8, operation)
    manifest = field(3, 4096) + field(13, partition)
    return b"CrAU" + struct.pack(">QQI", 2, len(manifest), 0) + manifest + data


def ota_zip(path, kind, entries):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("META-INF/com/android/metadata", f"ota-type={kind}\npost-build-incremental=TEST\n")
        for name, data in entries.items():
            archive.writestr(name, data)
    return path


@pytest.mark.parametrize("kind", ["block", "ab"])
def test_complete_ota_zip_applies_and_resumes_verified_output(tmp_path, kind):
    data = bytes(range(256)) * 16
    if kind == "block":
        entries = {"vendor.transfer.list": b"4\n2\n0\n0\nnew 2,0,1\nzero 2,1,2\n", "vendor.new.dat": data}
        expected = data + bytes(4096)
    else:
        entries = {"payload.bin": make_payload(data)}
        expected = data
    path = ota_zip(tmp_path / "update.zip", kind, entries)
    plan = inspect_ota(path)
    assert plan.metadata.ota_type == kind
    assert plan.partitions[0].name == "vendor"
    output = tmp_path / "output"
    result = merge_ota(path, output, {}, jobs=2)
    assert result.paths[0].read_bytes() == expected
    resumed = merge_ota(path, output, {}, resume=True, jobs=2)
    assert resumed.skipped == resumed.paths
    assert resumed.paths[0].read_bytes() == expected


@pytest.mark.parametrize("kind", ["block", "ab"])
def test_complete_ota_zip_rejects_truncated_operation_data(tmp_path, kind):
    data = bytes(range(256)) * 16
    entries = (
        {"vendor.transfer.list": b"4\n1\n0\n0\nnew 2,0,1\n", "vendor.new.dat": data[:-1]}
        if kind == "block"
        else {"payload.bin": make_payload(data)[:-1]}
    )
    path = ota_zip(tmp_path / "broken.zip", kind, entries)
    with pytest.raises(FUSError):
        merge_ota(path, tmp_path / "output", {}, jobs=1)
    assert not (tmp_path / "output" / "vendor.img").exists()


def test_payload_rejects_wrong_operation_hash(tmp_path):
    path = ota_zip(tmp_path / "broken.zip", "ab", {"payload.bin": make_payload(bytes(4096), bad_hash=True)})
    with pytest.raises(FUSError, match="hash"):
        merge_ota(path, tmp_path / "output", {}, jobs=1)


def test_streamed_patch_rejects_missing_bzip2_trailer(tmp_path):
    patch = bsdiff4.diff(b"", b"target" * 100)[:-1]
    path = tmp_path / "base.img"
    path.write_bytes(b"")
    with pytest.raises(FUSError):
        apply_bsdiff_to_file(path, tuple(io.BytesIO(patch) for _ in range(3)), len(patch), io.BytesIO())


@pytest.mark.parametrize("manifest", [b"\x80" * 10, b"\x00", b"\x6a\xff\xff\x7f"])
def test_payload_rejects_malformed_protobuf_manifest(tmp_path, manifest):
    payload = b"CrAU" + struct.pack(">QQI", 2, len(manifest), 0) + manifest
    path = ota_zip(tmp_path / "broken.zip", "ab", {"payload.bin": payload})
    with pytest.raises(FUSError):
        inspect_ota(path)
