# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import hashlib
import io
import struct

import pytest
from lz4 import frame as lz4_frame

from asgard.core.errors import FUSError
from asgard.formats import archive as archive_module
from asgard.formats import images as images_module


def super_image(partitions):
    data_offset = 5 * 4096
    geometry = bytearray(4096)
    struct.pack_into("<II32sIII", geometry, 0, 0x616C4467, 52, bytes(32), 4096, 1, 4096)
    geometry[8:40] = hashlib.sha256(geometry[:52]).digest()
    partition_records = []
    extent_records = []
    offset = data_offset
    for index, (name, data) in enumerate(partitions.items()):
        partition_records.append(struct.pack("<36sIIII", name.encode(), 0, index, 1, 0))
        extent_records.append(struct.pack("<QIQI", len(data) // 512, 0, offset // 512, 0))
        offset += len(data)
    records = (
        b"".join(partition_records),
        b"".join(extent_records),
        struct.pack("<36sIQ", b"default", 0, 0),
        struct.pack("<QIIQ36sI", data_offset // 512, 4096, 0, offset, b"super", 0),
    )
    tables = b"".join(records)
    header = bytearray(128)
    struct.pack_into(
        "<IHHI32sI32s", header, 0, 0x414C5030, 10, 0, 128, bytes(32), len(tables), hashlib.sha256(tables).digest()
    )
    offset = 0
    for index, record in enumerate(records):
        count = len(partitions) if index < 2 else 1
        struct.pack_into("<III", header, 80 + index * 12, offset, count, len(record) // count)
        offset += len(record)
    header[12:44] = hashlib.sha256(header).digest()
    metadata = (header + tables).ljust(4096, b"\0")
    return bytes(4096) + bytes(geometry) * 2 + bytes(metadata) * 2 + b"".join(partitions.values())


@pytest.fixture(params=["raw", "lz4", "sparse", "sparse-lz4"])
def firmware_super(request, monkeypatch):
    partitions = {"system_a": b"s" * 8192, "system_ext_a": b"e" * 4096}
    data = super_image(partitions)
    name = "super.img"
    if request.param.startswith("sparse"):
        block_count = len(data) // 4096
        header = struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, 4096, block_count, 1, 0)
        chunk = struct.pack("<HHII", 0xCAC1, 0, block_count, len(data) + 12)
        data = header + chunk + data
    if request.param.endswith("lz4"):
        data = lz4_frame.compress(data, content_checksum=True)
        name += ".lz4"
    source = io.BytesIO(data)
    monkeypatch.setattr(
        archive_module, "_run_firmware_super_operation", lambda **kwargs: kwargs["operation"](source, name, len(data))
    )
    return partitions, data, name, source


def download(output, partitions=("system_a", "system_ext_a"), *, resume=True, **kwargs):
    return archive_module.download_firmware_super_partitions(
        model="SM-S942B",
        region="EUX",
        outer_selector="AP",
        partitions=partitions,
        output=output,
        resume=resume,
        **kwargs,
    )


@pytest.mark.parametrize("requested", [("system_a", "system_ext_a"), None], ids=["selected", "all"])
@pytest.mark.parametrize("completed", [(), ("system_a",), ("system_ext_a",), ("system_a", "system_ext_a")])
def test_resume_keeps_completed_partitions_and_extracts_remaining(tmp_path, firmware_super, requested, completed):
    partitions, _data, _name, _source = firmware_super
    previous_stats = {}
    for name in completed:
        path = tmp_path / f"{name}.img"
        path.write_bytes(partitions[name])
        previous_stats[name] = path.stat()

    paths = download(tmp_path, requested)

    assert paths == tuple(tmp_path / f"{name}.img" for name in partitions)
    for name, data in partitions.items():
        path = tmp_path / f"{name}.img"
        assert path.read_bytes() == data
        if name in previous_stats:
            assert path.stat().st_ino == previous_stats[name].st_ino
            assert path.stat().st_mtime_ns == previous_stats[name].st_mtime_ns
    assert not list(tmp_path.glob("*.part"))


@pytest.mark.parametrize("cache_complete", [False, True], ids=["partial-cache", "complete-cache"])
def test_resume_restarts_interrupted_partition_from_cached_source(tmp_path, firmware_super, cache_complete):
    partitions, data, name, source = firmware_super
    completed = tmp_path / "system_a.img"
    completed.write_bytes(partitions["system_a"])
    previous_stat = completed.stat()
    partial = tmp_path / "system_ext_a.img.part"
    partial.write_bytes(b"interrupted extraction")
    source_cache = tmp_path / f".{name}.{len(data)}.asgard-source.part"
    source_cache.write_bytes(data if cache_complete else data[: len(data) // 2])

    paths = download(tmp_path)

    assert [path.read_bytes() for path in paths] == list(partitions.values())
    assert completed.stat().st_mtime_ns == previous_stat.st_mtime_ns
    assert source.tell() == (0 if cache_complete else len(data))
    assert not list(tmp_path.glob("*.part"))


@pytest.mark.parametrize("existing", [b"", b"short", b"x" * 16384, None], ids=["empty", "short", "long", "directory"])
def test_resume_rejects_invalid_existing_partition_output(tmp_path, firmware_super, existing):
    partitions, _data, _name, _source = firmware_super
    completed = tmp_path / "system_a.img"
    if existing is None:
        completed.mkdir()
    else:
        completed.write_bytes(existing)
    other = tmp_path / "system_ext_a.img"
    other.write_bytes(partitions["system_ext_a"])

    with pytest.raises(FUSError, match="system_a.img.*(size|regular file)"):
        download(tmp_path)

    assert completed.is_dir() if existing is None else completed.read_bytes() == existing
    assert other.read_bytes() == partitions["system_ext_a"]


def test_resume_validates_requested_partition_before_reusing_output(tmp_path, firmware_super):
    invalid = tmp_path / "missing.img"
    invalid.write_bytes(b"existing output")

    with pytest.raises(FUSError, match="super partition not found: missing"):
        download(tmp_path, ("missing",))

    assert invalid.read_bytes() == b"existing output"


def test_resume_supports_slot_fallback(tmp_path, firmware_super):
    partitions, _data, _name, _source = firmware_super
    completed = tmp_path / "system.img"
    completed.write_bytes(partitions["system_a"])

    paths = download(tmp_path, ("system", "system_ext"), slot_fallback=True)

    assert paths == (completed, tmp_path / "system_ext.img")
    assert [path.read_bytes() for path in paths] == list(partitions.values())
    assert not list(tmp_path.glob("*.part"))


def test_failed_resume_preserves_completed_outputs_and_source_cache(tmp_path, firmware_super, monkeypatch):
    partitions, data, name, _source = firmware_super
    completed = tmp_path / "system_a.img"
    completed.write_bytes(partitions["system_a"])
    previous_stat = completed.stat()
    source_cache = tmp_path / f".{name}.{len(data)}.asgard-source.part"

    def interrupted_copy(*args, **kwargs):
        raise OSError("interrupted extraction")

    with monkeypatch.context() as interrupted:
        interrupted.setattr(images_module._RawForwardReader, "copy_to", interrupted_copy)
        interrupted.setattr(images_module._SparseRawReader, "copy_to", interrupted_copy)
        with pytest.raises(OSError, match="interrupted extraction"):
            download(tmp_path)

    assert completed.read_bytes() == partitions["system_a"]
    assert completed.stat().st_mtime_ns == previous_stat.st_mtime_ns
    assert source_cache.read_bytes() == data
    assert not (tmp_path / "system_ext_a.img.part").exists()
    assert not (tmp_path / "system_ext_a.img").exists()

    paths = download(tmp_path)

    assert [path.read_bytes() for path in paths] == list(partitions.values())
    assert completed.stat().st_mtime_ns == previous_stat.st_mtime_ns
    assert not list(tmp_path.glob("*.part"))


@pytest.mark.parametrize("suffix", [".img", ".img.part"])
def test_extraction_without_resume_preserves_existing_outputs(tmp_path, firmware_super, suffix):
    existing = tmp_path / f"system_a{suffix}"
    existing.write_bytes(b"existing output")

    with pytest.raises(FUSError, match="already exists"):
        download(tmp_path, resume=False)

    assert existing.read_bytes() == b"existing output"
    assert not (tmp_path / "system_ext_a.img").exists()
