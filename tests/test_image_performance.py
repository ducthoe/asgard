from __future__ import annotations

import random
import stat
import struct

import pytest
from Cryptodome.Cipher import AES

from asgard.formats.erofs import EROFS
from asgard.formats.erofs import _Inode as ErofsInode
from asgard.formats.ext4 import Ext4
from asgard.formats.ext4 import _Inode as Ext4Inode
from asgard.fus import crypto
from asgard.fus.resume import _prepare_range_resume_state, _resume_done_bytes


class Image:
    def __init__(self, data):
        self.data = data
        self.size = len(data)
        self.reads = 0

    def read_at(self, offset, size):
        self.reads += 1
        assert 0 <= offset <= offset + size <= self.size
        return self.data[offset : offset + size]


def extent_node(entries, depth=0, size=4096):
    node = bytearray(size)
    struct.pack_into("<HHHHI", node, 0, 0xF30A, len(entries), (size - 12) // 12, depth, 0)
    for index, (logical, count, physical) in enumerate(entries):
        if depth:
            struct.pack_into("<IIHH", node, 12 + index * 12, logical, physical, 0, 0)
        else:
            struct.pack_into("<IHHI", node, 12 + index * 12, logical, count, 0, physical)
    return bytes(node)


def test_ext4_extent_batches_preserve_holes_and_unwritten_data():
    data = bytearray(random.Random(8).randbytes(5 * 1024 * 1024))
    entries = [(0, 700, 16), (710, 32768 + 10, 0), (720, 11, 800)]
    data[4096:8192] = extent_node(entries)
    image = Image(data)
    filesystem = object.__new__(Ext4)
    filesystem.image = image
    filesystem.block_size = 4096
    inode = Ext4Inode(stat.S_IFREG | 0o644, 730 * 4096 + 100, 0x80000, extent_node([(0, 0, 1)], depth=1, size=60))
    expected = b"".join(filesystem._data(inode))
    previous_reads = image.reads
    image.reads = 0
    assert b"".join(filesystem.iter_file(inode)) == expected
    assert image.reads <= 6
    assert previous_reads > 1400


@pytest.mark.parametrize("layout", [0, 2])
def test_erofs_batches_preserve_inline_tails(layout):
    image = Image(random.Random(9).randbytes(4 * 1024 * 1024))
    filesystem = object.__new__(EROFS)
    filesystem.image = image
    filesystem.block_size = 4096
    inode = ErofsInode(128, 32, 8, stat.S_IFREG | 0o644, 2 * 1024 * 1024 + 123, layout, 16)
    expected = b"".join(filesystem._data(inode))
    previous_reads = image.reads
    image.reads = 0
    assert b"".join(filesystem.iter_file(inode)) == expected
    assert image.reads == 3
    assert previous_reads == 513


def test_failed_decryption_checkpoint_can_resume(tmp_path, monkeypatch):
    plain = random.Random(10).randbytes(65536)
    key = crypto.get_v2_key("A/B/C/D", "SM-TEST", "EUX")
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(plain + bytes([16]) * 16)
    source = tmp_path / "input.enc2"
    output = tmp_path / "output.zip"
    source.write_bytes(encrypted)
    real_decrypt = crypto._decrypt_range
    monkeypatch.setattr(crypto, "_render_progress", lambda *args, **kwargs: None)

    def interrupted(in_path, out_path, key, start, end, progress):
        real_decrypt(in_path, out_path, key, start, start + 32767, progress)
        raise OSError("interrupted")

    monkeypatch.setattr(crypto, "_decrypt_range", interrupted)
    kwargs = dict(
        version="A/B/C/D", model="SM-TEST", region="EUX", in_file=source, out_file=output, enc_ver=2, threads=1
    )
    with pytest.raises(OSError, match="interrupted"):
        crypto.decrypt_firmware(**kwargs)
    parts, _ = _prepare_range_resume_state(
        output.with_name("output.zip.part"), len(encrypted), True, part_count=1, alignment=16
    )
    assert _resume_done_bytes(parts) == 32768
    monkeypatch.setattr(crypto, "_decrypt_range", real_decrypt)
    crypto.decrypt_firmware(**kwargs, resume=True)
    assert output.read_bytes() == plain
