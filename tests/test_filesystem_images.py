from __future__ import annotations

import gzip
import hashlib
import json
import struct
from pathlib import Path

import pytest

from asgard.core.errors import FUSError
from asgard.formats.erofs import EROFS
from asgard.formats.ext4 import Ext4
from asgard.formats.f2fs import F2FS
from asgard.formats.random_access import ImageView

FIXTURES = Path(__file__).parent / "fixtures"
MANIFEST = json.loads((FIXTURES / "filesystems.json").read_text())
FILESYSTEMS = {"ext4": Ext4, "erofs": EROFS, "f2fs": F2FS}


class OverlayImage:
    def __init__(self, source, replacements):
        self.source = source
        self.size = source.size
        self.replacements = replacements

    def read_at(self, offset, size):
        data = bytearray(self.source.read_at(offset, size))
        for start, replacement in self.replacements.items():
            left = max(start, offset)
            right = min(start + len(replacement), offset + size)
            if left < right:
                data[left - offset : right - offset] = replacement[left - start : right - start]
        return bytes(data)


@pytest.fixture(params=FILESYSTEMS)
def filesystem_image(request):
    kind = request.param
    path = FIXTURES / f"{kind}.img.gz"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == MANIFEST[kind]["compressed_sha256"]
    with gzip.open(path, "rb") as source:
        yield kind, ImageView(source, 0, MANIFEST[kind]["size"])


@pytest.mark.parametrize("path", ["etc/hello.txt", "data/large.bin"])
def test_complete_images_resolve_paths_and_extract_expected_bytes(filesystem_image, path):
    kind, image = filesystem_image
    filesystem = FILESYSTEMS[kind](image)
    inode = filesystem.find(path)
    expected = MANIFEST[kind]["files"][path]
    assert inode.size == expected["size"]
    digest = hashlib.sha256()
    received = 0
    for chunk in filesystem.iter_file(inode):
        digest.update(chunk)
        received += len(chunk)
    assert received == expected["size"]
    assert digest.hexdigest() == expected["sha256"]


def test_complete_images_reject_missing_paths_and_directories(filesystem_image):
    kind, image = filesystem_image
    filesystem = FILESYSTEMS[kind](image)
    with pytest.raises(FUSError, match="not found"):
        filesystem.find("etc/missing.txt")
    with pytest.raises(FUSError, match="not a regular file"):
        filesystem.find("etc")


def test_complete_images_reject_bad_magic(filesystem_image):
    kind, image = filesystem_image
    with pytest.raises(FUSError, match="not an"):
        FILESYSTEMS[kind](OverlayImage(image, {1024 + (0x38 if kind == "ext4" else 0): bytes(4)}))


def test_complete_images_reject_truncation(filesystem_image):
    kind, image = filesystem_image
    truncated = ImageView(image.source, 0, 1024)
    with pytest.raises(FUSError):
        FILESYSTEMS[kind](truncated)


def test_f2fs_rejects_invalid_segment_geometry():
    with gzip.open(FIXTURES / "f2fs.img.gz", "rb") as source:
        image = ImageView(source, 0, MANIFEST["f2fs"]["size"])
        for value in (0, 10, 0xFFFFFFFF):
            with pytest.raises(FUSError, match="segment size"):
                F2FS(OverlayImage(image, {1024 + 20: struct.pack("<I", value)}))


@pytest.mark.parametrize("corrupt_backup", [False, True])
def test_f2fs_uses_valid_checkpoint_and_rejects_corrupted_packs(corrupt_backup):
    with gzip.open(FIXTURES / "f2fs.img.gz", "rb") as source:
        image = ImageView(source, 0, MANIFEST["f2fs"]["size"])
        checkpoint = struct.unpack("<I", image.read_at(1024 + 76, 4))[0]
        replacements = {checkpoint * 4096: b"\xff" * 8}
        if corrupt_backup:
            replacements[(checkpoint + 512) * 4096] = b"\xff" * 8
            with pytest.raises(FUSError, match="checkpoint not found"):
                F2FS(OverlayImage(image, replacements))
        else:
            filesystem = F2FS(OverlayImage(image, replacements))
            assert filesystem.root_nid == 3


@pytest.mark.parametrize("kind", ["footer", "extra_size", "inline_xattrs"])
def test_f2fs_rejects_corrupted_inode_metadata(kind):
    with gzip.open(FIXTURES / "f2fs.img.gz", "rb") as source:
        image = ImageView(source, 0, MANIFEST["f2fs"]["size"])
        filesystem = F2FS(image)
        nat = filesystem.nat_block + (512 if filesystem.nat_bitmap[0] & 0x80 else 0)
        block = struct.unpack("<I", image.read_at(nat * 4096 + filesystem.root_nid * 9 + 5, 4))[0]
        offset = block * 4096
        if kind == "footer":
            replacements = {offset + 4096 - 24: bytes(4)}
            expected = "footer"
        elif kind == "extra_size":
            replacements = {offset + 3: b"\x20", offset + 360: b"\xff\xff"}
            expected = "extra inode size"
        else:
            feature = struct.unpack("<I", image.read_at(1024 + 2180, 4))[0] | 0x40
            replacements = {
                1024 + 2180: struct.pack("<I", feature),
                offset + 3: b"\x21",
                offset + 360: b"\x04\x00\xff\xff",
            }
            expected = "inline attribute size"
        with pytest.raises(FUSError, match=expected):
            F2FS(OverlayImage(image, replacements)).find("etc/hello.txt")
