# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

"""Read EROFS directories and flat, chunked, or LZ4-compressed files."""

from __future__ import annotations

import stat
import struct
from collections.abc import Iterator
from dataclasses import dataclass

from ..core.errors import FUSError
from .random_access import ReadableImage


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


@dataclass(frozen=True)
class _Inode:
    position: int
    inode_size: int
    xattr_size: int
    mode: int
    size: int
    layout: int
    start_block: int


class EROFS:
    name = "erofs"

    def __init__(self, image: ReadableImage):
        self.image = image
        superblock = image.read_at(1024, 128)
        if _u32(superblock, 0) != 0xE0F5E1E2:
            raise FUSError("not an EROFS filesystem")
        block_bits = superblock[12]
        if not 9 <= block_bits <= 16:
            raise FUSError("unsupported EROFS block size")
        self.block_size = 1 << block_bits
        self.root_nid = _u16(superblock, 14)
        self.metadata_start = _u32(superblock, 40) * self.block_size
        self.incompat = _u32(superblock, 80)
        self.packed_nid = struct.unpack_from("<Q", superblock, 96)[0]
        if self.incompat & ~0x7F:
            raise FUSError("unsupported EROFS incompatible features")
        if self.incompat & 0x08:
            # This bit can also mean a separate device table; reject rather than misread data.
            raise FUSError("EROFS multi-device or HEAD2 data is not supported")

    def _inode(self, nid: int) -> _Inode:
        position = self.metadata_start + nid * 32
        head = self.image.read_at(position, 32)
        fmt = _u16(head, 0)
        inode_size = 64 if fmt & 1 else 32
        if inode_size == 64:
            head = self.image.read_at(position, 64)
        layout = (fmt >> 1) & 7
        if layout > 4:
            raise FUSError("unsupported EROFS inode layout")
        xattr_count = _u16(head, 2)
        return _Inode(
            position,
            inode_size,
            (8 + xattr_count * 4) if xattr_count else 0,
            _u16(head, 4),
            struct.unpack_from("<Q" if inode_size == 64 else "<I", head, 8)[0],
            layout,
            _u32(head, 16),
        )

    def _compressed_indices(self, inode: _Inode, header: bytes, bits: int) -> tuple[list[tuple[int, int, int]], int]:
        count = (inode.size + (1 << bits) - 1) >> bits
        base = (inode.position + inode.inode_size + inode.xattr_size + 7) & ~7
        if inode.layout == 1:
            start = base + 16
            indices = []
            for number in range(count):
                raw = self.image.read_at(start + 8 * number, 8)
                kind = _u16(raw, 0) & 3
                value = _u16(raw, 2) if kind != 2 else _u16(raw, 4)
                indices.append((kind, value, _u32(raw, 4)))
            return indices, start + count * 8
        start = base + 8
        first_four = ((32 - start % 32) // 4) & 7
        two_byte_count = ((count - first_four) // 16) * 16 if _u16(header, 4) & 1 and count > first_four else 0
        indices = []
        index = 0
        while index < count:
            four_byte = index < first_four or index >= first_four + two_byte_count
            group_count = 2 if four_byte else 16
            entry_size = 4 if four_byte else 2
            group = self.image.read_at(start, group_count * entry_size)
            encoded_bits = ((len(group) - 4) * 8) // group_count
            low_bits = max(bits, 12)
            base_block = _u32(group, len(group) - 4)
            previous_heads = 0
            for local in range(min(group_count, count - index)):
                word = int.from_bytes(group, "little") >> (local * encoded_bits)
                kind = (word >> low_bits) & 3
                value = word & ((1 << low_bits) - 1)
                if kind != 2:
                    previous_heads += 1
                indices.append((kind, value, base_block + previous_heads))
            start += len(group)
            index += group_count
        return indices, start

    def _lz4(self, physical: bytes, length: int) -> bytes:
        try:
            from lz4.block import decompress
        except ImportError as exc:
            raise FUSError("LZ4 support is not installed; reinstall asgard") from exc
        if self.incompat & 1:
            physical = physical.lstrip(b"\0")
        try:
            return decompress(physical, uncompressed_size=length)
        except Exception as exc:
            raise FUSError(f"could not decode EROFS LZ4 cluster: {exc}") from exc

    def _compressed_data(self, inode: _Inode) -> Iterator[bytes]:
        base = (inode.position + inode.inode_size + inode.xattr_size + 7) & ~7
        header = self.image.read_at(base, 8)
        advise = _u16(header, 4)
        bits = self.block_size.bit_length() - 1 + (header[7] & 0x0F)
        if bits > 16 or header[6] & 0x0F:
            raise FUSError("unsupported EROFS compression algorithm or cluster size")
        if header[7] & 0x80:
            if not self.packed_nid:
                raise FUSError("EROFS packed fragment inode is missing")
            packed = self._inode(self.packed_nid)
            offset = _u32(header, 0)
            yield from self._range(packed, offset, inode.size)
            return
        if advise & (0x02 | 0x04):
            raise FUSError("unsupported EROFS big or interlaced compressed cluster")
        indices, end_of_indices = self._compressed_indices(inode, header, bits)
        heads = [
            (number, value, block, kind)
            for number, (kind, value, block) in enumerate(indices)
            if kind != 2 and (number << bits) + value < inode.size
        ]
        if not heads and inode.size:
            raise FUSError("EROFS file has no compressed cluster heads")
        for head_number, (lcn, cluster_offset, physical_block, kind) in enumerate(heads):
            start = (lcn << bits) + cluster_offset
            end = (
                (heads[head_number + 1][0] << bits) + heads[head_number + 1][1]
                if head_number + 1 < len(heads)
                else inode.size
            )
            if end <= start or end > inode.size:
                raise FUSError("invalid EROFS compressed extent")
            length = end - start
            if advise & 0x20 and head_number + 1 == len(heads):
                packed = self._inode(self.packed_nid)
                yield from self._range(packed, _u32(header, 0), length)
                continue
            if advise & 0x08 and head_number + 1 == len(heads):
                physical_offset = end_of_indices
                physical_size = _u16(header, 2)
            else:
                physical_offset = physical_block * self.block_size
                physical_size = self.block_size
            physical = self.image.read_at(physical_offset, physical_size)
            if kind == 0:
                yield physical[:length]
            elif kind == 1:
                yield self._lz4(physical, length)
            else:
                raise FUSError("unsupported EROFS compressed cluster type")

    def _range(self, inode: _Inode, offset: int, length: int) -> Iterator[bytes]:
        if offset < 0 or length < 0 or offset + length > inode.size:
            raise FUSError("EROFS file range is outside its bounds")
        position = 0
        for chunk in self._data(inode):
            end = position + len(chunk)
            if end > offset and position < offset + length:
                yield chunk[max(0, offset - position) : min(len(chunk), offset + length - position)]
            position = end
            if position >= offset + length:
                break

    def _chunked_data(self, inode: _Inode) -> Iterator[bytes]:
        if not self.incompat & 0x04:
            raise FUSError("EROFS chunk-based inode has no chunked-file feature")
        chunk_format = inode.start_block
        if chunk_format & ~0x3F:
            raise FUSError("unsupported EROFS chunk format")
        chunk_size = self.block_size << (chunk_format & 0x1F)
        entry_size = 8 if chunk_format & 0x20 else 4
        index_offset = (inode.position + inode.inode_size + inode.xattr_size + entry_size - 1) & -entry_size
        chunk_count = (inode.size + chunk_size - 1) // chunk_size
        remaining = inode.size
        for first in range(0, chunk_count, 4096):
            batch_size = min(4096, chunk_count - first)
            entries = self.image.read_at(index_offset + first * entry_size, batch_size * entry_size)
            for number in range(batch_size):
                entry = entries[number * entry_size : (number + 1) * entry_size]
                if entry_size == 8:
                    device_id = _u16(entry, 2)
                    if device_id:
                        raise FUSError("EROFS chunk uses an external device")
                    block = _u32(entry, 4)
                else:
                    block = _u32(entry, 0)
                length = min(remaining, chunk_size)
                offset = block * self.block_size
                while length:
                    amount = min(length, 1024 * 1024)
                    yield bytes(amount) if block == 0xFFFFFFFF else self.image.read_at(offset, amount)
                    offset += amount
                    remaining -= amount
                    length -= amount

    def _data(self, inode: _Inode) -> Iterator[bytes]:
        if inode.layout in (1, 3):
            yield from self._compressed_data(inode)
            return
        if inode.layout == 4:
            yield from self._chunked_data(inode)
            return
        full, tail = divmod(inode.size, self.block_size)
        for number in range(full):
            yield self.image.read_at((inode.start_block + number) * self.block_size, self.block_size)
        if tail:
            if inode.layout == 2:
                inline = inode.position + inode.inode_size + inode.xattr_size
                yield self.image.read_at(inline, tail)
            else:
                yield self.image.read_at((inode.start_block + full) * self.block_size, tail)

    def _lookup(self, inode: _Inode, wanted: str) -> int:
        if not stat.S_ISDIR(inode.mode):
            raise FUSError("a path component is not an EROFS directory")
        target = wanted.encode("utf-8")
        for block in self._data(inode):
            if len(block) < 12:
                continue
            count = _u16(block, 8) // 12
            if count < 1 or count * 12 > len(block):
                raise FUSError("invalid EROFS directory block")
            for index in range(count):
                nid, name_start = struct.unpack_from("<QH", block, index * 12)
                name_end = _u16(block, (index + 1) * 12 + 8) if index + 1 < count else len(block)
                name = block[name_start:name_end].split(b"\0", 1)[0]
                if name == target:
                    return nid
        raise FUSError(f"file not found in EROFS image: {wanted}")

    def find(self, path: str) -> _Inode:
        inode = self._inode(self.root_nid)
        for component in path.split("/"):
            if component:
                inode = self._inode(self._lookup(inode, component))
        if not stat.S_ISREG(inode.mode):
            raise FUSError(f"EROFS path is not a regular file: {path}")
        return inode

    def iter_file(self, inode: _Inode) -> Iterator[bytes]:
        yield from self._data(inode)
