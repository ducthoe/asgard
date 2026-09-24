# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

"""Read F2FS checkpoint, NAT, directories, and regular file data."""

from __future__ import annotations

import stat
import struct
from collections.abc import Iterator
from dataclasses import dataclass

from ..core.errors import FUSError
from .random_access import ReadableImage

_BLOCK = 4096
_DIRECT_INODE = 923
_DIRECT_NODE = 1018


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


@dataclass(frozen=True)
class _Inode:
    raw: bytes
    mode: int
    size: int
    inline_flags: int
    extra_words: int
    inline_xattrs: int


class F2FS:
    name = "f2fs"

    def __init__(self, image: ReadableImage):
        self.image = image
        superblock = image.read_at(1024, _BLOCK - 1024)
        if _u32(superblock, 0) != 0xF2F52010:
            raise FUSError("not an F2FS filesystem")
        if _u32(superblock, 16) != 12:
            raise FUSError("unsupported F2FS block size")
        self.blocks_per_segment = 1 << _u32(superblock, 20)
        self.checkpoint_block = _u32(superblock, 76)
        self.nat_block = _u32(superblock, 84)
        self.root_nid = _u32(superblock, 96)
        self._node_cache: dict[int, bytes] = {}
        self.flexible_inline_xattr = bool(_u32(superblock, 2180) & 0x40)
        payload = _u32(superblock, 1664)
        checkpoints = []
        for number in range(2):
            block = self.checkpoint_block + number * self.blocks_per_segment
            if image.size is not None and (block + 1) * _BLOCK > image.size:
                continue
            try:
                raw = image.read_at(block * _BLOCK, _BLOCK)
            except FUSError:
                continue
            version = struct.unpack_from("<Q", raw, 0)[0]
            if version and _u32(raw, 136) < self.blocks_per_segment:
                checkpoints.append((version, block, raw))
        if not checkpoints:
            raise FUSError("F2FS checkpoint not found")
        _, checkpoint_block, checkpoint = max(checkpoints)
        nat_size = _u32(checkpoint, 160)
        sit_size = _u32(checkpoint, 156)
        flags = _u32(checkpoint, 132)
        if flags & 0x4000:
            raise FUSError("resizing F2FS checkpoints are not supported")
        if flags & 0x400:  # CP_LARGE_NAT_BITMAP_FLAG
            bitmap_offset = 196
        else:
            bitmap_offset = 192 if payload else 192 + sit_size
        bitmap_block = checkpoint_block * _BLOCK + bitmap_offset
        self.nat_bitmap = image.read_at(bitmap_block, nat_size)

    def _node(self, nid: int) -> bytes:
        cached = self._node_cache.get(nid)
        if cached is not None:
            return cached
        entries_per_block = _BLOCK // 9
        nat_index, entry_index = divmod(nid, entries_per_block)
        first = self.nat_block + (nat_index << 1) - (nat_index & (self.blocks_per_segment - 1))
        bit = nat_index < len(self.nat_bitmap) * 8 and self.nat_bitmap[nat_index // 8] & (0x80 >> (nat_index % 8))
        address = first + (self.blocks_per_segment if bit else 0)
        entry = self.image.read_at(address * _BLOCK + entry_index * 9, 9)
        block = _u32(entry, 5)
        if not block or block == 0xFFFFFFFF:
            raise FUSError(f"F2FS node {nid} is missing from NAT")
        raw = self.image.read_at(block * _BLOCK, _BLOCK)
        if _u32(raw, _BLOCK - 24) != nid:
            raise FUSError(f"F2FS node {nid} has an invalid footer")
        if len(self._node_cache) >= 2048:
            self._node_cache.pop(next(iter(self._node_cache)))
        self._node_cache[nid] = raw
        return raw

    def _inode(self, nid: int) -> _Inode:
        raw = self._node(nid)
        if _u32(raw, _BLOCK - 20) != nid:
            raise FUSError("F2FS inode footer mismatch")
        flags = raw[3]
        extra_words = _u16(raw, 360) // 4 if flags & 0x20 else 0
        inline_xattrs = (_u16(raw, 362) if flags & 0x20 and self.flexible_inline_xattr else 50) if flags & 1 else 0
        mode = _u16(raw, 0)
        size = struct.unpack_from("<Q", raw, 16)[0]
        if _u32(raw, 80) & 0x04:
            raise FUSError("compressed F2FS files are not supported")
        return _Inode(raw, mode, size, flags, extra_words, inline_xattrs)

    def _address(self, inode: _Inode, logical: int) -> int:
        direct_count = _DIRECT_INODE - inode.extra_words - inode.inline_xattrs
        if logical < direct_count:
            return _u32(inode.raw, 360 + inode.extra_words * 4 + logical * 4)
        logical -= direct_count
        ids = [_u32(inode.raw, 4052 + number * 4) for number in range(5)]
        if logical < _DIRECT_NODE * 2:
            nid = ids[logical // _DIRECT_NODE]
            return _u32(self._node(nid), (logical % _DIRECT_NODE) * 4) if nid else 0
        logical -= _DIRECT_NODE * 2
        indirect_span = _DIRECT_NODE * _DIRECT_NODE
        if logical < 2 * indirect_span:
            nid = ids[2 + logical // indirect_span]
            if not nid:
                return 0
            branch = self._node(nid)
            logical %= indirect_span
            child = _u32(branch, (logical // _DIRECT_NODE) * 4)
            return _u32(self._node(child), (logical % _DIRECT_NODE) * 4) if child else 0
        logical -= 2 * indirect_span
        if logical >= _DIRECT_NODE * indirect_span or not ids[4]:
            raise FUSError("F2FS file exceeds supported node addressing")
        branch = self._node(ids[4])
        child = _u32(branch, (logical // indirect_span) * 4)
        if not child:
            return 0
        branch = self._node(child)
        logical %= indirect_span
        child = _u32(branch, (logical // _DIRECT_NODE) * 4)
        return _u32(self._node(child), (logical % _DIRECT_NODE) * 4) if child else 0

    def _inline(self, inode: _Inode) -> bytes:
        start = 360 + inode.extra_words * 4 + 4
        size = 4 * (_DIRECT_INODE - inode.extra_words - inode.inline_xattrs - 1)
        return inode.raw[start : start + size]

    def _data(self, inode: _Inode) -> Iterator[bytes]:
        if inode.inline_flags & 0x02:
            yield self._inline(inode)[: inode.size]
            return
        remaining = inode.size
        logical = 0
        while remaining:
            size = min(_BLOCK, remaining)
            address = self._address(inode, logical)
            if address in (0, 0xFFFFFFFF):
                yield bytes(size)
            elif address == 0xFFFFFFFE:
                raise FUSError("compressed F2FS cluster is not supported")
            else:
                yield self.image.read_at(address * _BLOCK, size)
            logical += 1
            remaining -= size

    @staticmethod
    def _dentry(block: bytes, target: bytes, inline: bool = False) -> int | None:
        if inline:
            slots = len(block) * 8 // 153
            bitmap_size = (slots + 7) // 8
            reserved = len(block) - (19 * slots + bitmap_size)
            entries = bitmap_size + reserved
        else:
            slots = 214
            bitmap_size = 27
            entries = 30
        names = entries + slots * 11
        for slot in range(slots):
            if not block[slot // 8] & (1 << (slot % 8)):
                continue
            position = entries + slot * 11
            number = _u32(block, position + 4)
            size = _u16(block, position + 8)
            if not number or size > 255 or names + slot * 8 + size > len(block):
                continue
            if block[names + slot * 8 : names + slot * 8 + size] == target:
                return number
        return None

    def _lookup(self, inode: _Inode, name: str) -> int:
        if not stat.S_ISDIR(inode.mode):
            raise FUSError("a path component is not an F2FS directory")
        target = name.encode("utf-8")
        if inode.inline_flags & 0x04:
            found = self._dentry(self._inline(inode), target, inline=True)
            if found is not None:
                return found
        else:
            for block in self._data(inode):
                if len(block) == _BLOCK:
                    found = self._dentry(block, target)
                    if found is not None:
                        return found
        raise FUSError(f"file not found in F2FS image: {name}")

    def find(self, path: str) -> _Inode:
        inode = self._inode(self.root_nid)
        for component in path.split("/"):
            if component:
                inode = self._inode(self._lookup(inode, component))
        if not stat.S_ISREG(inode.mode):
            raise FUSError(f"F2FS path is not a regular file: {path}")
        return inode

    def iter_file(self, inode: _Inode) -> Iterator[bytes]:
        if not inode.inline_flags & 0x02:
            first_node_block = _DIRECT_INODE - inode.extra_words - inode.inline_xattrs
            for logical in range(first_node_block, (inode.size + _BLOCK - 1) // _BLOCK):
                self._address(inode, logical)
        yield from self._data(inode)
