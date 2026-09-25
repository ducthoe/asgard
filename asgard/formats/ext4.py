# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

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
    mode: int
    size: int
    flags: int
    block: bytes


class Ext4:
    name = "ext4"

    def __init__(self, image: ReadableImage):
        self.image = image
        sb = image.read_at(1024, 1024)
        if _u16(sb, 0x38) != 0xEF53:
            raise FUSError("not an ext4 filesystem")
        self.block_size = 1024 << _u32(sb, 0x18)
        self.inodes_per_group = _u32(sb, 0x28)
        self.inode_size = _u16(sb, 0x58) or 128
        self.descriptor_size = max(32, _u16(sb, 0xFE))
        if (
            self.block_size > 65536
            or not self.inodes_per_group
            or self.inode_size < 128
            or self.inode_size > self.block_size
            or self.descriptor_size > self.block_size
        ):
            raise FUSError("unsupported ext4 geometry")
        # Encrypted filenames or data cannot be resolved without the key.
        self.incompat = _u32(sb, 0x60)
        if self.incompat & 0x10000:
            raise FUSError("encrypted ext4 directories are not supported")
        self.group_table = 2048 if self.block_size == 1024 else self.block_size

    def _inode(self, number: int) -> _Inode:
        if number < 1:
            raise FUSError("invalid ext4 inode")
        group, within = divmod(number - 1, self.inodes_per_group)
        descriptor = self.image.read_at(self.group_table + group * self.descriptor_size, self.descriptor_size)
        table = _u32(descriptor, 8)
        if self.descriptor_size >= 64 and self.incompat & 0x80:
            table |= _u32(descriptor, 40) << 32
        raw = self.image.read_at(table * self.block_size + within * self.inode_size, self.inode_size)
        mode = _u16(raw, 0)
        size = _u32(raw, 4)
        if stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
            size |= _u32(raw, 108) << 32
        return _Inode(mode, size, _u32(raw, 32), raw[40:100])

    def _extent_block(self, node: bytes, logical: int, depth_limit: int = 5) -> int | None:
        if len(node) < 12 or _u16(node, 0) != 0xF30A:
            raise FUSError("invalid ext4 extent tree")
        entries, maximum, depth = struct.unpack_from("<HHH", node, 2)
        if entries > maximum or 12 + entries * 12 > len(node) or depth > depth_limit:
            raise FUSError("corrupt ext4 extent tree")
        chosen = None
        for index in range(entries):
            entry = node[12 + 12 * index : 24 + 12 * index]
            start = _u32(entry, 0)
            if start > logical:
                break
            chosen = entry
        if chosen is None:
            return None
        if depth:
            child = _u32(chosen, 4) | (_u16(chosen, 8) << 32)
            return self._extent_block(
                self.image.read_at(child * self.block_size, self.block_size), logical, depth_limit - 1
            )
        start = _u32(chosen, 0)
        count = _u16(chosen, 4)
        unwritten = count > 32768
        count = count - 32768 if unwritten else count
        if logical >= start + count or unwritten:
            return None
        physical = _u32(chosen, 8) | (_u16(chosen, 6) << 32)
        return physical + logical - start

    def _legacy_block(self, inode: _Inode, logical: int) -> int | None:
        per_block = self.block_size // 4
        if logical < 12:
            address = _u32(inode.block, logical * 4)
            return address or None
        logical -= 12
        if logical < per_block:
            address = _u32(inode.block, 48)
            levels = (logical,)
        elif logical < per_block + per_block**2:
            logical -= per_block
            address = _u32(inode.block, 52)
            levels = divmod(logical, per_block)
        else:
            logical -= per_block + per_block**2
            if logical >= per_block**3:
                raise FUSError("ext4 file exceeds triple indirect addressing")
            address = _u32(inode.block, 56)
            levels = (logical // per_block**2, (logical // per_block) % per_block, logical % per_block)
        for index in levels:
            if not address:
                return None
            raw = self.image.read_at(address * self.block_size + index * 4, 4)
            address = _u32(raw, 0)
        return address or None

    def _block(self, inode: _Inode, logical: int) -> int | None:
        if inode.flags & 0x10000000:
            raise FUSError("ext4 inline data is not supported")
        if inode.flags & 0x80000:
            return self._extent_block(inode.block, logical)
        return self._legacy_block(inode, logical)

    def _data(self, inode: _Inode) -> Iterator[bytes]:
        if stat.S_ISLNK(inode.mode) and inode.size <= 60 and not inode.flags & 0x80000:
            yield inode.block[: inode.size]
            return
        remaining = inode.size
        logical = 0
        while remaining:
            amount = min(self.block_size, remaining)
            address = self._block(inode, logical)
            yield bytes(amount) if address is None else self.image.read_at(address * self.block_size, amount)
            remaining -= amount
            logical += 1

    def _lookup(self, directory: _Inode, name: str) -> int:
        if not stat.S_ISDIR(directory.mode):
            raise FUSError("a path component is not an ext4 directory")
        wanted = name.encode("utf-8")
        for block in self._data(directory):
            position = 0
            while position + 8 <= len(block):
                number, record = struct.unpack_from("<IH", block, position)
                if record < 8 or position + record > len(block):
                    raise FUSError("corrupt ext4 directory entry")
                name_size = block[position + 6] if self.incompat & 2 else _u16(block, position + 6)
                if number and name_size <= record - 8 and block[position + 8 : position + 8 + name_size] == wanted:
                    return number
                position += record
        raise FUSError(f"file not found in ext4 image: {name}")

    def _find(self, path: str, links: int) -> _Inode:
        components = [component for component in path.split("/") if component]
        inode = self._inode(2)
        for index, component in enumerate(components):
            inode = self._inode(self._lookup(inode, component))
            if stat.S_ISLNK(inode.mode):
                if links >= 32:
                    raise FUSError("too many ext4 symbolic links")
                target = b"".join(self._data(inode)).decode("utf-8", "surrogateescape")
                rest = "/".join(components[index + 1 :])
                prefix = "" if target.startswith("/") else "/".join(components[:index])
                return self._find("/".join(part for part in (prefix, target, rest) if part), links + 1)
        if not stat.S_ISREG(inode.mode):
            raise FUSError(f"ext4 path is not a regular file: {path}")
        return inode

    def find(self, path: str) -> _Inode:
        return self._find(path, 0)

    def iter_file(self, inode: _Inode) -> Iterator[bytes]:
        yield from self._data(inode)
