# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

"""Small, seekable views over firmware images. No decoded image is staged on disk."""

from __future__ import annotations

import bisect
import io
import struct
from functools import lru_cache
from typing import Protocol

from ..core.errors import FUSError
from .images import _read_lp_metadata, _select_lp_partitions


class ReadableImage(Protocol):
    """An image that can serve bounded reads; size may be unknown until decoded."""

    @property
    def size(self) -> int | None: ...

    def read_at(self, offset: int, size: int) -> bytes: ...


class ImageView:
    def __init__(self, source: io.BufferedIOBase, offset: int, size: int):
        self.source = source
        self.offset = offset
        self.size = size

    def read_at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self.size:
            raise FUSError("image read is outside its bounds")
        target = self.offset + offset
        if self.source.tell() != target:
            self.source.seek(target)
        data = self.source.read(size)
        if len(data) != size:
            raise FUSError("truncated firmware image")
        return data


class CachedView:
    """Cache small metadata reads without retaining file data or whole images."""

    def __init__(self, source: ReadableImage, page_size: int = 65536):
        self.source = source
        self.size = source.size
        self.page_size = page_size
        self._page_cache = lru_cache(maxsize=16)(self._read_page)

    def _read_page(self, index: int) -> bytes:
        offset = index * self.page_size
        return self.source.read_at(offset, min(self.page_size, self.size - offset))

    def read_at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or (self.size is not None and offset + size > self.size):
            raise FUSError("image read is outside its bounds")
        if not size:
            return b""
        if self.size is None:
            return self.source.read_at(offset, size)
        if size > self.page_size * 2:
            return self.source.read_at(offset, size)
        index, inside = divmod(offset, self.page_size)
        if inside + size <= self.page_size:
            return self._page_cache(index)[inside : inside + size]
        chunks = []
        while size:
            index, inside = divmod(offset, self.page_size)
            part = self._page_cache(index)[inside : inside + size]
            chunks.append(part)
            offset += len(part)
            size -= len(part)
        return b"".join(chunks)


class LZ4View:
    """Read LZ4 images using block offsets and linked-block dictionary checkpoints."""

    def __init__(self, source: ReadableImage):
        try:
            from lz4 import block as lz4_block
        except ImportError as exc:
            raise FUSError("LZ4 support is not installed; reinstall asgard") from exc
        self.source = source
        self._lz4 = lz4_block
        magic = source.read_at(0, 4)
        self._blocks: list[tuple[int, int, int, bool]] = []
        self._starts: list[int] = []
        self._logical = 0
        self._finished = False
        self._dictionaries: dict[int, bytes] = {0: b""}
        self._scan_dictionary = b""
        self._last_decoded_index = -1
        self._last_decoded = b""
        if magic == b"\x04\x22\x4d\x18":
            self._legacy = False
            flg, bd = source.read_at(4, 2)
            if flg >> 6 != 1:
                raise FUSError("unsupported LZ4 frame version")
            self._linked = not bool(flg & 0x20)
            max_block = (0, 0, 0, 0, 65536, 262144, 1048576, 4194304)[(bd >> 4) & 7]
            if not max_block:
                raise FUSError("invalid LZ4 maximum block size")
            self._block_size = max_block
            position = 6
            self._size: int | None = None
            if flg & 0x08:
                self._size = struct.unpack("<Q", source.read_at(position, 8))[0]
                position += 8
            if flg & 1:
                position += 4
            position += 1  # header checksum
            self._block_checksum = bool(flg & 0x10)
            self._scan_position = position
        elif magic == b"\x02\x21\x4c\x18":
            # Legacy frames consist of independently compressed 8 MiB blocks.
            self._legacy = True
            self._linked = False
            self._block_size = 8 * 1024 * 1024
            self._size = None
            self._scan_position = 4
            self._block_checksum = False
        else:
            raise FUSError("unsupported LZ4 image frame")
        self._checkpoint_stride = max(1, (16 * 1024 * 1024) // self._block_size)
        self._decoded_cache = lru_cache(maxsize=4)(self._decode_block)

    @property
    def size(self) -> int | None:
        return self._size

    def _scan_until(self, end: int | None) -> None:
        while not self._finished and (end is None or self._logical < end):
            if self._legacy and self._scan_position + 4 > self.source.size:
                self._finished = True
                break
            header = struct.unpack("<I", self.source.read_at(self._scan_position, 4))[0]
            self._scan_position += 4
            if not header:
                self._finished = True
                break
            raw = bool(header & 0x80000000) if not self._legacy else False
            length = header & 0x7FFFFFFF if not self._legacy else header
            if not length or length > self._block_size or self._scan_position + length > self.source.size:
                raise FUSError("invalid LZ4 image block length")
            self._starts.append(self._logical)
            self._blocks.append((self._logical, self._scan_position, length, raw))
            if self._linked:
                number = len(self._blocks) - 1
                data = self.source.read_at(self._scan_position, length)
                try:
                    decoded = (
                        data
                        if raw
                        else self._lz4.decompress(data, uncompressed_size=self._block_size, dict=self._scan_dictionary)
                    )
                except Exception as exc:
                    raise FUSError(f"could not decode linked LZ4 image block {number}: {exc}") from exc
                self._scan_dictionary = (self._scan_dictionary + decoded)[-65536:]
                self._last_decoded_index = number
                self._last_decoded = decoded
                if (number + 1) % self._checkpoint_stride == 0:
                    self._dictionaries[number + 1] = self._scan_dictionary
            self._scan_position += length + (4 if self._block_checksum else 0)
            self._logical += length if raw else self._block_size
        if self._finished and self._size is not None and self._size > self._logical:
            raise FUSError("LZ4 image ended before its declared size")

    def _decode_block(self, index: int) -> bytes:
        if self._linked:
            if index == self._last_decoded_index:
                return self._last_decoded
            start = max(saved for saved in self._dictionaries if saved <= index)
            dictionary = self._dictionaries[start]
            decoded = b""
            for number in range(start, index + 1):
                _, offset, length, raw = self._blocks[number]
                data = self.source.read_at(offset, length)
                try:
                    decoded = (
                        data if raw else self._lz4.decompress(data, uncompressed_size=self._block_size, dict=dictionary)
                    )
                except Exception as exc:
                    raise FUSError(f"could not decode linked LZ4 image block {number}: {exc}") from exc
                dictionary = (dictionary + decoded)[-65536:]
                if number == index or (number + 1) % self._checkpoint_stride == 0:
                    self._dictionaries[number + 1] = dictionary
            if len(self._dictionaries) > 1024:
                for saved in sorted(self._dictionaries)[1:513]:
                    del self._dictionaries[saved]
            return decoded
        _, offset, length, raw = self._blocks[index]
        data = self.source.read_at(offset, length)
        if raw:
            return data
        try:
            return self._lz4.decompress(data, uncompressed_size=self._block_size)
        except Exception as exc:
            raise FUSError(f"could not decode LZ4 image block {index}: {exc}") from exc

    def read_at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or (self._size is not None and offset + size > self._size):
            raise FUSError("LZ4 image read is outside its bounds")
        self._scan_until(offset + size)
        if offset + size > self._logical:
            raise FUSError("LZ4 image read is outside its bounds")
        chunks = []
        while size:
            index = bisect.bisect_right(self._starts, offset) - 1
            if index < 0:
                raise FUSError("invalid LZ4 image offset")
            inside = offset - self._starts[index]
            part = self._decoded_cache(index)[inside : inside + size]
            if not part:
                raise FUSError("truncated LZ4 image block")
            chunks.append(part)
            offset += len(part)
            size -= len(part)
        return b"".join(chunks)


class SparseView:
    def __init__(self, source: ReadableImage):
        self.source = source
        header = source.read_at(0, 28)
        magic, major, _, file_header, chunk_header, block_size, blocks, chunks, _ = struct.unpack("<IHHHHIIII", header)
        if magic != 0xED26FF3A or major != 1 or file_header < 28 or chunk_header < 12 or not block_size:
            raise FUSError("invalid Android sparse image")
        self.size = blocks * block_size
        self._chunks: list[tuple[int, int, int, int, bytes]] = []
        starts = []
        position = file_header
        logical = 0
        for _ in range(chunks):
            kind, _, count, total = struct.unpack("<HHII", source.read_at(position, 12))
            length = count * block_size
            data_position = position + chunk_header
            if kind == 0xCAC1 and total != chunk_header + length:
                raise FUSError("invalid sparse RAW chunk")
            if kind == 0xCAC2 and total != chunk_header + 4:
                raise FUSError("invalid sparse FILL chunk")
            if kind == 0xCAC3 and total != chunk_header:
                raise FUSError("invalid sparse empty chunk")
            if kind == 0xCAC4:
                position += total
                continue
            if kind not in (0xCAC1, 0xCAC2, 0xCAC3) or not length:
                raise FUSError("unsupported sparse chunk")
            pattern = source.read_at(data_position, 4) if kind == 0xCAC2 else b"\0\0\0\0"
            starts.append(logical)
            self._chunks.append((logical, length, kind, data_position, pattern))
            logical += length
            position += total
        if logical != self.size:
            raise FUSError("sparse image size does not match its chunks")
        self._starts = starts

    def read_at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self.size:
            raise FUSError("sparse image read is outside its bounds")
        output = []
        while size:
            index = bisect.bisect_right(self._starts, offset) - 1
            start, length, kind, data_position, pattern = self._chunks[index]
            inside = offset - start
            count = min(size, length - inside)
            if kind == 0xCAC1:
                output.append(self.source.read_at(data_position + inside, count))
            else:
                phase = inside % len(pattern)
                rotated = pattern[phase:] + pattern[:phase]
                output.append((rotated * ((count + len(pattern) - 1) // len(pattern)))[:count])
            offset += count
            size -= count
        return b"".join(output)


class _MetadataReader:
    def __init__(self, image: ReadableImage):
        self.image = image
        self.raw_size = image.size
        self.position = 0

    def skip_to(self, offset: int) -> None:
        self.position = offset

    def read(self, size: int) -> bytes:
        data = self.image.read_at(self.position, size)
        self.position += len(data)
        return data


class PartitionView:
    def __init__(self, super_image: ReadableImage, name: str):
        self.source = super_image
        metadata = _read_lp_metadata(_MetadataReader(super_image))
        selected = _select_lp_partitions(metadata, (name,), slot_fallback=True, allow_missing=True)
        if not selected:
            raise FUSError(f"super image does not contain a non-empty {name} partition")
        chosen = selected[0]
        self._extents: list[tuple[int, int, int | None]] = []
        self._starts: list[int] = []
        logical = 0
        for extent in metadata.extents[chosen.first_extent_index : chosen.first_extent_index + chosen.num_extents]:
            length = extent.num_sectors * 512
            if extent.target_source and extent.target_type == 0:
                raise FUSError("split super images are not supported for file extraction")
            self._starts.append(logical)
            self._extents.append((logical, length, extent.target_data * 512 if extent.target_type == 0 else None))
            logical += length
        self.size = logical

    def read_at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self.size:
            raise FUSError("partition read is outside its bounds")
        output = []
        while size:
            index = bisect.bisect_right(self._starts, offset) - 1
            start, length, physical = self._extents[index]
            inside = offset - start
            count = min(size, length - inside)
            output.append(bytes(count) if physical is None else self.source.read_at(physical + inside, count))
            offset += count
            size -= count
        return b"".join(output)


def decoded_image(source: ReadableImage, name: str) -> ReadableImage:
    image = source
    if name.casefold().endswith(".lz4"):
        image = LZ4View(image)
    cached = CachedView(image)
    if cached.read_at(0, 4) == b"\x3a\xff\x26\xed":
        return CachedView(SparseView(cached))
    return cached
