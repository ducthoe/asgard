# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import heapq
from bisect import bisect_left

from ...core.errors import FUSError


def operation_order(operations, block_size: int):
    targets = sorted(
        (extent.start, extent.start + extent.blocks, index)
        for index, operation in enumerate(operations)
        for extent in operation.target_extents
    )
    if any(right[0] < left[1] for left, right in zip(targets, targets[1:])):
        raise FUSError("overlapping payload target extents")
    starts = [start for start, _, _ in targets]
    outgoing = [set() for _ in operations]
    incoming = [0] * len(operations)
    for reader, operation in enumerate(operations):
        for extent in operation.source_extents:
            index = max(0, bisect_left(starts, extent.start) - 1)
            while index < len(targets) and targets[index][0] < extent.start + extent.blocks:
                start, end, writer = targets[index]
                if end > extent.start and writer != reader and writer not in outgoing[reader]:
                    outgoing[reader].add(writer)
                    incoming[writer] += 1
                index += 1
    ready = [index for index, count in enumerate(incoming) if count == 0]
    heapq.heapify(ready)
    candidates = [
        (sum(extent.blocks for extent in operation.source_extents) * block_size, index)
        for index, operation in enumerate(operations)
        if outgoing[index]
    ]
    heapq.heapify(candidates)
    done = set()
    released = set()
    while len(done) < len(operations):
        if ready:
            index = heapq.heappop(ready)
            yield False, index
            done.add(index)
        else:
            while candidates and candidates[0][1] in released:
                heapq.heappop(candidates)
            if not candidates:
                raise FUSError("could not resolve payload dependencies")
            _, index = heapq.heappop(candidates)
            yield True, index
        if index not in released:
            released.add(index)
            for writer in outgoing[index]:
                incoming[writer] -= 1
                if incoming[writer] == 0:
                    heapq.heappush(ready, writer)
