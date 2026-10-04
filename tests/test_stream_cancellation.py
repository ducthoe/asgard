from __future__ import annotations

import threading
import time

from asgard.core.streaming import _PrefetchReader, cancellable_stream, open_prefetched_stream


class BlockingSource:
    def __init__(self):
        self.entered = threading.Event()
        self.released = threading.Event()

    def read(self, size):
        self.entered.set()
        self.released.wait()
        return b""

    def cancel(self):
        self.released.set()


def test_prefetch_close_interrupts_its_source():
    source = BlockingSource()
    reader = _PrefetchReader(source, cancel=source.cancel)
    try:
        assert source.entered.wait(1)
        started = time.monotonic()
        reader.close()
        assert time.monotonic() - started < 0.5
        assert not reader._thread.is_alive()
    finally:
        source.cancel()
        reader.close()


def test_nested_prefetch_inherits_source_cancellation():
    source = BlockingSource()
    try:
        with cancellable_stream(source.cancel), open_prefetched_stream(source) as inner:
            with open_prefetched_stream(inner):
                assert source.entered.wait(1)
                started = time.monotonic()
            assert time.monotonic() - started < 0.5
    finally:
        source.cancel()
    assert not any(thread.name == "asgard-prefetch" for thread in threading.enumerate())
