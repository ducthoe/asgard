# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

import sys


class FUSError(RuntimeError):
    pass


class RetryableDownloadError(FUSError):
    pass


class RateLimitedError(RetryableDownloadError):
    def __init__(self, message: str, *, retry_after_s: float | None = None):
        super().__init__(message)
        self.retry_after_s = retry_after_s


class StreamSourceError(Exception):
    pass


def report_error(error: Exception, *, request_failed: bool = False) -> int:
    if isinstance(error, FileNotFoundError):
        message = f"file not found: {error}"
        status = 2
    elif request_failed:
        message = f"request failed: {error}"
        status = 1
    else:
        message = str(error)
        status = 1
    print(f"error: {message}", file=sys.stderr)
    return status
