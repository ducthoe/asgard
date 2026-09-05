# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

import sys


class FUSError(RuntimeError):
    pass


class RetryableDownloadError(FUSError):
    pass


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
