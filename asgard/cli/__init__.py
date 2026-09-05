# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations


def main(argv: list[str] | None = None) -> int:
    from .app import main as run

    return run(argv)
