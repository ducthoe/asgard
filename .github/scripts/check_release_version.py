#!/usr/bin/env python3
# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

import tomllib
from packaging.version import InvalidVersion, Version

PROJECT = "asgard-fus"
PYPROJECT = Path("pyproject.toml")
TRUTHY = {"1", "true", "yes", "on"}


def error(message: str) -> None:
    print(f"::error::{message}")
    raise SystemExit(1)


def output(name: str, value: str) -> None:
    print(f"{name}={value}")
    target = os.environ.get("GITHUB_OUTPUT")
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(f"{name}={value}\n")


def parse_version(value: str) -> Version | None:
    candidate = value[1:] if value[:1] in ("v", "V") else value
    if not candidate[:1].isdigit():
        return None
    try:
        return Version(candidate)
    except InvalidVersion:
        return None


def project_version() -> Version:
    try:
        raw = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as exc:
        error(f"could not read the version from {PYPROJECT}: {exc}")
    version = parse_version(str(raw))
    if version is None:
        error(f"{PYPROJECT} version {raw!r} is not a valid version")
    return version


def tagged_versions() -> list[Version]:
    tags = subprocess.run(["git", "tag", "--list"], check=True, capture_output=True, text=True).stdout.split()
    return sorted(version for tag in tags if (version := parse_version(tag)) is not None)


def latest_pypi_version() -> Version | None:
    url = f"https://pypi.org/pypi/{PROJECT}/json"
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            payload = json.load(response)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        print(f"::warning::could not read {url}: {exc}; relying on git tags only")
        return None
    versions = [version for name in payload.get("releases", {}) if (version := parse_version(name)) is not None]
    return max(versions, default=None)


def check_release_tag(version: Version) -> None:
    tag = (os.environ.get("TAG_NAME") or "").strip()
    if not tag:
        print("no release tag to check")
        return
    tag_version = parse_version(tag)
    if tag_version is None:
        error(f"release tag {tag!r} is not a version")
    if tag_version != version:
        error(f"release tag {tag!r} does not match the {PYPROJECT} version {version}")
    print(f"release tag {tag!r} matches {PYPROJECT}")


def main() -> int:
    version = project_version()
    print(f"{PYPROJECT} version: {version}")
    check_release_tag(version)

    tagged = tagged_versions()
    if tagged:
        print(f"newest git tag version: {tagged[-1]}")
    published = latest_pypi_version()
    if published is not None:
        print(f"newest version on PyPI: {published}")

    forced = (os.environ.get("FORCE") or "").strip().lower() in TRUTHY
    # The tag for this version is expected, so only a newer tag or a version on PyPI blocks.
    blocking_versions = [item for item in tagged if item > version]
    if published is not None and published >= version:
        blocking_versions.append(published)
    blocking = max(blocking_versions, default=None)
    if blocking is not None and not forced:
        print(
            f"::notice::{version} is already released (newest is {blocking}), so nothing is published. "
            "Bump the version in pyproject.toml to release, or re-run this workflow with force."
        )
        output("changed", "false")
        output("version", str(version))
        return 0
    if blocking is not None:
        print(f"::warning::{version} is already released (newest is {blocking}); publishing because force was set")

    print(f"publishing {version}")
    output("changed", "true")
    output("version", str(version))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
