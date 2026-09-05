# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import argparse
import json
import re
import textwrap
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import __version__, settings
from .errors import FUSError, report_error
from .progress import format_bytes, set_quiet

if TYPE_CHECKING:
    from . import fus

_HISTORY_WRAP_WIDTH = 100
_FIRMWARE_HELP = "Firmware version to use, for example S721BXXSACZB2/S721BOXMACZB2/S721BXXSACZB2/S721BXXSACZB2"
_HISTORY_DETAIL_SKIP_TAGS = {
    "ANDROID_VERSION",
    "BINARY_ANDROID_VERSION",
    "BINARY_DISPLAY_NAME",
    "BINARY_DISPLAY_VERSION",
    "BINARY_INDEX",
    "BINARY_LOCAL_CODE",
    "BINARY_MODEL_DISPLAYNAME",
    "BINARY_MODEL_NAME",
    "BINARY_NATURE",
    "BINARY_OPEN_DATE",
    "BINARY_OS_NAME",
    "BINARY_OS_VERSION",
    "BINARY_SEQUENCE",
    "BINARY_SW_DISPLAYVERSION",
    "BINARY_SW_VERSION",
    "DEVICE_DISPLAY_NAME",
    "DEVICE_LOCAL_CODE",
    "DEVICE_MODEL_NAME",
    "DISPLAY_NAME",
    "DISPLAY_VERSION",
    "LOCAL_CODE",
    "MODEL_NAME",
    "OS_NAME",
    "OS_VERSION",
    "SW_DISPLAYVERSION",
}
_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]?)(?:i?b)?\s*$", re.IGNORECASE)


def _json_print(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, default=str))


def _join_history_values(values: tuple[str, ...]) -> str:
    return " | ".join(value for value in values if value)


def _format_labeled_value(label: str, value: str, *, indent: str = "  ", label_width: int = 12) -> list[str]:
    prefix = f"{indent}{label:<{label_width}}: "
    wrapped = textwrap.wrap(
        str(value or ""),
        width=max(24, _HISTORY_WRAP_WIDTH - len(prefix)),
        break_long_words=True,
        break_on_hyphens=False,
    ) or [""]
    continuation = " " * len(prefix)
    return [prefix + wrapped[0], *(continuation + line for line in wrapped[1:])]


def _format_history_entry(row: fus.FirmwareHistoryEntry) -> str:
    title = [f"sequence {row.sequence or '?'}", f"index {row.index or '?'}"]
    if row.open_date:
        title.append(row.open_date)
    lines = [", ".join(title)]
    fields = [
        ("Firmware", row.firmware_version),
        ("Android", row.android_version),
        ("Nature", _join_history_values(row.natures)),
        ("OS", row.os_name),
        ("Model", row.model_name),
        ("Name", row.display_name),
        ("Region", row.local_code),
        ("Display", row.display_version),
    ]
    if row.sw_display_version and row.sw_display_version != row.firmware_version:
        fields.append(("SW display", row.sw_display_version))
    for label, value in fields:
        if value:
            lines.extend(_format_labeled_value(label, value))
    extras = [
        (tag, _join_history_values(values))
        for tag, values in row.fields.items()
        if tag not in _HISTORY_DETAIL_SKIP_TAGS and _join_history_values(values)
    ]
    if extras:
        lines.append("  Extra")
        for tag, value in extras:
            lines.extend(_format_labeled_value(tag, value, indent="    ", label_width=24))
    return "\n".join(lines)


def _parse_byte_rate(value: str) -> int:
    match = _SIZE_RE.fullmatch(str(value))
    if match is None:
        raise argparse.ArgumentTypeError("use a byte rate such as 500K, 10M, or 1GiB")
    multiplier = 1024 ** ("", "k", "m", "g", "t").index(match.group(2).lower())
    result = int(float(match.group(1)) * multiplier)
    if result <= 0:
        raise argparse.ArgumentTypeError("byte rate must be positive")
    return result


def _positive_int(value: str) -> int:
    result = int(value)
    if result <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return result


def _add_device_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("model", help="Device model or a saved profile name")
    parser.add_argument("region", nargs="?", help="CSC/region; omit when using a saved profile")


def _add_firmware_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--firmware", help=_FIRMWARE_HELP)


def _add_output_mode(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--quiet", action="store_true", help="Hide informational and progress output")


def _add_network_options(parser: argparse.ArgumentParser, *, threads: bool = False) -> None:
    parser.add_argument("--timeout", type=_positive_int, default=30, metavar="SECONDS")
    parser.add_argument("--limit-rate", type=_parse_byte_rate, metavar="RATE", help="Aggregate limit, e.g. 10M")
    if threads:
        parser.add_argument(
            "--threads", type=_positive_int, help="Fixed download worker limit (default: automatic), or decrypt workers"
        )


def _add_manifest_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--manifest",
        nargs="?",
        const="",
        metavar="PATH",
        help="Write a verification manifest; omit PATH to place it beside the output",
    )


def _download_output_args(output: str) -> tuple[Path | None, Path | None]:
    path = Path(output).expanduser()
    if path.is_dir() or path.suffix == "":
        return path, None
    return None, path


def _resolve_args_device(args: argparse.Namespace) -> tuple[str, str]:
    return settings.resolve_device(args.model, args.region)


def _write_output_manifests(
    paths: list[Path],
    option: str | None,
    *,
    metadata: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    if option is None:
        return []
    from .verification import write_manifest

    if option and len(paths) != 1:
        raise ValueError("an explicit --manifest path requires exactly one output file")
    manifests: list[dict[str, object]] = []
    for path in paths:
        output = option or None
        manifest_path, payload = write_manifest(path, output, metadata=metadata)
        manifests.append({"path": str(manifest_path), "sha256": payload["sha256"]})
    return manifests


def _result_dict(result: fus.DownloadResult) -> dict[str, object]:
    path = result.decrypted_path or result.encrypted_path
    return {
        "path": str(path),
        "encrypted_path": str(result.encrypted_path),
        "decrypted_path": str(result.decrypted_path) if result.decrypted_path else None,
        "firmware": result.firmware_version,
        "filename": result.filename,
        "encrypted_size": result.size,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="asgard", description=f"asgard {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("checkupdate", help="Get the latest firmware version")
    _add_device_args(check)
    _add_network_options(check)
    _add_output_mode(check)

    history = subparsers.add_parser("history", help="Show firmware history for a device and CSC")
    _add_device_args(history)
    _add_network_options(history)
    _add_output_mode(history)

    download = subparsers.add_parser("download", help="Download firmware or selected firmware content")
    _add_device_args(download)
    _add_firmware_arg(download)
    download.add_argument("-o", "--output", help="Output file or directory; content extraction uses a directory")
    download.add_argument("--resume", action="store_true", help="Resume downloads and extraction staging")
    download.add_argument("--decrypt", action="store_true", help="Decrypt while downloading")
    content = download.add_mutually_exclusive_group()
    content.add_argument("--list-entries", action="store_true", help="List firmware ZIP or selected TAR entries")
    content.add_argument("--file", metavar="NAME", help="Extract one file from --archive")
    content.add_argument("--list-partitions", action="store_true", help="List logical super partitions")
    content.add_argument("--partition", action="append", metavar="NAME", help="Extract a logical partition; repeatable")
    content.add_argument("--unpack-super", action="store_true", help="Extract every logical super partition")
    download.add_argument(
        "--archive", action="append", metavar="SELECTOR", help="Archive selector; repeatable/globs allowed"
    )
    download.add_argument("--keep-sparse", action="store_true", help="Keep Android sparse images sparse")
    _add_network_options(download, threads=True)
    _add_output_mode(download)
    _add_manifest_option(download)

    decrypt = subparsers.add_parser("decrypt", help="Decrypt an encrypted FUS package")
    _add_device_args(decrypt)
    decrypt.add_argument("input")
    decrypt.add_argument("-o", "--output")
    _add_firmware_arg(decrypt)
    decrypt.add_argument("--enc-ver", type=int, choices=[2, 4], default=4)
    decrypt.add_argument("--resume", action="store_true")
    _add_network_options(decrypt, threads=True)
    _add_output_mode(decrypt)
    _add_manifest_option(decrypt)

    compare = subparsers.add_parser("compare", help="Compare firmware history between two CSCs")
    compare.add_argument("model")
    compare.add_argument("region_a")
    compare.add_argument("region_b")
    compare.add_argument("--firmware-a")
    compare.add_argument("--firmware-b")
    _add_network_options(compare)
    _add_output_mode(compare)

    batch = subparsers.add_parser("batch", help="Download jobs from a TOML or JSON file")
    batch.add_argument("file")
    batch.add_argument("-o", "--output", help="Default output directory")
    batch.add_argument("--fail-fast", action="store_true")
    batch.add_argument("--dry-run", action="store_true")
    _add_network_options(batch, threads=True)
    _add_output_mode(batch)

    verify = subparsers.add_parser("verify", help="Validate a local package/image and calculate hashes")
    verify.add_argument("file")
    verify.add_argument("--no-entries", action="store_true", help="Do not include archive entry metadata")
    _add_output_mode(verify)

    manifest = subparsers.add_parser("manifest", help="Create a JSON verification manifest")
    manifest.add_argument("file")
    manifest.add_argument("-o", "--output")
    manifest.add_argument("--model")
    manifest.add_argument("--region")
    manifest.add_argument("--firmware")
    _add_output_mode(manifest)

    profile = subparsers.add_parser("profile", help="Manage saved model/CSC profiles")
    profile_sub = profile.add_subparsers(dest="profile_command", required=True)
    profile_list = profile_sub.add_parser("list")
    profile_list.add_argument("--json", action="store_true")
    profile_add = profile_sub.add_parser("add")
    profile_add.add_argument("name")
    profile_add.add_argument("model")
    profile_add.add_argument("region")
    profile_add.add_argument("--replace", action="store_true")
    profile_add.add_argument("--json", action="store_true")
    profile_show = profile_sub.add_parser("show")
    profile_show.add_argument("name")
    profile_show.add_argument("--json", action="store_true")
    profile_remove = profile_sub.add_parser("remove")
    profile_remove.add_argument("name")
    profile_remove.add_argument("--json", action="store_true")

    return parser


def _handle_profiles(args: argparse.Namespace) -> int:
    if args.profile_command == "list":
        profiles = settings.load_profiles()
        if args.json:
            _json_print(profiles)
        else:
            for name, value in profiles.items():
                print(f"{name:<20} {value['model']:<16} {value['region']}")
        return 0
    if args.profile_command == "add":
        value = settings.add_profile(args.name, args.model, args.region, replace=args.replace)
        result = {"name": args.name, **value}
    elif args.profile_command == "show":
        value = settings.load_profiles().get(args.name)
        if value is None:
            raise FUSError(f"profile not found: {args.name}")
        result = {"name": args.name, **value}
    else:
        value = settings.remove_profile(args.name)
        result = {"name": args.name, **value, "removed": True}
    _json_print(result) if args.json else print(f"{result['name']}: {result['model']} {result['region']}")
    return 0


def _history_diff(a: fus.FirmwareHistoryEntry, b: fus.FirmwareHistoryEntry) -> dict[str, dict[str, object]]:
    left, right = a.to_dict(), b.to_dict()
    return {
        key: {"a": left.get(key), "b": right.get(key)}
        for key in sorted(set(left) | set(right))
        if left.get(key) != right.get(key)
    }


def _select_history(rows: list[fus.FirmwareHistoryEntry], version: str | None, label: str) -> fus.FirmwareHistoryEntry:
    from . import fus

    if not rows:
        raise FUSError(f"no firmware history returned for {label}")
    if version is None:
        candidates = [row for row in rows if str(row.index).strip() != "90"]
        return (candidates or rows)[-1]
    normalized = fus.normalize_version_code(version)
    matches = [row for row in rows if fus.normalize_version_code(row.firmware_version) == normalized]
    if not matches:
        raise FUSError(f"firmware {version!r} was not found in {label} history")
    return matches[-1]


def _handle_compare(args: argparse.Namespace) -> int:
    from . import fus

    model = args.model.upper()
    region_a, region_b = args.region_a.upper(), args.region_b.upper()
    rows_a = fus.get_firmware_history(model, region_a, timeout_s=args.timeout)
    rows_b = fus.get_firmware_history(model, region_b, timeout_s=args.timeout)
    selected_a = _select_history(rows_a, args.firmware_a, region_a)
    selected_b = _select_history(rows_b, args.firmware_b, region_b)
    versions_a = {row.firmware_version for row in rows_a}
    versions_b = {row.firmware_version for row in rows_b}
    result = {
        "model": model,
        "a": {"region": region_a, "selected": selected_a.to_dict(), "history_count": len(rows_a)},
        "b": {"region": region_b, "selected": selected_b.to_dict(), "history_count": len(rows_b)},
        "only_a": sorted(versions_a - versions_b),
        "only_b": sorted(versions_b - versions_a),
        "common": sorted(versions_a & versions_b),
        "differences": _history_diff(selected_a, selected_b),
    }
    if args.json:
        _json_print(result)
    else:
        print(f"{model}: {region_a} vs {region_b}")
        print(f"  {region_a}: {selected_a.firmware_version}")
        print(f"  {region_b}: {selected_b.firmware_version}")
        print(f"  common releases: {len(result['common'])}")
        print(f"  only {region_a}: {len(result['only_a'])}")
        print(f"  only {region_b}: {len(result['only_b'])}")
        if result["differences"]:
            print("  selected release differences:")
            for key, values in result["differences"].items():
                print(f"    {key}: {values['a']!r} -> {values['b']!r}")
    return 0


def _load_batch(path_value: str) -> list[dict[str, Any]]:
    path = Path(path_value).expanduser()
    if not path.is_file():
        raise FileNotFoundError(path)
    try:
        if path.suffix.lower() == ".json":
            payload = json.loads(path.read_text(encoding="utf-8"))
        else:
            try:
                import tomllib
            except ImportError as exc:
                raise FUSError("TOML batch files require Python 3.11 or newer; use JSON instead") from exc
            with path.open("rb") as source:
                payload = tomllib.load(source)
    except (json.JSONDecodeError, ValueError) as exc:
        raise FUSError(f"invalid batch file {path}: {exc}") from exc
    jobs = payload if isinstance(payload, list) else payload.get("downloads") if isinstance(payload, dict) else None
    if not isinstance(jobs, list) or any(not isinstance(job, dict) for job in jobs):
        raise FUSError("batch file must contain a 'downloads' array/table")
    return jobs


def _handle_batch(args: argparse.Namespace) -> int:
    from . import fus

    jobs = _load_batch(args.file)
    results: list[dict[str, object]] = []
    for index, job in enumerate(jobs, start=1):
        record: dict[str, object] = {"index": index}
        try:
            profile = str(job.get("profile", "")).strip()
            if profile:
                model, region = settings.resolve_device(profile, None)
            else:
                model, region = settings.resolve_device(str(job.get("model", "")), str(job.get("region", "")))
            output_value = job.get("output", args.output)
            if not output_value:
                raise ValueError(f"batch job {index} requires output or batch --output")
            output = Path(str(output_value)).expanduser()
            out_dir, out_file = _download_output_args(str(output))
            record.update({"model": model, "region": region, "output": str(output)})
            if args.dry_run:
                record["status"] = "planned"
            else:
                job_rate = job.get("limit_rate", args.limit_rate)
                if isinstance(job_rate, str):
                    job_rate = _parse_byte_rate(job_rate)
                result = fus.download_firmware(
                    model=model,
                    region=region,
                    firmware_version=str(job["firmware"]) if job.get("firmware") else None,
                    out_dir=out_dir,
                    out_file=out_file,
                    resume=bool(job.get("resume", True)),
                    auto_decrypt=bool(job.get("decrypt", False)),
                    threads=int(job.get("threads", args.threads)) if job.get("threads", args.threads) else None,
                    timeout_s=int(job.get("timeout", args.timeout)),
                    rate_limit=int(job_rate) if job_rate else None,
                )
                record.update(_result_dict(result))
                if job.get("manifest") is not None:
                    manifest_option = str(job.get("manifest") or "")
                    record["manifests"] = _write_output_manifests(
                        [result.decrypted_path or result.encrypted_path],
                        manifest_option,
                        metadata={
                            "model": model,
                            "region": region,
                            "firmware": result.firmware_version,
                            "firmware_filename": result.filename,
                            "encrypted_size": result.size,
                        },
                    )
                record["status"] = "complete"
        except Exception as exc:
            record.update({"status": "failed", "error": str(exc)})
            results.append(record)
            if args.fail_fast:
                break
            continue
        results.append(record)
    if args.json:
        _json_print(results)
    else:
        for result in results:
            print(f"{result['index']}: {result['status']}" + (f" - {result['error']}" if result.get("error") else ""))
    return 1 if any(result["status"] == "failed" for result in results) else 0


def _handle_download(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from . import archive, fus

    model, region = _resolve_args_device(args)
    common = {
        "model": model,
        "region": region,
        "firmware_version": args.firmware,
        "timeout_s": args.timeout,
        "rate_limit": args.limit_rate,
    }
    if args.keep_sparse and not args.file:
        parser.error("--keep-sparse requires --file")
    if args.list_entries:
        if args.decrypt:
            parser.error("--decrypt cannot be used with --list-entries")
        if args.output or args.manifest is not None:
            parser.error("--output/--manifest cannot be used with --list-entries")
        if args.archive:
            if len(args.archive) != 1:
                parser.error("listing files requires exactly one --archive selector")
            entries = list(archive.iter_firmware_tar_entries(outer_selector=args.archive[0], **common))
            payload = [{"name": entry.name, "size": entry.size} for entry in entries]
            if args.json:
                _json_print(payload)
            else:
                print(f"{'Size':>12}  Name")
                for entry in entries:
                    print(f"{format_bytes(entry.size):>12}  {entry.name}")
            return 0
        listing = archive.list_firmware_entries(**common)
        payload = {
            "firmware": listing.firmware_version,
            "filename": listing.filename,
            "size": listing.size,
            "entries": [
                {"name": entry.name, "size": entry.size, "compressed_size": entry.compressed_size}
                for entry in listing.entries
            ],
        }
        if args.json:
            _json_print(payload)
        else:
            print(
                f"firmware: {listing.firmware_version}\nfilename: {listing.filename}\nsize: {format_bytes(listing.size)}\n"
            )
            print(f"{'Size':>12} {'Compressed':>12}  Name")
            for entry in listing.entries:
                print(f"{format_bytes(entry.size):>12} {format_bytes(entry.compressed_size):>12}  {entry.name}")
        return 0
    if args.list_partitions:
        if not args.archive or len(args.archive) != 1:
            parser.error("--list-partitions requires exactly one --archive selector")
        if args.output or args.manifest is not None:
            parser.error("--output/--manifest cannot be used with --list-partitions")
        if args.decrypt:
            parser.error("--decrypt cannot be used with --list-partitions")
        partitions = list(archive.iter_firmware_super_partitions(outer_selector=args.archive[0], **common))
        payload = [{"name": item.name, "size": item.size} for item in partitions]
        if args.json:
            _json_print(payload)
        else:
            print(f"{'Size':>12}  Name")
            for item in partitions:
                print(f"{format_bytes(item.size):>12}  {item.name}")
        return 0
    if not args.output:
        parser.error("--output is required unless a listing option is used")
    paths: list[Path]
    payload: dict[str, object]
    if args.file:
        if not args.archive or len(args.archive) != 1:
            parser.error("--file requires exactly one --archive selector")
        if args.decrypt:
            parser.error("--decrypt is not needed with --file")
        path = archive.download_firmware_tar_member(
            outer_selector=args.archive[0],
            member_name=args.file,
            out_dir=args.output,
            keep_sparse=args.keep_sparse,
            resume=args.resume,
            **common,
        )
        paths, payload = [path], {"paths": [str(path)]}
    elif args.partition is not None or args.unpack_super:
        if not args.archive or len(args.archive) != 1:
            parser.error("partition extraction requires exactly one --archive selector")
        if args.decrypt:
            parser.error("--decrypt is not needed with partition extraction")
        extracted = archive.download_firmware_super_partitions(
            outer_selector=args.archive[0],
            partitions=tuple(args.partition) if args.partition is not None else None,
            output=args.output,
            resume=args.resume,
            **common,
        )
        paths, payload = list(extracted), {"paths": [str(path) for path in extracted]}
    elif args.archive:
        if args.decrypt:
            parser.error("--decrypt is not needed with --archive")
        extracted = archive.download_firmware_entries(
            selectors=args.archive,
            out_dir=args.output,
            resume=args.resume,
            **common,
        )
        paths, payload = list(extracted), {"paths": [str(path) for path in extracted]}
    else:
        out_dir, out_file = _download_output_args(args.output)
        result = fus.download_firmware(
            model=model,
            region=region,
            firmware_version=args.firmware,
            out_dir=out_dir,
            out_file=out_file,
            resume=args.resume,
            auto_decrypt=args.decrypt,
            threads=args.threads,
            timeout_s=args.timeout,
            rate_limit=args.limit_rate,
        )
        path = result.decrypted_path or result.encrypted_path
        paths, payload = [path], _result_dict(result)
    manifest_metadata = None
    if not (args.file or args.partition is not None or args.unpack_super or args.archive):
        manifest_metadata = {
            "model": model,
            "region": region,
            "firmware": payload.get("firmware"),
            "firmware_filename": payload.get("filename"),
            "encrypted_size": payload.get("encrypted_size"),
        }
    manifests = _write_output_manifests(paths, args.manifest, metadata=manifest_metadata)
    if manifests:
        payload["manifests"] = manifests
    if args.json:
        _json_print(payload)
    else:
        for path in paths:
            print(path)
        for item in manifests:
            print(item["path"])
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    set_quiet(bool(getattr(args, "quiet", False) or getattr(args, "json", False)))
    request_errors: tuple[type[Exception], ...] = ()
    try:
        if args.command == "profile":
            return _handle_profiles(args)
        if args.command == "verify":
            from .verification import verify_file

            result = verify_file(args.file, include_entries=not args.no_entries)
            if args.json:
                _json_print(result)
            else:
                print(
                    f"valid: {result['path']}\nformat: {result['format']}\nsize: {format_bytes(result['size'])}\nsha256: {result['sha256']}\nmd5: {result['md5']}"
                )
                if result.get("entry_count") is not None:
                    print(f"entries: {result['entry_count']}")
            return 0
        if args.command == "manifest":
            from .verification import write_manifest

            metadata = {
                key: value
                for key, value in {
                    "model": args.model.upper() if args.model else None,
                    "region": args.region.upper() if args.region else None,
                    "firmware": args.firmware,
                }.items()
                if value is not None
            }
            path, payload = write_manifest(args.file, args.output, metadata=metadata)
            _json_print({"path": str(path), "manifest": payload}) if args.json else print(path)
            return 0
        import requests

        from . import fus

        request_errors = (requests.RequestException,)
        if args.command == "compare":
            return _handle_compare(args)
        if args.command == "batch":
            return _handle_batch(args)
        if args.command == "checkupdate":
            model, region = _resolve_args_device(args)
            version = fus.get_latest_version(model, region, timeout_s=args.timeout)
            _json_print({"model": model, "region": region, "firmware": version}) if args.json else print(version)
            return 0
        if args.command == "history":
            model, region = _resolve_args_device(args)
            rows = fus.get_firmware_history(model, region, timeout_s=args.timeout)
            if args.json:
                _json_print([row.to_dict() for row in rows])
            elif not rows:
                print("No history found.")
            else:
                for index, row in enumerate(rows):
                    if index:
                        print()
                    print(_format_history_entry(row))
            return 0
        if args.command == "download":
            return _handle_download(args, parser)

        model, region = _resolve_args_device(args)
        output = Path(args.output).expanduser() if args.output else fus.decrypted_output_path(args.input)
        final_path = fus.decrypt_firmware(
            version=args.firmware,
            model=model,
            region=region,
            in_file=args.input,
            out_file=output,
            enc_ver=args.enc_ver,
            resume=args.resume,
            threads=args.threads,
            timeout_s=args.timeout,
        )
        manifests = _write_output_manifests([final_path], args.manifest)
        payload = {"path": str(final_path), "manifests": manifests}
        if args.json:
            _json_print(payload)
        else:
            print(final_path)
            for item in manifests:
                print(item["path"])
        return 0
    except ValueError as exc:
        parser.error(str(exc))
    except (FileNotFoundError, FUSError) as exc:
        return report_error(exc)
    except request_errors as exc:
        return report_error(exc, request_failed=True)
    return 1
