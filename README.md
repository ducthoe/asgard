<!--
Copyright (C) 2026 ducthoe
SPDX-License-Identifier: GPL-3.0-only
-->

# Asgard

Asgard is a command-line client for downloading and inspecting Samsung firmware
from the Firmware Update Server (FUS). It can decrypt firmware packages, inspect
remote archives, extract individual files, and unpack logical partitions from
Android super images without downloading the complete package first.

## Features

- Query the latest firmware version for a model and CSC.
- Display and compare firmware release histories.
- Download encrypted or decrypted firmware with resume support.
- Inspect remote ZIP and TAR archives.
- Extract selected firmware archives or individual files.
- Decode LZ4-compressed and Android sparse images while extracting them.
- List and extract logical partitions from Android super images.
- Verify local firmware files and generate JSON manifests.
- Save frequently used model and CSC combinations as profiles.
- Process multiple download jobs from TOML or JSON files.
- Produce machine-readable JSON output for automation.

## Installation

Install the package from PyPI:

```console
python3 -m pip install asgard-fus
```

Verify the installation:

```console
asgard --help
```

## Quick start

Check for the latest firmware available for a model and CSC:

```console
asgard checkupdate SM-S721B EUX
```

Download and decrypt the latest firmware:

```console
asgard download SM-S721B EUX --decrypt --resume --output ./downloads
```

List the files in the remote firmware package:

```console
asgard download SM-S721B EUX --list-entries
```

Run `asgard COMMAND --help` for the complete set of options supported by a
command.

## Usage

### Firmware information

Display the latest firmware version:

```console
asgard checkupdate SM-S721B EUX
```

Display the release history:

```console
asgard history SM-S721B EUX
asgard history SM-S721B EUX --json
```

Compare the histories of two CSCs:

```console
asgard compare SM-S721B EUX ZTO
asgard compare SM-S721B EUX ZTO --json
```

Use `--firmware-a` and `--firmware-b` to compare specific releases instead of
the latest releases.

### Firmware downloads

Download the latest encrypted package:

```console
asgard download SM-S721B EUX --output ./downloads --resume
```

Download and decrypt the package in one operation:

```console
asgard download SM-S721B EUX --output ./downloads --decrypt --resume
```

Download a specific firmware version:

```console
asgard download SM-S721B EUX \
  --firmware S721BXXSACZB2/S721BOXMACZB2/S721BXXSACZB2/S721BXXSACZB2 \
  --output ./downloads
```

The following options control download behavior:

| Option | Description |
| --- | --- |
| `--resume` | Resume an interrupted download or extraction operation. |
| `--threads N` | Use a fixed limit of `N` download workers, or `N` decryption workers. |
| `--timeout SECONDS` | Set the network request timeout. |
| `--limit-rate RATE` | Limit the aggregate transfer rate, for example `500K`, `10M`, or `1GiB`. |
| `--quiet` | Suppress informational and progress output. |
| `--json` | Write machine-readable JSON to standard output. |

Full downloads use four workers by default; `--threads` overrides this limit.
Workers share 16–128 MiB ranges based on remaining size and worker count, so
faster connections can pick up more work. Larger requests reduce handoff pauses
on large downloads. Adjacent unfinished ranges are combined when resuming.

Resume progress is independent of worker count. You can change `--threads`
between runs; valid progress from older resume files is retained too. The
partial data file and its `.resume.json` file must both be present.

### Archive inspection and extraction

List the archives in a firmware package:

```console
asgard download SM-S721B EUX --list-entries
```

List the files in the AP archive:

```console
asgard download SM-S721B EUX --archive AP --list-entries
```

Download one or more archives. Archive selectors accept names and glob
patterns:

```console
asgard download SM-S721B EUX --archive BL --output ./downloads --resume
asgard download SM-S721B EUX --archive '*.zip' --output ./downloads --resume
```

Extract a single file from an archive:

```console
asgard download SM-S721B EUX \
  --archive AP \
  --file super.img.lz4 \
  --output ./downloads \
  --resume
```

LZ4 and Android sparse images are decoded automatically. Pass `--keep-sparse`
to retain the Android sparse representation:

```console
asgard download SM-S721B EUX \
  --archive AP \
  --file super.img.lz4 \
  --keep-sparse \
  --output ./downloads \
  --resume
```

### Super images

List the logical partitions in the super image contained in an archive:

```console
asgard download SM-S721B EUX --archive AP --list-partitions
```

Extract selected logical partitions:

```console
asgard download SM-S721B EUX \
  --archive AP \
  --partition system \
  --partition vendor \
  --output ./downloads \
  --resume
```

Extract every logical partition:

```console
asgard download SM-S721B EUX \
  --archive AP \
  --unpack-super \
  --output ./downloads \
  --resume
```

When extraction is resumed, Asgard preserves the source stream locally. This
allows transformed LZ4 and sparse outputs to be rebuilt without downloading the
source data again.

### Decryption

Decrypt an existing FUS package:

```console
asgard decrypt SM-S721B EUX ./firmware.zip.enc4 \
  --output ./firmware.zip \
  --resume
```

Specify the firmware version when the package is not the latest release:

```console
asgard decrypt SM-S721B EUX ./firmware.zip.enc4 \
  --firmware S721BXXSACZB2/S721BOXMACZB2/S721BXXSACZB2/S721BXXSACZB2 \
  --output ./firmware.zip
```

Use `--enc-ver 2` for ENC2 packages. ENC2 decryption always requires an
explicit firmware version.

## Profiles

Profiles assign a name to a model and CSC combination:

```console
asgard profile add my-phone SM-S721B EUX
asgard profile list
asgard profile show my-phone
```

The profile name can then be used in place of the model and CSC:

```console
asgard checkupdate my-phone
asgard download my-phone --output ./downloads --resume
```

Remove a profile when it is no longer required:

```console
asgard profile remove my-phone
```

Profiles are stored in `$XDG_CONFIG_HOME/asgard` when `XDG_CONFIG_HOME` is set,
or in `~/.config/asgard` otherwise.

## Batch downloads

Batch files may be written in TOML or JSON. A TOML batch file uses one
`[[downloads]]` table for each job:

```toml
[[downloads]]
profile = "my-phone"
output = "./downloads"
decrypt = true
resume = true
manifest = ""

[[downloads]]
model = "SM-S721B"
region = "ZTO"
firmware = "S721BXXSDDZG1/S721BOWODDZG1/S721BXXSDDZG1/S721BXXSDDZG1"
output = "./downloads"
threads = 4
limit_rate = "20M"
```

Run the batch:

```console
asgard batch firmware.toml
```

Validate the jobs without downloading any files:

```console
asgard batch firmware.toml --dry-run --json
```

A JSON batch file may contain either an array of job objects or an object with a
`downloads` array.

## Verification and manifests

Verify a local package or image:

```console
asgard verify ./firmware.zip
asgard verify ./super.img --json
```

Verification calculates SHA-256 and MD5 digests. It also validates ZIP CRCs,
TAR structure, AES block alignment for encrypted FUS packages, and Android
sparse-image structure where applicable.

Generate a JSON manifest for an existing file:

```console
asgard manifest ./firmware.zip \
  --model SM-S721B \
  --region EUX \
  --firmware S721BXXSACZB2/S721BOXMACZB2/S721BXXSACZB2/S721BXXSACZB2
```

Generate a manifest when downloading or decrypting firmware:

```console
asgard download SM-S721B EUX --decrypt --output ./downloads --manifest
```

Manifests contain hashes and archive entry metadata. A manifest generated for
`super.img` or `super.img.lz4` also contains logical partition metadata.

## Exit status

Asgard exits with status `0` when a command completes successfully. Invalid
usage and missing input files return status `2`; operational and network errors
return status `1`.

## Contributing

Bug reports and pull requests are welcome. Before submitting a change, run the
configured linter:

```console
ruff check asgard
```

## License

Asgard is licensed under the GNU General Public License v3.0 only. See
[`LICENSE`](LICENSE) for the complete license text.
