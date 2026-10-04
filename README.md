<!--
Copyright (C) 2026 ducthoe
SPDX-License-Identifier: GPL-3.0-only
-->

# Asgard

Asgard downloads Samsung firmware from the Firmware Update Server (FUS).
Use it to check releases, download and decrypt a package, or extract an archive,
image, logical partition, or file inside a partition.

It also applies OTA updates to base firmware and checks local packages and
images. Most commands support JSON output for scripts.

## Install

Requires Python 3.10 or newer.

```console
python3 -m pip install asgard-fus
asgard --help
```

Use a virtual environment if your Python installation blocks package installs.
Run `asgard COMMAND --help` for that command's options.

## Check a release and download it

You need a device model and a CSC, the region or carrier code. Replace the
example codes below with your device's codes, such as `SM-A566B` and `EUX`.

```console
asgard checkupdate SM-A566B EUX
asgard download SM-A566B EUX --decrypt --resume -o ./downloads
```

The download command decrypts the package as it arrives and saves a ZIP in
`./downloads`. If the transfer stops, run the same command again to resume.
Omit `--decrypt` to keep the encrypted package.

Browse release history or compare two CSCs:

```console
asgard history SM-S721B EUX
asgard compare SM-S721B EUX ZTO --json
```

To choose an older release, copy its full four-part version from `history` and
pass it with `--firmware`. For example:

```console
asgard download SM-A566B EUX \
  --firmware A566BXXSECZI2/A566BOXMECZI2/A566BXXSECZI2/A566BXXSECZI2 \
  --decrypt --resume -o ./downloads
```

`compare` accepts `--firmware-a` and `--firmware-b` to compare specific releases.

## Extract an archive or image

List the package's archives, then inspect the files inside AP:

```console
asgard download SM-A566B EUX --list-entries
asgard download SM-A566B EUX --archive AP --list-entries
```

Select an archive by name or a quoted glob pattern:

```console
asgard download SM-A566B EUX --archive BL -o ./downloads --resume
asgard download SM-A566B EUX --archive '*.zip' -o ./downloads --resume
```

To extract a file from AP:

```console
asgard download SM-A566B EUX \
  --archive AP --file super.img.lz4 -o ./images
```

Asgard decompresses LZ4 members and expands Android sparse images. Add
`--keep-sparse` to retain the Android sparse form. Archive and image extraction
already decrypt the incoming data, so these commands do not need `--decrypt`.

## Extract logical partitions

List the partitions in `super.img` or `super.img.lz4`:

```console
asgard download SM-A566B EUX --archive AP --list-partitions
```

Use the names from that list to select partitions. Repeat `--partition` to
extract several in one pass:

```console
asgard download SM-A566B EUX \
  --archive AP --partition system_a --partition vendor_a -o ./images
```

The command writes `system_a.img` and `vendor_a.img`. To extract every logical
partition:

```console
asgard download SM-A566B EUX --archive AP --unpack-super -o ./images
```

Asgard reads compressed data in order. Reaching a partition near the end of a
super image can require downloading and decoding the data before it. A small
output does not necessarily mean a small transfer.

Without `--resume`, partition extraction streams the source without saving a
local copy. With `--resume`, Asgard caches the source stream on disk before
extracting partitions, so it can reuse that data after an interruption.

## Read files inside partitions

Use `--path` with a full device path. Repeat it to extract several files:

```console
asgard download SM-A566E SER --archive AP \
  --path /system/build.prop --path /vendor/build.prop -o ./files
```

This writes `./files/system/build.prop` and `./files/vendor/build.prop` without
saving the decoded partition images. Finding the image in a compressed AP
archive can still require downloading earlier archive data.

Asgard reads ext4, F2FS, and EROFS filesystems, including chunked and
LZ4-compressed EROFS files. It handles system-as-root layouts and resolves
unsuffixed partition paths against slot A, then slot B, when needed. It reports
an error for unsupported filesystem features, encrypted files, or multi-device
images.

## Transfer speed and resuming

Progress shows a bar, transfer speed, and ETA when the total is known.
Extraction keeps separate download and decode rows. Unknown download totals
show an activity bar; stalled transfers show `ETA --:--` until data resumes.

Downloads use up to six connections by default, including archive, image,
partition, and OTA base-image extraction. `--threads N` changes this limit;
use `--threads 1` for a single connection. Small transfers and metadata reads
use fewer connections.

Extraction fetches separate byte ranges in parallel and delivers them in order
to the decoder. Each connection can buffer up to 16 MiB ahead, so the default
network buffer holds at most 96 MiB. ZIP decoding, LZ4 decoding, and partition
copying can overlap through buffered worker threads.

Extraction starts with a smaller first range and adjusts later ranges from
1 to 16 MiB using measured transfer speeds. This reduces waiting behind a slow
range while keeping the connection limit and request spacing.

HTTP 429 or 503 responses reduce concurrency. Workers share the cooldown and
honor `Retry-After`. After the cooldown, Asgard increases concurrency when
measured aggregate throughput improves.

| Option | Use |
| --- | --- |
| `--resume` | Continue an interrupted package download or reuse extraction staging. |
| `--threads N` | Set download connections for all modes, or workers for local decryption. |
| `--timeout SECONDS` | Set the network request timeout. |
| `--limit-rate RATE` | Cap total transfer speed, for example `500K`, `10M`, or `1GiB`. |
| `--quiet` | Hide progress and informational output. |
| `--json` | Write machine-readable output. |

For a resumed package download, keep both the partial data file and its
`.resume.json` file. You can change `--threads` between runs.

Remote readers cache recently decrypted data, fetch bounded blocks for metadata,
and fetch sequential extraction data through ordered ranges. Transfer speed also
depends on the CDN connection and network route; increasing the worker limit
does not guarantee a faster download.

## Apply an OTA update

Inspect an OTA ZIP and its targets:

```console
asgard ota-info update.zip
asgard download SM-S938U VZW --ota update.zip --ota-list-targets
```

Apply it to the matching base firmware, or select only the targets you need:

```console
asgard download SM-S938U VZW --ota update.zip -o ./updated
asgard download SM-S938U VZW --ota update.zip \
  --ota-partition 'system,vendor' -o ./updated
asgard download SM-S908B EUX --ota update.zip \
  --ota-file 'vbmeta*' -o ./updated
```

Asgard finds the base release in FUS history and downloads the images it needs.
Pass `--firmware` if it cannot resolve a single full base version. To supply
local bases, use `--ota-base-dir DIR` or repeat
`--ota-base-image PARTITION=PATH`. For slotted images, Asgard prefers the `_a`
base unless you supply an explicit image. It leaves local raw base images
unchanged and decodes LZ4 or sparse inputs as needed.

`--ota-partition` and `--ota-file` accept comma-separated names and quoted glob
patterns. Repeat either option for more selectors. With no selectors, Asgard
produces every partition and full image in the OTA. Full-replacement targets
need no base image.

Downloaded base images become the merge output. Use `--ota-keep-base` to retain
separate copies. `--resume` reuses finished outputs, but an interrupted patch
starts again from its base. Asgard produces images; it does not create an Odin
package or flash a device.

The default OTA worker limit scales with available CPUs and memory, allowing
roughly 768 MiB per worker. It uses one worker when it cannot measure memory.
Set `--ota-jobs N` to choose a limit. Operations stream in bounded chunks where
possible; overlapping in-place operations can need source buffers.

Asgard checks source data, available target hashes, and ZIP contents. Use
`--ota-force` to replace outputs or override the declared base version.
`--ota-no-verify` disables source and target hash checks. Asgard does not
authenticate OTA signing certificates.

A/B payloads support REPLACE, REPLACE_BZ, REPLACE_XZ, SOURCE_COPY,
SOURCE_BSDIFF, BROTLI_BSDIFF, ZERO, and DISCARD. Block OTAs support BSDIFF
patches and move, new, zero, erase, stash, and free commands. Asgard rejects
unsupported operations and payloads requiring generated verity/FEC data
before downloading base images.

## Decrypt a local package

```console
asgard decrypt SM-A566B EUX ./firmware.zip.enc4 \
  --output ./firmware.zip --resume
```

For an older release, pass its full version with `--firmware`. ENC2 packages
require both `--enc-ver 2` and `--firmware`.

## Save a device profile

Save a model and CSC under a name, then use that name in place of both codes:

```console
asgard profile add my-phone SM-A566B EUX
asgard checkupdate my-phone
asgard download my-phone --decrypt --resume -o ./downloads
```

Inspect or remove saved profiles:

```console
asgard profile list
asgard profile show my-phone
asgard profile remove my-phone
```

Profiles live in `$XDG_CONFIG_HOME/asgard` when `XDG_CONFIG_HOME` is set, or
`~/.config/asgard` otherwise.

## Batch downloads

Put full package download jobs in a TOML or JSON file. Each TOML job gets its
own `[[downloads]]` table:

```toml
[[downloads]]
model = "SM-A566B"
region = "EUX"
output = "./downloads/a56"
decrypt = true
resume = true
manifest = ""

[[downloads]]
model = "SM-S721B"
region = "EUX"
output = "./downloads/s721b"
threads = 4
limit_rate = "20M"
```

Preview the jobs before downloading:

```console
asgard batch firmware.toml --dry-run --json
asgard batch firmware.toml
```

A job can use `profile = "my-phone"` instead of `model` and `region`, or include
`firmware` to select a release. JSON files accept an array of jobs or an object
with a `downloads` array. TOML batch files require Python 3.11 or newer; use
JSON on Python 3.10.

## Check files and write manifests

```console
asgard verify ./firmware.zip
asgard verify ./super.img --json
asgard manifest ./firmware.zip -o ./firmware.json
```

`verify` calculates SHA-256 and MD5 hashes. Depending on the format, it also
checks ZIP CRCs, TAR structure, AES block alignment, and Android sparse-image
structure.

`manifest` records hashes and archive entries in JSON. Super-image manifests
also include logical partition details. Add `--model`, `--region`, and
`--firmware` to include device metadata, or add `--manifest` to a download or
decryption command:

```console
asgard download SM-A566B EUX --decrypt --resume -o ./downloads --manifest
```

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Command succeeded. |
| `1` | Operation or network request failed. |
| `2` | Invalid usage or a missing input file. |
| `130` | Interrupted with Ctrl+C. |

## Development

Install the project and its test tools from a checkout:

```console
python3 -m pip install -e . pytest ruff
ruff check asgard tests
python3 -m pytest
```

The regression tests use a local HTTP server to check interrupted transfers,
range validation, rate limits, authentication recovery, decryption, and
extraction. They do not contact FUS.

Compare request counts, transferred bytes, and extraction time with an earlier
Git revision:

```console
python3 -m benchmarks.performance --baseline REVISION --latency-ms 50
python3 -m benchmarks.performance --parallel-stream-only
python3 -m benchmarks.performance --compare-ranges --first-range-factor 0.25
```

Replace `REVISION` with a commit or tag. The benchmark serves synthetic firmware
locally; its timing depends on the configured latency and local hardware.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
