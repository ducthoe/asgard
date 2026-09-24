<!--
Copyright (C) 2026 ducthoe
SPDX-License-Identifier: GPL-3.0-only
-->

# Asgard

Asgard is a command-line tool for getting Samsung firmware from the Firmware
Update Server (FUS). You can check what is available, download and decrypt a
package, or pull out the files and partitions you need without downloading the
whole thing.

It can also combine an over-the-air (OTA) update with its base firmware to
produce updated images, check local files, and write JSON manifests. Most
commands can return JSON if you want to use Asgard in a script.

## Install

```console
python3 -m pip install asgard-fus
asgard --help
```

## Start here

You will usually need a device model and a CSC (region or carrier code). For
example, `SM-S721B` and `EUX`:

```console
asgard checkupdate SM-S721B EUX
asgard download SM-S721B EUX --decrypt --resume --output ./downloads
```

The first command checks the latest version. The second downloads it, decrypts
it, and saves it in `./downloads`. If the transfer stops, run the same download
command again with `--resume`.

Run `asgard COMMAND --help` whenever you need the full list of options for a
command.

## Find a firmware version

Check the latest release, browse older releases, or compare the release
histories of two CSCs:

```console
asgard checkupdate SM-S721B EUX
asgard history SM-S721B EUX
asgard compare SM-S721B EUX ZTO
```

`history` and `compare` also support `--json`. With `compare`, use
`--firmware-a` and `--firmware-b` if you want to compare specific releases
instead of the latest ones.

## Download firmware

Without `--decrypt`, Asgard saves the encrypted package. Add `--decrypt` to
get a decrypted ZIP in the same run:

```console
asgard download SM-S721B EUX --output ./downloads --resume
asgard download SM-S721B EUX --decrypt --output ./downloads --resume
```

To download an older release, pass its full firmware version:

```console
asgard download SM-S721B EUX \
  --firmware S721BXXSACZB2/S721BOXMACZB2/S721BXXSACZB2/S721BXXSACZB2 \
  --output ./downloads
```

Downloads use a small number of workers by default: at most four for a large
file, and fewer when the file or system is smaller. Asgard starts with fewer
active streams, opens more when requests succeed, and slows down after HTTP
429 or 503 responses. When the server sends `Retry-After`, Asgard follows it.
You can set your own worker limit with `--threads N`, though a high value may
slow a download or trigger more rate limits.

Useful download options:

| Option | What it does |
| --- | --- |
| `--resume` | Continues an interrupted download or extraction. |
| `--threads N` | Sets the worker limit for downloading or decrypting. |
| `--timeout SECONDS` | Sets the network request timeout. |
| `--limit-rate RATE` | Caps total transfer speed, for example `500K`, `10M`, or `1GiB`. |
| `--quiet` | Hides progress and informational output. |
| `--json` | Writes machine-readable output. |

You can change `--threads` between resumed runs. Keep both the partial data
file and its `.resume.json` file; Asgard needs them to continue the download.

## Get files from a package

You can inspect a remote package before deciding what to download:

```console
asgard download SM-S721B EUX --list-entries
asgard download SM-S721B EUX --archive AP --list-entries
```

The first command lists the package's archives. The second lists files inside
the AP archive. To download an archive, choose it by name or with a quoted glob
pattern:

```console
asgard download SM-S721B EUX --archive BL --output ./downloads --resume
asgard download SM-S721B EUX --archive '*.zip' --output ./downloads --resume
```

You can also extract one file directly:

```console
asgard download SM-S721B EUX \
  --archive AP --file super.img.lz4 \
  --output ./downloads --resume
```

Asgard decodes LZ4 compression and Android sparse images during extraction.
Add `--keep-sparse` if you want the Android sparse form of an image:

```console
asgard download SM-S721B EUX \
  --archive AP --file super.img.lz4 --keep-sparse \
  --output ./downloads --resume
```

### Logical partitions in a super image

List the partitions first, then extract the ones you want:

```console
asgard download SM-S721B EUX --archive AP --list-partitions
asgard download SM-S721B EUX \
  --archive AP --partition system --partition vendor \
  --output ./downloads --resume
```

Use `--unpack-super` to extract every logical partition:

```console
asgard download SM-S721B EUX \
  --archive AP --unpack-super --output ./downloads --resume
```

To download only a file inside a partition, give its full device path with
`--path`. Asgard stops scanning the AP archive when it finds an image that can
supply the requested partition. It reads filesystem data in memory and writes
only the requested file to the output directory:

```console
asgard download SM-A566E SER --archive AP \
  --path /system/build.prop --output ./files
asgard download SM-A566E SER --archive AP \
  --path /vendor/build.prop --output ./files
```

If the AP TAR is compressed inside the firmware ZIP, finding the image can
still require downloading earlier compressed archive data. The partition image
is not saved to disk. System images that keep their files inside a `system/`
directory are handled as well.

These commands save `./files/system/build.prop` and
`./files/vendor/build.prop`. You can repeat `--path` for more files, such as
`--path /vendor/etc/build.prop`. The reader handles EROFS,
F2FS, and ext4 images, including chunked and LZ4-compressed EROFS files. Some
newer filesystem features, encrypted files, and multi-device images are not
supported; Asgard reports an error if it encounters one.

You can also request both files in one download by repeating `--path`:

```console
asgard download SM-A566E SER --archive AP \
  --path /system/build.prop --path /vendor/build.prop --output ./files
```

For A/B firmware, `/system/build.prop` also works when the image is named
`system_a.img` or the logical partition is `system_a`. Asgard tries the
unsuffixed partition first, then slot A, then slot B.

For resumed extraction, Asgard keeps the source stream locally so it can
rebuild decoded output without fetching the same source data again.

## Apply an OTA update

Give Asgard an OTA ZIP and the model and CSC of its base firmware:

```console
asgard download SM-S938U VZW --ota update.zip --output ./updated
```

Asgard reads the OTA, finds the matching base release in firmware history, and
downloads the base images it needs from FUS. If the history does not give a
single full version, pass the four-part version with `--firmware`. You can also
provide local base images with `--ota-base-dir DIR` or by repeating
`--ota-base-image PARTITION=PATH`. Local raw images stay unchanged; LZ4 and
Android sparse inputs are decoded as needed. For slotted images, Asgard prefers
the `_a` base unless you supply an image explicitly.

By default, Asgard produces every partition and full image in the OTA. Use
these commands to see the targets and choose only the ones you need:

```console
asgard ota-info update.zip
asgard download SM-S938U VZW --ota update.zip --ota-list-targets
asgard download SM-S938U VZW --ota update.zip \
  --ota-partition 'system,vendor' --output ./updated
asgard download SM-S908B EUX --ota update.zip \
  --ota-file 'vbmeta*' --output ./updated
```

`--ota-partition` and `--ota-file` can be repeated. They accept comma-separated
names and quoted glob patterns. Once you select a target, Asgard produces only
matching targets. A full-replacement target needs no base image.

Asgard writes downloaded base images into the merge output. Add
`--ota-keep-base` if you want separate copies of those bases. `--resume` can
reuse finished outputs, but an interrupted patch starts again from its base
image. Asgard does not build an Odin package or flash a device.

OTA work uses one worker when available memory cannot be measured. Otherwise,
the default scales with available CPUs and memory, allowing roughly 768 MiB
per worker. Use `--ota-jobs N` to set a limit yourself. Full-image block patches
and safe A/B source copies stream in bounded chunks; overlapping in-place
operations may still need source buffers. Asgard streams compressed firmware
packages and super images without staging them to disk.

Asgard checks patch source data, available target hashes, and ZIP contents.
`--ota-force` lets you replace existing outputs or override the declared base
version. Source hash checks still run unless you add `--ota-no-verify`.
OTA signing certificates are not authenticated.

Supported A/B payload operations are REPLACE, REPLACE_BZ, REPLACE_XZ,
SOURCE_COPY, SOURCE_BSDIFF, BROTLI_BSDIFF, ZERO, and DISCARD. Block OTAs
support BSDIFF patches and move, new, zero, erase, stash, and free commands.
Asgard rejects unsupported operations and payloads that need generated
verity/FEC data before downloading base images.

## Decrypt a package you already have

```console
asgard decrypt SM-S721B EUX ./firmware.zip.enc4 \
  --output ./firmware.zip --resume
```

If the package is from an older release, give its version:

```console
asgard decrypt SM-S721B EUX ./firmware.zip.enc4 \
  --firmware S721BXXSACZB2/S721BOXMACZB2/S721BXXSACZB2/S721BXXSACZB2 \
  --output ./firmware.zip
```

For an ENC2 package, add `--enc-ver 2` and always provide the firmware version.

## Save a model and CSC as a profile

If you use the same device often, give its model and CSC a name:

```console
asgard profile add my-phone SM-S721B EUX
asgard profile list
asgard profile show my-phone
asgard checkupdate my-phone
asgard download my-phone --output ./downloads --resume
```

Remove it with `asgard profile remove my-phone`. Profiles live in
`$XDG_CONFIG_HOME/asgard` when `XDG_CONFIG_HOME` is set, or in
`~/.config/asgard` otherwise.

## Run several downloads

Put jobs in a TOML or JSON file. A TOML file has one `[[downloads]]` table per
job:

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

```console
asgard batch firmware.toml
asgard batch firmware.toml --dry-run --json
```

`--dry-run` checks the jobs without downloading. A JSON batch file can be an
array of jobs or an object with a `downloads` array.

## Check files and write manifests

Check a local package or image with `verify`:

```console
asgard verify ./firmware.zip
asgard verify ./super.img --json
```

Asgard calculates SHA-256 and MD5 hashes. Where applicable, it also checks
ZIP CRCs, TAR structure, AES block alignment for encrypted FUS packages, and
Android sparse-image structure.

Use `manifest` to write a JSON record for a file:

```console
asgard manifest ./firmware.zip \
  --model SM-S721B --region EUX \
  --firmware S721BXXSACZB2/S721BOXMACZB2/S721BXXSACZB2/S721BXXSACZB2
```

Or add `--manifest` to a download or decryption command:

```console
asgard download SM-S721B EUX --decrypt --output ./downloads --manifest
```

Manifests include hashes and archive entry details. For `super.img` and
`super.img.lz4`, they also include logical partition details.

## Exit codes

`0` means the command succeeded. `2` means invalid usage or a missing input
file. `1` means an operation or network request failed.

## Contributing

Bug reports and pull requests are welcome. Run the linter before submitting a
change:

```console
ruff check asgard
```

## License

Asgard is licensed under the GNU General Public License v3.0 only. See
[`LICENSE`](LICENSE) for the full text.
