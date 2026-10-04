These complete filesystem images were generated with
`python3 tests/generate_filesystem_fixtures.py` using mke2fs 1.47.2,
mkfs.f2fs/sload.f2fs 1.16.0, and mkfs.erofs 1.8.6. No filesystem was mounted.

Each image contains `etc/hello.txt` and `data/large.bin`. The larger file is
5 MiB plus 73 bytes, enough to exercise F2FS direct-node addressing. The JSON
manifest records image sizes, fixture hashes, and expected extracted file hashes.
Tests read the gzip images with Python's standard library; formatting tools
are needed only to regenerate them.

F2FS checkpoint and geometry checks follow the Linux implementation in
[checkpoint.c](https://github.com/torvalds/linux/blob/master/fs/f2fs/checkpoint.c)
and [super.c](https://github.com/torvalds/linux/blob/master/fs/f2fs/super.c).
