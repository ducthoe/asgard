from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

TIMESTAMP = 1700000000
UUID = "00000000-0000-0000-0000-000000000042"
SMALL = b"asgard filesystem regression fixture\n"
LARGE_SIZE = 5 * 1024 * 1024 + 73


def tool(name):
    return shutil.which(name) or str(Path("/usr/sbin") / name)


def generate():
    destination = Path(__file__).parent / "fixtures"
    destination.mkdir(exist_ok=True)
    manifest = {}
    with TemporaryDirectory() as directory:
        work = Path(directory)
        root = work / "root"
        (root / "etc").mkdir(parents=True)
        (root / "data").mkdir()
        (root / "etc" / "hello.txt").write_bytes(SMALL)
        large = (bytes(range(256)) * ((LARGE_SIZE + 255) // 256))[:LARGE_SIZE]
        (root / "data" / "large.bin").write_bytes(large)
        for path in sorted(root.rglob("*"), reverse=True) + [root]:
            os.utime(path, (TIMESTAMP, TIMESTAMP))
        for kind, size in (("ext4", 16 * 1024 * 1024), ("f2fs", 128 * 1024 * 1024), ("erofs", 0)):
            image = work / f"{kind}.img"
            if size:
                with image.open("wb") as output:
                    output.truncate(size)
            if kind == "ext4":
                commands = [
                    [
                        tool("mke2fs"),
                        "-q",
                        "-F",
                        "-t",
                        "ext4",
                        "-b",
                        "4096",
                        "-I",
                        "256",
                        "-U",
                        UUID,
                        "-d",
                        str(root),
                        str(image),
                    ]
                ]
            elif kind == "f2fs":
                commands = [
                    [tool("mkfs.f2fs"), "-f", "-q", "-t", "0", "-r", "-U", UUID, "-T", str(TIMESTAMP), str(image)],
                    [tool("sload.f2fs"), "-T", str(TIMESTAMP), "-f", str(root), str(image)],
                ]
            else:
                commands = [[tool("mkfs.erofs"), "--all-root", "-U", UUID, "-T", str(TIMESTAMP), str(image), str(root)]]
            for command in commands:
                result = subprocess.run(command, text=True, capture_output=True)
                if result.returncode:
                    raise RuntimeError(f"{command[0]} failed:\n{result.stdout}\n{result.stderr}")
            packed = destination / f"{kind}.img.gz"
            with image.open("rb") as source, packed.open("wb") as output:
                with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed:
                    shutil.copyfileobj(source, compressed)
            manifest[kind] = {
                "size": image.stat().st_size,
                "compressed_sha256": hashlib.sha256(packed.read_bytes()).hexdigest(),
                "files": {
                    "etc/hello.txt": {"size": len(SMALL), "sha256": hashlib.sha256(SMALL).hexdigest()},
                    "data/large.bin": {"size": len(large), "sha256": hashlib.sha256(large).hexdigest()},
                },
            }
            print(kind, image.stat().st_size, "bytes, compressed to", packed.stat().st_size)
    (destination / "filesystems.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    generate()
