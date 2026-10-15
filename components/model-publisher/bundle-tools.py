#!/usr/bin/env python3
"""Collect pinned, unpacked lab tools into a private userspace tree.

Run in the digest-pinned AMD64 compiler after kernel-lab/fetch.py. No package
installation, host mounts, keys or storage effects. The private ELF loader keeps
these Debian lab libraries separate from the downstream guest's libraries.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    tools = args.tools.resolve(strict=True)
    files = {}
    env = os.environ | {
        "LD_LIBRARY_PATH": f"{tools}/lib/x86_64-linux-gnu:{tools}/usr/lib/x86_64-linux-gnu"
    }
    for source, name in [
        ("sbin/cryptsetup", "cryptsetup"),
        ("sbin/veritysetup", "veritysetup"),
        ("sbin/integritysetup", "integritysetup"),
        ("sbin/dmsetup", "dmsetup"),
        ("sbin/mke2fs", "mkfs.ext4"),
        ("sbin/blkid", "blkid"),
        ("usr/bin/setpriv", "setpriv"),
    ]:
        executable = tools / source
        files[f"bin/{name}"] = executable.read_bytes()
        result = subprocess.run(
            ["ldd", str(executable)],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        if "not found" in result.stdout:
            raise ValueError(f"unresolved library for {name}")
        for line in result.stdout.splitlines():
            paths = [Path(w) for w in line.split() if w.startswith("/")]
            if not paths:
                continue
            path = paths[0]
            data = path.read_bytes()
            dest = f"lib/{path.name}"
            if dest in files and files[dest] != data:
                raise ValueError("library name collision")
            files[dest] = data
    files["bin/busybox"] = (tools / "bin/busybox").read_bytes()
    files["etc/mke2fs.conf"] = (tools / "etc/mke2fs.conf").read_bytes()
    inventory = {
        p: hashlib.sha256(data).hexdigest() for p, data in sorted(files.items())
    }
    with args.output.open("xb") as stream, tarfile.open(
        fileobj=stream, mode="w"
    ) as archive:
        for path, data in sorted(files.items()):
            item = tarfile.TarInfo(path)
            item.mode = 0o600 if path.startswith("etc/") else 0o700
            item.size = len(data)
            archive.addfile(item, io.BytesIO(data))
    print(
        json.dumps({"purpose": "isolated-lab-userspace", "files": inventory}, indent=2)
    )


if __name__ == "__main__":
    main()
