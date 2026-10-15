#!/usr/bin/env python3
"""Rootless fetch of the hash-pinned Debian packages for this disposable lab."""

import argparse
import hashlib
import os
from pathlib import Path
import subprocess


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    work = args.work.absolute()
    work.mkdir(mode=0o700)
    for name in ("lists/partial", "cache/archives/partial", "packages", "tools"):
        (work / name).mkdir(parents=True)
    lock = Path(__file__).with_name("packages.txt")
    lines = lock.read_text().splitlines()
    packages = []
    hashes = {}
    for index in range(0, len(lines), 4):
        name = lines[index].removeprefix("Package: ")
        version = lines[index + 1].removeprefix("Version: ")
        checksum, filename = lines[index + 3].split()
        if Path(filename).name != filename:
            raise ValueError("invalid lock filename")
        packages.append(f"{name}={version}")
        hashes[filename] = checksum
    apt = [
        "apt-get",
        "-o",
        f"Dir::State::lists={work}/lists",
        "-o",
        f"Dir::Cache={work}/cache",
    ]
    subprocess.run(apt + ["update"], check=True)
    subprocess.run(apt + ["download", *packages], cwd=work / "packages", check=True)
    for filename, expected in hashes.items():
        package = work / "packages" / filename
        if hashlib.sha256(package.read_bytes()).hexdigest() != expected:
            raise RuntimeError(f"package hash mismatch: {filename}")
        # Verified Debian payloads only; no installation or maintainer scripts.
        with subprocess.Popen(
            ["ar", "p", str(package), "data.tar.xz"], stdout=subprocess.PIPE
        ) as archive:
            subprocess.run(
                ["tar", "-xJf", "-", "-C", str(work / "tools")],
                stdin=archive.stdout,
                check=True,
            )
            archive.stdout.close()
            if archive.wait():
                raise RuntimeError("package extraction failed")
    print(f"Verified and unpacked {len(hashes)} pinned packages into {work / 'tools'}")


if __name__ == "__main__":
    main()
