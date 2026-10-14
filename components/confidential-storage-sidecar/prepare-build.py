#!/usr/bin/env python3
"""Package only public add-on inputs; reject truncated or substituted downloads."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service", type=Path, required=True)
    parser.add_argument(
        "--service-sha256",
        required=True,
        help="SHA-256 read directly from the successful compiler output",
    )
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    service = args.service.read_bytes()
    if not re.fullmatch(r"[a-f0-9]{64}", args.service_sha256):
        raise ValueError("Invalid compiler digest")
    if (
        not service.startswith(b"\x7fELF")
        or hashlib.sha256(service).hexdigest() != args.service_sha256
    ):
        raise ValueError("Service binary does not match compiler output")
    inventory = json.loads(args.inventory.read_text())
    if (
        hashlib.sha256(args.payload.read_bytes()).hexdigest()
        != inventory["payloadSha256"]
    ):
        raise ValueError("Public payload inventory mismatch")
    here = Path(__file__).resolve().parent
    entries = [
        (here / "Containerfile", "Containerfile"),
        (here / "runtime.py", "runtime.py"),
        (args.service, "confidential-storage-service"),
        (args.payload, "payload.tar.gz"),
    ]
    with args.output.open("xb") as stream, tarfile.open(
        fileobj=stream, mode="w:gz"
    ) as archive:
        for path, name in entries:
            archive.add(path, arcname=name, recursive=False)
    report = {
        "inputs": {
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path, name in entries
        },
        "archiveSha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
        "stockInitrdSha256": inventory["stockInitrdSha256"],
    }
    args.output.with_suffix(".inputs.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
