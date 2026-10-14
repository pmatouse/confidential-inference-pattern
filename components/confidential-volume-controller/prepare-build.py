#!/usr/bin/env python3
"""Create an offline build archive from a fixed public source allowlist."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--wheels", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    authority = ROOT / "components/confidential-storage-authority"
    lock = json.loads((authority / "runtime-wheels.json").read_text())
    files = []
    for filename, sha in lock.items():
        path = args.wheels / filename
        if hashlib.sha256(path.read_bytes()).hexdigest() != sha:
            raise ValueError("wheel digest mismatch")
        files.append((path, "wheels/" + filename))
    for relative in [
        "components/confidential-volume-controller/controller.py",
        "components/confidential-volume-controller/sidecar.py",
        "components/confidential-volume-controller/test_sidecar.py",
        "components/confidential-volume-controller/test_controller.py",
        "components/confidential-volume-controller/approve.py",
        "components/confidential-volume-contract/compiler.py",
        "components/confidential-volume-contract/test_compiler.py",
        "components/confidential-storage-authority/runtime-requirements.txt",
    ]:
        files.append((ROOT / relative, relative))
    files.append((Path(__file__).with_name("Containerfile"), "Dockerfile"))
    with args.output.open("xb") as out, tarfile.open(fileobj=out, mode="w:gz") as tar:
        for path, dest in files:
            tar.add(path, arcname=dest, recursive=False)
    print(
        json.dumps(
            {
                "publicOnly": True,
                "files": len(files),
                "archiveSha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
            }
        )
    )


if __name__ == "__main__":
    main()
