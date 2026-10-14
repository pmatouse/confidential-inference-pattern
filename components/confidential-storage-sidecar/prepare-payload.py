#!/usr/bin/env python3
"""Extract unchanged guest components for an add-on image, never alter an initrd."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import stat
import tarfile
import io

GPU_BASE = "abd755287282a268578687137bf437caeda6139c1a654f18d13f8a72a68892ca"
TOOLS = "c4230b2b6ed01202beffdd7e9213567651239ecc72a1d8797664223c16b9c33f"


def prepare(base, tools, output):
    image = base.read_bytes()
    if hashlib.sha256(image).hexdigest() != GPU_BASE:
        raise ValueError("Unapproved stock GPU initrd")
    tool_bytes = tools.read_bytes()
    if hashlib.sha256(tool_bytes).hexdigest() != TOOLS:
        raise ValueError("Unapproved tools/modules bundle")
    raw, offset, seen, selected = gzip.decompress(image), 0, set(), {}
    inventory = {}
    while offset + 110 <= len(raw):
        header = raw[offset : offset + 110]
        if header[:6] != b"070701":
            raise ValueError("Invalid cpio header")
        fields = [int(header[n : n + 8], 16) for n in range(6, 110, 8)]
        name_end = offset + 110 + fields[11]
        name = raw[offset + 110 : name_end - 1].decode()
        start = (name_end + 3) & ~3
        end = start + fields[6]
        if (
            end > len(raw)
            or name in seen
            or name.startswith("/")
            or ".." in Path(name).parts
        ):
            raise ValueError("Unsafe cpio entry")
        offset = (end + 3) & ~3
        seen.add(name)
        if name == "TRAILER!!!":
            break
        mode, data = fields[1], raw[start:end]
        if name in [
            "usr/local/bin/attestation-agent",
            "usr/local/bin/confidential-data-hub",
        ] or (
            (name.startswith("usr/lib64/") and ".so" in name)
            or name
            == "usr/lib/modules/6.12.0-211.16.1.el10_2.x86_64/kernel/drivers/md/dm-bufio.ko.xz"
        ):
            if not (stat.S_ISREG(mode) or stat.S_ISLNK(mode)):
                raise ValueError("Unexpected payload type")
            selected["stock/" + name] = (mode, data)
    for required in ["attestation-agent", "confidential-data-hub"]:
        if "stock/usr/local/bin/" + required not in selected:
            raise ValueError("Missing unchanged guest component")
    with output.open("xb") as stream, tarfile.open(
        fileobj=stream, mode="w:gz"
    ) as archive:
        for name, (mode, data) in sorted(selected.items()):
            entry = tarfile.TarInfo(name)
            entry.mode = mode & 0o777
            if stat.S_ISLNK(mode):
                link = data.decode()
                if link.startswith("/") or ".." in Path(link).parts:
                    raise ValueError("Unexpected library symlink")
                entry.type, entry.linkname = tarfile.SYMTYPE, link
                archive.addfile(entry)
            else:
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
            inventory[name] = hashlib.sha256(data).hexdigest()
        with tarfile.open(fileobj=io.BytesIO(tool_bytes)) as source:
            for member in source:
                if (
                    not member.isfile()
                    or member.name.startswith("/")
                    or ".." in Path(member.name).parts
                ):
                    raise ValueError("Unsafe tool member")
                data = source.extractfile(member).read()
                member.name = "tools/" + member.name
                member.uid = member.gid = 0
                member.uname = member.gname = ""
                archive.addfile(member, io.BytesIO(data))
                inventory[member.name] = hashlib.sha256(data).hexdigest()
    output.with_suffix(".inventory.json").write_text(
        json.dumps(
            {
                "stockInitrdSha256": GPU_BASE,
                "toolsBundleSha256": TOOLS,
                "payloadSha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                "files": inventory,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["base", "tools", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    prepare(args.base, args.tools, args.output)
