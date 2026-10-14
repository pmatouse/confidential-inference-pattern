#!/usr/bin/env python3
"""Trusted Linux publisher: prepare a LUKS/verity model image in software QEMU.

Only regular scratch files are accepted. No host mounts, devices, KVM or elevated
outer-container privileges are used. The private work directory temporarily holds
plaintext and an initramfs containing the publisher key: never publish those.
"""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--disk-mib", type=int, default=2048)
    args = parser.parse_args()
    if not 64 <= args.disk_mib <= 65536 or args.disk_mib % 64:
        raise ValueError("disk size must be a multiple of 64 MiB, up to 64 GiB")
    if args.key.is_symlink() or not args.key.is_file() or args.key.stat().st_size != 32:
        raise ValueError("publisher requires a private 32-byte key file")
    if args.key.stat().st_mode & 0o077:
        raise ValueError("publisher key must not be group/world accessible")
    tools, model = args.tools.resolve(strict=True), args.model.resolve(strict=True)
    work = args.work.absolute()
    work.mkdir(mode=0o700)
    disk_bytes = args.disk_mib << 20
    data_bytes = disk_bytes - max(16 << 20, (disk_bytes // 64 + 4095) // 4096 * 4096)
    files, checksums = [], []
    for path in sorted(model.rglob("*")):
        relative = str(path.relative_to(model))
        if path.is_symlink() or not re.fullmatch(r"[a-zA-Z0-9._/-]+", relative):
            raise ValueError("model contains an unsupported path")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("model contains a non-regular file")
        sha = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(8 << 20), b""):
                sha.update(chunk)
        files.append(
            {"path": relative, "bytes": path.stat().st_size, "sha256": sha.hexdigest()}
        )
        checksums.append(f"{sha.hexdigest()}  {relative}\n")
    if (
        not files
        or sum(f["bytes"] for f in files) > (data_bytes - (16 << 20)) * 9 // 10
    ):
        raise ValueError("model is empty or insufficient filesystem capacity")
    env = os.environ | {
        "LD_LIBRARY_PATH": (
            f"{tools}/lib/x86_64-linux-gnu:" f"{tools}/usr/lib/x86_64-linux-gnu"
        )
    }
    plain = work / "plaintext.ext4"
    with plain.open("xb") as stream:
        stream.truncate(data_bytes - (16 << 20))
    subprocess.run(
        [
            str(tools / "sbin/mke2fs"),
            "-q",
            "-t",
            "ext4",
            "-F",
            "-b",
            "4096",
            "-E",
            "lazy_itable_init=0,lazy_journal_init=0,root_owner=1000:1000",
            "-d",
            str(model),
            str(plain),
        ],
        env=env,
        check=True,
    )
    root = work / "root"
    for name in (
        "bin",
        "sbin",
        "usr/bin",
        "usr/sbin",
        "dev",
        "proc",
        "sys",
        "run",
        "etc",
        "tmp",
    ):
        (root / name).mkdir(parents=True, exist_ok=True)
    shutil.copy2(tools / "bin/busybox", root / "bin/busybox")
    for applet in subprocess.check_output(
        [str(tools / "bin/busybox"), "--list"], text=True
    ).splitlines():
        if applet != "busybox":
            (root / "bin" / applet).symlink_to("busybox")
    (root / "sbin/modprobe").symlink_to("/bin/modprobe")

    def binary(name):
        source = tools / "sbin" / name
        shutil.copy2(source, root / "usr/sbin" / name)
        result = subprocess.run(
            ["ldd", str(source)], env=env, capture_output=True, text=True, check=True
        )
        if "not found" in result.stdout:
            raise RuntimeError("unresolved publisher library")
        for line in result.stdout.splitlines():
            for word in line.split():
                if word.startswith("/"):
                    lib = Path(word)
                    relative = (
                        lib.relative_to(tools)
                        if lib.is_relative_to(tools)
                        else Path(word.lstrip("/"))
                    )
                    target = root / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(lib, target, follow_symlinks=True)
                    break

    for name in ("cryptsetup", "veritysetup", "dmsetup"):
        binary(name)
    kernels = list((tools / "boot").glob("vmlinuz-*"))
    if len(kernels) != 1:
        raise ValueError("expected one hash-pinned kernel")
    version = kernels[0].name.removeprefix("vmlinuz-")
    shutil.copy2(kernels[0], work / "vmlinuz")
    shutil.copytree(tools / "lib/modules" / version, root / "lib/modules" / version)
    subprocess.run(
        ["depmod", "-b", str(root), version],
        executable=str(tools / "bin/kmod"),
        env=env,
        check=True,
    )
    shutil.copy2(Path(__file__).with_name("publisher-init"), root / "init")
    (root / "init").chmod(0o700)
    shutil.copy2(args.key, root / "publisher-key")
    (root / "publisher-key").chmod(0o600)
    (root / "model-checksums").write_text("".join(checksums))
    (root / "data-bytes").write_text(str(data_bytes))
    (root / "disk-bytes").write_text(str(disk_bytes))
    for directory, _, _ in os.walk(root):
        Path(directory).chmod(0o755)
    paths = subprocess.check_output(["find", ".", "-print0"], cwd=root)
    archive = subprocess.run(
        [str(tools / "bin/cpio"), "--null", "-o", "-H", "newc", "--owner=0:0"],
        input=paths,
        cwd=root,
        capture_output=True,
        check=True,
    )
    with gzip.open(work / "initrd.gz", "wb", compresslevel=1) as output:
        output.write(archive.stdout)
    with (work / "volume.raw").open("xb") as output:
        output.truncate(disk_bytes)
    command = [
        str(tools / "usr/bin/qemu-system-x86_64"),
        "-L",
        str(tools / "usr/share/qemu"),
        "-M",
        "microvm",
        "-accel",
        "tcg,thread=multi",
        "-cpu",
        "max",
        "-m",
        "1024",
        "-smp",
        "2",
        "-nodefaults",
        "-no-user-config",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-monitor",
        "none",
        "-no-reboot",
        "-kernel",
        str(work / "vmlinuz"),
        "-initrd",
        str(work / "initrd.gz"),
        "-append",
        "console=ttyS0 reboot=t panic=-1 coco.publisher=1",
        "-drive",
        f"id=input,file={plain},format=raw,if=none,readonly=on",
        "-device",
        "virtio-blk-device,drive=input,serial=publisher-plaintext",
        "-drive",
        f"id=output,file={work}/volume.raw,format=raw,if=none,cache=none",
        "-device",
        "virtio-blk-device,drive=output,serial=publisher-ciphertext",
    ]
    with (work / "publisher.log").open("wb") as output:
        result = subprocess.run(
            command, env=env, stdout=output, stderr=subprocess.STDOUT, timeout=3600
        )
    log = (work / "publisher.log").read_text()
    if (
        result.returncode
        or "MODEL_PUBLISHER_FAIL:" in log
        or "MODEL_PUBLISHER_PASS:" not in log
    ):
        raise RuntimeError(
            "publisher failed; private work directory retained for diagnosis"
        )
    records = [
        json.loads(line.split(":", 1)[1])
        for line in log.splitlines()
        if line.startswith("MODEL_PUBLISHER_RESULT:")
    ]
    if (
        len(records) != 1
        or records[0]["diskBytes"] != disk_bytes
        or records[0]["dataBytes"] != data_bytes
    ):
        raise RuntimeError("publisher returned unexpected geometry")
    descriptor = records[0] | {"files": files}
    (work / "guest-manifest.unsigned.json").write_text(
        json.dumps(descriptor, sort_keys=True) + "\n"
    )
    # Only volume.raw, the public descriptor and sanitized logs may leave this
    # trusted publisher. Credentials are provisioned separately, never in OCI.
    shutil.rmtree(root)
    (work / "initrd.gz").unlink()
    plain.unlink()
    print("MODEL_DISK_PREPARED " + json.dumps(records[0], sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
