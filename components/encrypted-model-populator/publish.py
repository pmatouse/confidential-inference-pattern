#!/usr/bin/env python3
"""Publish an already encrypted disk. This process has no decryption-key input.

The resulting source pins transport bytes only. A separate authenticated guest
manifest must authorize the verity root, model identity, generation and key.
"""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import ssl
import stat
import tarfile
import urllib.parse
import urllib.request

CHUNK = 8 << 20
MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
CONFIG = "application/vnd.docker.container.image.v1+json"
LAYER = "application/vnd.docker.image.rootfs.diff.tar.gzip"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(stream):
    sha = hashlib.sha256()
    for chunk in iter(lambda: stream.read(CHUNK), b""):
        sha.update(chunk)
    return "sha256:" + sha.hexdigest()


class HashWriter:
    def __init__(self, output):
        self.output = output
        self.sha = hashlib.sha256()

    def write(self, data):
        self.sha.update(data)
        return self.output.write(data)


def pack(disk, work):
    """Fail if the regular-file disk changes while being packaged."""
    fd = os.open(disk, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or not 64 << 20 <= info.st_size <= 64 << 30
            or info.st_size % 4096
        ):
            raise ValueError("disk must be a regular, aligned 64 MiB–64 GiB image")
        disk_digest = digest(source)
        source.seek(0)
        release = {
            "format": "luks-verity-v1",
            "diskDigest": disk_digest,
            "diskBytes": info.st_size,
        }
        with (work / "layer.tar.gz").open("xb") as output:
            with gzip.GzipFile(
                fileobj=output, mode="wb", filename="", mtime=0, compresslevel=1
            ) as gz:
                hashed = HashWriter(gz)
                with tarfile.open(
                    fileobj=hashed, mode="w|", format=tarfile.GNU_FORMAT
                ) as archive:
                    header = tarfile.TarInfo("volume.raw")
                    header.size, header.mode = info.st_size, 0o400
                    archive.addfile(header, source)
                    data = canonical(release)
                    header = tarfile.TarInfo("release.json")
                    header.size, header.mode = len(data), 0o400
                    archive.addfile(header, io.BytesIO(data))
        source.seek(0)
        after = os.fstat(source.fileno())

        def identity(st):
            return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)

        if digest(source) != disk_digest or identity(after) != identity(info):
            raise ValueError("disk changed during packaging")
    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashed.sha.hexdigest()]},
    }
    (work / "config.json").write_bytes(canonical(config))
    return release


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("registry redirects forbidden")


class Registry:
    def __init__(self, origin, repository, ca, token):
        parsed = urllib.parse.urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("registry must be an HTTPS origin")
        if not re.fullmatch(
            r"[a-z0-9][a-z0-9-]{0,62}/[a-z0-9][a-z0-9._-]{0,127}", repository
        ):
            raise ValueError("invalid same-namespace registry repository")
        self.origin, self.repository, self.token = origin, repository, token
        self.opener = urllib.request.build_opener(
            NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca)),
        )

    def request(
        self, path, method="GET", data=None, content_type="application/octet-stream"
    ):
        url = urllib.parse.urljoin(self.origin, path)
        parsed, origin = urllib.parse.urlsplit(url), urllib.parse.urlsplit(self.origin)
        prefix = "/v2/" + self.repository + "/"
        if (
            parsed.scheme != origin.scheme
            or parsed.netloc != origin.netloc
            or parsed.username
            or parsed.password
            or parsed.fragment
            or not parsed.path.startswith(prefix)
        ):
            raise ValueError("registry upload location crossed repository boundary")
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": "Bearer " + Path(self.token).read_text().strip(),
                "Content-Type": content_type,
                "Accept": MANIFEST,
            },
        )
        return self.opener.open(req, timeout=180)

    def blob(self, path, media_type):
        with path.open("rb") as stream:
            value = digest(stream)
        with self.request(
            "/v2/" + self.repository + "/blobs/uploads/", "POST", b""
        ) as response:
            location = response.headers["Location"]
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(CHUNK), b""):
                with self.request(location, "PATCH", chunk) as response:
                    location = response.headers["Location"]
        separator = "&" if "?" in location else "?"
        with self.request(
            location + separator + urllib.parse.urlencode({"digest": value}), "PUT", b""
        ):
            pass
        return {"mediaType": media_type, "size": path.stat().st_size, "digest": value}

    def publish(self, work, release):
        config = self.blob(work / "config.json", CONFIG)
        layer = self.blob(work / "layer.tar.gz", LAYER)
        raw = canonical(
            {
                "schemaVersion": 2,
                "mediaType": MANIFEST,
                "config": config,
                "layers": [layer],
            }
        )
        value = "sha256:" + hashlib.sha256(raw).hexdigest()
        # An immutable digest is the only consumer reference. A content-derived
        # tag also keeps the artifact reachable by the OpenShift image pruner.
        tag = "disk-" + release["diskDigest"].split(":")[1]
        with self.request(
            "/v2/" + self.repository + "/manifests/" + tag, "PUT", raw, MANIFEST
        ):
            pass
        with self.request("/v2/" + self.repository + "/manifests/" + value) as response:
            if response.read((1 << 20) + 1) != raw:
                raise ValueError(
                    "published registry manifest differs from pinned bytes"
                )
        return release | {"repository": self.repository, "manifestDigest": value}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disk", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--registry", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument(
        "--token", default="/var/run/secrets/kubernetes.io/serviceaccount/token"
    )
    args = parser.parse_args()
    args.work.mkdir(mode=0o700)  # Never overwrite an earlier publication.
    client = Registry(args.registry, args.repository, args.ca, args.token)
    release = pack(args.disk, args.work)
    source = client.publish(args.work, release)
    (args.work / "source.json").write_bytes(canonical(source) + b"\n")
    print(json.dumps(source, sort_keys=True))


if __name__ == "__main__":
    main()
