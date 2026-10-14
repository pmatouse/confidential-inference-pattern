"""Packaging and credential-boundary tests; no attestation claims."""

import gzip
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import publish


class PublishTests(unittest.TestCase):
    def test_archive_contract_and_diff_id(self):
        import tarfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            disk = root / "disk"
            with disk.open("wb") as stream:
                stream.write(b"ciphertext-test-only")
                stream.truncate(64 << 20)
            work = root / "work"
            work.mkdir()
            release = publish.pack(disk, work)
            with gzip.open(work / "layer.tar.gz", "rb") as stream:
                raw = stream.read()
            config = json.loads((work / "config.json").read_text())
            self.assertEqual(
                config["rootfs"]["diff_ids"],
                ["sha256:" + hashlib.sha256(raw).hexdigest()],
            )
            with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
                self.assertEqual(archive.getnames(), ["volume.raw", "release.json"])
                self.assertEqual(
                    publish.digest(archive.extractfile("volume.raw")),
                    release["diskDigest"],
                )
                self.assertEqual(
                    json.load(archive.extractfile("release.json")), release
                )

    def test_symlink_and_changed_disk_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            disk = root / "disk"
            with disk.open("wb") as stream:
                stream.truncate(64 << 20)
            link = root / "alias"
            link.symlink_to(disk)
            with self.assertRaises(OSError):
                publish.pack(link, root)
            with patch.object(
                publish,
                "digest",
                side_effect=["sha256:" + "a" * 64, "sha256:" + "b" * 64],
            ):
                with self.assertRaisesRegex(ValueError, "changed"):
                    publish.pack(disk, root)

    def test_upload_locations_cannot_forward_credentials(self):
        client = object.__new__(publish.Registry)
        client.origin, client.repository = "https://registry.test:5000", "test/model"
        client.token = "/no-token-should-be-read"
        for path in (
            "https://evil.test/v2/test/model/blobs/uploads/id",
            "http://registry.test:5000/v2/test/model/x",
            "/v2/other/model/x",
            "https://user@registry.test:5000/v2/test/model/x",
            "/v2/test/model/x#fragment",
        ):
            with self.subTest(path=path), self.assertRaisesRegex(
                ValueError, "boundary"
            ):
                client.request(path, "PATCH", b"ciphertext")
        with self.assertRaisesRegex(ValueError, "redirects"):
            publish.NoRedirect().redirect_request(
                None, None, 307, "redirect", {}, "/anywhere"
            )


if __name__ == "__main__":
    unittest.main()
