"""Immutable model approval/receipt tests; synthetic peers, no key delivery."""

import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from authority import AttestedPeer, Authority, Denied
from publication import from_publisher, profile_sha256
from receipts import ReceiptIssuer, compact
from test_receipts import PLAN, decode, initialized

EVIDENCE = (
    Path(__file__).resolve().parents[2]
    / "tests/confidential-storage/evidence/2026-10-13/model-populator"
)
BINDING = {
    "manifest_uri": "kbs:///storage-test/model-records/qwen-v1",
    "container_name": "model",
    "destination": "/models",
    "access": "ro",
}


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.authority = Authority(Path(self.tmp.name) / "authority.db")
        self.peer = AttestedPeer("a" * 64, "b" * 64)
        self.record = self.authority.register(
            "qwen-v1",
            self.peer.policy_sha256,
            profile_sha256(),
            "kbs:///storage-test/model-keys/qwen-v1",
            mount_binding=BINDING,
        )
        self.descriptor = json.loads(
            (EVIDENCE / "guest-manifest.unsigned.json").read_text()
        )
        self.source = json.loads((EVIDENCE / "source.json").read_text())
        self.raw = from_publisher(self.record, self.descriptor, self.source)
        self.issuer = ReceiptIssuer(
            self.authority,
            Ed25519PrivateKey.generate(),
            "storage-test",
            "receipt-v1",
            clock=lambda: 2000000000,
        )

    def open(self, **changes):
        args = dict(
            volume_id="qwen-v1",
            peer=self.peer,
            operation_id="open-1",
            generation=1,
            nonce="c" * 64,
            binding=BINDING,
            profile_sha256=profile_sha256(),
        )
        return self.issuer.reopen(**{**args, **changes})

    def test_actual_publisher_descriptor_binds_signed_ro_receipt(self):
        with self.assertRaises(Denied):
            self.open()
        approved = self.authority.approve_published_model("qwen-v1", self.raw)
        self.assertEqual(approved["state"], "Ready")
        self.assertIsNone(approved["owner"])
        self.assertNotIn("initialization_steps", approved)
        receipt = decode(self.open())
        self.assertEqual(
            receipt["manifest_sha256"], hashlib.sha256(self.raw).hexdigest()
        )
        self.assertEqual(receipt["header_sha256"], self.descriptor["headerSha256"])
        self.assertEqual((receipt["access"], receipt["destination"]), ("ro", "/models"))
        self.authority.approve_published_model("qwen-v1", self.raw)
        self.assertEqual(
            self.authority.inspect("qwen-v1")["owner"]["activation_id"],
            receipt["activation_id"],
        )
        self.authority.close("qwen-v1", self.peer, receipt["activation_id"])
        self.assertIsNotNone(decode(self.open(operation_id="open-2")))

    def test_approved_root_manifest_and_source_are_immutable(self):
        self.authority.approve_published_model("qwen-v1", self.raw)
        for path in (
            ("verity", "root"),
            ("verity", "salt"),
            ("source", "manifestDigest"),
            ("source", "diskDigest"),
            ("headerSha256",),
        ):
            m = json.loads(self.raw)
            parent = m if len(path) == 1 else m[path[0]]
            parent[path[-1]] = ("sha256:" if path[0] == "source" else "") + "1" * 64
            with self.subTest(path=path), self.assertRaises(Denied):
                self.authority.approve_published_model("qwen-v1", compact(m))
        with self.assertRaises(Denied):
            self.authority.approve_published_model("qwen-v1", self.raw + b"\n")

    def test_ro_cannot_gain_format_or_rw_permissions(self):
        with self.assertRaises(Denied):
            self.authority.approve_initialization("qwen-v1", PLAN)
        self.authority.approve_published_model("qwen-v1", self.raw)
        with self.assertRaises(Denied):
            self.authority.begin("qwen-v1", self.peer, "format", "initialize", 1)
        with self.assertRaises(Denied):
            self.open(binding={**BINDING, "destination": "/data", "access": "rw"})
        with self.assertRaises(Denied):
            self.open(generation=0)

    def test_rw_cannot_skip_durable_initialization_using_publication(self):
        authority, peer, _, issuer = initialized(Path(self.tmp.name) / "rw.db")
        with self.assertRaises(Denied):
            authority.approve_published_model("scratch", self.raw)
        self.authority.register(
            "blank-rw",
            peer.policy_sha256,
            profile_sha256(),
            "kbs:///storage-test/keys/rw",
            mount_binding={**BINDING, "destination": "/data", "access": "rw"},
        )
        with self.assertRaises(Denied):
            self.authority.approve_published_model("blank-rw", self.raw)

    def test_revocation_wrong_peer_and_conflicting_owner_are_denied(self):
        self.authority.approve_published_model("qwen-v1", self.raw)
        with self.assertRaises(Denied):
            self.open(peer=AttestedPeer("d" * 64, "b" * 64))
        self.open()
        with self.assertRaises(Denied):
            self.open(peer=AttestedPeer("a" * 64, "d" * 64))
        self.authority.revoke("qwen-v1")
        with self.assertRaises(Denied):
            self.open()
        with self.assertRaises(Denied):
            self.authority.approve_published_model("qwen-v1", self.raw)

    def test_duplicate_and_malformed_manifest_cannot_be_approved(self):
        altered = [
            self.raw.replace(
                b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1'
            )
        ]
        mutations = [
            lambda m: m.update(generation=True),
            lambda m: m.update(deviceBytes=False),
            lambda m: m["verity"].update(hashOffsetBytes=1),
            lambda m: m["verity"].update(
                dataBytes=m["deviceBytes"] - 4096,
                hashOffsetBytes=m["deviceBytes"] - 4096,
            ),
            lambda m: m["verity"].update(hashAlgorithm="sha1"),
            lambda m: m["source"].update(manifestDigest="latest"),
            lambda m: m["source"].update(diskBytes=64),
            lambda m: m["files"][0].update(path="../escape"),
            lambda m: m["files"].append(copy.deepcopy(m["files"][0])),
        ]
        for mutate in mutations:
            m = json.loads(self.raw)
            mutate(m)
            altered.append(compact(m))
        for raw in altered:
            with self.subTest(raw=hashlib.sha256(raw).hexdigest()), self.assertRaises(
                Denied
            ):
                self.authority.approve_published_model("qwen-v1", raw)
        self.assertEqual(self.authority.inspect("qwen-v1")["state"], "Uninitialized")

    def test_conflicting_concurrent_approvals_choose_one_immutable_release(self):
        changed = json.loads(self.raw)
        changed["verity"]["root"] = "f" * 64

        def approve(raw):
            try:
                return self.authority.approve_published_model("qwen-v1", raw)[
                    "manifest_sha256"
                ]
            except Denied:
                return None

        with ThreadPoolExecutor(2) as pool:
            results = list(pool.map(approve, [self.raw, compact(changed)]))
        self.assertEqual(sum(value is not None for value in results), 1)
        self.assertIn(self.authority.inspect("qwen-v1")["manifest_sha256"], results)


if __name__ == "__main__":
    unittest.main()
