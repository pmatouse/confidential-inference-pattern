"""Cryptographic receipt tests with synthetic peers; not attestation tests."""

import base64
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from authority import AttestedPeer, Authority, Denied
from receipts import ReceiptIssuer

BINDING = {
    "manifest_uri": "kbs:///storage-test/records/scratch-v1",
    "container_name": "app",
    "destination": "/data",
    "access": "rw",
}


PLAN = {
    "schema_version": 1,
    "new_volume": True,
    "provisioning_id": "01234567-89ab-4cde-8123-456789abcdef",
    "device_bytes": 67108864,
    "luks_uuid": "abcdef01-2345-4678-8123-456789abcdef",
    "filesystem": "ext4",
    "header_bytes": 16777216,
    "data_offset_bytes": 16777216,
}


def finish_steps(
    authority,
    peer,
    handle,
    header_sha256="d" * 64,
    manifest_sha256="e" * 64,
    volume_id="scratch",
):
    # Synthetic adapter assertions only; no formatter or disk is involved.
    from initialization import STEPS

    for step in STEPS:
        decision = authority.begin_initialization_step(volume_id, peer, handle, step)
        result = {"header_sha256": header_sha256}
        if step == "integrity-initialize":
            result["stack_sha256"] = "9" * 64
        elif step == "filesystem-create":
            result["filesystem_uuid"] = "abcdef01-2345-4678-8123-456789abcdef"
        elif step == "durability-barrier":
            result["manifest_sha256"] = manifest_sha256
        authority.complete_initialization_step(
            volume_id, peer, handle, decision["step_id"], result, "8" * 64
        )


def initialized(path, key=None, *, header_sha256="d" * 64, manifest_sha256="e" * 64):
    authority = Authority(path)
    peer = AttestedPeer("a" * 64, "b" * 64)
    authority.register(
        "scratch",
        peer.policy_sha256,
        "c" * 64,
        "kbs:///storage-test/keys/scratch-v1",
        mount_binding=BINDING,
    )
    authority.approve_initialization("scratch", PLAN)
    initial = authority.begin("scratch", peer, "init-1", "initialize", 1)
    handle = initial["owner"]["activation_id"]
    finish_steps(authority, peer, handle, header_sha256, manifest_sha256)
    authority.commit_ready(
        "scratch", peer, handle, header_sha256, manifest_sha256=manifest_sha256
    )
    authority.close("scratch", peer, handle)
    key = key or Ed25519PrivateKey.generate()
    issuer = ReceiptIssuer(
        authority, key, "storage-authority", "test-1", clock=lambda: 2000000000
    )
    return authority, peer, key, issuer


def decode(token):
    return json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.authority, self.peer, self.key, self.issuer = initialized(
            Path(self.tmp.name) / "authority.db"
        )

    def issue(self, **changes):
        args = dict(
            volume_id="scratch",
            peer=self.peer,
            operation_id="open-1",
            generation=1,
            nonce="f" * 64,
            binding=BINDING,
            profile_sha256="c" * 64,
        )
        return self.issuer.reopen(**(args | changes))

    def test_signature_and_durable_owner(self):
        token = self.issue()
        header, payload, signature = token.split(".")
        self.key.public_key().verify(
            base64.urlsafe_b64decode(signature + "=="),
            (header + "." + payload).encode(),
        )
        claims = decode(token)
        restored = Authority(self.authority.path).inspect("scratch")
        self.assertEqual(restored["owner"]["activation_id"], claims["activation_id"])
        self.assertEqual(claims["header_sha256"], "d" * 64)
        self.assertEqual(claims["manifest_sha256"], "e" * 64)
        self.assertEqual(claims["exp"] - claims["iat"], 60)
        self.assertEqual(claims["operation"], "reopen")

    def test_exact_retry_same_owner_changed_nonce_denied(self):
        original = self.issue()
        self.assertEqual(self.issue(), original)
        with self.assertRaises(Denied):
            self.issue(nonce="1" * 64)
        self.assertEqual(self.issue(), original)

    def test_binding_and_profile_substitution_before_ownership(self):
        for field in BINDING:
            changed = BINDING | {field: "different"}
            with self.subTest(field=field), self.assertRaises(Denied):
                self.issue(binding=changed)
        with self.assertRaises(Denied):
            self.issue(profile_sha256="1" * 64)
        self.assertIsNone(self.authority.inspect("scratch")["owner"])

    def test_unbound_peer_revocation_and_stale_generation(self):
        for change in [
            dict(peer=AttestedPeer("1" * 64, "b" * 64)),
            dict(generation=2),
            dict(nonce="short"),
        ]:
            with self.assertRaises(Denied):
                self.issue(**change)
        self.authority.revoke("scratch")
        with self.assertRaises(Denied):
            self.issue()

    def test_consumed_operation_cannot_issue_new_receipt(self):
        first = decode(self.issue())
        self.authority.close("scratch", self.peer, first["activation_id"])
        with self.assertRaises(Denied):
            self.issue()
        next_claims = decode(self.issue(operation_id="open-2", nonce="2" * 64))
        self.assertNotEqual(first["activation_id"], next_claims["activation_id"])
        with self.assertRaises(Denied):
            self.authority.close("scratch", self.peer, first["activation_id"])

    def test_ready_manifest_cannot_be_changed_on_retry(self):
        a = Authority(Path(self.tmp.name) / "other.db")
        a.register(
            "scratch",
            "a" * 64,
            "c" * 64,
            "kbs:///storage-test/keys/scratch-v1",
            mount_binding=BINDING,
        )
        a.approve_initialization("scratch", PLAN)
        handle = a.begin("scratch", self.peer, "init-1", "initialize", 1)["owner"][
            "activation_id"
        ]
        with self.assertRaises(Denied):
            a.commit_ready("scratch", self.peer, handle, "d" * 64)
        finish_steps(a, self.peer, handle)
        a.commit_ready("scratch", self.peer, handle, "d" * 64, manifest_sha256="e" * 64)
        with self.assertRaises(Denied):
            a.commit_ready(
                "scratch", self.peer, handle, "d" * 64, manifest_sha256="1" * 64
            )

    def test_receipt_retry_after_authority_restart(self):
        original = self.issue()
        restored = Authority(self.authority.path)
        self.issuer = ReceiptIssuer(
            restored, self.key, "storage-authority", "test-1", clock=lambda: 2000000000
        )
        self.assertEqual(self.issue(), original)
        with self.assertRaises(Denied):
            self.issue(nonce="1" * 64)

    def test_signing_failure_keeps_committed_owner_for_exact_retry(self):
        with patch.object(self.issuer, "signing_key") as unavailable:
            unavailable.sign.side_effect = RuntimeError("synthetic signer failure")
            with self.assertRaises(RuntimeError):
                self.issue()
        owner = Authority(self.authority.path).inspect("scratch")["owner"]
        self.assertIsNotNone(owner)
        self.assertEqual(decode(self.issue())["activation_id"], owner["activation_id"])

    def test_old_ready_record_without_step_journal_cannot_issue_receipt(self):
        # Represent a pre-journal DB from an earlier development checkpoint.
        with self.authority._transaction() as db:
            record = self.authority._load(db, "scratch")
            record.pop("initialization_steps")
            self.authority._save(db, record, "synthetic-old-record")
        with self.assertRaises(Denied):
            self.issue()
        self.assertIsNone(self.authority.inspect("scratch")["owner"])

    def test_legacy_record_cannot_issue_receipt(self):
        self.authority.register(
            "legacy", "a" * 64, "c" * 64, "kbs:///storage-test/keys/legacy-v1"
        )
        with self.assertRaises(Denied):
            self.issue(volume_id="legacy")


if __name__ == "__main__":
    unittest.main()
