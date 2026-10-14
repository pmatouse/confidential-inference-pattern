"""Unit-level state guarantees only; no simulated attestation presented as E2E."""

from concurrent.futures import ThreadPoolExecutor
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from authority import AttestedPeer, Authority, Denied
from test_receipts import BINDING, PLAN, finish_steps


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "authority.db"
        self.authority = Authority(self.path)
        self.peer = AttestedPeer("a" * 64, "b" * 64)
        self.other = AttestedPeer("a" * 64, "c" * 64)
        self.authority.register(
            "volume-1",
            "a" * 64,
            "d" * 64,
            "kbs:///storage-test/keys/volume-1-v1",
            mount_binding=BINDING,
        )

        self.authority.approve_initialization("volume-1", PLAN)

    def begin(self, peer=None, operation_id="init-1", operation="initialize"):
        return self.authority.begin(
            "volume-1", peer or self.peer, operation_id, operation, 1
        )

    def ready(self):
        grant = self.begin()
        handle = grant["owner"]["activation_id"]
        finish_steps(
            self.authority, self.peer, handle, "e" * 64, "f" * 64, volume_id="volume-1"
        )
        self.authority.commit_ready(
            "volume-1", self.peer, handle, "e" * 64, manifest_sha256="f" * 64
        )
        return handle

    def test_intent_is_durable_before_return(self):
        grant = self.begin()
        restored = Authority(self.path)
        self.assertEqual(restored.inspect("volume-1")["state"], "Initializing")
        retry = restored.begin("volume-1", self.peer, "init-1", "initialize", 1)
        self.assertEqual(grant["action"], "plan-initialization")
        self.assertEqual(retry["action"], "resume-initialization")
        self.assertEqual(grant["owner"], retry["owner"])

    def test_ambiguous_initialization_cannot_be_reassigned(self):
        self.begin()
        with self.assertRaises(Denied):
            self.begin(self.other, "init-2")
        with self.assertRaises(Denied):
            self.begin(operation="reopen")

    def test_no_reset_of_registered_volume(self):
        self.ready()
        with self.assertRaises(Denied):
            self.authority.register(
                "volume-1", "a" * 64, "d" * 64, "kbs:///storage-test/keys/new"
            )

    def test_ready_retry_is_open_not_format(self):
        self.ready()
        self.assertEqual(self.begin()["action"], "open")

    def test_reopen_preserves_identity_and_does_not_format(self):
        handle = self.ready()
        self.authority.close("volume-1", self.peer, handle)
        restored = Authority(self.path)
        grant = restored.begin("volume-1", self.other, "open-1", "reopen", 1)
        self.assertEqual(grant["action"], "open")
        self.assertEqual(grant["header_sha256"], "e" * 64)
        with self.assertRaises(Denied):
            restored.commit_ready(
                "volume-1", self.other, grant["owner"]["activation_id"], "f" * 64
            )

    def test_no_initialization_after_close(self):
        self.authority.close("volume-1", self.peer, self.ready())
        with self.assertRaises(Denied):
            self.begin(operation_id="init-2")

    def test_mismatched_and_unbound_evidence_denied(self):
        with self.assertRaises(Denied):
            self.begin(AttestedPeer("f" * 64, "b" * 64))
        with self.assertRaises(Denied):
            self.begin(AttestedPeer("a" * 64, ""))

    def test_wrong_generation(self):
        with self.assertRaises(Denied):
            self.authority.begin("volume-1", self.peer, "init-1", "initialize", 0)

    def test_header_substitution_rejected_on_commit_retry(self):
        handle = self.ready()
        with self.assertRaises(Denied):
            self.authority.commit_ready(
                "volume-1", self.peer, handle, "f" * 64, manifest_sha256="f" * 64
            )
        self.assertEqual(self.authority.inspect("volume-1")["header_sha256"], "e" * 64)

    def test_close_wrong_owner_and_stale_handle(self):
        handle = self.ready()
        with self.assertRaises(Denied):
            self.authority.close("volume-1", self.other, handle)
        self.authority.close("volume-1", self.peer, handle)
        self.begin(self.other, "open-1", "reopen")
        with self.assertRaises(Denied):
            self.authority.close("volume-1", self.peer, handle)

    def test_no_close_during_ambiguous_initialization(self):
        grant = self.begin()
        with self.assertRaises(Denied):
            self.authority.close("volume-1", self.peer, grant["owner"]["activation_id"])

    def test_operation_replay_after_close(self):
        self.authority.close("volume-1", self.peer, self.ready())
        grant = self.begin(operation_id="open-1", operation="reopen")
        self.authority.close("volume-1", self.peer, grant["owner"]["activation_id"])
        with self.assertRaises(Denied):
            self.begin(operation_id="open-1", operation="reopen")

    def test_revocation_denies_active_retry_and_new_start(self):
        self.begin()
        self.authority.revoke("volume-1")
        with self.assertRaises(Denied):
            self.begin()

    def test_two_concurrent_owners_only_one_wins(self):
        def attempt(i):
            try:
                return self.authority.begin(
                    "volume-1", self.peer, f"op-{i}", "initialize", 1
                )
            except Denied:
                return None

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt, range(8)))
        self.assertEqual(sum(result is not None for result in results), 1)

    def test_close_retry_is_idempotent(self):
        handle = self.ready()
        self.authority.close("volume-1", self.peer, handle)
        self.authority.close("volume-1", self.peer, handle)
        self.assertIsNone(self.authority.inspect("volume-1")["owner"])

    def test_failed_transaction_never_returns_or_records_permission(self):
        original = self.authority._save

        def fail_after_write(db, record, action):
            original(db, record, action)
            raise OSError("injected storage failure before commit")

        with patch.object(self.authority, "_save", side_effect=fail_after_write):
            with self.assertRaises(OSError):
                self.begin()
        self.assertEqual(self.authority.inspect("volume-1")["state"], "Uninitialized")
        self.assertIsNone(self.authority.inspect("volume-1")["owner"])
        self.assertEqual(self.begin()["action"], "plan-initialization")


if __name__ == "__main__":
    unittest.main()
