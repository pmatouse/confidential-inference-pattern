"""A fenced Ready reopen can be released without resetting its disk history."""

from pathlib import Path
import tempfile
import unittest

from authority import AttestedPeer, Denied
from recover_fenced_reopen import recover, record_digest
from test_receipts import initialized


class FencedReopenTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.a, self.peer, _, _ = initialized(Path(self.tmp.name) / "authority.db")
        self.a.begin("scratch", self.peer, "reopen-old", "reopen", 1)
        self.before = self.a.inspect("scratch")
        self.expected = {"scratch": record_digest(self.before)}

    def test_dry_run_and_preservation_and_old_session_rejection(self):
        recover(self.a, self.expected, "e" * 64)
        self.assertEqual(self.a.inspect("scratch"), self.before)
        recover(self.a, self.expected, "e" * 64, apply=True)
        after = self.a.inspect("scratch")
        self.assertIsNone(after["owner"])
        for key, value in self.before.items():
            if key not in ("owner", "retired_initialization_sessions"):
                self.assertEqual(after[key], value, key)
        with self.assertRaises(Denied):
            self.a.begin("scratch", self.peer, "new-operation", "reopen", 1)
        fresh = AttestedPeer(self.peer.policy_sha256, "9" * 64)
        self.a.begin("scratch", fresh, "fresh-operation", "reopen", 1)
        with self.assertRaises(Denied):
            recover(self.a, self.expected, "e" * 64, apply=True)

    def test_stale_or_revoked_record_is_rejected_atomically(self):
        with self.assertRaises(Denied):
            recover(self.a, {"scratch": "f" * 64}, "e" * 64, apply=True)
        with self.assertRaises(Denied):
            recover(
                self.a, {**self.expected, "missing": "f" * 64}, "e" * 64, apply=True
            )
        self.assertEqual(self.a.inspect("scratch"), self.before)
        self.a.revoke("scratch")
        with self.assertRaises(Denied):
            recover(
                self.a,
                {"scratch": record_digest(self.a.inspect("scratch"))},
                "e" * 64,
                apply=True,
            )

    def test_uninitialized_and_initializing_are_never_recovered(self):
        from test_receipts import BINDING, PLAN

        self.a.register(
            "blank", "a" * 64, "c" * 64, "kbs:///test/keys/blank", mount_binding=BINDING
        )
        for initialize in (False, True):
            if initialize:
                self.a.approve_initialization(
                    "blank",
                    {**PLAN, "provisioning_id": "e9690b6e-01f0-45b1-ae67-344f5ac51c91"},
                )
                self.a.begin("blank", self.peer, "first", "initialize", 1)
            with self.assertRaises(Denied):
                recover(
                    self.a,
                    {"blank": record_digest(self.a.inspect("blank"))},
                    "e" * 64,
                    apply=True,
                )


if __name__ == "__main__":
    unittest.main()
