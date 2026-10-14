"""No-write recovery is possible only before any destructive permit was issued."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest

from authority import AttestedPeer, Authority, Denied
from test_receipts import BINDING, PLAN
from initialization_api import PROFILE
import hashlib


class UnstartedRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.authority = Authority(Path(self.tmp.name) / "authority.db")
        self.authority.register(
            "data",
            "a" * 64,
            hashlib.sha256(PROFILE.read_bytes()).hexdigest(),
            "kbs:///default/keys/data",
            mount_binding=BINDING,
        )
        self.authority.approve_initialization("data", PLAN)
        self.peer = AttestedPeer("a" * 64, "b" * 64)
        self.record = self.authority.begin(
            "data", self.peer, "attempt1", "initialize", 1
        )
        self.activation = self.record["owner"]["activation_id"]

    def release(self):
        return self.authority.release_unstarted_initialization(
            "data", self.activation, "e" * 64
        )

    def test_preserves_approval_history_and_fences_old_session(self):
        released = self.release()
        self.assertEqual(released["state"], "Uninitialized")
        self.assertIsNone(released["owner"])
        for field in (
            "generation",
            "credential_uri",
            "initialization_approval",
            "mount_binding",
        ):
            self.assertEqual(released[field], self.record[field])
        with self.assertRaises(Denied):
            self.authority.begin_initialization_step(
                "data", self.peer, self.activation, "luks-format"
            )
        for operation in ("attempt1", "new-attempt-from-old-session"):
            with self.assertRaises(Denied):
                self.authority.begin("data", self.peer, operation, "initialize", 1)
        new_peer = AttestedPeer("a" * 64, "c" * 64)
        with self.assertRaises(Denied):
            self.authority.begin("data", new_peer, "attempt1", "initialize", 1)
        self.authority.begin("data", new_peer, "attempt2", "initialize", 1)
        with self.assertRaises(Denied):
            self.release()  # Cannot release a different activation.
        with self.authority._transaction() as db:
            self.assertEqual(
                db.execute("select count(*) from operations").fetchone()[0], 2
            )
            self.assertEqual(
                db.execute(
                    "select count(*) from events where action='release-unstarted-initialization'"
                ).fetchone()[0],
                1,
            )

    def test_started_but_unfinished_step_can_never_be_released(self):
        self.authority.begin_initialization_step(
            "data", self.peer, self.activation, "luks-format"
        )
        with self.assertRaises(Denied):
            self.release()
        self.assertEqual(self.authority.inspect("data")["state"], "Initializing")

    def test_recovery_racing_step_has_only_one_winner(self):
        def run(operation):
            try:
                operation()
                return True
            except Denied:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(
                pool.map(
                    run,
                    [
                        self.release,
                        lambda: self.authority.begin_initialization_step(
                            "data", self.peer, self.activation, "luks-format"
                        ),
                    ],
                )
            )
        self.assertEqual(sum(results), 1)

    def test_revoked_wrong_activation_or_invalid_evidence_rejected(self):
        with self.assertRaises(Denied):
            self.authority.release_unstarted_initialization(
                "data", "00000000-0000-4000-8000-000000000000", "e" * 64
            )
        with self.assertRaises(Denied):
            self.authority.release_unstarted_initialization(
                "data", self.activation, "invalid"
            )
        self.authority.revoke("data")
        with self.assertRaises(Denied):
            self.release()
