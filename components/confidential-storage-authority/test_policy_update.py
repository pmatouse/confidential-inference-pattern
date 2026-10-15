"""Policy upgrades preserve initialized storage and cannot take over an owner."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest
from authority import AttestedPeer, Denied
from test_receipts import initialized


class PolicyUpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.a, self.peer, _, _ = initialized(Path(self.tmp.name) / "authority.db")

    def update(self, names=None, old="a", new="f"):
        return self.a.update_workload_policy(
            names or ["scratch"], old * 64, new * 64, "e" * 64
        )

    def test_preserves_disk_identity_and_history_and_fences_old_policy(self):
        before = self.a.inspect("scratch")
        after = self.update()[0]
        for key in before:
            if key != "policy_sha256":
                self.assertEqual(before[key], after[key], key)
        with self.assertRaises(Denied):
            self.a.begin("scratch", self.peer, "old", "reopen", 1)
        new = AttestedPeer("f" * 64, "1" * 64)
        r = self.a.begin("scratch", new, "new", "reopen", 1)
        self.a.close("scratch", new, r["owner"]["activation_id"])
        with self.assertRaises(Denied):
            self.update(old="f", new="a")
        with self.assertRaises(Denied):
            self.a.begin("scratch", new, "init-1", "reopen", 1)

    def test_initialization_identity_is_preserved_and_corrupt_history_is_denied(self):
        from initialization import approved_policy

        original = self.a.inspect("scratch")["initialization_approval"]
        first = self.update()[0]
        self.assertEqual(first["initialization_policy_sha256"], "a" * 64)
        second = self.update(old="f", new="9")[0]
        self.assertEqual(second["initialization_approval"], original)
        self.assertEqual(approved_policy(second), "a" * 64)
        # Earlier deployment records can reconstruct this field only by matching
        # the immutable plan hash against retained, explicitly retired policies.
        del second["initialization_policy_sha256"]
        self.assertEqual(approved_policy(second), "a" * 64)
        second["retired_workload_policies"] = []
        with self.assertRaises(Denied):
            approved_policy(second)

    def test_owned_revoked_unready_and_stale_records_rejected(self):
        r = self.a.begin("scratch", self.peer, "open", "reopen", 1)
        with self.assertRaises(Denied):
            self.update()
        self.a.close("scratch", self.peer, r["owner"]["activation_id"])
        with self.assertRaises(Denied):
            self.update(old="b")
        self.a.register("blank", "a" * 64, "c" * 64, "kbs:///test/keys/blank")
        with self.assertRaises(Denied):
            self.update(["scratch", "blank"])
        self.assertEqual(self.a.inspect("scratch")["policy_sha256"], "a" * 64)
        self.a.revoke("scratch")
        with self.assertRaises(Denied):
            self.update()

    def test_update_racing_reopen_has_only_one_winner(self):
        def run(fn):
            try:
                fn()
                return True
            except Denied:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(
                pool.map(
                    run,
                    [
                        self.update,
                        lambda: self.a.begin(
                            "scratch", self.peer, "racing-open", "reopen", 1
                        ),
                    ],
                )
            )
        self.assertEqual(sum(outcomes), 1)

    def blank(self):
        from test_receipts import BINDING, PLAN
        self.a.register("blank", "a" * 64, "c" * 64,
                        "kbs:///storage-test/keys/blank", mount_binding=BINDING)
        self.a.approve_initialization("blank", PLAN | {"provisioning_id": "7f3399dd-4f0c-4fa3-83ec-cc6898e4b691"})

    def test_explicit_never_started_upgrade_preserves_first_use_approval(self):
        from initialization import approved_policy
        self.blank()
        before = self.a.inspect("blank")
        with self.assertRaises(Denied):
            self.update(["blank"])
        after = self.a.update_workload_policy(["blank"], "a"*64, "f"*64,
                                             "e"*64, allow_never_started=True)[0]
        self.assertEqual(after["initialization_approval"], before["initialization_approval"])
        self.assertEqual(approved_policy(after), "a"*64)
        self.assertEqual(after["state"], "Uninitialized")
        with self.assertRaises(Denied):
            self.a.begin("blank", self.peer, "old", "initialize", 1)
        self.a.begin("blank", AttestedPeer("f"*64,"1"*64), "new", "initialize", 1)

    def test_never_started_option_rejects_even_released_operation_history(self):
        self.blank()
        opened = self.a.begin("blank", self.peer, "started", "initialize", 1)
        with self.assertRaises(Denied):
            self.a.update_workload_policy(["scratch","blank"], "a"*64, "f"*64,
                                         "e"*64, allow_never_started=True)
        self.a.release_unstarted_initialization("blank", opened["owner"]["activation_id"], "e"*64)
        with self.assertRaises(Denied):
            self.a.update_workload_policy(["scratch","blank"], "a"*64, "f"*64,
                                         "e"*64, allow_never_started=True)
        self.assertEqual(self.a.inspect("scratch")["policy_sha256"], "a"*64)

    def test_blank_reapproval_binds_current_policy_and_retains_geometry(self):
        from initialization import approved_policy
        self.blank()
        before = self.a.inspect("blank")
        self.a.update_workload_policy(["blank"], "a"*64, "f"*64, "e"*64,
                                     allow_never_started=True)
        old_hash = before["initialization_approval"]["plan_sha256"]
        after = self.a.rebind_unstarted_initialization("blank", "f"*64, old_hash, "e"*64)
        self.assertEqual(after["initialization_approval"]["plan"], before["initialization_approval"]["plan"])
        self.assertNotEqual(after["initialization_approval"]["plan_sha256"], old_hash)
        self.assertEqual(approved_policy(after), "f"*64)
        self.assertEqual(after["retired_initialization_approvals"][0]["approval"], before["initialization_approval"])
        for k in ("credential_uri", "profile_sha256", "mount_binding", "generation", "state"):
            self.assertEqual(before[k], after[k])
        with self.assertRaises(Denied):
            self.a.rebind_unstarted_initialization("blank", "f"*64, old_hash, "e"*64)

    def test_blank_reapproval_rejects_released_attempt_and_ready_volume(self):
        self.blank()
        old_hash = self.a.inspect("blank")["initialization_approval"]["plan_sha256"]
        r = self.a.begin("blank", self.peer, "attempt", "initialize", 1)
        self.a.release_unstarted_initialization("blank", r["owner"]["activation_id"], "e"*64)
        with self.assertRaises(Denied):
            self.a.rebind_unstarted_initialization("blank", "a"*64, old_hash, "e"*64)
        with self.assertRaises(Denied):
            self.a.rebind_unstarted_initialization("scratch", "a"*64,
                self.a.inspect("scratch")["initialization_approval"]["plan_sha256"], "e"*64)
