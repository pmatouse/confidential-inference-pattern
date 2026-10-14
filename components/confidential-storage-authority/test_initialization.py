"""First-use protocol fault tests; synthetic peers/results, no disk or TEE."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from authority import AttestedPeer, Authority, Denied
from initialization import STEPS, completed
from test_receipts import BINDING, PLAN, finish_steps


class InitializationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "state.db"
        self.a = Authority(self.path)
        self.peer = AttestedPeer("a" * 64, "b" * 64)
        self.other = AttestedPeer("a" * 64, "f" * 64)
        self.a.register(
            "scratch",
            "a" * 64,
            "c" * 64,
            "kbs:///storage-test/keys/scratch-v1",
            mount_binding=BINDING,
        )

    def start(self):
        self.a.approve_initialization("scratch", PLAN)
        return self.a.begin("scratch", self.peer, "init-1", "initialize", 1)["owner"][
            "activation_id"
        ]

    def step(self, handle, name="luks-format"):
        return self.a.begin_initialization_step("scratch", self.peer, handle, name)

    def complete(self, handle, decision, **changes):
        args = dict(
            volume_id="scratch",
            peer=self.peer,
            activation_id=handle,
            step_id=decision["step_id"],
            result={"header_sha256": "d" * 64},
            evidence_sha256="8" * 64,
        )
        return self.a.complete_initialization_step(**(args | changes))

    def test_no_format_without_explicit_approval(self):
        with self.assertRaises(Denied):
            self.a.begin("scratch", self.peer, "init-1", "initialize", 1)
        r = self.a.inspect("scratch")
        self.assertEqual(r["state"], "Uninitialized")
        self.assertIsNone(r["owner"])
        with self.assertRaises(Denied):
            self.a.approve_initialization("unknown-drive", PLAN)
        with self.assertRaises(Denied):
            self.a.approve_initialization("scratch", PLAN | {"new_volume": False})

    def test_approval_is_exact_immutable_and_durable(self):
        approval = self.a.approve_initialization("scratch", PLAN)
        restored = Authority(self.path)
        self.assertEqual(restored.approve_initialization("scratch", PLAN), approval)
        with self.assertRaises(Denied):
            restored.approve_initialization(
                "scratch", PLAN | {"device_bytes": 134217728}
            )
        self.assertEqual(
            restored.inspect("scratch")["initialization_approval"], approval
        )

    def test_geometry_unknown_fields_and_noncanonical_ids_denied(self):
        for field, value in [
            ("schema_version", True),
            ("new_volume", 1),
            ("provisioning_id", "pvc-name"),
            ("luks_uuid", "ABCDEF01-2345-4678-8123-456789ABCDEF"),
            ("device_bytes", True),
            ("device_bytes", 4096),
            ("device_bytes", 2**63),
            ("device_bytes", 67108865),
            ("header_bytes", 4096),
            ("data_offset_bytes", 0),
            ("filesystem", "xfs"),
            ("extra", True),
        ]:
            with self.subTest(field=field, value=value), self.assertRaises(Denied):
                self.a.approve_initialization("scratch", PLAN | {field: value})
        self.assertNotIn("initialization_approval", self.a.inspect("scratch"))

    def test_only_one_concurrent_format_decision(self):
        handle = self.start()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.step(handle), range(8)))
        self.assertEqual(sum(r["decision"] == "execute" for r in results), 1)
        self.assertEqual(sum(r["decision"] == "reconcile" for r in results), 7)
        self.assertEqual(len({r["step_id"] for r in results}), 1)

    def test_lost_format_response_and_restart_never_reissue_execute(self):
        handle = self.start()
        original = self.step(handle)  # pretend its response was lost
        self.a = Authority(self.path)
        retry = self.step(handle)
        self.assertEqual(retry["decision"], "reconcile")
        self.assertEqual(retry["step_id"], original["step_id"])
        with self.assertRaises(Denied):
            self.a.begin("scratch", self.other, "new-init", "initialize", 1)
        with self.assertRaises(Denied):
            self.a.close("scratch", self.peer, handle)

    def test_cannot_skip_steps_or_commit_ready_early(self):
        handle = self.start()
        for step in STEPS[1:]:
            with self.assertRaises(Denied):
                self.step(handle, step)
        with self.assertRaises(Denied):
            self.a.commit_ready(
                "scratch", self.peer, handle, "d" * 64, manifest_sha256="e" * 64
            )
        first = self.step(handle)
        with self.assertRaises(Denied):
            self.step(handle, STEPS[1])
        self.complete(handle, first)
        self.assertEqual(self.step(handle)["decision"], "complete")
        self.assertEqual(self.step(handle, STEPS[1])["decision"], "execute")

    def test_completion_retry_is_exact_and_bound_to_step_owner(self):
        handle = self.start()
        first = self.step(handle)
        result = self.complete(handle, first)
        self.assertEqual(self.complete(handle, first), result)
        for change in [
            {"peer": self.other},
            {"activation_id": "other"},
            {"step_id": "other"},
            {"result": {"header_sha256": "e" * 64}},
            {"evidence_sha256": "9" * 64},
            {"result": {"header_sha256": "d" * 64, "format_again": True}},
        ]:
            with self.subTest(change=change), self.assertRaises(Denied):
                self.complete(handle, first, **change)

    def test_header_identity_cannot_change_between_steps(self):
        handle = self.start()
        self.complete(handle, self.step(handle))
        second = self.step(handle, STEPS[1])
        with self.assertRaises(Denied):
            self.complete(
                handle,
                second,
                result={"header_sha256": "e" * 64, "stack_sha256": "9" * 64},
            )
        self.assertEqual(self.step(handle, STEPS[1])["decision"], "reconcile")

    def test_ready_requires_final_barrier_digests_and_prevents_reformat(self):
        handle = self.start()
        finish_steps(self.a, self.peer, handle)
        self.assertTrue(completed(self.a.inspect("scratch")))
        with self.assertRaises(Denied):
            self.a.commit_ready(
                "scratch", self.peer, handle, "d" * 64, manifest_sha256="f" * 64
            )
        self.a.commit_ready(
            "scratch", self.peer, handle, "d" * 64, manifest_sha256="e" * 64
        )
        with self.assertRaises(Denied):
            self.step(handle)
        with self.assertRaises(Denied):
            self.a.approve_initialization("scratch", PLAN)
        self.a.close("scratch", self.peer, handle)
        with self.assertRaises(Denied):
            self.a.begin("scratch", self.peer, "init-again", "initialize", 1)
        opened = self.a.begin("scratch", self.peer, "open-1", "reopen", 1)
        self.assertEqual(opened["action"], "open")
        self.assertEqual(opened["header_sha256"], "d" * 64)

    def test_revocation_blocks_initialization_and_keeps_started_intent(self):
        handle = self.start()
        first = self.step(handle)
        self.a.revoke("scratch")
        with self.assertRaises(Denied):
            self.step(handle)
        with self.assertRaises(Denied):
            self.complete(handle, first)
        self.assertEqual(
            self.a.inspect("scratch")["initialization_steps"][0]["status"], "Started"
        )

    def test_uncommitted_step_intent_never_returns_permission(self):
        handle = self.start()
        original = self.a._save

        def fail(db, record, action):
            original(db, record, action)
            raise OSError("synthetic database failure")

        with patch.object(self.a, "_save", side_effect=fail), self.assertRaises(
            OSError
        ):
            self.step(handle)
        self.assertEqual(
            Authority(self.path).inspect("scratch")["initialization_steps"], []
        )
        self.assertEqual(self.step(handle)["decision"], "execute")

    def test_lost_completion_commit_retains_started_and_allows_only_reconciliation(
        self,
    ):
        handle = self.start()
        first = self.step(handle)
        original = self.a._save

        def fail(db, record, action):
            original(db, record, action)
            raise OSError("synthetic database failure after disk effect")

        with patch.object(self.a, "_save", side_effect=fail), self.assertRaises(
            OSError
        ):
            self.complete(handle, first)
        self.a = Authority(self.path)
        self.assertEqual(self.step(handle)["decision"], "reconcile")
        self.complete(handle, first)
        self.assertEqual(self.step(handle)["decision"], "complete")

    def test_provisioning_identity_cannot_be_approved_under_two_volume_names(self):
        self.a.register(
            "alias",
            "a" * 64,
            "c" * 64,
            "kbs:///storage-test/keys/alias-v1",
            mount_binding=BINDING,
        )

        def approve_name(name):
            try:
                self.a.approve_initialization(name, PLAN)
                return name
            except Denied:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(approve_name, ["scratch", "alias"]))
        winner = next(name for name in results if name is not None)
        self.assertEqual(sum(name is not None for name in results), 1)
        loser = "alias" if winner == "scratch" else "scratch"
        self.assertNotIn("initialization_approval", self.a.inspect(loser))
        with self.assertRaises(Denied):
            Authority(self.path).approve_initialization(loser, PLAN)

    def test_failed_approval_rolls_back_provisioning_reservation(self):
        original = self.a._save

        def fail(db, record, action):
            original(db, record, action)
            raise OSError("synthetic approval commit failure")

        with patch.object(self.a, "_save", side_effect=fail), self.assertRaises(
            OSError
        ):
            self.a.approve_initialization("scratch", PLAN)
        self.assertNotIn(
            "initialization_approval", Authority(self.path).inspect("scratch")
        )
        # The unique reservation also rolled back; an exact fresh approval works.
        approval = Authority(self.path).approve_initialization("scratch", PLAN)
        self.assertEqual(approval["plan"], PLAN)

    def test_readonly_and_legacy_records_cannot_get_format_approval(self):
        for name, binding in [
            ("ro", BINDING | {"destination": "/models", "access": "ro"}),
            ("legacy", None),
        ]:
            self.a.register(
                name,
                "a" * 64,
                "c" * 64,
                "kbs:///storage-test/keys/ro-v1",
                mount_binding=binding,
            )
            with self.assertRaises(Denied):
                self.a.approve_initialization(name, PLAN)
            with self.assertRaises(Denied):
                self.a.begin(name, self.peer, "init-1", "initialize", 1)


if __name__ == "__main__":
    unittest.main()
