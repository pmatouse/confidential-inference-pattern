"""Fault injection at every journal/effect boundary, using synthetic disk effects."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from authority import AttestedPeer, Authority, Denied
from executor import Completion, DeviceBinding, Executor, RecoveryRequired
from initialization import STEPS
from test_receipts import BINDING, PLAN


class SimulatedDeath(BaseException):
    pass


class Backend:
    binding = DeviceBinding(
        "scratch",
        PLAN["provisioning_id"],
        PLAN["device_bytes"],
        "c" * 64,
        "kbs:///storage-test/keys/scratch-v1",
    )

    def __init__(self, authority):
        self.authority = authority
        self.effects = []
        self.preflights = 0

    def preflight(self, context):
        self.preflights += 1

    def execute(self, step, context):
        # Independently reload from SQLite at the exact moment of the effect.
        current = Authority(self.authority.path).inspect("scratch")
        assert current["initialization_steps"][-1]["status"] == "Started"
        assert current["initialization_steps"][-1]["step"] == step
        self.effects.append(step)
        result = {"header_sha256": "d" * 64}
        if step == "integrity-initialize":
            result["stack_sha256"] = "e" * 64
        elif step == "filesystem-create":
            result["filesystem_uuid"] = PLAN["luks_uuid"]
        elif step == "durability-barrier":
            result["manifest_sha256"] = "f" * 64
        return Completion(result, {"synthetic": True})


class ExecutorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.a = Authority(Path(self.tmp.name) / "authority.db")
        self.peer = AttestedPeer("a" * 64, "b" * 64)
        self.a.register(
            "scratch",
            "a" * 64,
            "c" * 64,
            Backend.binding.credential_uri,
            mount_binding=BINDING,
        )
        self.a.approve_initialization("scratch", PLAN)
        self.backend = Backend(self.a)

    def run_executor(self):
        return Executor(self.a, self.peer, self.backend).initialize("init-1", 1)

    def test_complete_sequence_is_ordered_and_owned(self):
        result = self.run_executor()
        self.assertEqual(self.backend.effects, list(STEPS))
        self.assertEqual(result["state"], "Ready")
        self.assertIsNotNone(result["owner"])
        self.assertEqual(result["header_sha256"], "d" * 64)
        self.assertEqual(result["manifest_sha256"], "f" * 64)
        with self.assertRaises(RecoveryRequired):
            self.run_executor()
        self.assertEqual(self.backend.effects, list(STEPS))

    def test_binding_mismatch_has_no_preflight_or_effect(self):
        for change in (
            {"device_bytes": 128 * 1024 * 1024},
            {"provisioning_id": "other"},
            {"profile_sha256": "9" * 64},
            {"credential_uri": "kbs:///other/keys/v1"},
        ):
            self.backend.binding = replace(Backend.binding, **change)
            with self.assertRaises(RecoveryRequired):
                self.run_executor()
        self.assertEqual(self.backend.preflights, 0)
        self.assertEqual(self.backend.effects, [])

    def test_preflight_failure_never_claims_or_formats(self):
        with patch.object(
            self.backend, "preflight", side_effect=Denied("existing data")
        ):
            with self.assertRaises(Denied):
                self.run_executor()
        self.assertIsNone(self.a.inspect("scratch")["owner"])
        self.assertEqual(self.backend.effects, [])

    def test_concurrent_workers_execute_each_effect_once(self):
        def run(_):
            try:
                return self.run_executor()["state"]
            except Denied:
                return "denied"

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(run, range(8)))
        self.assertEqual(results.count("Ready"), 1)
        self.assertEqual(self.backend.effects, list(STEPS))

    def test_failed_worker_cannot_be_reused_even_before_begin(self):
        worker = Executor(self.a, self.peer, self.backend)
        with patch.object(self.backend, "preflight", side_effect=SimulatedDeath):
            with self.assertRaises(SimulatedDeath):
                worker.initialize("init-1", 1)
        with self.assertRaises(RecoveryRequired):
            worker.initialize("init-1", 1)
        self.assertEqual(self.backend.effects, [])

    def test_all_effect_boundaries_fail_closed_after_restart(self):
        # Fresh DB/backend for each boundary: no reset/reformat API exists.
        for step in STEPS:
            for boundary in (
                "before-effect",
                "after-effect",
                "before-complete",
                "after-complete",
            ):
                with self.subTest(step=step, boundary=boundary):
                    with TemporaryDirectory() as tmp:
                        a = Authority(Path(tmp) / "authority.db")
                        a.register(
                            "scratch",
                            "a" * 64,
                            "c" * 64,
                            Backend.binding.credential_uri,
                            mount_binding=BINDING,
                        )
                        a.approve_initialization("scratch", PLAN)
                        backend = Backend(a)
                        execute = backend.execute
                        complete = a.complete_initialization_step

                        def effect(name, context):
                            if name == step and boundary == "before-effect":
                                raise SimulatedDeath()
                            result = execute(name, context)
                            if name == step and boundary == "after-effect":
                                raise SimulatedDeath()
                            return result

                        def finish(*args):
                            name = a.inspect("scratch")["initialization_steps"][-1][
                                "step"
                            ]
                            if name == step and boundary == "before-complete":
                                raise SimulatedDeath()
                            result = complete(*args)
                            if name == step and boundary == "after-complete":
                                raise SimulatedDeath()
                            return result

                        with patch.object(
                            backend, "execute", side_effect=effect
                        ), patch.object(
                            a, "complete_initialization_step", side_effect=finish
                        ):
                            with self.assertRaises(SimulatedDeath):
                                Executor(a, self.peer, backend).initialize("init-1", 1)
                        effects = list(backend.effects)
                        restored = Authority(a.path)
                        with self.assertRaises(RecoveryRequired):
                            Executor(restored, self.peer, backend).initialize(
                                "init-1", 1
                            )
                        self.assertEqual(backend.effects, effects)
                        self.assertEqual(
                            restored.inspect("scratch")["state"], "Initializing"
                        )

    def test_invalid_result_never_advances_or_formats_again(self):
        execute = self.backend.execute

        def invalid(step, context):
            result = execute(step, context)
            result.result["unexpected"] = True
            return result

        with patch.object(self.backend, "execute", side_effect=invalid):
            with self.assertRaises(Denied):
                self.run_executor()
        self.assertEqual(
            self.a.inspect("scratch")["initialization_steps"][0]["status"], "Started"
        )
        with self.assertRaises(RecoveryRequired):
            self.run_executor()
        self.assertEqual(self.backend.effects, ["luks-format"])

    def test_lost_ready_response_cannot_trigger_reinitialization(self):
        commit = self.a.commit_ready

        def lost(*args, **kwargs):
            commit(*args, **kwargs)
            raise SimulatedDeath()

        with patch.object(self.a, "commit_ready", side_effect=lost):
            with self.assertRaises(SimulatedDeath):
                self.run_executor()
        self.assertEqual(self.a.inspect("scratch")["state"], "Ready")
        with self.assertRaises(RecoveryRequired):
            self.run_executor()
        self.assertEqual(self.backend.effects, list(STEPS))

    def test_failure_before_ready_commit_retains_completed_journal(self):
        with patch.object(self.a, "commit_ready", side_effect=SimulatedDeath):
            with self.assertRaises(SimulatedDeath):
                self.run_executor()
        record = Authority(self.a.path).inspect("scratch")
        self.assertEqual(record["state"], "Initializing")
        self.assertTrue(
            all(s["status"] == "Complete" for s in record["initialization_steps"])
        )
        with self.assertRaises(RecoveryRequired):
            self.run_executor()
        self.assertEqual(self.backend.effects, list(STEPS))

    def test_revocation_after_effect_blocks_completion_and_later_effects(self):
        execute = self.backend.execute

        def revoke(step, context):
            completion = execute(step, context)
            self.a.revoke("scratch")
            return completion

        with patch.object(self.backend, "execute", side_effect=revoke):
            with self.assertRaises(Denied):
                self.run_executor()
        self.assertEqual(self.backend.effects, ["luks-format"])
        self.assertEqual(
            self.a.inspect("scratch")["initialization_steps"][0]["status"], "Started"
        )
        with self.assertRaises(RecoveryRequired):
            self.run_executor()


if __name__ == "__main__":
    unittest.main()
