"""Real guest/authority signatures around a synthetic first-use journal.

No hardware evidence or disk operations occur in these tests.
"""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from attestation import unb64
from authority import Authority, Denied
import initialization_api as api
from initialization import STEPS
from receipts import compact
import test_gateway as fixtures
from test_receipts import BINDING, PLAN


class InitializationApiTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.GatewayTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.authority = Authority(Path(self.f.tmp.name) / "first-use.db")
        self.f.issuer.authority = self.f.authority
        profile = hashlib.sha256(api.PROFILE.read_bytes()).hexdigest()
        self.f.authority.register(
            "scratch",
            "a" * 64,
            profile,
            "kbs:///storage-test/keys/scratch-v1",
            mount_binding=BINDING,
        )
        approval = self.f.authority.approve_initialization("scratch", PLAN)
        self.common = {
            "volume_id": "scratch",
            "operation_id": "network-init",
            "generation": 1,
            "nonce": "e" * 64,
            "profile_sha256": profile,
            "plan_sha256": approval["plan_sha256"],
            "binding": BINDING,
        }

    def call(self, action, **fields):
        raw = compact(self.common | {"action": "initialization-" + action} | fields)
        args, _ = self.f.prepare(raw)
        result = self.f.gateway.execute(*args)
        h, p, sig = result["decision"].split(".")
        self.f.issuer.signing_key.public_key().verify(
            unb64(sig), (h + "." + p).encode()
        )
        self.assertEqual(json.loads(unb64(h))["typ"], api.TOKEN_TYPE)
        claims = json.loads(unb64(p))
        self.assertEqual(claims["challenge"], args[0])
        self.assertEqual(claims["request_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(claims["action"], "initialization-" + action)
        return claims["result"]

    def begin(self):
        return self.call("begin")["record"]["owner"]["activation_id"]

    def finish(self, activation):
        for step in STEPS:
            decision = self.call("step", activation_id=activation, step=step)
            result = {"header_sha256": "d" * 64}
            if step == "integrity-initialize":
                result["stack_sha256"] = "9" * 64
            elif step == "filesystem-create":
                result["filesystem_uuid"] = "01234567-89ab-4cde-8123-456789abcdef"
            elif step == "durability-barrier":
                raw = api.manifest(self.f.authority.inspect("scratch"), "d" * 64)
                result["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
            self.call(
                "complete",
                activation_id=activation,
                step=step,
                step_id=decision["step_id"],
                result=result,
                evidence_sha256="8" * 64,
            )

    def test_signed_plan_initialize_steps_ready_close_and_reopen(self):
        plan = self.call("plan")["record"]
        self.assertIsNone(plan["owner"])
        self.assertEqual(plan["state"], "Uninitialized")
        activation = self.begin()
        self.finish(activation)
        ready = self.call("ready", activation_id=activation, header_sha256="d" * 64)[
            "record"
        ]
        self.assertEqual(ready["state"], "Ready")
        self.assertEqual(
            hashlib.sha256(ready["manifest"].encode()).hexdigest(),
            self.f.authority.inspect("scratch")["manifest_sha256"],
        )
        self.assertEqual(
            self.call("ready", activation_id=activation, header_sha256="d" * 64)[
                "record"
            ],
            ready,
        )
        self.assertTrue(self.f.execute(self.f.close_body(activation))["closed"])
        request = {k: v for k, v in self.common.items() if k != "plan_sha256"}
        request.update(action="reopen", operation_id="network-reopen")
        self.assertIn("receipt", self.f.execute(compact(request)))

    def test_started_step_is_never_reissued_after_retry_or_response_loss(self):
        activation = self.begin()

        class UnavailableSigner:
            def sign(self, _data):
                raise OSError("synthetic signer failure after commit")

        with patch.object(self.f.issuer, "signing_key", UnavailableSigner()):
            with self.assertRaises(OSError):
                self.call("step", activation_id=activation, step="luks-format")
        result = self.call("step", activation_id=activation, step="luks-format")
        self.assertEqual(result["decision"], "reconcile")
        self.assertEqual(result["status"], "Started")
        self.assertEqual(self.call("begin")["action"], "resume-initialization")

    def test_parallel_step_requests_have_only_one_execute_decision(self):
        activation = self.begin()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(
                pool.map(
                    lambda _: self.call(
                        "step", activation_id=activation, step="luks-format"
                    ),
                    range(2),
                )
            )
        self.assertEqual(
            sorted(r["decision"] for r in results), ["execute", "reconcile"]
        )
        self.assertEqual(results[0]["step_id"], results[1]["step_id"])

    def test_unapproved_plan_profile_binding_or_nonce_cannot_acquire(self):
        for field in ("plan_sha256", "profile_sha256"):
            original = self.common[field]
            self.common[field] = "f" * 64
            with self.assertRaises(Denied):
                self.call("begin")
            self.common[field] = original
        self.assertIsNone(self.f.owner())
        self.begin()
        self.common["nonce"] = "f" * 64
        with self.assertRaises(Denied):
            self.call("begin")

    def test_readonly_or_administrative_operations_are_not_exposed(self):
        self.common["binding"] = BINDING | {"destination": "/models", "access": "ro"}
        with self.assertRaises(Denied):
            self.call("begin")
        self.common["binding"] = BINDING
        for action in ("approve", "register", "reset", "format", "keys"):
            with self.assertRaises(Denied):
                self.call(action)
        self.assertIsNone(self.f.owner())

    def test_wrong_completion_step_or_header_does_not_advance(self):
        activation = self.begin()
        first = self.call("step", activation_id=activation, step="luks-format")
        with self.assertRaises(Denied):
            self.call(
                "complete",
                activation_id=activation,
                step="integrity-initialize",
                step_id=first["step_id"],
                result={"header_sha256": "d" * 64, "stack_sha256": "9" * 64},
                evidence_sha256="8" * 64,
            )
        self.assertEqual(
            self.f.authority.inspect("scratch")["initialization_steps"][0]["status"],
            "Started",
        )
        with self.assertRaises(Denied):
            self.call("ready", activation_id=activation, header_sha256="d" * 64)
        with self.assertRaises(Denied):
            self.call("step", activation_id=activation, step="filesystem-create")

    def test_signed_guest_claims_cannot_commit_an_arbitrary_manifest_layout(self):
        activation = self.begin()
        for step in STEPS:
            decision = self.call("step", activation_id=activation, step=step)
            result = {"header_sha256": "d" * 64}
            if step == "integrity-initialize":
                result["stack_sha256"] = "9" * 64
            elif step == "filesystem-create":
                result["filesystem_uuid"] = "01234567-89ab-4cde-8123-456789abcdef"
            elif step == "durability-barrier":
                result["manifest_sha256"] = "f" * 64
            self.call(
                "complete",
                activation_id=activation,
                step=step,
                step_id=decision["step_id"],
                result=result,
                evidence_sha256="8" * 64,
            )
        with self.assertRaises(Denied):
            self.call("ready", activation_id=activation, header_sha256="d" * 64)
        self.assertEqual(self.f.authority.inspect("scratch")["state"], "Initializing")

    def test_ready_can_be_recovered_as_metadata_but_never_reformatted(self):
        activation = self.begin()
        self.finish(activation)
        self.call("ready", activation_id=activation, header_sha256="d" * 64)
        self.assertEqual(self.call("begin")["action"], "open")
        with self.assertRaises(Denied):
            self.call("step", activation_id=activation, step="luks-format")
        self.f.execute(self.f.close_body(activation))
        self.assertIn("manifest", self.call("plan")["record"])
        with self.assertRaises(Denied):
            self.call("begin")

    def test_revoked_or_other_session_cannot_operate(self):
        self.begin()
        original = self.f.guest_key
        self.f.guest_key = self.f.as_key
        with self.assertRaises(Denied):
            self.call("plan")
        self.f.guest_key = original
        self.f.authority.revoke("scratch")
        with self.assertRaises(Denied):
            self.call("plan")


if __name__ == "__main__":
    unittest.main()
