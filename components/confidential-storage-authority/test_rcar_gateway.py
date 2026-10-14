"""Real signatures on synthetic composite claims; no claim of hardware verification."""

import base64
import copy
import hashlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from attestation import ANNOTATED, PROFILE, Appraisal, EarVerifier, b64, proof_message
from authority import Denied
from kbs_rcar import Session
from rcar_gateway import RcarGateway
from receipts import compact
from test_gateway import jwk, signature, signed_token
from test_receipts import BINDING, initialized


class FakeKbs:
    def __init__(self, owner):
        self.owner, self.count, self.calls, self.mutate = owner, 0, [], lambda x: None

    def begin(self):
        self.count += 1
        return Session(
            base64.b64encode(self.count.to_bytes(32, "big")).decode(),
            f"{self.count:032x}",
        )

    def attest(self, session, key, evidence):
        self.calls.append(session.cookie)
        runtime = {"nonce": session.nonce, "tee-pubkey": {**key, "alg": "ES256"}}
        claims = {
            "iss": "test-as",
            "eat_profile": PROFILE,
            "iat": self.owner.wall,
            "exp": self.owner.wall + 300,
            "submods": {},
        }
        for name, tee in (("cpu0", "snp"), ("gpu0", "nvidia")):
            data = {
                tee: {"synthetic": True},
                "runtime_data_claims": copy.deepcopy(runtime),
            }
            if name == "cpu0":
                data["init_data"] = "9" * 96
                data["runtime_data_claims"]["additional-evidence"] = evidence[
                    "additional_evidence"
                ]
            claims["submods"][name] = {
                "ear.status": "affirming",
                "ear.appraisal-policy-id": "default",
                "ear.trustworthiness-vector": {
                    "hardware": 2,
                    "configuration": 2,
                    "executables": 3,
                },
                ANNOTATED: data,
            }
        self.mutate(claims)
        return signed_token(self.owner.as_key, claims)


class RcarGatewayTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.authority, _, _, self.issuer = initialized(
            Path(temp.name) / "authority.db"
        )
        self.as_key = ec.generate_private_key(ec.SECP256R1())
        self.guest_key = ec.generate_private_key(ec.SECP256R1())
        self.wall, self.elapsed = 2000000000, 100.0
        self.verifier = EarVerifier(
            self.as_key.public_key(),
            "test-as",
            "https://storage.test/v1",
            "9" * 96,
            "a" * 64,
            [
                Appraisal("cpu0", "snp", "default"),
                Appraisal("gpu0", "nvidia", "default"),
            ],
        )
        self.kbs = FakeKbs(self)
        self.gateway = RcarGateway(
            self.verifier,
            self.issuer,
            rcar=self.kbs,
            clock=lambda: self.wall,
            monotonic=lambda: self.elapsed,
            capacity=4,
        )
        self.raw = compact(
            {
                "action": "reopen",
                "volume_id": "scratch",
                "operation_id": "open-1",
                "generation": 1,
                "nonce": "f" * 64,
                "binding": BINDING,
                "profile_sha256": "c" * 64,
            }
        )
        self.evidence = b64(
            compact(
                {
                    "primary_evidence": {"synthetic": True},
                    "additional_evidence": '{"nvidia":{"synthetic":true}}',
                }
            )
        )

    def prepare(self):
        challenge = self.gateway.challenge(self.raw)
        self.assertEqual(
            set(challenge["attestation"]), {"kind", "nonce", "hash_algorithm"}
        )
        token = self.gateway.attest(
            challenge["nonce"], jwk(self.guest_key), self.evidence
        )["token"]
        proof = signature(
            self.guest_key,
            proof_message(
                challenge["audience"],
                challenge["nonce"],
                challenge["request_sha256"],
                token,
            ),
        )
        return challenge["nonce"], self.raw, token, proof

    def test_fresh_composite_handshake_executes_once_and_cookie_stays_private(self):
        args = self.prepare()
        result = self.gateway.execute(*args)
        self.assertIn("receipt", result)
        self.assertNotIn(args[0], self.gateway.sessions)
        with self.assertRaises(Denied):
            self.gateway.execute(*args)
        self.assertEqual(len(self.kbs.calls), 1)

    def test_explicit_absent_issuer_profile_requires_rcar_and_pinned_signature(self):
        self.kbs.mutate = lambda c: c.pop("iss")
        with self.assertRaises(Denied):
            self.prepare()  # Default profile still requires the issuer.
        self.verifier.issuer_claim = "absent-rcar"
        args = self.prepare()
        self.gateway.execute(*args)
        with self.assertRaises(Denied):
            self.verifier.verify(args[2], args[0], "a" * 64, self.wall)
        self.kbs.mutate = lambda c: c.update(iss="test-as")
        with self.assertRaises(Denied):
            self.prepare()  # Even matching iss is wrong for the absence profile.
        self.elapsed += 61
        self.kbs.mutate = lambda c: c.pop("iss")
        self.verifier.signer = ec.generate_private_key(ec.SECP256R1()).public_key()
        with self.assertRaises(Denied):
            self.prepare()

    def test_configuration_three_is_explicit_and_cannot_accept_warning(self):
        def installed(c):
            for a in c["submods"].values():
                a["ear.trustworthiness-vector"]["configuration"] = 3

        self.kbs.mutate = installed
        with self.assertRaises(Denied):
            self.prepare()
        self.verifier.appraisals = tuple(
            Appraisal(a.submod, a.tee, a.policy_id, configuration=3)
            for a in self.verifier.appraisals
        )
        args = self.prepare()
        self.gateway.execute(*args)

        def warning(c):
            installed(c)
            c["submods"]["cpu0"]["ear.status"] = "warning"
            c["submods"]["cpu0"]["ear.trustworthiness-vector"]["executables"] = 33

        self.kbs.mutate = warning
        with self.assertRaises(Denied):
            self.prepare()

    def installed_gpu_claims(self, claims):
        cpu = claims["submods"]["cpu0"][ANNOTATED]
        cpu["report_data"] = (
            hashlib.sha384(compact(cpu["runtime_data_claims"])).hexdigest() + "0" * 32
        )
        gpu = claims["submods"]["gpu0"][ANNOTATED]
        del gpu["runtime_data_claims"]
        gpu["nvidia"] = {
            "x-nvidia-gpu-attestation-report-nonce-match": True,
            "x-nvidia-overall-att-result": True,
            "secboot": True,
            "dbgstat": "disabled",
            "measres": "success",
        }

    def test_nvidia_nonce_binding_requires_exact_cpu_composite_and_secure_gpu(self):
        self.kbs.mutate = self.installed_gpu_claims
        with self.assertRaises(Denied):
            self.prepare()  # No automatic fallback for missing GPU runtime claims.
        self.verifier.gpu_binding = "nvidia-nonce-match"
        args = self.prepare()
        self.gateway.execute(*args)
        mutations = [
            lambda c: c["submods"]["cpu0"][ANNOTATED].update(report_data="0" * 128),
            lambda c: c["submods"]["cpu0"][ANNOTATED].pop("report_data"),
            lambda c: c["submods"]["gpu0"][ANNOTATED].update(runtime_data_claims={}),
            lambda c: c["submods"].pop("gpu0"),
        ]
        for field in (
            "x-nvidia-gpu-attestation-report-nonce-match",
            "x-nvidia-overall-att-result",
            "secboot",
            "dbgstat",
            "measres",
        ):
            mutations.append(
                lambda c, f=field: c["submods"]["gpu0"][ANNOTATED]["nvidia"].pop(f)
            )
            mutations.append(
                lambda c, f=field: c["submods"]["gpu0"][ANNOTATED]["nvidia"].update(
                    {f: "invalid"}
                )
            )
        for mutation in mutations:
            self.elapsed += 61

            def mutate(c):
                self.installed_gpu_claims(c)
                mutation(c)

            self.kbs.mutate = mutate
            with self.assertRaises(Denied):
                self.prepare()

    def test_parallel_execute_only_one_dispatches(self):
        args = self.prepare()

        def execute(_):
            try:
                self.gateway.execute(*args)
                return True
            except Denied:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(execute, range(2))), [False, True])

    def test_wrong_guest_proof_changed_request_and_cross_challenge_token_rejected(self):
        nonce, raw, token, proof = self.prepare()
        with self.assertRaises(Denied):
            self.gateway.execute(nonce, raw + b" ", token, proof)
        bad_proof = signature(ec.generate_private_key(ec.SECP256R1()), b"different")
        with self.assertRaises(Denied):
            self.gateway.execute(nonce, raw, token, bad_proof)
        other = self.gateway.challenge(raw)
        with self.assertRaises(Denied):
            self.gateway.execute(other["nonce"], raw, token, proof)
        self.gateway.execute(nonce, raw, token, proof)

    def test_no_second_attest_or_retry_after_uncertain_upstream_result(self):
        args = self.prepare()
        with self.assertRaises(Denied):
            self.gateway.attest(args[0], jwk(self.guest_key), self.evidence)
        next_challenge = self.gateway.challenge(self.raw)

        def fail(_):
            raise Denied("lost response")

        self.kbs.mutate = fail
        for _ in range(2):
            with self.assertRaises(Denied):
                self.gateway.attest(
                    next_challenge["nonce"], jwk(self.guest_key), self.evidence
                )
        self.assertEqual(len(self.kbs.calls), 2)

    def test_signed_wrong_gpu_cpu_policy_initdata_nonce_or_key_cannot_pass(self):
        mutations = [
            lambda c: c["submods"].pop("gpu0"),
            lambda c: c["submods"]["gpu0"].update({"ear.status": "contraindicated"}),
            lambda c: c["submods"]["gpu0"].update({"ear.appraisal-policy-id": "other"}),
            lambda c: c["submods"]["gpu0"]["ear.trustworthiness-vector"].update(
                {"hardware": 0}
            ),
            lambda c: c["submods"]["cpu0"][ANNOTATED].update({"init_data": "8" * 96}),
            lambda c: c["submods"]["cpu0"][ANNOTATED]["runtime_data_claims"].update(
                {"nonce": "old"}
            ),
            lambda c: c["submods"]["gpu0"][ANNOTATED]["runtime_data_claims"].update(
                {"nonce": "old"}
            ),
            lambda c: c["submods"]["cpu0"][ANNOTATED]["runtime_data_claims"].update(
                {"additional-evidence": "{}"}
            ),
            lambda c: c["submods"]["gpu0"][ANNOTATED]["runtime_data_claims"][
                "tee-pubkey"
            ].update({"alg": "ECDH-ES+A256KW"}),
            lambda c: c.update({"iat": self.wall - 61}),
        ]
        for mutate in mutations:
            self.elapsed += (
                61  # Expire prior failed challenges, preserving bounded capacity.
            )
            self.kbs.mutate = mutate
            c = self.gateway.challenge(self.raw)
            with self.assertRaises(Denied):
                self.gateway.attest(c["nonce"], jwk(self.guest_key), self.evidence)

    def test_missing_gpu_extra_device_and_duplicate_json_rejected_before_kbs(self):
        challenge = self.gateway.challenge(self.raw)
        for additional in (
            "",
            "{}",
            '{"nvidia":{},"tdx":{}}',
            '{"nvidia":{},"nvidia":{}}',
        ):
            evidence = b64(
                compact({"primary_evidence": {}, "additional_evidence": additional})
            )
            with self.assertRaises(Denied):
                self.gateway.attest(challenge["nonce"], jwk(self.guest_key), evidence)
        self.assertEqual(self.kbs.calls, [])

    def test_expired_challenge_and_restart_never_reuse_a_token(self):
        args = self.prepare()
        self.elapsed += 61
        with self.assertRaises(Denied):
            self.gateway.execute(*args)
        fresh = RcarGateway(self.verifier, self.issuer, rcar=self.kbs)
        with self.assertRaises(Denied):
            fresh.execute(*args)
