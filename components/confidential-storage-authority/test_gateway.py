"""Real signature/proof tests with synthetic EAR claims; no hardware attestation."""

import copy
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from attestation import (
    ANNOTATED,
    PROFILE,
    PROTOCOL,
    Appraisal,
    EarVerifier,
    b64,
    proof_message,
)
from authority import Authority, Denied
from gateway import Gateway
from receipts import compact
from test_receipts import BINDING, decode, initialized


def jwk(key):
    numbers = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64(numbers.x.to_bytes(32, "big")),
        "y": b64(numbers.y.to_bytes(32, "big")),
    }


def signature(key, message):
    r, s = utils.decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def signed_token(key, claims, header=None, payload=None):
    header = header or {"alg": "ES256", "typ": "JWT", "jwk": jwk(key)}
    data = b64(compact(header)) + "." + b64(payload or compact(claims))
    return data + "." + signature(key, data.encode())


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.authority, _, _, self.issuer = initialized(
            Path(self.tmp.name) / "authority.db"
        )
        self.as_key = ec.generate_private_key(ec.SECP256R1())
        self.guest_key = ec.generate_private_key(ec.SECP256R1())
        self.wall = 2000000000
        self.elapsed = 100.0
        self.verifier = EarVerifier(
            self.as_key.public_key(),
            "storage-test-as",
            "https://storage.test/v1",
            "9" * 96,
            "a" * 64,
            [Appraisal("cpu0", "snp", "storage-v1")],
        )
        self.gateway = self.new_gateway()
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

    def new_gateway(self, **kwargs):
        return Gateway(
            self.verifier,
            self.issuer,
            clock=lambda: self.wall,
            monotonic=lambda: self.elapsed,
            **kwargs,
        )

    def claims(self, challenge, guest=None):
        binding = {
            "protocol": PROTOCOL,
            "audience": challenge["audience"],
            "nonce": challenge["nonce"],
            "request_sha256": challenge["request_sha256"],
            "key": jwk(guest or self.guest_key),
        }
        return {
            "eat_profile": PROFILE,
            "iss": "storage-test-as",
            "iat": self.wall,
            "exp": self.wall + 300,
            "submods": {
                "cpu0": {
                    "ear.status": "affirming",
                    "ear.appraisal-policy-id": "storage-v1",
                    "ear.trustworthiness-vector": {
                        "hardware": 2,
                        "configuration": 2,
                        "executables": 3,
                    },
                    ANNOTATED: {
                        "init_data": "9" * 96,
                        "snp": {"fixture": True},
                        "runtime_data_claims": {"storage-binding": binding},
                    },
                }
            },
        }

    def prepare(self, raw=None, guest=None, gateway=None):
        gateway = gateway or self.gateway
        raw = self.raw if raw is None else raw
        challenge = gateway.challenge(raw)
        claims = self.claims(challenge, guest)
        token = signed_token(self.as_key, claims)
        proof = signature(
            guest or self.guest_key,
            proof_message(
                challenge["audience"],
                challenge["nonce"],
                challenge["request_sha256"],
                token,
            ),
        )
        return (challenge["nonce"], raw, token, proof), claims

    def execute(self, raw=None, **kwargs):
        args, _ = self.prepare(raw, **kwargs)
        return (kwargs.get("gateway") or self.gateway).execute(*args)

    def replace_token(self, args, token):
        # Re-sign the request proof so negative token tests cannot pass merely
        # because an old proof no longer matches the changed token bytes.
        proof = signature(
            self.guest_key,
            proof_message(
                self.verifier.audience,
                args[0],
                self.gateway.pending[args[0]][0],
                token,
            ),
        )
        return (*args[:2], token, proof)

    def close_body(self, activation):
        return compact(
            {
                "action": "close",
                "volume_id": "scratch",
                "activation_id": activation,
            }
        )

    def owner(self):
        return Authority(self.authority.path).inspect("scratch")["owner"]

    def test_reopen_receipt_and_close_bind_verified_session(self):
        receipt = self.execute()["receipt"]
        claims = decode(receipt)
        self.assertEqual(claims["session_sha256"], self.owner()["session_sha256"])
        self.assertNotEqual(claims["session_sha256"], "b" * 64)
        self.assertEqual(claims["policy_sha256"], "a" * 64)
        close = self.close_body(claims["activation_id"])
        self.assertTrue(self.execute(close)["closed"])
        self.assertIsNone(self.owner())
        self.assertTrue(self.execute(close)["closed"])
        with self.assertRaises(Denied):
            self.execute()  # Consumed durable operation may not reacquire.

    def test_exact_retry_gets_same_activation_with_fresh_challenge(self):
        first = decode(self.execute()["receipt"])
        self.wall += 5
        second = decode(self.execute()["receipt"])
        self.assertEqual(first["activation_id"], second["activation_id"])
        self.assertEqual(first["session_sha256"], second["session_sha256"])

    def test_lost_signed_response_preserves_owner_for_retry(self):
        original = self.issuer.reopen

        def lose(**kwargs):
            original(**kwargs)
            raise OSError("synthetic response loss")

        args, _ = self.prepare()
        with patch.object(self.issuer, "reopen", side_effect=lose):
            with self.assertRaises(OSError):
                self.gateway.execute(*args)
        handle = self.owner()["activation_id"]
        with self.assertRaises(Denied):
            self.gateway.execute(*args)
        self.assertEqual(handle, decode(self.execute()["receipt"])["activation_id"])

    def test_wrong_guest_key_cannot_reopen_or_release_existing_owner(self):
        handle = decode(self.execute()["receipt"])["activation_id"]
        other = ec.generate_private_key(ec.SECP256R1())
        for raw in [self.raw, self.close_body(handle)]:
            with self.subTest(raw=raw), self.assertRaises(Denied):
                self.execute(raw, guest=other)
        self.assertEqual(handle, self.owner()["activation_id"])

    def test_token_alone_and_proof_by_another_key_are_denied(self):
        args, _ = self.prepare()
        other = ec.generate_private_key(ec.SECP256R1())
        forged = signature(
            other,
            proof_message(
                self.verifier.audience,
                args[0],
                self.gateway.pending[args[0]][0],
                args[2],
            ),
        )
        for proof in ["", args[3][:-1], forged, "x" * 129, None]:
            with self.subTest(proof_type=type(proof)), self.assertRaises(Denied):
                self.gateway.execute(*args[:3], proof)
        self.assertIsNone(self.owner())

    def test_concurrent_challenge_replay_only_dispatches_once(self):
        args, _ = self.prepare()

        def call(_):
            try:
                return self.gateway.execute(*args)
            except Denied:
                return None

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(call, range(8)))
        self.assertEqual(sum(r is not None for r in results), 1)

    def test_body_substitution_and_cross_action_proof_are_denied(self):
        args, _ = self.prepare()
        for body in [self.raw + b" ", self.close_body("other")]:
            with self.subTest(body=body), self.assertRaises(Denied):
                self.gateway.execute(args[0], body, *args[2:])
        close = self.close_body("other")
        close_challenge = self.gateway.challenge(close)
        with self.assertRaises(Denied):
            self.gateway.execute(close_challenge["nonce"], close, *args[2:])
        self.assertIsNone(self.owner())

    def test_embedded_attacker_jwk_is_not_a_trust_anchor(self):
        args, claims = self.prepare()
        attacker = ec.generate_private_key(ec.SECP256R1())
        token = signed_token(attacker, claims)
        with self.assertRaises(Denied):
            self.gateway.execute(*self.replace_token(args, token))
        self.assertIsNone(self.owner())

    def test_signed_but_unacceptable_claims_do_not_acquire(self):
        mutations = [
            lambda c: c.update(iss="attacker"),
            lambda c: c.update(eat_profile="legacy"),
            lambda c: c.update(iat=self.wall + 1),
            lambda c: c.update(iat=self.wall - 61),
            lambda c: c.update(exp=self.wall),
            lambda c: c.update(exp=self.wall + 301),
            lambda c: c.update(iat=True),
            lambda c: c.update(exp=float(self.wall + 100)),
            lambda c: c.update(nbf=self.wall + 1),
            lambda c: c.update(nbf=False),
            lambda c: c["submods"].update(cpu1=c["submods"]["cpu0"]),
            lambda c: c["submods"]["cpu0"].update({"ear.status": "warning"}),
            lambda c: c["submods"]["cpu0"].update(
                {"ear.appraisal-policy-id": "default"}
            ),
            lambda c: c["submods"]["cpu0"]["ear.trustworthiness-vector"].update(
                hardware=0
            ),
            lambda c: c["submods"]["cpu0"]["ear.trustworthiness-vector"].update(
                configuration=True
            ),
            lambda c: c["submods"]["cpu0"]["ear.trustworthiness-vector"].update(
                **{"runtime-opaque": 97}
            ),
            lambda c: c["submods"]["cpu0"][ANNOTATED].update(init_data="8" * 96),
            lambda c: c["submods"]["cpu0"][ANNOTATED].pop("snp"),
            lambda c: c["submods"]["cpu0"][ANNOTATED].pop("runtime_data_claims"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                args, claims = self.prepare()
                mutate(claims)
                token = signed_token(self.as_key, claims)
                with self.assertRaises(Denied):
                    self.gateway.execute(*self.replace_token(args, token))
                self.assertIsNone(self.owner())

    def test_each_runtime_binding_field_is_checked(self):
        for field in ["protocol", "audience", "nonce", "request_sha256", "key"]:
            with self.subTest(field=field):
                args, claims = self.prepare()
                binding = claims["submods"]["cpu0"][ANNOTATED]["runtime_data_claims"][
                    "storage-binding"
                ]
                binding[field] = "wrong"
                token = signed_token(self.as_key, claims)
                with self.assertRaises(Denied):
                    self.gateway.execute(*self.replace_token(args, token))
        self.assertIsNone(self.owner())

    def test_proof_cannot_be_moved_to_another_valid_token(self):
        args, claims = self.prepare()
        claims["exp"] -= 1
        token = signed_token(self.as_key, claims)
        with self.assertRaises(Denied):
            self.gateway.execute(*args[:2], token, args[3])

    def test_attested_key_substitution_and_invalid_points_are_denied(self):
        other = ec.generate_private_key(ec.SECP256R1())
        keys = [
            jwk(other),
            jwk(self.guest_key) | {"crv": "P-384"},
            jwk(self.guest_key) | {"d": "private-key-field-forbidden"},
            jwk(self.guest_key) | {"x": b64(bytes(32)), "y": b64(bytes(32))},
            jwk(self.guest_key) | {"x": b64(bytes(31))},
        ]
        for key in keys:
            with self.subTest(fields=list(key)):
                args, claims = self.prepare()
                runtime = claims["submods"]["cpu0"][ANNOTATED]["runtime_data_claims"]
                runtime["storage-binding"]["key"] = key
                token = signed_token(self.as_key, claims)
                with self.assertRaises(Denied):
                    self.gateway.execute(*self.replace_token(args, token))
        self.assertIsNone(self.owner())

    def test_configuration_has_no_sample_or_implicit_trust_default(self):
        config = dict(
            signer=self.as_key.public_key(),
            issuer="storage-test-as",
            audience="https://storage.test/v1",
            init_data="9" * 96,
            policy_sha256="a" * 64,
            appraisals=[Appraisal("cpu0", "snp", "storage-v1")],
        )
        changes = [
            {"signer": None},
            {"issuer": ""},
            {"audience": ""},
            {"init_data": ""},
            {"appraisals": []},
            {"appraisals": [Appraisal("cpu0", "sample", "storage-v1")]},
            {"appraisals": [Appraisal("cpu0", "snp", "")]},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                EarVerifier(**(config | change))

    def test_gpu_requirement_cannot_fall_back_to_cpu(self):
        self.verifier.appraisals += (Appraisal("gpu0", "nvidia", "storage-v1"),)
        args, _ = self.prepare()
        with self.assertRaises(Denied):
            self.gateway.execute(*args)
        self.assertIsNone(self.owner())

    def test_gpu_requires_same_verified_binding(self):
        self.verifier.appraisals += (Appraisal("gpu0", "nvidia", "storage-v1"),)
        args, claims = self.prepare()
        gpu = copy.deepcopy(claims["submods"]["cpu0"])
        gpu[ANNOTATED]["nvidia"] = gpu[ANNOTATED].pop("snp")
        claims["submods"]["gpu0"] = gpu
        token = signed_token(self.as_key, claims)
        # Synthetic complete GPU binding is accepted by the verifier; this is
        # explicitly not evidence that the inspected NVIDIA backend exports it.
        self.verifier.verify(
            token, args[0], self.gateway.pending[args[0]][0], self.wall
        )
        gpu[ANNOTATED]["runtime_data_claims"]["storage-binding"]["nonce"] = "0" * 64
        with self.assertRaises(Denied):
            self.verifier.verify(
                signed_token(self.as_key, claims),
                args[0],
                self.gateway.pending[args[0]][0],
                self.wall,
            )
        gpu[ANNOTATED].pop("runtime_data_claims")
        with self.assertRaises(Denied):
            self.verifier.verify(
                signed_token(self.as_key, claims),
                args[0],
                self.gateway.pending[args[0]][0],
                self.wall,
            )

    def test_expiry_capacity_and_restart_do_not_release_owner(self):
        handle = decode(self.execute()["receipt"])["activation_id"]
        gateway = self.new_gateway(capacity=1)
        args, _ = self.prepare(self.close_body(handle), gateway=gateway)
        with self.assertRaises(Denied):
            gateway.challenge(self.raw)
        self.elapsed += 60
        with self.assertRaises(Denied):
            gateway.execute(*args)
        gateway.challenge(self.raw)  # Expired pending challenge is evicted.
        restarted = self.new_gateway()
        with self.assertRaises(Denied):
            restarted.execute(*args)
        self.assertEqual(handle, self.owner()["activation_id"])
        self.assertTrue(
            self.execute(self.close_body(handle), gateway=restarted)["closed"]
        )

    def test_challenge_expiring_during_verification_cannot_dispatch(self):
        args, _ = self.prepare()
        verify = self.verifier.verify

        def delayed(*args):
            result = verify(*args)
            self.elapsed += 60
            return result

        with patch.object(self.verifier, "verify", side_effect=delayed):
            with self.assertRaises(Denied):
                self.gateway.execute(*args)
        self.assertIsNone(self.owner())

    def test_token_expiring_during_verification_cannot_dispatch(self):
        args, _ = self.prepare()
        verify = self.verifier.verify

        def delayed(*args):
            result = verify(*args)
            self.wall += 61
            return result

        with patch.object(self.verifier, "verify", side_effect=delayed):
            with self.assertRaises(Denied):
                self.gateway.execute(*args)
        self.assertIsNone(self.owner())

    def test_untrusted_peer_admin_and_malformed_requests_are_denied(self):
        original = json.loads(self.raw)
        malformed = [
            compact(original | {"peer": {"policy_sha256": "a" * 64}}),
            compact(original | {"generation": True}),
            compact(original | {"generation": 2**64}),
            compact(original | {"action": "initialize"}),
            compact(original | {"action": "register"}),
            b'{"action":"close","action":"reopen"}',
            b'{"x":NaN}',
            b'{"x":Infinity}',
            b"[]",
            b"\xff",
            b"x" * 8193,
            b"{",
        ]
        for raw in malformed:
            with self.subTest(size=len(raw)), self.assertRaises(Denied):
                self.gateway.challenge(raw)
        self.assertEqual(self.gateway.pending, {})

    def test_jws_parser_and_algorithm_confusion_are_denied(self):
        args, claims = self.prepare()
        tokens = [
            "a.b.c",
            "x" * (256 * 1024 + 1),
            signed_token(self.as_key, claims, {"alg": "none"}),
            signed_token(self.as_key, claims, {"alg": "HS256"}),
            signed_token(self.as_key, claims, {"alg": "ES256", "crit": []}),
            signed_token(self.as_key, claims, {"alg": "ES256", "b64": True}),
            signed_token(self.as_key, claims, payload=b'{"iat":1,"iat":2}'),
            signed_token(self.as_key, claims, payload=b'{"iat":NaN}'),
        ]
        for token in tokens:
            with self.subTest(size=len(token)), self.assertRaises(Denied):
                self.gateway.execute(*self.replace_token(args, token))
        self.assertIsNone(self.owner())

    def test_pending_challenge_does_not_bypass_revocation(self):
        args, _ = self.prepare()
        self.authority.revoke("scratch")
        with self.assertRaises(Denied):
            self.gateway.execute(*args)
        self.assertIsNone(self.owner())


if __name__ == "__main__":
    unittest.main()
