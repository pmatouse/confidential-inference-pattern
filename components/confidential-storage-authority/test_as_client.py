"""Exercise real loopback HTTP; signed SNP appraisal claims remain synthetic."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest

from as_client import AttestationServiceClient
from attestation import ANNOTATED, Appraisal, b64, proof_message
from authority import Denied
from receipts import compact
import test_gateway as fixtures


class AsClientTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.GatewayTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.requests = []
        self.response_status = 200
        self.change_claims = lambda claims: None
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                owner.requests.append((self.path, body))
                runtime = body["verification_requests"][0]["runtime_data"]["structured"]
                binding = runtime["storage-binding"]
                claims = owner.fixture.claims(binding)
                claims["submods"]["cpu0"][ANNOTATED]["runtime_data_claims"] = runtime
                owner.change_claims(claims)
                raw = fixtures.signed_token(owner.fixture.as_key, claims).encode()
                self.send_response(owner.response_status)
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Location", "http://must-not-follow.invalid/")
                self.end_headers()
                self.wfile.write(raw)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.addCleanup(self.stop)
        self.fixture.gateway.attester = AttestationServiceClient(
            self.fixture.verifier,
            self.server.server_port,
        )
        self.challenge = self.fixture.gateway.challenge(self.fixture.raw)
        self.jwk = fixtures.jwk(self.fixture.guest_key)
        # This is intentionally not real hardware evidence.
        self.evidence = b64(compact({"synthetic-evidence": True}))

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def attest(self, **changes):
        args = {
            "nonce": self.challenge["nonce"],
            "key": self.jwk,
            "evidence": self.evidence,
        }
        return self.fixture.gateway.attest(**{**args, **changes})

    def test_verified_relay_then_guest_proof_acquires_storage(self):
        token = self.attest()["token"]
        self.assertIsNone(self.fixture.owner())
        path, body = self.requests[0]
        self.assertEqual(path, "/attestation")
        self.assertEqual(body["policy_ids"], ["storage-v1"])
        request = body["verification_requests"][0]
        self.assertEqual(request["tee"], "snp")
        self.assertEqual(request["runtime_data_hash_algorithm"], "sha256")
        self.assertEqual(
            request["init_data"], {"init_data_digest": b64(bytes.fromhex("9" * 96))}
        )
        self.assertEqual(request["evidence"], self.evidence)
        proof = fixtures.signature(
            self.fixture.guest_key,
            proof_message(
                self.challenge["audience"],
                self.challenge["nonce"],
                self.challenge["request_sha256"],
                token,
            ),
        )
        result = self.fixture.gateway.execute(
            self.challenge["nonce"], self.fixture.raw, token, proof
        )
        self.assertIn("receipt", result)
        with self.assertRaises(Denied):
            self.attest()
        self.assertEqual(len(self.requests), 1)

    def test_requests_cannot_select_another_key_or_policy_in_returned_token(self):
        def wrong_key(claims):
            claims["submods"]["cpu0"][ANNOTATED]["runtime_data_claims"][
                "storage-binding"
            ]["key"] = fixtures.jwk(self.fixture.as_key)

        self.change_claims = wrong_key
        with self.assertRaisesRegex(Denied, "key binding"):
            self.attest()

        def wrong_policy(claims):
            claims["submods"]["cpu0"]["ear.appraisal-policy-id"] = "other"

        self.change_claims = wrong_policy
        with self.assertRaisesRegex(Denied, "appraisal"):
            self.attest()
        self.assertIsNone(self.fixture.owner())

    def test_redirect_and_upstream_errors_are_denied(self):
        for status in (302, 404, 500):
            self.response_status = status
            with self.assertRaisesRegex(Denied, "denied evidence"):
                self.attest()
        self.assertEqual(len(self.requests), 3)
        self.assertIsNone(self.fixture.owner())

    def test_expired_or_malformed_requests_do_not_contact_as(self):
        for changes in (
            {"nonce": "a" * 64},
            {"key": {}},
            {"evidence": "not+url+safe"},
            {"evidence": b64(b"[]")},
            {"evidence": "A" * (192 * 1024 + 1)},
        ):
            with self.assertRaises(Denied):
                self.attest(**changes)
        self.fixture.elapsed += 61
        with self.assertRaises(Denied):
            self.attest()
        self.assertEqual(self.requests, [])

    def test_challenge_expiry_during_as_evaluation_denies_response(self):
        def expire(_):
            self.fixture.elapsed += 61

        self.change_claims = expire
        with self.assertRaisesRegex(Denied, "during attestation"):
            self.attest()
        self.assertIsNone(self.fixture.owner())

    def test_gpu_required_configuration_cannot_be_downgraded(self):
        self.fixture.verifier.appraisals += (Appraisal("gpu0", "nvidia", "gpu-v1"),)
        with self.assertRaises(ValueError):
            AttestationServiceClient(self.fixture.verifier, self.server.server_port)


if __name__ == "__main__":
    unittest.main()
