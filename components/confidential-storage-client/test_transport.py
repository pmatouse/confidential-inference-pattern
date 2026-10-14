"""Rust guest -> Python TLS gateway, real signatures, explicitly synthetic EAR.

Set STORAGE_CLIENT_FIXTURE to the locally built Linux example. No model/volume
keys or disks are used. The loopback server and signing keys are temporary.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "confidential-storage-authority")
)
from attestation import ANNOTATED, unb64, b64  # noqa: E402
from authority import Authority, Denied  # noqa: E402
import initialization_api  # noqa: E402
from test_receipts import PLAN  # noqa: E402
from receipts import compact  # noqa: E402
import test_gateway as fixtures  # noqa: E402
from transport import Server, tls_context  # noqa: E402


class RustClientTests(unittest.TestCase):
    def setUp(self):
        self.binary = os.environ.get("STORAGE_CLIENT_FIXTURE")
        if not self.binary:
            self.skipTest("explicit compiled Rust fixture required")
        self.f = fixtures.GatewayTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.path = Path(self.f.tmp.name)
        self.f.wall = int(time.time())
        self.f.issuer.clock = time.time
        self.f.gateway.clock = time.time
        self.f.gateway.monotonic = time.monotonic
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(minutes=10))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]), False
            )
            .sign(key, hashes.SHA256())
        )
        (self.path / "cert.pem").write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        (self.path / "cert.der").write_bytes(
            cert.public_bytes(serialization.Encoding.DER)
        )
        (self.path / "key.pem").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        (self.path / "key.pem").chmod(0o600)
        self.server = Server(
            ("127.0.0.1", 0),
            self.f.gateway,
            tls_context(self.path / "cert.pem", self.path / "key.pem"),
        )
        audience = f"https://localhost:{self.server.server_port}/v1"
        self.f.verifier.audience = audience
        owner = self

        class SyntheticAttester:
            def evaluate(self, runtime, evidence):
                if json.loads(unb64(evidence)) != {
                    "SYNTHETIC_TEST_RUNTIME_DIGEST": hashlib.sha256(
                        compact(runtime)
                    ).hexdigest()
                }:
                    raise Denied("fixture runtime hash mismatch")
                owner.f.wall = int(time.time())
                claims = owner.f.claims(runtime["storage-binding"])
                claims["submods"]["cpu0"][ANNOTATED]["runtime_data_claims"] = runtime
                owner.change_claims(claims)
                return fixtures.signed_token(owner.f.as_key, claims)

        self.change_claims = lambda _: None
        self.f.gateway.attester = SyntheticAttester()
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.addCleanup(self.stop)
        self.config = {
            "audience": audience,
            "address": f"127.0.0.1:{self.server.server_port}",
            "certificate_der": str(self.path / "cert.der"),
            "policy_sha256": "a" * 64,
            "init_data": "9" * 96,
            "receipt_public_key": list(
                self.f.issuer.signing_key.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
            ),
            "receipt_issuer": self.f.issuer.issuer,
            "receipt_key_id": self.f.issuer.key_id,
            "expected": {
                "volume_id": "scratch",
                "generation": 1,
                "policy_sha256": "a" * 64,
                "profile_sha256": "c" * 64,
                "session_sha256": "0" * 64,
                "operation_id": "rust-open-1",
                "nonce": "f" * 64,
                **fixtures.BINDING,
            },
            "deny": False,
        }

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def run_client(self, deny=False):
        self.config["deny"] = deny
        path = self.path / "client.json"
        path.write_text(json.dumps(self.config))
        result = subprocess.run(
            [self.binary, str(path)],
            capture_output=True,
            text=True,
            timeout=45,
            env=os.environ
            | {
                "HTTPS_PROXY": "http://127.0.0.1:1",
                "ALL_PROXY": "http://127.0.0.1:1",
                "NO_PROXY": "",
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_slightly_future_receipt_waits_until_actually_valid(self):
        self.f.issuer.clock = lambda: time.time() + 1
        self.run_client()

    def test_far_future_receipt_remains_denied(self):
        self.f.issuer.clock = lambda: time.time() + 30
        self.run_client(deny=True)

    def test_expired_receipt_remains_denied(self):
        self.f.issuer.clock = lambda: time.time() - 61
        self.run_client(deny=True)

    def test_real_tls_ecdsa_proof_receipt_retry_close(self):
        self.run_client()
        self.assertIsNone(self.f.owner())

    def prepare_initialization(self):
        self.f.authority = Authority(self.path / "first-use.db")
        self.f.issuer.authority = self.f.authority
        profile = hashlib.sha256(initialization_api.PROFILE.read_bytes()).hexdigest()
        self.f.authority.register(
            "scratch",
            "a" * 64,
            profile,
            "kbs:///storage-test/keys/scratch-v1",
            mount_binding=fixtures.BINDING,
        )
        approval = self.f.authority.approve_initialization("scratch", PLAN)
        self.config.update(mode="initialize", plan_sha256=approval["plan_sha256"])
        self.config["expected"]["profile_sha256"] = profile

    def test_signed_initialization_ready_close_and_reopen(self):
        self.prepare_initialization()
        self.run_client()
        record = self.f.authority.inspect("scratch")
        self.assertEqual(record["state"], "Ready")
        self.assertIsNone(record["owner"])
        self.assertEqual(len(record["initialization_steps"]), 4)

    def test_lost_execute_response_never_reissues_format(self):
        self.prepare_initialization()
        self.config["stop_started"] = True
        self.run_client()
        record = self.f.authority.inspect("scratch")
        self.assertEqual(record["state"], "Initializing")
        self.assertEqual(record["initialization_steps"][0]["status"], "Started")

    def test_initialization_wrong_plan_cannot_acquire(self):
        self.prepare_initialization()
        self.config["plan_sha256"] = "1" * 64
        self.run_client(deny=True)
        self.assertIsNone(self.f.owner())

    def test_initialization_wrong_signer_rejected(self):
        self.prepare_initialization()
        self.config["receipt_public_key"] = [1] * 32
        self.run_client(deny=True)
        self.assertIsNone(self.f.owner())

    def test_signed_initialization_decision_requires_exact_fresh_binding(self):
        self.prepare_initialization()
        original = self.f.gateway.execute

        def changed(field):
            def execute(*args):
                wire = original(*args)
                h, p, _ = wire["decision"].split(".")
                claims = json.loads(unb64(p))
                if field == "expired":
                    claims.update(iat=int(time.time()) - 120, exp=int(time.time()) - 60)
                elif field == "plan":
                    claims["result"]["record"]["initialization_approval"]["plan"][
                        "device_bytes"
                    ] *= 2
                elif field == "unknown":
                    claims["result"]["record"]["unexpected"] = True
                else:
                    claims[field] = "0" * 64
                data = h.encode() + b"." + b64(compact(claims)).encode()
                return {
                    "decision": data.decode()
                    + "."
                    + b64(self.f.issuer.signing_key.sign(data))
                }

            return execute

        for field in (
            "expired",
            "plan",
            "unknown",
            "challenge",
            "request_sha256",
            "session_sha256",
            "policy_sha256",
        ):
            with self.subTest(field=field), patch.object(
                self.f.gateway, "execute", side_effect=changed(field)
            ):
                self.run_client(deny=True)
            self.assertIsNone(self.f.owner())

    def test_changed_challenge_does_not_collect_or_execute(self):
        original = self.f.gateway.challenge
        with patch.object(
            self.f.gateway,
            "challenge",
            side_effect=lambda raw: original(raw) | {"request_sha256": "0" * 64},
        ):
            self.run_client(deny=True)
        self.assertIsNone(self.f.owner())

    def test_wrong_hostname_is_rejected(self):
        self.config["audience"] = self.config["audience"].replace(
            "localhost", "wrong.invalid"
        )
        self.run_client(deny=True)
        self.assertEqual(self.f.gateway.pending, {})

    def test_unknown_ca_is_rejected(self):
        # A different valid certificate is a different root; no system-root fallback.
        key = ec.generate_private_key(ec.SECP256R1())
        cert = x509.load_pem_x509_certificate((self.path / "cert.pem").read_bytes())
        unrelated = (
            x509.CertificateBuilder()
            .subject_name(cert.subject)
            .issuer_name(cert.issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(cert.not_valid_before_utc)
            .not_valid_after(cert.not_valid_after_utc)
            .sign(key, hashes.SHA256())
        )
        (self.path / "cert.der").write_bytes(
            unrelated.public_bytes(serialization.Encoding.DER)
        )
        self.run_client(deny=True)
        self.assertEqual(self.f.gateway.pending, {})

    def test_wrong_receipt_signer_is_rejected_after_durable_acquisition(self):
        self.config["receipt_public_key"] = [1] * 32
        self.run_client(deny=True)
        self.assertIsNotNone(self.f.owner())

    def test_new_guest_key_cannot_take_over_after_rejected_response(self):
        original = self.config["receipt_public_key"]
        self.config["receipt_public_key"] = [1] * 32
        self.run_client(deny=True)
        owner = self.f.owner()
        self.config["receipt_public_key"] = original
        self.run_client(deny=True)  # New process creates a different guest key.
        self.assertEqual(self.f.owner(), owner)

    def test_unknown_challenge_fields_are_rejected(self):
        original = self.f.gateway.challenge
        with patch.object(
            self.f.gateway,
            "challenge",
            side_effect=lambda raw: original(raw) | {"unexpected": True},
        ):
            self.run_client(deny=True)
        self.assertIsNone(self.f.owner())

    def test_oversized_response_is_rejected_before_body_read(self):
        def oversized(handler, _status, _body):
            handler.send_response(200)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", "1048576")
            handler.end_headers()

        with patch.object(self.server.RequestHandlerClass, "reply", oversized):
            self.run_client(deny=True)
        self.assertIsNone(self.f.owner())

    def test_changed_initdata_session_binding_rejects_receipt(self):
        self.config["init_data"] = "8" * 96
        self.run_client(deny=True)
        self.assertIsNotNone(self.f.owner())

    def test_unapproved_hardware_claim_is_rejected(self):
        def weaken(claims):
            claims["submods"]["cpu0"]["ear.trustworthiness-vector"]["hardware"] = 0

        self.change_claims = weaken
        self.run_client(deny=True)
        self.assertIsNone(self.f.owner())

    def test_response_redirect_is_not_followed(self):
        original = self.server.RequestHandlerClass.reply

        def redirect(handler, status, body):
            if handler.path == "/v1/challenge":
                handler.send_response(302)
                handler.send_header("Location", "/v1/challenge")
                handler.send_header("Content-Length", "0")
                handler.end_headers()
            else:
                original(handler, status, body)

        with patch.object(self.server.RequestHandlerClass, "reply", redirect):
            self.run_client(deny=True)
        self.assertEqual(len(self.f.gateway.pending), 1)


if __name__ == "__main__":
    unittest.main()
