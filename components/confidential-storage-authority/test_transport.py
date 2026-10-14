"""Real TLS + durable gateway tests; EAR evidence is explicitly synthetic."""

from datetime import datetime, timedelta, timezone
import http.client
import json
from pathlib import Path
import socket
import ssl
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from attestation import audit_signed_appraisals, b64, proof_message
from authority import Denied
from receipts import compact
from serve import configured_server, private_pem
import test_gateway as fixtures
from test_receipts import decode
from transport import MAX_ENVELOPE, Server, tls_context


class TransportTests(unittest.TestCase):
    def test_audit_contains_only_fixed_route_and_status(self):
        with patch("builtins.print") as audit:
            status, _ = self.post("/unknown?token=must-not-log", b"secret-body")
            self.assertEqual(status, 404)
            status, _ = self.post("/v1/attest", b'{"token":"must-not-log"}')
            self.assertEqual(status, 403)
        self.assertEqual(
            [call.args[0] for call in audit.call_args_list],
            [
                "STORAGE_AUTHORITY route=other status=404",
                "STORAGE_AUTHORITY denial=other",
                "STORAGE_AUTHORITY route=/v1/attest status=403",
            ],
        )

    def test_denial_audit_never_prints_exception_text(self):
        for error, code in [
            ("secret-evidence-must-not-log", "other"),
            ("unacceptable device appraisal", "device-appraisal"),
        ]:
            with patch.object(
                self.fixture.gateway, "challenge", side_effect=Denied(error)
            ):
                with patch("builtins.print") as audit:
                    status, body = self.post("/v1/challenge", self.fixture.raw)
            self.assertEqual(status, 403)
            self.assertEqual(body, {"error": "request denied"})
            self.assertEqual(
                audit.call_args_list[0].args[0], f"STORAGE_AUTHORITY denial={code}"
            )

    def test_signed_appraisal_audit_is_bounded_and_fixed(self):
        with patch("builtins.print") as audit:
            audit_signed_appraisals(
                {
                    "submods": {
                        "cpu0": {
                            "ear.status": "secret-token",
                            "ear.trustworthiness-vector": {
                                "hardware": "secret-evidence",
                                "configuration": True,
                                "executables": 999999999999999999999,
                            },
                        }
                    }
                }
            )
        self.assertEqual(
            [c.args[0] for c in audit.call_args_list],
            [
                "STORAGE_EAR submod=cpu0 status=other "
                "hardware=other configuration=other executables=other",
                "STORAGE_EAR submod=gpu0 status=other "
                "hardware=other configuration=other executables=other",
            ],
        )

    def setUp(self):
        self.fixture = fixtures.GatewayTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        path = Path(self.fixture.tmp.name)
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
        self.cert = path / "tls.crt"
        self.key = path / "tls.key"
        self.cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.key.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.key.chmod(0o600)
        self.context = ssl.create_default_context(cafile=str(self.cert))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.server = Server(
            ("127.0.0.1", 0),
            self.fixture.gateway,
            tls_context(self.cert, self.key),
            workers=2,
            deadline=1,
        )
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def post(self, path, raw, context=None):
        conn = http.client.HTTPSConnection(
            "localhost",
            self.server.server_port,
            timeout=3,
            context=context or self.context,
        )
        try:
            conn.request("POST", path, raw, {"Content-Type": "application/json"})
            response = conn.getresponse()
            self.assertEqual(response.getheader("Cache-Control"), "no-store")
            self.assertEqual(response.getheader("Connection"), "close")
            return response.status, json.loads(response.read())
        finally:
            conn.close()

    def envelope(self, raw=None):
        fixture = self.fixture
        raw = fixture.raw if raw is None else raw
        status, challenge = self.post("/v1/challenge", raw)
        self.assertEqual(status, 200)
        token = fixtures.signed_token(fixture.as_key, fixture.claims(challenge))
        proof = fixtures.signature(
            fixture.guest_key,
            proof_message(
                challenge["audience"],
                challenge["nonce"],
                challenge["request_sha256"],
                token,
            ),
        )
        return compact(
            {
                "nonce": challenge["nonce"],
                "request": b64(raw),
                "token": token,
                "proof": proof,
            }
        )

    def wire(self, raw):
        sock = socket.create_connection(self.server.server_address, timeout=3)
        with self.context.wrap_socket(sock, server_hostname="localhost") as tls:
            self.assertEqual(tls.version(), "TLSv1.3")
            tls.sendall(raw)
            chunks = []
            while data := tls.recv(4096):
                chunks.append(data)
            return b"".join(chunks)

    def test_signed_reopen_retry_and_close_over_verified_tls(self):
        envelope = self.envelope()
        status, result = self.post("/v1/execute", envelope)
        self.assertEqual(status, 200)
        first = decode(result["receipt"])
        self.assertEqual(self.post("/v1/execute", envelope)[0], 403)
        status, retried = self.post("/v1/execute", self.envelope())
        self.assertEqual(status, 200)
        self.assertEqual(
            decode(retried["receipt"])["activation_id"], first["activation_id"]
        )
        close = self.fixture.close_body(first["activation_id"])
        self.assertEqual(
            self.post("/v1/execute", self.envelope(close))[1]["closed"], True
        )
        self.assertIsNone(self.fixture.owner())

    def test_bad_signature_cannot_acquire_volume(self):
        body = json.loads(self.envelope())
        body["proof"] = b64(bytes(64))
        status, result = self.post("/v1/execute", compact(body))
        self.assertEqual((status, result), (403, {"error": "request denied"}))
        self.assertIsNone(self.fixture.owner())

    def test_tls_attestation_relay_requires_verified_result(self):
        status, challenge = self.post("/v1/challenge", self.fixture.raw)
        self.assertEqual(status, 200)
        token = fixtures.signed_token(
            self.fixture.as_key, self.fixture.claims(challenge)
        )
        observed = []

        def evaluate(runtime, evidence):
            observed.append((runtime, evidence))
            return token

        self.fixture.gateway.attester = SimpleNamespace(evaluate=evaluate)
        raw = compact(
            {
                "nonce": challenge["nonce"],
                "key": fixtures.jwk(self.fixture.guest_key),
                "evidence": b64(b'{"synthetic":true}'),
            }
        )
        self.assertEqual(self.post("/v1/attest", raw), (200, {"token": token}))
        self.assertEqual(
            observed[0][0]["storage-binding"]["request_sha256"],
            challenge["request_sha256"],
        )
        self.assertIsNone(self.fixture.owner())
        self.fixture.gateway.attester = SimpleNamespace(evaluate=lambda *_: "invalid")
        self.assertEqual(self.post("/v1/attest", raw)[0], 403)

    def test_untrusted_certificate_and_old_tls_fail(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.post("/v1/challenge", self.fixture.raw, ssl.create_default_context())
        old = ssl.create_default_context(cafile=str(self.cert))
        old.maximum_version = ssl.TLSVersion.TLSv1_2
        with self.assertRaises(ssl.SSLError):
            self.post("/v1/challenge", self.fixture.raw, old)
        self.assertEqual(self.fixture.gateway.pending, {})

    def test_admin_key_and_unknown_routes_are_absent(self):
        for path in (
            "/policy",
            "/v1/register",
            "/v1/initialize",
            "/key",
            "/v1/challenge?admin=true",
            "/v1/challenge/",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.post(path, b"{}")[0], 404)
        self.assertEqual(self.post("/v1/challenge", b'{"action":"register"}')[0], 403)
        self.assertEqual(self.fixture.gateway.pending, {})

    def test_framing_and_size_rejected_before_gateway(self):
        headers = [
            (b"Content-Length: 2\r\nContent-Length: 2\r\n", 400),
            (b"Content-Length: 2\r\nTransfer-Encoding: chunked\r\n", 400),
            (b"Content-Length: 2\r\nContent-Encoding: gzip\r\n", 400),
            (b"Content-Length: 2\r\nExpect: 100-continue\r\n", 400),
            (b"Content-Length: -1\r\n", 400),
            (b"Content-Length: 0\r\n", 413),
            (f"Content-Length: {MAX_ENVELOPE + 1}\r\n".encode(), 413),
        ]
        for header, status in headers:
            with self.subTest(header=header):
                response = self.wire(
                    b"POST /v1/execute HTTP/1.1\r\nHost: localhost\r\n"
                    b"Content-Type: application/json\r\n" + header + b"\r\n{}"
                )
                self.assertTrue(
                    response.startswith(f"HTTP/1.0 {status}".encode()), response
                )
        self.assertEqual(self.fixture.gateway.pending, {})

    def test_duplicate_json_fields_and_trailing_data_rejected(self):
        for raw in (b'{"nonce":"a","nonce":"b"}', b"{}{}", b"[]"):
            self.assertEqual(self.post("/v1/execute", raw)[0], 403)
        self.assertEqual(self.fixture.gateway.pending, {})

    def test_deadline_includes_incomplete_tls_handshake_and_body(self):
        start = time.monotonic()
        with socket.create_connection(self.server.server_address, timeout=3) as raw:
            self.assertEqual(raw.recv(1), b"")
        self.assertLess(time.monotonic() - start, 2.5)
        start = time.monotonic()
        response = self.wire(
            b"POST /v1/challenge HTTP/1.1\r\nHost: localhost\r\n"
            b"Content-Type: application/json\r\nContent-Length: 8000\r\n\r\n{"
        )
        self.assertEqual(response, b"")
        self.assertLess(time.monotonic() - start, 2.5)
        self.assertEqual(self.fixture.gateway.pending, {})

    def test_worker_bound_includes_handshakes(self):
        self.assertTrue(self.server.slots.acquire(False))
        self.assertTrue(self.server.slots.acquire(False))
        try:
            with socket.create_connection(self.server.server_address, timeout=3) as raw:
                self.assertEqual(raw.recv(1), b"")
        finally:
            self.server.slots.release()
            self.server.slots.release()
        self.assertEqual(self.post("/v1/challenge", self.fixture.raw)[0], 200)

    def test_internal_exceptions_never_disclose_details(self):
        with patch.object(
            self.fixture.gateway, "challenge", side_effect=RuntimeError("secret-value")
        ):
            self.assertEqual(
                self.post("/v1/challenge", self.fixture.raw),
                (500, {"error": "authority unavailable"}),
            )

    def test_connection_expiry_does_not_cancel_or_release_durable_transition(self):
        envelope = self.envelope()
        entered, proceed, finished = (
            threading.Event(),
            threading.Event(),
            threading.Event(),
        )
        original = self.fixture.issuer.reopen

        def delayed(**kwargs):
            entered.set()
            if not proceed.wait(4):
                raise RuntimeError("test did not release delayed operation")
            try:
                return original(**kwargs)
            finally:
                finished.set()

        with patch.object(self.fixture.issuer, "reopen", side_effect=delayed):
            with self.assertRaises(http.client.RemoteDisconnected):
                self.post("/v1/execute", envelope)
            self.assertTrue(entered.is_set())
            proceed.set()
            self.assertTrue(finished.wait(3))
        owner = self.fixture.owner()
        self.assertIsNotNone(owner)
        status, retried = self.post("/v1/execute", self.envelope())
        self.assertEqual(status, 200)
        self.assertEqual(
            decode(retried["receipt"])["activation_id"], owner["activation_id"]
        )

    def test_explicit_pins_and_private_keys_are_required_for_startup(self):
        path = Path(self.fixture.tmp.name)
        as_signer = path / "as.pub"
        as_signer.write_bytes(
            self.fixture.as_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        receipt_key = path / "receipt.key"
        receipt_key.write_bytes(
            self.fixture.issuer.signing_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        receipt_key.chmod(0o600)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        config = {
            "as_loopback_port": 8089,
            "listen": {"host": "127.0.0.1", "port": port},
            "database": str(self.fixture.authority.path),
            "tls_certificate": str(self.cert),
            "tls_key": str(self.key),
            "as_signer": str(as_signer),
            "as_issuer": "storage-test-as",
            "audience": "https://localhost/v1",
            "init_data": "9" * 96,
            "policy_sha256": "a" * 64,
            "appraisals": [{"submod": "cpu0", "tee": "snp", "policy_id": "storage-v1"}],
            "receipt_key": str(receipt_key),
            "receipt_issuer": "storage-authority",
            "receipt_key_id": "test-1",
        }
        config_path = path / "server.json"
        config_path.write_bytes(compact(config))
        with configured_server(config_path) as server:
            self.assertEqual(server.gateway.verifier.audience, config["audience"])
            self.assertEqual(
                server.gateway.issuer.authority.path, self.fixture.authority.path
            )
        # The standard-KBS mode uses existing public protocol endpoints and
        # requires an explicit GPU appraisal; it never falls back to loopback AS.
        import hashlib
        from rcar_gateway import RcarGateway

        init_path = path / "approved-initdata.toml"
        init_path.write_text('version = "0.1.0"\n')
        rcar_config = {k: v for k, v in config.items() if k != "as_loopback_port"}
        rcar_config["init_data"] = hashlib.sha384(init_path.read_bytes()).hexdigest()
        rcar_config["appraisals"] = config["appraisals"] + [
            {"submod": "gpu0", "tee": "nvidia", "policy_id": "storage-v1"}
        ]
        rcar_config["trustee_rcar"] = {
            "origin": "https://localhost",
            "ca_file": str(self.cert),
            "init_data_file": str(init_path),
            "address": None,
            "policy_selector": None,
        }
        config_path.write_bytes(compact(rcar_config))
        with configured_server(config_path) as server:
            self.assertIsInstance(server.gateway, RcarGateway)
        for bad in (
            {**rcar_config, "as_loopback_port": 8089},
            {**rcar_config, "init_data": "8" * 96},
            {**rcar_config, "appraisals": config["appraisals"]},
        ):
            config_path.write_bytes(compact(bad))
            with self.assertRaises(ValueError):
                configured_server(config_path)
        for audience in (
            "http://localhost/v1",
            "https://localhost/v1?policy=other",
            "https://user@localhost/v1",
            "https://localhost/",
        ):
            config_path.write_bytes(compact({**config, "audience": audience}))
            with self.assertRaises(ValueError):
                configured_server(config_path)
        config_path.write_bytes(compact(config))
        receipt_key.chmod(0o644)
        with self.assertRaises(ValueError):
            configured_server(config_path)
        receipt_key.chmod(0o600)
        link = path / "linked.key"
        link.symlink_to(receipt_key)
        with self.assertRaises(OSError):
            private_pem(link)


if __name__ == "__main__":
    unittest.main()
