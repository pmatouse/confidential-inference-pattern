"""Actual Rust RCAR/TLS/JWE interoperability; synthetic attestation, test keys only."""

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import struct
import sys
import threading
import time
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "confidential-storage-client")
)
import test_transport as transport_tests  # noqa: E402
from attestation import ANNOTATED, b64, unb64  # noqa: E402
from publication import from_publisher, profile_sha256  # noqa: E402
from test_publication import BINDING as MODEL_BINDING, EVIDENCE  # noqa: E402
from receipts import compact  # noqa: E402
from transport import tls_context  # noqa: E402


class KeyTests(unittest.TestCase):
    def setUp(self):
        if not os.environ.get("STORAGE_CLIENT_FIXTURE"):
            self.skipTest("explicit compiled key_fixture required")
        self.f = transport_tests.RustClientTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.prepare_initialization()
        self.config = self.f.config
        self.set_initdata("sha384")
        self.key = bytes(range(32))
        self.sessions = {}
        self.public_keys = []
        self.paths = []
        self.failure = None
        self.resource_path = "/kbs/v0/resource/storage-test/keys/scratch-v1"
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def reply(self, status, data, cookie=None, location=None):
                raw = compact(data)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                if cookie:
                    self.send_header(
                        "Set-Cookie",
                        "kbs-session=" + cookie + "; Secure; HttpOnly; Path=/",
                    )
                if location:
                    self.send_header("Location", location)
                self.end_headers()
                self.wfile.write(raw)

            def state(self):
                cookie = self.headers.get("Cookie", "").removeprefix("kbs-session=")
                return owner.sessions.get(cookie)

            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path == "/kbs/v0/auth":
                    owner.assertEqual(data["version"], "0.4.0")
                    owner.assertEqual(data["tee"], "snp")
                    cookie = secrets.token_hex(16)
                    nonce = secrets.token_hex(32)
                    owner.sessions[cookie] = {"nonce": nonce}
                    self.reply(
                        200,
                        {
                            "nonce": nonce,
                            "extra-params": {"selected-hash-algorithm": "sha384"},
                        },
                        cookie,
                    )
                elif self.path == "/kbs/v0/attest":
                    state = self.state()
                    owner.assertIsNotNone(state)
                    runtime = data["runtime-data"]
                    owner.assertEqual(runtime["nonce"], state["nonce"])
                    owner.assertEqual(data["init-data"]["body"], owner.raw_initdata)
                    owner.assertEqual(data["tee-evidence"]["additional_evidence"], "")
                    expected = hashlib.sha384(
                        compact(
                            {
                                "tee-pubkey": runtime["tee-pubkey"],
                                "nonce": runtime["nonce"],
                                "additional-evidence": "",
                            }
                        )
                    ).hexdigest()
                    owner.assertEqual(
                        data["tee-evidence"]["primary_evidence"],
                        {"SYNTHETIC_KBS_RUNTIME_DIGEST": expected},
                    )
                    if owner.failure == "attestation":
                        self.reply(
                            401, {"type": "denied", "detail": "synthetic rejection"}
                        )
                        return
                    state["key"] = runtime["tee-pubkey"]
                    owner.public_keys.append(state["key"])
                    token = (
                        "e30."
                        + b64(compact({"exp": int(time.time()) + 60}))
                        + ".c3ludGhldGlj"
                    )
                    self.reply(200, {"token": token})
                else:
                    self.reply(404, {"type": "not-found", "detail": "fixture"})

            def do_GET(self):
                owner.paths.append(self.path)
                owner.assertEqual(self.path, owner.resource_path)
                if owner.failure == "redirect":
                    self.reply(302, {}, location="https://localhost:1/forbidden")
                    return
                if owner.failure == "oversize":
                    self.reply(200, {"padding": "x" * (300 * 1024)})
                    return
                state = self.state()
                if not state or "key" not in state:
                    self.reply(401, {"type": "unauthorized", "detail": "attest first"})
                    return
                key = state["key"]
                owner.assertEqual(key["alg"], "ECDH-ES+A256KW")
                public = ec.EllipticCurvePublicNumbers(
                    int.from_bytes(unb64(key["x"])),
                    int.from_bytes(unb64(key["y"])),
                    ec.SECP256R1(),
                ).public_key()
                ephemeral = ec.generate_private_key(ec.SECP256R1())
                numbers = ephemeral.public_key().public_numbers()
                alg = b"ECDH-ES+A256KW"
                other = (
                    struct.pack(">I", len(alg)) + alg + struct.pack(">III", 0, 0, 256)
                )
                kek = ConcatKDFHash(
                    algorithm=hashes.SHA256(), length=32, otherinfo=other
                ).derive(ephemeral.exchange(ec.ECDH(), public))
                cek, iv = secrets.token_bytes(32), secrets.token_bytes(12)
                # kbs-types serializes alg/enc first, then the sorted flattened fields.
                protected = {
                    "alg": alg.decode(),
                    "enc": "A256GCM",
                    "epk": {
                        "crv": "P-256",
                        "kty": "EC",
                        "x": b64(numbers.x.to_bytes(32)),
                        "y": b64(numbers.y.to_bytes(32)),
                    },
                }
                if owner.failure == "short-point":
                    protected["epk"]["x"] = b64(b"x")
                aad = b64(json.dumps(protected, separators=(",", ":")).encode())
                payload = owner.key if owner.failure != "wrong-length" else b"short"
                encrypted = AESGCM(cek).encrypt(iv, payload, aad.encode())
                tag = encrypted[-16:] if owner.failure != "tamper" else bytes(16)
                self.reply(
                    200,
                    {
                        "protected": aad,
                        "encrypted_key": b64(
                            b"x"
                            if owner.failure == "short-wrap"
                            else aes_key_wrap(kek, cek)
                        ),
                        "iv": b64(iv),
                        "ciphertext": b64(encrypted[:-16]),
                        "tag": b64(tag),
                    },
                )

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.server.socket = tls_context(
            self.f.path / "cert.pem", self.f.path / "key.pem"
        ).wrap_socket(self.server.socket, server_side=True)
        thread = threading.Thread(target=self.server.serve_forever)
        thread.start()
        self.addCleanup(
            lambda: (self.server.shutdown(), self.server.server_close(), thread.join())
        )
        self.config["kbs"] = {
            "origin": f"https://localhost:{self.server.server_port}",
            "address": f"127.0.0.1:{self.server.server_port}",
            "certificate_der": str(self.f.path / "cert.der"),
            "init_data_toml": self.raw_initdata,
            "allowed_resources": ["kbs:///storage-test/keys/scratch-v1"],
            "require_gpu": False,
        }
        self.config["expected_key_sha256"] = hashlib.sha256(self.key).hexdigest()

    def test_real_rcar_and_encrypted_key_response_twice(self):
        self.f.run_client()
        self.assertEqual(len(self.public_keys), 2)
        self.assertNotEqual(self.public_keys[0], self.public_keys[1])

    def set_initdata(self, algorithm):
        self.raw_initdata = (
            f'algorithm = "{algorithm}"\nversion = "0.1.0"\n'
            '\n[data]\n"fixture" = "synthetic, not approved for a guest"\n'
        )
        digest = hashlib.new(algorithm, self.raw_initdata.encode()).hexdigest()
        self.config["init_data"] = digest
        self.f.f.verifier.init_data = digest
        self.f.change_claims = lambda c: c["submods"]["cpu0"][ANNOTATED].update(
            init_data=digest
        )
        if "kbs" in self.config:
            self.config["kbs"]["init_data_toml"] = self.raw_initdata

    def test_sha256_initdata_with_sha384_rcar_negotiation(self):
        self.set_initdata("sha256")
        self.f.run_client()
        self.assertEqual(len(self.public_keys), 2)

    def test_sha512_initdata_with_sha384_rcar_negotiation(self):
        self.set_initdata("sha512")
        self.f.run_client()
        self.assertEqual(len(self.public_keys), 2)

    def test_wrong_pinned_initdata_algorithm_denied_before_kbs_access(self):
        # The raw bytes still declare sha384; a sha256 pin for other bytes
        # must not be accepted merely because that length is now supported.
        digest = hashlib.sha256(b"different approved configuration").hexdigest()
        self.config["init_data"] = digest
        self.f.f.verifier.init_data = digest
        self.f.change_claims = lambda c: c["submods"]["cpu0"][ANNOTATED].update(
            init_data=digest
        )
        self.config["deny_configuration"] = True
        self.f.run_client()
        self.assertEqual(self.public_keys, [])

    def test_readonly_published_model_key_permit(self):
        authority = self.f.f.authority
        uri = "kbs:///storage-test/model-keys/qwen-v1"
        record = authority.register(
            "qwen-v1", "a" * 64, profile_sha256(), uri, mount_binding=MODEL_BINDING
        )
        descriptor = json.loads((EVIDENCE / "guest-manifest.unsigned.json").read_text())
        source = json.loads((EVIDENCE / "source.json").read_text())
        authority.approve_published_model(
            "qwen-v1", from_publisher(record, descriptor, source)
        )
        self.config["mode"] = "readonly"
        self.config["expected"].update(
            volume_id="qwen-v1", profile_sha256=profile_sha256(), **MODEL_BINDING
        )
        self.config["kbs"]["allowed_resources"] = [uri]
        self.resource_path = "/kbs/v0/resource/storage-test/model-keys/qwen-v1"
        self.f.run_client()
        self.assertEqual(len(self.public_keys), 2)

    def test_resource_not_allowlisted_makes_no_kbs_request(self):
        self.config["kbs"]["allowed_resources"] = ["kbs:///storage-test/keys/other"]
        self.f.run_client(deny=True)
        self.assertEqual(self.paths, [])

    def test_gpu_required_cannot_fall_back_to_cpu(self):
        self.config["kbs"]["require_gpu"] = True
        self.config["deny_configuration"] = True
        self.f.run_client()
        self.assertEqual(self.paths, [])

    def test_changed_initdata_rejected_before_kbs_access(self):
        self.config["kbs"]["init_data_toml"] += "# changed\n"
        self.config["deny_configuration"] = True
        self.f.run_client()
        self.assertEqual(self.paths, [])

    def test_wrong_kbs_hostname(self):
        self.config["kbs"]["origin"] = self.config["kbs"]["origin"].replace(
            "localhost", "wrong.invalid"
        )
        self.f.run_client(deny=True)
        self.assertEqual(self.paths, [])

    def test_tampered_encrypted_key_denied(self):
        self.failure = "tamper"
        self.f.run_client(deny=True)

    def test_wrong_key_length_denied(self):
        self.failure = "wrong-length"
        self.f.run_client(deny=True)

    def test_short_wrapped_key_rejected_without_panic(self):
        self.failure = "short-wrap"
        self.f.run_client(deny=True)
        self.assertEqual(len(self.public_keys), 1)

    def test_short_curve_coordinate_rejected_without_panic(self):
        self.failure = "short-point"
        self.f.run_client(deny=True)
        self.assertEqual(len(self.public_keys), 1)

    def test_attestation_denied(self):
        self.failure = "attestation"
        self.f.run_client(deny=True)

    def test_redirect_not_followed(self):
        self.failure = "redirect"
        self.f.run_client(deny=True)
        self.assertEqual(len(self.paths), 1)

    def test_response_size_bounded(self):
        self.failure = "oversize"
        self.f.run_client(deny=True)


if __name__ == "__main__":
    unittest.main()
