#!/usr/bin/env python3
"""Generate public Rust test vectors; ephemeral signing keys never leave memory."""
import argparse
import base64
import json
import hashlib
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from receipts import compact, encoded
from test_receipts import BINDING, decode, initialized


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as directory:
        manifest = compact({"fixture": "synthetic manifest; not a LUKS volume"})
        copied_header = b"synthetic authenticated header; not a LUKS volume"
        _, peer, key, issuer = initialized(
            Path(directory) / "authority.db",
            header_sha256=hashlib.sha256(copied_header).hexdigest(),
            manifest_sha256=hashlib.sha256(manifest).hexdigest(),
        )
        token = issuer.reopen("scratch", peer, "open-1", 1, "f" * 64, BINDING, "c" * 64)
        claims = decode(token)
        header = {
            "alg": "Ed25519",
            "typ": "confidential-storage-grant+jwt",
            "kid": "test-1",
        }

        def sign(h, c):
            h = h if isinstance(h, bytes) else compact(h)
            c = c if isinstance(c, bytes) else compact(c)
            content = encoded(h) + b"." + encoded(c)
            return (content + b"." + encoded(key.sign(content))).decode()

        invalid = []
        for field in [
            "iss",
            "aud",
            "volume_id",
            "policy_sha256",
            "profile_sha256",
            "manifest_sha256",
            "header_sha256",
            "session_sha256",
            "operation_id",
            "operation",
            "nonce",
            "manifest_uri",
            "container_name",
            "destination",
            "access",
            "credential_uri",
        ]:
            invalid.append(
                {
                    "name": "changed-" + field,
                    "token": sign(header, claims | {field: "substituted"}),
                }
            )
        for name, change in [
            ("future", {"iat": 2000000001, "exp": 2000000061}),
            ("expired", {"iat": 1999999940, "exp": 2000000000}),
            ("too-long", {"exp": 2000000061}),
            ("zero-generation", {"generation": 0}),
            ("new-version", {"schema_version": 2}),
            ("extra-field", {"format": True}),
        ]:
            invalid.append({"name": name, "token": sign(header, claims | change)})
        for name, change in [
            ("alg-none", {"alg": "none"}),
            ("alg-polymorphic", {"alg": "EdDSA"}),
            ("wrong-key-id", {"kid": "another"}),
            ("embedded-jwk", {"jwk": {"kty": "OKP"}}),
        ]:
            invalid.append({"name": name, "token": sign(header | change, claims)})
        invalid.append(
            {
                "name": "duplicate-claim",
                "token": sign(
                    header,
                    compact(claims).replace(
                        b'"generation":1', b'"generation":1,"generation":1'
                    ),
                ),
            }
        )
        h, p, sig = token.split(".")
        signature = bytearray(base64.urlsafe_b64decode(sig + "=="))
        signature[0] ^= 1
        invalid.append(
            {
                "name": "bad-signature",
                "token": h + "." + p + "." + encoded(signature).decode(),
            }
        )
        expected = {
            k: claims[k]
            for k in [
                "volume_id",
                "generation",
                "policy_sha256",
                "profile_sha256",
                "session_sha256",
                "operation_id",
                "nonce",
                "manifest_uri",
                "container_name",
                "destination",
                "access",
            ]
        }
        result = {
            "description": (
                "Synthetic peers only; public signature vectors, "
                "not attestation evidence"
            ),
            "public_key": encoded(
                key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            ).decode(),
            "issuer": "storage-authority",
            "key_id": "test-1",
            "now": 2000000000,
            "expected": expected,
            "valid": token,
            "invalid": invalid,
            "manifest": encoded(manifest).decode(),
            "copied_header": encoded(copied_header).decode(),
        }
        args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
