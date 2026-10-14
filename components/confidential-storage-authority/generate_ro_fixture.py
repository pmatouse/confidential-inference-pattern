"""Public cross-language fixture: real publisher metadata, synthetic authority."""

import json
from pathlib import Path
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from authority import AttestedPeer, Authority
from publication import from_publisher, profile_sha256
from receipts import ReceiptIssuer, compact


def main():
    root = Path(__file__).resolve().parents[2]
    evidence = root / "tests/confidential-storage/evidence/2026-10-13/model-populator"
    binding = {
        "manifest_uri": "kbs:///storage-test/model-records/qwen-v1",
        "container_name": "model",
        "destination": "/models",
        "access": "ro",
    }
    key = Ed25519PrivateKey.generate()
    peer = AttestedPeer("a" * 64, "b" * 64)
    with tempfile.TemporaryDirectory() as temp:
        authority = Authority(Path(temp) / "authority.db")
        record = authority.register(
            "qwen-v1",
            peer.policy_sha256,
            profile_sha256(),
            "kbs:///storage-test/model-keys/qwen-v1",
            mount_binding=binding,
        )
        manifest = from_publisher(
            record,
            json.loads((evidence / "guest-manifest.unsigned.json").read_text()),
            json.loads((evidence / "source.json").read_text()),
        )
        authority.approve_published_model("qwen-v1", manifest)
        issuer = ReceiptIssuer(
            authority, key, "storage-test", "fixture-v1", clock=lambda: 2000000000
        )
        expected = dict(
            volume_id="qwen-v1",
            generation=1,
            policy_sha256=peer.policy_sha256,
            profile_sha256=profile_sha256(),
            session_sha256=peer.session_sha256,
            operation_id="open-1",
            nonce="c" * 64,
            **binding
        )
        token = issuer.reopen(
            volume_id="qwen-v1",
            peer=peer,
            operation_id="open-1",
            generation=1,
            nonce="c" * 64,
            binding=binding,
            profile_sha256=profile_sha256(),
        )
        output = {
            "purpose": "synthetic-signature-real-publisher-metadata-no-attestation",
            "issuer": "storage-test",
            "key_id": "fixture-v1",
            "now": 2000000000,
            "public_key_hex": key.public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            .hex(),
            "token": token,
            "expected": expected,
            "manifest": manifest.decode(),
        }
    target = (
        root / "components/confidential-storage-guest/tests/ro-receipt-fixture.json"
    )
    target.write_bytes(compact(output) + b"\n")


if __name__ == "__main__":
    main()
