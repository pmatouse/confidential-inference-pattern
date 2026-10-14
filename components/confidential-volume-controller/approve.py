#!/usr/bin/env python3
"""Trusted, offline publication of a reviewed PUBLIC deployment package.

This signs configuration provenance only. It never approves a disk in the storage
state authority, changes Trustee policy or provisions a key. Complete and review
those operations independently before signing. Keep this key outside the controller.
"""
import argparse
import base64
import json
from pathlib import Path
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from controller import (
    ARTIFACTS,
    MAX_BYTES,
    canonical,
    digest,
    name,
    parse,
    require,
    resource_name,
    validate_artifacts,
)


def sign(request, artifacts, key, key_id, issued, expires):
    name(key_id)
    require(
        request.get("purpose") == "confidential-volume-reconcile-request/v1",
        "invalid request",
    )
    require(
        type(issued) is int
        and type(expires) is int
        and 0 < expires - issued <= 7 * 86400,
        "invalid approval lifetime",
    )
    validate_artifacts(artifacts, request)
    payload = {
        "purpose": "confidential-volume-deployment-approval/v1",
        "requestSha256": digest(request),
        "issuedAt": issued,
        "expiresAt": expires,
        "artifacts": artifacts,
    }
    return {
        "keyId": key_id,
        "payload": payload,
        "signature": base64.b64encode(key.sign(canonical(payload))).decode(),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--request", type=Path, required=True)
    p.add_argument("--artifacts", type=Path, required=True)
    p.add_argument("--key", type=Path, required=True)
    p.add_argument("--key-id", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--lifetime", type=int, default=3600)
    args = p.parse_args()
    request = parse(args.request.read_bytes(), MAX_BYTES)
    if request.get("kind") == "ConfigMap":
        request = parse(request["data"]["request.json"].encode(), MAX_BYTES)
    names = ARTIFACTS | (
        {"sidecar-deployment.json"} if "deployment" in request else set()
    )
    artifacts = {n: (args.artifacts / n).read_text() for n in names}
    require(
        args.key.is_file()
        and not args.key.is_symlink()
        and args.key.stat().st_mode & 0o077 == 0,
        "private approval key permissions required",
    )
    key = serialization.load_pem_private_key(args.key.read_bytes(), password=None)
    require(isinstance(key, Ed25519PrivateKey), "Ed25519 approval key required")
    now = int(time.time())
    envelope = sign(request, artifacts, key, args.key_id, now, now + args.lifetime)
    cm = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": resource_name("approval", digest(request)),
            "namespace": request["contract"]["namespace"],
        },
        "data": {"approval.json": canonical(envelope).decode()},
    }
    require(len(canonical(cm)) <= MAX_BYTES, "approval package too large")
    with args.output.open("x") as stream:
        json.dump(cm, stream, indent=2)
        stream.write("\n")
    print("Public approval ConfigMap prepared; no cluster or authority changes made.")


if __name__ == "__main__":
    main()
