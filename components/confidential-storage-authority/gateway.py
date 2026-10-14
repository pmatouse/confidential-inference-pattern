"""Internal attested-request gateway. No HTTP listener, disk or key delivery.

transport.py supplies bounded TLS; the measured private guest API is still needed.
No request can supply AttestedPeer or administrative operations.
"""

import secrets
import threading
import time

from attestation import (
    PROTOCOL,
    proof_message,
    public_key,
    read_object,
    sha256,
    unb64,
    verify_signature,
)
from authority import Denied, digest, identifier
from receipts import validate_binding
import initialization_api

MAX_REQUEST = 8192


def request_body(raw):
    body = read_object(raw, MAX_REQUEST)
    action = body.get("action")
    if isinstance(action, str) and action in initialization_api.ACTIONS:
        initialization_api.validate_request(body)
    elif action == "reopen":
        if set(body) != {
            "action",
            "volume_id",
            "operation_id",
            "generation",
            "nonce",
            "binding",
            "profile_sha256",
        }:
            raise Denied("invalid reopen fields")
        identifier(body["operation_id"])
        if type(body["generation"]) is not int or not 0 < body["generation"] < 2**63:
            raise Denied("invalid generation")
        digest(body["nonce"])
        digest(body["profile_sha256"])
        validate_binding(body["binding"])
    elif action == "close":
        if set(body) != {"action", "volume_id", "activation_id"}:
            raise Denied("invalid close fields")
        identifier(body["activation_id"])
    else:
        raise Denied("unsupported guest action")
    identifier(body["volume_id"])
    return body


class Gateway:
    """One-use fresh evidence + guest-key proof before each durable transition.

    The challenge is consumed before dispatch. On an ambiguous response a guest
    obtains a fresh challenge and retries the same operation/receipt nonce with
    the same key. Durable ownership/idempotence lives in Authority, not here.
    Restart loses challenges, never releases a volume or issues a format grant.
    """

    def __init__(
        self,
        verifier,
        issuer,
        *,
        clock=time.time,
        monotonic=time.monotonic,
        capacity=128,
        attester=None,
    ):
        if type(capacity) is not int or not 0 < capacity <= 4096:
            raise ValueError("invalid challenge capacity")
        self.verifier = verifier
        self.issuer = issuer
        self.clock = clock
        self.monotonic = monotonic
        self.capacity = capacity
        self.attester = attester
        self.pending = {}
        self.lock = threading.Lock()

    def challenge(self, raw):
        request_body(raw)
        with self.lock:
            now = self.monotonic()
            self.pending = {
                n: entry for n, entry in self.pending.items() if now < entry[1]
            }
            if len(self.pending) >= self.capacity:
                raise Denied("challenge capacity exhausted")
            nonce = secrets.token_hex(32)
            if nonce in self.pending:
                raise Denied("challenge collision")
            request_hash = sha256(raw)
            self.pending[nonce] = (request_hash, now + 60)
        return {
            "audience": self.verifier.audience,
            "nonce": nonce,
            "request_sha256": request_hash,
            "expires_in": 60,
        }

    def attest(self, nonce, key, evidence):
        """Relay evidence using only authority-selected AS inputs and trust pins.

        This issues no storage grant and consumes no challenge. Execute still
        requires the guest's request proof, then atomically consumes the nonce.
        """
        if self.attester is None:
            raise Denied("attestation relay unavailable")
        digest(nonce)
        expected_key = public_key(key)
        if not isinstance(evidence, str) or not 0 < len(evidence) <= 192 * 1024:
            raise Denied("invalid evidence size")
        read_object(unb64(evidence), 144 * 1024)
        with self.lock:
            expected = self.pending.get(nonce)
        if expected is None or self.monotonic() >= expected[1]:
            raise Denied("unknown or expired challenge")
        runtime = {
            "storage-binding": {
                "protocol": PROTOCOL,
                "audience": self.verifier.audience,
                "nonce": nonce,
                "request_sha256": expected[0],
                "key": key,
            }
        }
        token = self.attester.evaluate(runtime, evidence)
        # Never relay an unsigned, wrong-policy, stale or mismatched AS result.
        _, verified_key, _ = self.verify_result(
            token, nonce, expected[0], int(self.clock())
        )
        if verified_key.public_numbers() != expected_key.public_numbers():
            raise Denied("attestation key binding mismatch")
        with self.lock:
            if self.pending.get(nonce) != expected or self.monotonic() >= expected[1]:
                raise Denied("challenge consumed or expired during attestation")
        return {"token": token}

    def verify_result(self, token, nonce, request_sha256, now):
        return self.verifier.verify(token, nonce, request_sha256, now)

    def execute(self, nonce, raw, token, proof):
        body = request_body(raw)
        digest(nonce)
        # Keep only the final comparison/consume atomic. Cryptographic work and
        # durable transactions must not hold the challenge registry lock.
        with self.lock:
            expected = self.pending.get(nonce)
        if expected is None or sha256(raw) != expected[0]:
            raise Denied("unknown challenge or changed request")
        if self.monotonic() >= expected[1]:
            raise Denied("expired challenge")
        peer, key, valid = self.verify_result(
            token, nonce, expected[0], int(self.clock())
        )
        if not isinstance(proof, str) or len(proof) > 128:
            raise Denied("invalid proof size")
        verify_signature(
            key,
            proof,
            proof_message(self.verifier.audience, nonce, expected[0], token),
        )
        with self.lock:
            if self.pending.get(nonce) != expected or self.monotonic() >= expected[1]:
                raise Denied("challenge consumed or expired")
            if not valid[0] <= int(self.clock()) < valid[1]:
                raise Denied("attestation expired before dispatch")
            del self.pending[nonce]
        if body["action"] == "reopen":
            args = {k: v for k, v in body.items() if k != "action"}
            return {"receipt": self.issuer.reopen(peer=peer, **args)}
        if body["action"] in initialization_api.ACTIONS:
            return initialization_api.dispatch(
                self.issuer, peer, body, nonce, sha256(raw)
            )
        self.issuer.authority.close(body["volume_id"], peer, body["activation_id"])
        return {"closed": True, "activation_id": body["activation_id"]}
