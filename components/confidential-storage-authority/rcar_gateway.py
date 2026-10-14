"""Bind one standard KBS handshake to one authority request and guest proof.

No standalone AS endpoint, KBS resource fetch, admin token or signing-key export.
The old direct-AS gateway remains separate and is never a fallback.
"""

from dataclasses import dataclass

from attestation import public_key, read_object, sha256, unb64
from authority import Denied, digest
from gateway import Gateway


@dataclass(repr=False)
class Retained:
    session: object
    attempted: bool = False
    runtime: object = None
    token_sha256: str = ""


class RcarGateway(Gateway):
    def __init__(self, verifier, issuer, *, rcar, **kwargs):
        if (
            len(verifier.appraisals) != 2
            or verifier.appraisals[0].tee != "snp"
            or verifier.appraisals[1].tee != "nvidia"
            or verifier.appraisals[1].submod != "gpu0"
        ):
            raise ValueError(
                "RCAR integration requires explicit SNP and NVIDIA appraisals"
            )
        super().__init__(verifier, issuer, **kwargs)
        self.rcar = rcar
        self.sessions = {}

    def challenge(self, raw):
        challenge = super().challenge(raw)
        nonce = challenge["nonce"]
        try:
            session = self.rcar.begin()
            with self.lock:
                self.sessions = {
                    n: s for n, s in self.sessions.items() if n in self.pending
                }
                expected = self.pending.get(nonce)
                if expected is None or self.monotonic() >= expected[1]:
                    raise Denied("challenge expired during RCAR start")
                if any(
                    s.session.nonce == session.nonce
                    or s.session.cookie == session.cookie
                    for s in self.sessions.values()
                ):
                    raise Denied("reused Trustee handshake")
                self.sessions[nonce] = Retained(session)
            challenge["attestation"] = session.challenge()
            return challenge
        except Exception:
            with self.lock:
                self.pending.pop(nonce, None)
                self.sessions.pop(nonce, None)
            raise

    def attest(self, nonce, key, evidence):
        digest(nonce)
        expected_key = public_key(key)
        if not isinstance(evidence, str) or not 0 < len(evidence) <= 192 * 1024:
            raise Denied("invalid composite evidence size")
        composite = read_object(unb64(evidence), 144 * 1024)
        if (
            set(composite) != {"primary_evidence", "additional_evidence"}
            or not isinstance(composite["primary_evidence"], dict)
            or not isinstance(composite["additional_evidence"], str)
        ):
            raise Denied("invalid composite evidence envelope")
        additional = read_object(composite["additional_evidence"].encode(), 128 * 1024)
        if set(additional) != {"nvidia"} or not isinstance(additional["nvidia"], dict):
            raise Denied("NVIDIA evidence required")
        with self.lock:
            expected = self.pending.get(nonce)
            retained = self.sessions.get(nonce)
            if (
                expected is None
                or self.monotonic() >= expected[1]
                or retained is None
                or retained.attempted
            ):
                raise Denied("unknown, expired or already attempted handshake")
            # No retry over a cookie that KBS may already have marked attested.
            retained.attempted = True
        token = self.rcar.attest(retained.session, key, composite)
        runtime = {
            "nonce": retained.session.nonce,
            "tee-pubkey": {**key, "alg": "ES256"},
            "additional-evidence": composite["additional_evidence"],
        }
        _, verified_key, _ = self.verifier.verify_rcar(
            token, nonce, expected[0], int(self.clock()), runtime=runtime
        )
        if verified_key.public_numbers() != expected_key.public_numbers():
            raise Denied("RCAR signing-key binding mismatch")
        with self.lock:
            if self.pending.get(nonce) != expected or self.monotonic() >= expected[1]:
                raise Denied("challenge consumed or expired during RCAR")
            retained.runtime = runtime
            retained.token_sha256 = sha256(token.encode("ascii"))
        return {"token": token}

    def verify_result(self, token, nonce, request_sha256, now):
        with self.lock:
            retained = self.sessions.get(nonce)
            pending = self.pending.get(nonce)
            if (
                retained is None
                or retained.runtime is None
                or pending is None
                or pending[0] != request_sha256
                or not isinstance(token, str)
                or not token.isascii()
                or sha256(token.encode("ascii")) != retained.token_sha256
            ):
                raise Denied("no completed request-specific RCAR handshake")
            runtime = retained.runtime
        return self.verifier.verify_rcar(
            token, nonce, request_sha256, now, runtime=runtime
        )

    def execute(self, nonce, raw, token, proof):
        try:
            return super().execute(nonce, raw, token, proof)
        finally:
            with self.lock:
                if nonce not in self.pending:
                    self.sessions.pop(nonce, None)
