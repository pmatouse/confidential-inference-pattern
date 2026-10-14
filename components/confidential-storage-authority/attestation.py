"""Pinned Trustee EAR result verification; not a hardware evidence verifier.

No network/key discovery, test bypass or default trust root. Configuration comes
from the authority administrator. Hardware evidence is appraised by Trustee AS.
The storage-binding runtime extension still needs a measured guest/AS adapter.
"""

import base64
from dataclasses import dataclass
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from authority import AttestedPeer, Denied, digest
from receipts import compact

PROFILE = "tag:github.com,2024:confidential-containers/Trustee"
PROTOCOL = "confidential-storage-request/v1"
ANNOTATED = "ear.veraison.annotated-evidence"
MAX_TOKEN = 256 * 1024


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def unb64(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise Denied("invalid base64url")
    result = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if b64(result) != value:
        raise Denied("noncanonical base64url")
    return result


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Denied("duplicate JSON member")
        result[key] = value
    return result


def invalid_constant(_):
    raise Denied("nonfinite JSON number")


def read_object(value, limit):
    if not isinstance(value, bytes) or not 0 < len(value) <= limit:
        raise Denied("invalid message size")
    try:
        result = json.loads(
            value.decode("utf-8"),
            object_pairs_hook=object_pairs,
            parse_constant=invalid_constant,
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Denied("invalid JSON") from exc
    if not isinstance(result, dict):
        raise Denied("expected JSON object")
    return result


def public_key(jwk):
    """Dedicated storage signing key, never reuse a KBC decryption key."""
    if (
        not isinstance(jwk, dict)
        or set(jwk) != {"kty", "crv", "x", "y"}
        or jwk["kty"] != "EC"
        or jwk["crv"] != "P-256"
    ):
        raise Denied("expected dedicated P-256 storage key")
    try:
        x, y = unb64(jwk["x"]), unb64(jwk["y"])
        if len(x) != 32 or len(y) != 32:
            raise Denied("invalid EC coordinates")
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
        ).public_key()
    except (ValueError, TypeError) as exc:
        raise Denied("invalid EC key") from exc


def verify_signature(key, signature, message):
    try:
        raw = unb64(signature)
        if len(raw) != 64:
            raise Denied("invalid ES256 signature length")
        der = utils.encode_dss_signature(
            int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
        )
        key.verify(der, message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise Denied("invalid ES256 signature") from exc


@dataclass(frozen=True)
class Appraisal:
    submod: str
    tee: str
    policy_id: str
    configuration: int = 2


def audit_signed_appraisals(claims):
    """Fixed diagnostic fields, called only after pinned signature verification."""
    submods = claims.get("submods")
    for name in ("cpu0", "gpu0"):
        appraisal = submods.get(name) if isinstance(submods, dict) else None
        appraisal = appraisal if isinstance(appraisal, dict) else {}
        status = appraisal.get("ear.status")
        if status not in ("affirming", "warning", "contraindicated", "none"):
            status = "other"
        vector = appraisal.get("ear.trustworthiness-vector")
        vector = vector if isinstance(vector, dict) else {}
        values = []
        for field in ("hardware", "configuration", "executables"):
            value = vector.get(field)
            value = value if type(value) is int and -128 <= value <= 127 else "other"
            values.append(f"{field}={value}")
        print(
            f"STORAGE_EAR submod={name} status={status} " + " ".join(values), flush=True
        )


class EarVerifier:
    """Accept only configured appraisals, measured InitData and request binding.

    The signer is an administrator-pinned AS key; a token's embedded JWK is never
    a trust anchor. No signer/issuer/policy is selected from caller input.
    """

    def __init__(
        self,
        signer,
        issuer,
        audience,
        init_data,
        policy_sha256,
        appraisals,
        *,
        issuer_claim="required",
        gpu_binding="runtime-claims",
    ):
        if not isinstance(signer, ec.EllipticCurvePublicKey) or not isinstance(
            signer.curve, ec.SECP256R1
        ):
            raise ValueError("pin a P-256 AS signer")
        if not issuer or not audience:
            raise ValueError("issuer and authority audience must be explicit")
        if issuer_claim not in ("required", "absent-rcar"):
            raise ValueError("select an explicit issuer claim profile")
        self.issuer_claim = issuer_claim
        if gpu_binding not in ("runtime-claims", "nvidia-nonce-match"):
            raise ValueError("select an explicit GPU binding profile")
        self.gpu_binding = gpu_binding
        if not isinstance(init_data, str) or not re.fullmatch(
            r"(?:[0-9a-f]{64}|[0-9a-f]{96}|[0-9a-f]{128})", init_data
        ):
            raise ValueError("pin the exact verified InitData claim")
        digest(policy_sha256)
        appraisals = tuple(appraisals)
        if (
            not appraisals
            or appraisals[0].submod != "cpu0"
            or appraisals[0].tee not in ("snp", "tdx")
            or len({a.submod for a in appraisals}) != len(appraisals)
            or any(not a.policy_id for a in appraisals)
            or any(
                type(a.configuration) is not int or a.configuration not in (2, 3)
                for a in appraisals
            )
            or any(a.tee != "nvidia" for a in appraisals[1:])
        ):
            raise ValueError("require one real CPU and explicit optional GPUs")
        self.signer = signer
        self.issuer = issuer
        self.audience = audience
        self.init_data = init_data
        self.policy_sha256 = policy_sha256
        self.appraisals = appraisals

    def verify(self, token, nonce, request_sha256, now):
        """Called with authority-owned challenge data, never client expectations."""
        return self._verify(token, nonce, request_sha256, now)

    def verify_rcar(self, token, nonce, request_sha256, now, *, runtime):
        """Runtime is authority-owned RCAR state, never execute-request fields.

        KBS attests its nonce/key/composite evidence. Our gateway binds that
        fresh handshake to the storage request; the guest separately signs the
        authority nonce, exact request hash and resulting token hash.
        """
        if not isinstance(runtime, dict) or set(runtime) != {
            "nonce",
            "tee-pubkey",
            "additional-evidence",
        }:
            raise Denied("invalid retained RCAR context")
        return self._verify(token, nonce, request_sha256, now, rcar=runtime)

    def _verify(self, token, nonce, request_sha256, now, rcar=None):
        if self.gpu_binding != "runtime-claims" and rcar is None:
            raise Denied("RCAR device/session binding mismatch")
        if not isinstance(token, str) or not 0 < len(token) <= MAX_TOKEN:
            raise Denied("invalid token size")
        try:
            header64, payload64, signature = token.split(".")
            header = read_object(unb64(header64), 16 * 1024)
            if header.get("alg") != "ES256" or "crit" in header or "b64" in header:
                raise Denied("unsupported JWS profile")
            # AS may embed jwk/x5c. Verify exclusively with the pinned key.
            verify_signature(
                self.signer, signature, (header64 + "." + payload64).encode("ascii")
            )
            claims = read_object(unb64(payload64), MAX_TOKEN)
            audit_signed_appraisals(claims)
            iat, exp = claims["iat"], claims["exp"]
            if (
                type(now) is not int
                or type(iat) is not int
                or type(exp) is not int
                or not 0 <= iat <= now < exp
                or exp - iat > 300
                or now - iat > 60
                or (
                    "nbf" in claims
                    and (type(claims["nbf"]) is not int or claims["nbf"] > now)
                )
            ):
                raise Denied("stale attestation result")
            # Some installed Trustee EAR brokers omit iss. This explicit RCAR-only
            # profile requires its absence; it is never an issuer-check fallback.
            # Identity still comes exclusively from the administrator-pinned signer,
            # behind the pinned KBS TLS channel, with fresh request-specific RCAR.
            issuer_ok = (
                claims.get("iss") == self.issuer
                if self.issuer_claim == "required"
                else rcar is not None and "iss" not in claims
            )
            if not issuer_ok or claims["eat_profile"] != PROFILE:
                raise Denied("wrong attestation issuer/profile")
            submods = claims["submods"]
            if not isinstance(submods, dict) or set(submods) != {
                a.submod for a in self.appraisals
            }:
                raise Denied("unexpected device appraisal set")
            binding = None
            for required in self.appraisals:
                appraisal = submods[required.submod]
                vector = appraisal["ear.trustworthiness-vector"]
                if (
                    appraisal["ear.status"] != "affirming"
                    or appraisal["ear.appraisal-policy-id"] != required.policy_id
                    or not isinstance(vector, dict)
                    or any(
                        type(v) is not int or v not in range(4) for v in vector.values()
                    )
                    or vector.get("hardware") != 2
                    or vector.get("configuration") != required.configuration
                    or vector.get("executables") != 3
                ):
                    raise Denied("unacceptable device appraisal")
                evidence = appraisal[ANNOTATED]
                if not isinstance(evidence[required.tee], dict):
                    raise Denied("missing expected hardware evidence")
                if (
                    required.submod == "cpu0"
                    and evidence["init_data"] != self.init_data
                ):
                    raise Denied("wrong measured guest configuration")
                if rcar is None:
                    current = evidence["runtime_data_claims"]["storage-binding"]
                else:
                    expected_runtime = dict(rcar)
                    if required.submod != "cpu0":
                        del expected_runtime["additional-evidence"]
                    if (
                        self.gpu_binding == "nvidia-nonce-match"
                        and required.tee == "nvidia"
                    ):
                        # Standard Trustee's NVIDIA verifier checks the GPU nonce
                        # against SHA-384(nonce + tee-pubkey), but does not export
                        # runtime_data_claims for this submod. The CPU must bind the
                        # exact additional-evidence bytes; both appraisals originate
                        # from this gateway's one retained pinned-TLS KBS handshake.
                        gpu = evidence["nvidia"]
                        if (
                            "runtime_data_claims" in evidence
                            or gpu.get("x-nvidia-gpu-attestation-report-nonce-match")
                            is not True
                            or gpu.get("x-nvidia-overall-att-result") is not True
                            or gpu.get("secboot") is not True
                            or gpu.get("dbgstat") != "disabled"
                            or gpu.get("measres") != "success"
                        ):
                            raise Denied("RCAR device/session binding mismatch")
                    elif evidence["runtime_data_claims"] != expected_runtime:
                        raise Denied("RCAR device/session binding mismatch")
                    if (
                        self.gpu_binding == "nvidia-nonce-match"
                        and required.submod == "cpu0"
                    ):
                        expected_report = (
                            hashlib.sha384(compact(expected_runtime)).hexdigest()
                            + "0" * 32
                        )
                        if (
                            required.tee != "snp"
                            or evidence.get("report_data") != expected_report
                        ):
                            raise Denied("RCAR device/session binding mismatch")
                    tee_key = rcar["tee-pubkey"]
                    if (
                        not isinstance(tee_key, dict)
                        or set(tee_key) != {"kty", "crv", "x", "y", "alg"}
                        or tee_key["alg"] != "ES256"
                    ):
                        raise Denied("dedicated RCAR signing key required")
                    current = {
                        "protocol": PROTOCOL,
                        "audience": self.audience,
                        "nonce": nonce,
                        "request_sha256": request_sha256,
                        "key": {k: v for k, v in tee_key.items() if k != "alg"},
                    }
                if not isinstance(current, dict) or set(current) != {
                    "protocol",
                    "audience",
                    "nonce",
                    "request_sha256",
                    "key",
                }:
                    raise Denied("missing verified storage request binding")
                if (
                    current["protocol"] != PROTOCOL
                    or current["audience"] != self.audience
                    or current["nonce"] != nonce
                    or current["request_sha256"] != request_sha256
                    or (binding is not None and current != binding)
                ):
                    raise Denied("attestation request/device binding mismatch")
                binding = current
            key = public_key(binding["key"])
            # Stable across fresh tokens/challenges, unique to the guest-held key,
            # authority audience and pinned workload. This is not a bearer ID.
            session = sha256(
                compact(
                    {
                        "protocol": PROTOCOL,
                        "audience": self.audience,
                        "key": binding["key"],
                        "policy_sha256": self.policy_sha256,
                        "init_data": self.init_data,
                    }
                )
            )
            return (
                AttestedPeer(self.policy_sha256, session),
                key,
                (iat, min(exp, iat + 61)),
            )
        except (KeyError, TypeError, ValueError, RecursionError) as exc:
            field = exc.args[0] if isinstance(exc, KeyError) and exc.args else None
            if field not in (
                "iat",
                "exp",
                "iss",
                "eat_profile",
                "submods",
                "ear.status",
                "ear.appraisal-policy-id",
                "ear.trustworthiness-vector",
                ANNOTATED,
                "init_data",
                "runtime_data_claims",
                "snp",
                "nvidia",
            ):
                field = "other"
            print(f"STORAGE_EAR malformed_field={field}", flush=True)
            raise Denied("malformed attestation result") from exc


def proof_message(audience, nonce, request_sha256, token):
    """Canonical, domain-separated input to ES256; all digests are lowercase hex."""
    return compact(
        {
            "protocol": PROTOCOL,
            "audience": audience,
            "nonce": nonce,
            "request_sha256": request_sha256,
            "attestation_sha256": sha256(token.encode("ascii")),
        }
    )
