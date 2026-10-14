"""Internal signed-receipt issuer, not an attestation verifier or HTTP service.

Only an authenticated adapter may supply AttestedPeer and a channel-bound nonce.
Private signing keys are injected by the trusted administrator, never generated
or loaded from an unauthenticated request. The guest pins the public key in its
measured configuration. This module never accesses a model/volume encryption key.
"""

import base64
import hashlib
import json
import re
import time

from authority import Denied, digest, identifier
from initialization import require_ready_result

AUDIENCE = "confidential-storage-guest/v1"
TOKEN_TYPE = "confidential-storage-grant+jwt"
MAX_LIFETIME = 60
BINDING_FIELDS = {"manifest_uri", "container_name", "destination", "access"}


def validate_binding(value):
    if not isinstance(value, dict) or set(value) != BINDING_FIELDS:
        raise Denied("invalid immutable mount binding")
    result = dict(value)
    if any(not isinstance(v, str) for v in result.values()):
        raise Denied("mount binding fields must be strings")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", result["container_name"]):
        raise Denied("invalid target container")
    if not re.fullmatch(
        r"kbs:///[a-z0-9][a-z0-9-]{0,62}/[a-z0-9][a-z0-9-]{0,62}/"
        r"[a-z0-9][a-z0-9-]{0,62}",
        result["manifest_uri"],
    ):
        raise Denied("invalid manifest URI")
    from storage_profiles import destination

    if result["access"] not in {"rw", "ro"} or not destination(result["destination"]):
        raise Denied("invalid access/destination")
    return result


def encoded(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class ReceiptIssuer:
    """Signs only a Ready reopen grant committed by the authoritative state core.

    Session/nonce origin MUST be established by the future attested transport.
    TTL is an admission bound, not a lease and not revocation of an active key.
    """

    def __init__(self, authority, signing_key, issuer, key_id, *, clock=time.time):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        if not isinstance(signing_key, Ed25519PrivateKey):
            raise ValueError("expected administrator-supplied Ed25519 signing key")
        self.authority = authority
        self.signing_key = signing_key
        self.issuer = identifier(issuer)
        self.key_id = identifier(key_id)
        self.clock = clock

    def reopen(
        self, volume_id, peer, operation_id, generation, nonce, binding, profile_sha256
    ):
        peer.validate()
        digest(nonce)
        digest(profile_sha256)
        binding = validate_binding(binding)
        record = self.authority.inspect(volume_id)
        # Check before ownership acquisition. Admin bindings cannot change after
        # registration, and begin checks policy/revocation/state transactionally.
        if record.get("mount_binding") != binding:
            raise Denied("mount request does not match administrator binding")
        if record["profile_sha256"] != profile_sha256:
            raise Denied("profile mismatch")
        if record["state"] != "Ready" or not record.get("manifest_sha256"):
            raise Denied("only initialized volumes with a pinned manifest may reopen")
        if binding["access"] == "ro":
            from publication import require_ready

            require_ready(record, record["header_sha256"], record["manifest_sha256"])
        else:
            require_ready_result(
                record, record["header_sha256"], record["manifest_sha256"]
            )
        now = int(self.clock())
        if not 0 <= now <= (1 << 64) - MAX_LIFETIME - 1:
            raise Denied("invalid authority clock")
        request_sha256 = hashlib.sha256(
            compact(
                {
                    "nonce": nonce,
                    "binding": binding,
                    "profile_sha256": profile_sha256,
                }
            )
        ).hexdigest()
        grant = self.authority.begin(
            volume_id,
            peer,
            operation_id,
            "reopen",
            generation,
            request_sha256=request_sha256,
        )
        claims = {
            "schema_version": 1,
            "iss": self.issuer,
            "aud": AUDIENCE,
            "iat": now,
            "exp": now + MAX_LIFETIME,
            "volume_id": grant["volume_id"],
            "generation": grant["generation"],
            "policy_sha256": grant["policy_sha256"],
            "profile_sha256": grant["profile_sha256"],
            "manifest_sha256": grant["manifest_sha256"],
            "header_sha256": grant["header_sha256"],
            "credential_uri": grant["credential_uri"],
            "session_sha256": peer.session_sha256,
            "operation_id": operation_id,
            "operation": "reopen",
            "nonce": nonce,
            "activation_id": grant["owner"]["activation_id"],
            **binding,
        }
        header = {"alg": "Ed25519", "typ": TOKEN_TYPE, "kid": self.key_id}
        signing_input = encoded(compact(header)) + b"." + encoded(compact(claims))
        return (
            signing_input + b"." + encoded(self.signing_key.sign(signing_input))
        ).decode("ascii")
