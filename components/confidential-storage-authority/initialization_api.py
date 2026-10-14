"""Attested guest adapter for the administrator-approved first-use journal.

No registration, approval, reset, key access or disk effects are exposed. Every
call is dispatched only after Gateway verifies fresh evidence and a guest proof.
Signed responses bind the exact request/challenge; execute is still a one-shot
stateful decision, never a reusable formatting capability.
"""

import hashlib
from pathlib import Path

from authority import Denied, digest, identifier
from initialization import STEPS, validate_result
from receipts import AUDIENCE, MAX_LIFETIME, compact, encoded, validate_binding
from storage_profiles import supports

ACTIONS = {
    "initialization-plan",
    "initialization-begin",
    "initialization-step",
    "initialization-complete",
    "initialization-ready",
}
COMMON = {
    "action",
    "volume_id",
    "operation_id",
    "generation",
    "nonce",
    "binding",
    "profile_sha256",
    "plan_sha256",
}
TOKEN_TYPE = "confidential-storage-initialization+jwt"
PROFILE = (
    Path(__file__).resolve().parents[1]
    / "confidential-storage-guest/profiles/rw-luks2-v1.json"
)


def validate_request(body):
    action = body["action"]
    extra = {
        "initialization-plan": set(),
        "initialization-begin": set(),
        "initialization-step": {"activation_id", "step"},
        "initialization-complete": {
            "activation_id",
            "step",
            "step_id",
            "result",
            "evidence_sha256",
        },
        "initialization-ready": {"activation_id", "header_sha256"},
    }[action]
    if set(body) != COMMON | extra:
        raise Denied("invalid initialization request fields")
    for field in ("volume_id", "operation_id"):
        identifier(body[field])
    if type(body["generation"]) is not int or not 0 < body["generation"] < 2**63:
        raise Denied("invalid initialization generation")
    for field in ("nonce", "profile_sha256", "plan_sha256"):
        digest(body[field])
    binding = validate_binding(body["binding"])
    if binding["access"] != "rw":
        raise Denied("only private writable storage may initialize")
    if "activation_id" in extra:
        identifier(body["activation_id"])
    if "step" in extra and body["step"] not in STEPS:
        raise Denied("unsupported initialization step")
    if action == "initialization-complete":
        identifier(body["step_id"])
        digest(body["evidence_sha256"])
        validate_result(body["step"], body["result"], None)
    if action == "initialization-ready":
        digest(body["header_sha256"])


def request_identity(body):
    # Stable across the five actions; changing the guest nonce/plan/binding cannot
    # adopt an existing initialization, even with the same session/operation ID.
    return hashlib.sha256(
        compact({k: body[k] for k in COMMON - {"action"}})
    ).hexdigest()


def require_record(authority, peer, body):
    peer.validate()
    record = authority.inspect(body["volume_id"])
    approval = record.get("initialization_approval")
    if (
        record["revoked"]
        or peer.policy_sha256 != record["policy_sha256"]
        or record["generation"] != body["generation"]
        or record["profile_sha256"] != body["profile_sha256"]
        or not supports("rw", record["profile_sha256"], body["binding"]["destination"])
        or record.get("mount_binding") != body["binding"]
        or not approval
        or approval["plan_sha256"] != body["plan_sha256"]
        or record.get("publication_approval")
    ):
        raise Denied("initialization does not match administrative approval")
    owner = record["owner"]
    if owner and (
        owner["session_sha256"] != peer.session_sha256
        or owner["operation"] != "initialize"
        or owner["operation_id"] != body["operation_id"]
        or owner.get("request_sha256") != request_identity(body)
    ):
        raise Denied("initialization owner or request mismatch")
    if "activation_id" in body and (
        not owner or owner["activation_id"] != body["activation_id"]
    ):
        raise Denied("initialization activation mismatch")
    return record


def manifest(record, header):
    """Derive public manifest bytes from immutable approval plus the sealed header.

    This is also independently derived by the guest before its durability report.
    No new KBS administrator write is required to recover the public manifest:
    the authority can derive the exact bytes again from its durable record. The
    registered manifest URI remains its immutable logical identifier.
    """
    digest(header)
    plan = record["initialization_approval"]["plan"]
    return compact(
        {
            "schemaVersion": 1,
            "volumeId": record["volume_id"],
            "generation": record["generation"],
            "profileSha256": record["profile_sha256"],
            "credentialUri": record["credential_uri"],
            "luksUuid": plan["luks_uuid"],
            "deviceBytes": plan["device_bytes"],
            "headerSha256": header,
            "headerBytes": plan["header_bytes"],
            "dataOffsetBytes": plan["data_offset_bytes"],
            "filesystem": plan["filesystem"],
        }
    )


def view(record):
    result = {
        k: record[k]
        for k in (
            "volume_id",
            "generation",
            "policy_sha256",
            "profile_sha256",
            "credential_uri",
            "mount_binding",
            "initialization_approval",
            "initialization_steps",
            "state",
            "owner",
        )
    }
    if record["state"] == "Ready":
        if "initialization_policy_sha256" in record:
            from initialization import approved_policy

            result["initialization_policy_sha256"] = approved_policy(record)
        raw = manifest(record, record["header_sha256"])
        if hashlib.sha256(raw).hexdigest() != record["manifest_sha256"]:
            raise Denied("committed manifest is not the approved initialization layout")
        result["manifest"] = raw.decode("ascii")
    return result


def dispatch(issuer, peer, body, challenge, request_sha256):
    """Caller has already verified the fresh attestation/proof and consumed nonce."""
    validate_request(body)
    now = int(issuer.clock())
    if not 0 <= now <= (1 << 64) - MAX_LIFETIME - 1:
        raise Denied("invalid authority clock")
    authority = issuer.authority
    record = require_record(authority, peer, body)
    action = body["action"]
    volume = body["volume_id"]
    if action == "initialization-plan":
        result = {"record": view(record)}
    elif action == "initialization-begin":
        grant = authority.begin(
            volume,
            peer,
            body["operation_id"],
            "initialize",
            body["generation"],
            request_sha256=request_identity(body),
        )
        result = {"action": grant["action"], "record": view(grant)}
    elif action == "initialization-step":
        result = authority.begin_initialization_step(
            volume, peer, body["activation_id"], body["step"]
        )
    elif action == "initialization-complete":
        step = next(
            (
                s
                for s in record["initialization_steps"]
                if s["step_id"] == body["step_id"]
            ),
            None,
        )
        if not step or step["step"] != body["step"]:
            raise Denied("completion does not match started step")
        # The attested guest service must verify actual disk effects/durability.
        # An evidence digest alone is not proof that the disk was flushed.
        result = authority.complete_initialization_step(
            volume,
            peer,
            body["activation_id"],
            body["step_id"],
            body["result"],
            body["evidence_sha256"],
        )
    elif action == "initialization-ready":
        raw = manifest(record, body["header_sha256"])
        committed = authority.commit_ready(
            volume,
            peer,
            body["activation_id"],
            body["header_sha256"],
            manifest_sha256=hashlib.sha256(raw).hexdigest(),
        )
        result = {"record": view(committed)}
    else:
        raise Denied("unsupported initialization action")
    claims = {
        "schema_version": 1,
        "iss": issuer.issuer,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + MAX_LIFETIME,
        "action": action,
        "session_sha256": peer.session_sha256,
        "policy_sha256": peer.policy_sha256,
        "challenge": challenge,
        "request_sha256": request_sha256,
        "result": result,
    }
    header = {"alg": "Ed25519", "typ": TOKEN_TYPE, "kid": issuer.key_id}
    data = encoded(compact(header)) + b"." + encoded(compact(claims))
    return {
        "decision": (data + b"." + encoded(issuer.signing_key.sign(data))).decode(
            "ascii"
        )
    }
