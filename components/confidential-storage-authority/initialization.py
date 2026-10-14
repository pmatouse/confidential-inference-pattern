"""Durable first-use intent/step journal; no formatter or attestation verifier.

These are trusted in-process operations. A future adapter must authenticate every
caller and completion receipt before supplying peer/result/evidence fields here.
Started steps are never reissued as execute on retry, even after a lost response.
"""

import hashlib
import json
import sqlite3
import uuid

from authority import Denied, digest, identifier
from storage_profiles import destination

STEPS = (
    "luks-format",
    "integrity-initialize",
    "filesystem-create",
    "durability-barrier",
)
PLAN_FIELDS = {
    "schema_version",
    "new_volume",
    "provisioning_id",
    "device_bytes",
    "luks_uuid",
    "filesystem",
    "header_bytes",
    "data_offset_bytes",
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def approved_policy(record):
    """Recover the immutable initialization identity from retained policy history."""
    approval = record["initialization_approval"]
    intent = {
        k: record[k]
        for k in (
            "volume_id",
            "generation",
            "policy_sha256",
            "profile_sha256",
            "credential_uri",
            "mount_binding",
        )
    }
    intent["plan"] = approval["plan"]
    candidates = [record["policy_sha256"]] + record.get("retired_workload_policies", [])
    matches = []
    for policy in candidates:
        digest(policy)
        intent["policy_sha256"] = policy
        if (
            hashlib.sha256(canonical(intent).encode()).hexdigest()
            == approval["plan_sha256"]
        ):
            matches.append(policy)
    if len(set(matches)) != 1:
        raise Denied("initialization identity does not match retained history")
    policy = matches[0]
    if record.get("initialization_policy_sha256", policy) != policy:
        raise Denied("immutable initialization policy mismatch")
    return policy


def canonical_uuid(value):
    if not isinstance(value, str):
        raise Denied("expected canonical UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise Denied("expected canonical UUID") from exc
    if str(parsed) != value:
        raise Denied("expected canonical UUID")
    return value


def validate_plan(value):
    if not isinstance(value, dict) or set(value) != PLAN_FIELDS:
        raise Denied("invalid initialization plan")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise Denied("unsupported initialization plan version")
    if value["new_volume"] is not True:
        raise Denied("initialization requires an explicitly new disposable volume")
    canonical_uuid(value["provisioning_id"])
    canonical_uuid(value["luks_uuid"])
    for field in ("device_bytes", "header_bytes", "data_offset_bytes"):
        if type(value[field]) is not int:
            raise Denied("invalid initialization geometry")
    if (
        not 64 * 1024 * 1024 <= value["device_bytes"] < 2**63
        or value["device_bytes"] % 4096
        or value["header_bytes"] != 16 * 1024 * 1024
        or value["data_offset_bytes"] != value["header_bytes"]
        or value["filesystem"] != "ext4"
    ):
        raise Denied("unsupported initialization geometry or filesystem")
    return dict(value)


def approve(authority, volume_id, plan):
    """Administrative authorization to destroy contents of this NEW volume only.

    A provisioning ID binds administrative intent; it is not storage attestation.
    The profile digest and key reference come from immutable registration.
    """
    plan = validate_plan(plan)
    with authority._transaction() as db:
        record = authority._load(db, volume_id)
        binding = record.get("mount_binding")
        if (
            record["revoked"]
            or record["state"] != "Uninitialized"
            or record["owner"] is not None
            or not binding
            or binding["access"] != "rw"
            or not destination(binding["destination"])
        ):
            raise Denied("initialization approval requires a new bound writable volume")
        intent = {
            "plan": plan,
            **{
                k: record[k]
                for k in (
                    "volume_id",
                    "generation",
                    "policy_sha256",
                    "profile_sha256",
                    "credential_uri",
                    "mount_binding",
                )
            },
        }
        plan_sha256 = hashlib.sha256(canonical(intent).encode()).hexdigest()
        approval = {"plan": plan, "plan_sha256": plan_sha256}
        previous = record.get("initialization_approval")
        if previous is not None:
            if previous != approval:
                raise Denied("initialization approval is immutable")
            return previous
        try:
            db.execute(
                "INSERT INTO initialization_sources VALUES (?,?)",
                (plan["provisioning_id"], volume_id),
            )
        except sqlite3.IntegrityError as exc:
            raise Denied(
                "provisioning identity already reserved for initialization"
            ) from exc
        record["initialization_approval"] = approval
        record["initialization_steps"] = []
        authority._save(db, record, "approve-initialization")
        return approval


def require_owner(authority, record, peer, activation_id):
    authority._check_owner(record, peer, activation_id)
    if (
        record["revoked"]
        or record["state"] != "Initializing"
        or record["owner"]["operation"] != "initialize"
        or not record.get("initialization_approval")
    ):
        raise Denied("initialization step not authorized")


def begin_step(authority, volume_id, peer, activation_id, step):
    """Commit Started before returning execute. A retry is reconcile/complete.

    Do not sign this dictionary and replay it as a stateless format capability.
    The guest still needs a session-bound, serialized, one-shot executor.
    """
    if step not in STEPS:
        raise Denied("unknown initialization step")
    with authority._transaction() as db:
        record = authority._load(db, volume_id)
        require_owner(authority, record, peer, activation_id)
        steps = record["initialization_steps"]
        index = STEPS.index(step)
        if index < len(steps):
            saved = steps[index]
            decision = "complete" if saved["status"] == "Complete" else "reconcile"
        else:
            if index != len(steps) or any(s["status"] != "Complete" for s in steps):
                raise Denied("initialization steps must finish in order")
            saved = {"step": step, "step_id": str(uuid.uuid4()), "status": "Started"}
            steps.append(saved)
            authority._save(db, record, "start-" + step)
            decision = "execute"
        return {
            "decision": decision,
            "volume_id": volume_id,
            "generation": record["generation"],
            "owner": dict(record["owner"]),
            "plan_sha256": record["initialization_approval"]["plan_sha256"],
            **saved,
        }


def validate_result(step, result, expected_header):
    fields = {"header_sha256"}
    if step == "integrity-initialize":
        fields.add("stack_sha256")
    elif step == "filesystem-create":
        fields.add("filesystem_uuid")
    elif step == "durability-barrier":
        fields.add("manifest_sha256")
    if not isinstance(result, dict) or set(result) != fields:
        raise Denied("invalid initialization completion")
    for field in fields:
        if field == "filesystem_uuid":
            canonical_uuid(result[field])
        else:
            digest(result[field])
    if expected_header is not None and result["header_sha256"] != expected_header:
        raise Denied("initialized header identity changed")
    return dict(result)


def complete_step(
    authority, volume_id, peer, activation_id, step_id, result, evidence_sha256
):
    """Record adapter-verified completion; hashes alone do NOT verify disk effects."""
    identifier(step_id)
    digest(evidence_sha256)
    with authority._transaction() as db:
        record = authority._load(db, volume_id)
        require_owner(authority, record, peer, activation_id)
        steps = record["initialization_steps"]
        match = next((s for s in steps if s["step_id"] == step_id), None)
        if match is None:
            raise Denied("unknown initialization step instance")
        expected_header = steps[0].get("result", {}).get("header_sha256")
        result = validate_result(match["step"], result, expected_header)
        if match["status"] == "Complete":
            if match["result"] != result or match["evidence_sha256"] != evidence_sha256:
                raise Denied("conflicting initialization completion retry")
            return dict(match)
        match.update(status="Complete", result=result, evidence_sha256=evidence_sha256)
        authority._save(db, record, "complete-" + match["step"])
        return dict(match)


def completed(record):
    """Internal readiness invariant, not proof of attestation or disk durability."""
    steps = record.get("initialization_steps", [])
    return (
        bool(record.get("initialization_approval"))
        and len(steps) == len(STEPS)
        and all(
            s["step"] == expected and s["status"] == "Complete"
            for s, expected in zip(steps, STEPS)
        )
    )


def require_ready_result(record, header_sha256, manifest_sha256):
    if not completed(record):
        raise Denied("all initialization steps must complete before Ready")
    final = record["initialization_steps"][-1]["result"]
    if final != {"header_sha256": header_sha256, "manifest_sha256": manifest_sha256}:
        raise Denied("Ready digests do not match the completed durability barrier")
