"""Transactional authority core; no network, verifier, key delivery or disk I/O.

Only a trusted adapter may call this module after verifying peer attestation and
channel binding. AttestedPeer is a trusted input type, NOT attestation evidence.
Never expose these methods directly as unauthenticated HTTP/RPC endpoints.
The database must be outside the workload cluster's rollback domain.
"""

from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import sqlite3
import uuid


class Denied(Exception):
    """Rejected transition; callers must not perform the requested disk action."""


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}", value
    ):
        raise Denied("invalid identifier")
    return value


def digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise Denied("expected a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True)
class AttestedPeer:
    """Verified policy and fresh channel identity supplied by a future verifier."""

    policy_sha256: str
    session_sha256: str

    def validate(self):
        digest(self.policy_sha256)
        digest(self.session_sha256)


class Authority:
    """Single-authority SQLite backend, serialized across processes.

    No timeout-based takeover: a missing Close leaves the volume owned until a
    separately reviewed recovery procedure establishes that the old guest stopped.
    There is no reset or force takeover after a destructive step was issued.
    An explicitly released unstarted attempt permanently retires its old session.
    """

    def __init__(self, path):
        supplied = Path(path).absolute()
        self.path = supplied.parent.resolve() / supplied.name
        # Require an administrator-owned private directory. This is a trusted
        # configuration path, never a caller-supplied per-volume filesystem path.
        if self.path.parent.stat().st_mode & 0o077:
            raise ValueError("authority database directory must be private (0700)")
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        if self.path.stat().st_mode & 0o077:
            raise ValueError("authority database must be private (0600)")
        with self._transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS volumes "
                "(id TEXT PRIMARY KEY, record TEXT NOT NULL)"
            )
            db.execute(
                """CREATE TABLE IF NOT EXISTS operations (
                volume_id TEXT NOT NULL, operation_id TEXT NOT NULL,
                PRIMARY KEY (volume_id, operation_id))"""
            )
            db.execute(
                """CREATE TABLE IF NOT EXISTS initialization_sources (
                provisioning_id TEXT PRIMARY KEY, volume_id TEXT UNIQUE NOT NULL)"""
            )
            db.execute(
                """CREATE TABLE IF NOT EXISTS events (
                sequence INTEGER PRIMARY KEY, volume_id TEXT NOT NULL,
                action TEXT NOT NULL, record TEXT NOT NULL)"""
            )
        # Persist the initial directory entry as well as SQLite's committed data.
        directory = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    @contextmanager
    def _transaction(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    @staticmethod
    def _load(db, volume_id):
        row = db.execute(
            "SELECT record FROM volumes WHERE id=?", (identifier(volume_id),)
        ).fetchone()
        if row is None:
            raise Denied("unknown volume")
        return json.loads(row[0])

    @staticmethod
    def _save(db, record, action):
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"))
        db.execute(
            "UPDATE volumes SET record=? WHERE id=?", (encoded, record["volume_id"])
        )
        db.execute(
            "INSERT INTO events(volume_id,action,record) VALUES (?,?,?)",
            (record["volume_id"], action, encoded),
        )

    def register(
        self,
        volume_id,
        policy_sha256,
        profile_sha256,
        credential_uri,
        *,
        mount_binding=None
    ):
        """Trusted administrator operation. Contains a credential reference only."""
        identifier(volume_id)
        digest(policy_sha256)
        digest(profile_sha256)
        if (
            not isinstance(credential_uri, str)
            or not re.fullmatch(
                r"kbs:///[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+",
                credential_uri,
            )
            or any(part in (".", "..") for part in credential_uri[7:].split("/"))
        ):
            raise Denied("expected a versioned KBS resource reference")
        if mount_binding is not None:
            from receipts import validate_binding

            mount_binding = validate_binding(mount_binding)
        record = dict(
            mount_binding=mount_binding,
            manifest_sha256=None,
            volume_id=volume_id,
            policy_sha256=policy_sha256,
            profile_sha256=profile_sha256,
            credential_uri=credential_uri,
            generation=1,
            state="Uninitialized",
            header_sha256=None,
            owner=None,
            last_closed=None,
            revoked=False,
        )
        with self._transaction() as db:
            try:
                db.execute(
                    "INSERT INTO volumes VALUES (?,?)", (volume_id, json.dumps(record))
                )
            except sqlite3.IntegrityError as exc:
                raise Denied("volume already registered; reset is forbidden") from exc
            self._save(db, record, "register")
        return record

    def update_workload_policy(
        self, volume_ids, old_policy, new_policy, evidence_sha256
    ):
        """Administrator-only, atomic update of closed Ready volumes.

        This does not rotate keys, reset disks, change manifests, or recover an
        owner. Previous policies are permanently retired for these records.
        The administrator must separately update the measured guest and KBS
        release bindings. There is deliberately no network route for this action.
        """
        digest(old_policy)
        digest(new_policy)
        digest(evidence_sha256)
        if (
            not isinstance(volume_ids, list)
            or not 1 <= len(volume_ids) <= 32
            or len(set(volume_ids)) != len(volume_ids)
            or old_policy == new_policy
        ):
            raise Denied("invalid workload policy update")
        with self._transaction() as db:
            records = [self._load(db, name) for name in volume_ids]
            for record in records:
                if (
                    record["revoked"]
                    or record["state"] != "Ready"
                    or record["owner"] is not None
                    or record["policy_sha256"] != old_policy
                    or new_policy in record.get("retired_workload_policies", [])
                ):
                    raise Denied(
                        "policy update requires closed Ready volumes and fresh policy"
                    )
            for record in records:
                if record.get("initialization_approval"):
                    from initialization import approved_policy

                    record["initialization_policy_sha256"] = approved_policy(record)
                record.setdefault("retired_workload_policies", []).append(old_policy)
                record["policy_sha256"] = new_policy
                record["last_policy_update"] = {
                    "previous_policy_sha256": old_policy,
                    "evidence_sha256": evidence_sha256,
                }
                self._save(db, record, "update-workload-policy")
            return records

    def begin(
        self,
        volume_id,
        peer,
        operation_id,
        operation,
        expected_generation,
        *,
        request_sha256=None
    ):
        """Commit ownership; initialization effects need a separate step decision."""
        peer.validate()
        if request_sha256 is not None:
            digest(request_sha256)
        identifier(operation_id)
        if (
            operation not in ("initialize", "reopen")
            or type(expected_generation) is not int
        ):
            raise Denied("invalid operation or generation")
        with self._transaction() as db:
            record = self._load(db, volume_id)
            if record["revoked"] or peer.policy_sha256 != record["policy_sha256"]:
                raise Denied("volume or workload not authorized")
            if expected_generation != record["generation"]:
                raise Denied("stale generation")
            if peer.session_sha256 in record.get("retired_initialization_sessions", []):
                raise Denied("retired unstarted initialization session")
            if operation == "initialize":
                if not record.get("initialization_approval"):
                    raise Denied("explicit first-use initialization approval required")
            owner = record["owner"]
            if owner:
                if (
                    owner["session_sha256"],
                    owner["operation_id"],
                    owner["operation"],
                    owner.get("request_sha256"),
                ) != (peer.session_sha256, operation_id, operation, request_sha256):
                    raise Denied(
                        "previous owner not confirmed closed; recovery required"
                    )
                # Retry returns recorded state. Ready is never a fresh format grant.
                return self._grant(record)
            expected_state = "Uninitialized" if operation == "initialize" else "Ready"
            if record["state"] != expected_state:
                raise Denied("operation incompatible with authoritative volume state")
            try:
                db.execute(
                    "INSERT INTO operations VALUES (?,?)", (volume_id, operation_id)
                )
            except sqlite3.IntegrityError as exc:
                raise Denied("operation replay") from exc
            record["owner"] = dict(
                session_sha256=peer.session_sha256,
                operation_id=operation_id,
                operation=operation,
                activation_id=str(uuid.uuid4()),
                request_sha256=request_sha256,
            )
            if operation == "initialize":
                record["state"] = "Initializing"
            self._save(db, record, "begin-" + operation)
            grant = self._grant(record)
            if operation == "initialize":
                grant["action"] = "plan-initialization"
            return grant

    @staticmethod
    def _grant(record):
        # This is an internal result, not a signed bearer token or KBS capability.
        result = dict(record)
        result["action"] = (
            "resume-initialization" if record["state"] == "Initializing" else "open"
        )
        return result

    @staticmethod
    def _check_owner(record, peer, activation_id):
        peer.validate()
        owner = record["owner"]
        if (
            peer.policy_sha256 != record["policy_sha256"]
            or not owner
            or (
                owner["session_sha256"] != peer.session_sha256
                or owner["activation_id"] != activation_id
            )
        ):
            raise Denied("activation owner mismatch")

    def commit_ready(
        self, volume_id, peer, activation_id, header_sha256, *, manifest_sha256=None
    ):
        """Trusted adapter calls after verifying a durable initialization receipt.

        This core cannot verify disk writes, journal state or receipt attestation.
        The adapter and guest recovery protocol are required before deployment.
        """
        digest(header_sha256)
        if manifest_sha256 is not None:
            digest(manifest_sha256)
        with self._transaction() as db:
            record = self._load(db, volume_id)
            self._check_owner(record, peer, activation_id)
            if record["revoked"] or record["owner"]["operation"] != "initialize":
                raise Denied("initialization commit not authorized")
            if record.get("mount_binding") is not None and manifest_sha256 is None:
                raise Denied("bound mounts require an authenticated manifest digest")
            from initialization import require_ready_result

            require_ready_result(record, header_sha256, manifest_sha256)
            if record["state"] == "Ready":
                if header_sha256 != record[
                    "header_sha256"
                ] or manifest_sha256 != record.get("manifest_sha256"):
                    raise Denied("header identity cannot change on retry")
                return dict(record)
            if record["state"] != "Initializing":
                raise Denied("not initializing")
            record["state"] = "Ready"
            record["header_sha256"] = header_sha256
            record["manifest_sha256"] = manifest_sha256
            self._save(db, record, "commit-ready")
            return dict(record)

    def approve_initialization(self, volume_id, plan):
        """Trusted administrator explicitly authorizes first-use data destruction."""
        from initialization import approve

        return approve(self, volume_id, plan)

    def approve_published_model(self, volume_id, manifest):
        """Administrator approval of a verified immutable publisher result."""
        from publication import approve

        return approve(self, volume_id, manifest)

    def begin_initialization_step(self, volume_id, peer, activation_id, step):
        from initialization import begin_step

        return begin_step(self, volume_id, peer, activation_id, step)

    def complete_initialization_step(
        self, volume_id, peer, activation_id, step_id, result, evidence_sha256
    ):
        from initialization import complete_step

        return complete_step(
            self, volume_id, peer, activation_id, step_id, result, evidence_sha256
        )

    def close(self, volume_id, peer, activation_id):
        """Release ownership after trusted teardown; this does not provide fencing."""
        with self._transaction() as db:
            record = self._load(db, volume_id)
            peer.validate()
            previous = record.get("last_closed")
            if (
                record["owner"] is None
                and previous
                and peer.policy_sha256 == record["policy_sha256"]
                and previous["session_sha256"] == peer.session_sha256
                and previous["activation_id"] == activation_id
            ):
                return
            self._check_owner(record, peer, activation_id)
            if record["state"] != "Ready":
                raise Denied("interrupted initialization requires explicit recovery")
            record["last_closed"] = record["owner"]
            record["owner"] = None
            self._save(db, record, "close")

    def release_unstarted_initialization(
        self, volume_id, activation_id, evidence_sha256
    ):
        """Administrator-only recovery before ANY destructive step was issued.

        No network route exposes this method. The durable ledger is the safety
        condition: an empty step journal proves no formatting permit was issued.
        A racing step and recovery serialize in the same transaction. Retire the
        old session permanently, retain operation IDs/history, and require the
        next measured guest to repeat its complete blank-device check. This does
        not recover a Started step, initialized disk, lost journal or rollback.
        The operator records its teardown/import-readiness evidence hash here.
        """
        from initialization import canonical_uuid

        canonical_uuid(activation_id)
        digest(evidence_sha256)
        with self._transaction() as db:
            record = self._load(db, volume_id)
            owner = record.get("owner")
            if (
                record["revoked"]
                or record["state"] != "Initializing"
                or not owner
                or owner["operation"] != "initialize"
                or owner["activation_id"] != activation_id
                or not record.get("initialization_approval")
                or record.get("initialization_steps") != []
            ):
                raise Denied("only unstarted initialization may be released")
            retired = record.setdefault("retired_initialization_sessions", [])
            if owner["session_sha256"] in retired:
                raise Denied("initialization session already retired")
            retired.append(owner["session_sha256"])
            record["last_unstarted_release"] = {
                "owner": owner,
                "evidence_sha256": evidence_sha256,
            }
            record["owner"] = None
            record["state"] = "Uninitialized"
            self._save(db, record, "release-unstarted-initialization")
            return record

    def revoke(self, volume_id):
        """Administrative denial of new operations; does not revoke existing keys."""
        with self._transaction() as db:
            record = self._load(db, volume_id)
            record["revoked"] = True
            self._save(db, record, "revoke")

    def inspect(self, volume_id):
        with self._transaction() as db:
            return self._load(db, volume_id)
