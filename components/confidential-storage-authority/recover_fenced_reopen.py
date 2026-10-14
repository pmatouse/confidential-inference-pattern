"""Offline administrator recovery after external fencing, never an HTTP API.

Evidence hashes are audit references, not cryptographic proof of VM destruction.
The administrator must independently fence the old VM/storage access. A host
claim alone cannot establish this against a malicious host. This is deliberately
not automatic timeout-based recovery. It never permits interrupted formatting.
"""

import argparse
import hashlib
import json
from pathlib import Path

from authority import Authority, Denied, digest


def record_digest(record):
    return hashlib.sha256(
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def recover(authority, expected, evidence_sha256, *, apply=False):
    digest(evidence_sha256)
    if not expected:
        raise Denied("explicit volume records required")
    with authority._transaction() as db:
        records = []
        for volume_id, expected_sha in expected.items():
            digest(expected_sha)
            record = authority._load(db, volume_id)
            owner = record.get("owner")
            if (
                record_digest(record) != expected_sha
                or record["state"] != "Ready"
                or record["revoked"]
                or not owner
                or owner["operation"] != "reopen"
            ):
                raise Denied(
                    "requires unchanged Ready reopen owner and external fencing"
                )
            # Existing deployed authority checks this legacy-named list for ALL
            # begin operations. Reuse it so recovery cannot require a window
            # with an authority binary that accepts a retired session.
            retired = record.setdefault("retired_initialization_sessions", [])
            if owner["session_sha256"] in retired:
                raise Denied("session already retired")
            retired.append(owner["session_sha256"])
            record.setdefault("fenced_reopen_history", []).append(
                {"owner": owner, "evidence_sha256": evidence_sha256}
            )
            record["owner"] = None
            records.append(record)
        if apply:
            for record in records:
                authority._save(db, record, "release-fenced-reopen")
        return [r["volume_id"] for r in records]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--expected-records", type=Path, required=True)
    parser.add_argument("--evidence-sha256", required=True)
    parser.add_argument("--apply-after-external-fencing", action="store_true")
    args = parser.parse_args()
    if not args.database.is_file() or args.database.is_symlink():
        raise ValueError("Existing retained authority database required")
    names = recover(
        Authority(args.database),
        json.loads(args.expected_records.read_text()),
        args.evidence_sha256,
        apply=args.apply_after_external_fencing,
    )
    print(json.dumps({"volumes": names, "applied": args.apply_after_external_fencing}))


if __name__ == "__main__":
    main()
