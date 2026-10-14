"""Administrator approval of an already published immutable RO model volume.

The publisher is trusted and separately verifies plaintext/model provenance and
the complete encrypted disk. A matching registry digest alone is NOT publisher
authorization. This module neither contacts a registry nor exposes a guest API.
"""

import hashlib
from pathlib import Path
import re

from authority import Denied, digest
from initialization import canonical_uuid
from storage_profiles import profile_digest, supports

PROFILE_PATH = (
    Path(__file__).resolve().parents[1]
    / "confidential-storage-guest/profiles/ro-luks2-verity-v1.json"
)
HEADER_BYTES = 16 * 1024 * 1024
MANIFEST_FIELDS = {
    "schemaVersion",
    "volumeId",
    "generation",
    "profileSha256",
    "credentialUri",
    "luksUuid",
    "deviceBytes",
    "headerSha256",
    "headerBytes",
    "dataOffsetBytes",
    "filesystem",
    "verity",
    "source",
    "files",
}


def profile_sha256():
    return hashlib.sha256(PROFILE_PATH.read_bytes()).hexdigest()


def validate_manifest(raw, record):
    # Lazy import avoids the attestation/receipt module import cycle. The parser
    # rejects duplicate members, nonfinite values and oversized objects.
    from attestation import read_object

    m = read_object(raw, 64 * 1024)
    if set(m) != MANIFEST_FIELDS:
        raise Denied("invalid published model manifest fields")
    expected = {
        "schemaVersion": 1,
        "volumeId": record["volume_id"],
        "generation": record["generation"],
        "profileSha256": record["profile_sha256"],
        "credentialUri": record["credential_uri"],
        "headerBytes": HEADER_BYTES,
        "dataOffsetBytes": HEADER_BYTES,
        "filesystem": "ext4",
    }
    if any(m[k] != v or type(m[k]) is not type(v) for k, v in expected.items()):
        raise Denied("model manifest does not match registration")
    if m["profileSha256"] not in {profile_sha256(), profile_digest("ro-luks2-verity-v2")}:
        raise Denied("unsupported model storage profile")
    digest(m["headerSha256"])
    canonical_uuid(m["luksUuid"])
    size = m["deviceBytes"]
    if (
        type(size) is not int
        or not 64 * 1024 * 1024 <= size <= 64 * 1024**3
        or size % 4096
    ):
        raise Denied("invalid model disk size")
    v = m["verity"]
    if not isinstance(v, dict) or set(v) != {
        "root",
        "salt",
        "hashAlgorithm",
        "hashOffsetBytes",
        "dataBytes",
        "blockBytes",
    }:
        raise Denied("invalid verity description")
    digest(v["root"])
    digest(v["salt"])
    if (
        v["hashAlgorithm"] != "sha256"
        or type(v["blockBytes"]) is not int
        or v["blockBytes"] != 4096
        or type(v["dataBytes"]) is not int
        or type(v["hashOffsetBytes"]) is not int
        or v["hashOffsetBytes"] != v["dataBytes"]
        or not HEADER_BYTES < v["dataBytes"] < size
        or v["dataBytes"] % 4096
    ):
        raise Denied("unsupported verity geometry")
    # Publisher uses format-1 SHA-256, no superblock, 128 digests/block.
    blocks, tree_blocks = v["dataBytes"] // 4096, 0
    while blocks > 1:
        blocks = (blocks + 127) // 128
        tree_blocks += blocks
    if v["hashOffsetBytes"] + tree_blocks * 4096 > size:
        raise Denied("verity tree exceeds disk")
    source = m["source"]
    if not isinstance(source, dict) or set(source) != {
        "repository",
        "manifestDigest",
        "diskDigest",
        "diskBytes",
        "format",
    }:
        raise Denied("invalid OCI source")
    for field in ("manifestDigest", "diskDigest"):
        value = source[field]
        if not isinstance(value, str) or not value.startswith("sha256:"):
            raise Denied("OCI source must use immutable digests")
        digest(value[7:])
    if (
        type(source["diskBytes"]) is not int
        or source["diskBytes"] != size
        or source["format"] != "luks-verity-v1"
        or not isinstance(source["repository"], str)
        or not re.fullmatch(
            r"[a-z0-9][a-z0-9-]{0,62}/[a-z0-9][a-z0-9._-]{0,127}", source["repository"]
        )
    ):
        raise Denied("model manifest/source mismatch")
    files = m["files"]
    if not isinstance(files, list) or not 1 <= len(files) <= 256:
        raise Denied("bounded model file inventory required")
    paths, total = set(), 0
    for f in files:
        if not isinstance(f, dict) or set(f) != {"path", "bytes", "sha256"}:
            raise Denied("invalid model file entry")
        path = f["path"]
        if (
            not isinstance(path, str)
            or len(path) > 512
            or not re.fullmatch(r"[A-Za-z0-9._/-]+", path)
            or any(part in ("", ".", "..") for part in path.split("/"))
            or path in paths
            or type(f["bytes"]) is not int
            or not 0 <= f["bytes"] <= size
        ):
            raise Denied("invalid or duplicate model file")
        digest(f["sha256"])
        paths.add(path)
        total += f["bytes"]
    if total > v["dataBytes"] - HEADER_BYTES:
        raise Denied("model file inventory exceeds filesystem region")
    return m


def from_publisher(record, descriptor, source):
    """Build canonical bytes from a separately reviewed trusted publisher result.

    The caller verifies publisher provenance and artifact contents BEFORE approval.
    This conversion performs schema/binding checks, not publisher authentication.
    """
    from receipts import compact

    if (
        not isinstance(descriptor, dict)
        or set(descriptor)
        != {
            "format",
            "diskBytes",
            "dataBytes",
            "hashOffsetBytes",
            "blockBytes",
            "hashAlgorithm",
            "verityRoot",
            "veritySalt",
            "luksUuid",
            "headerSha256",
            "headerBytes",
            "filesystem",
            "files",
        }
        or descriptor["format"] != "luks-verity-v1"
    ):
        raise Denied("invalid publisher description")
    raw = compact(
        {
            "schemaVersion": 1,
            "volumeId": record["volume_id"],
            "generation": record["generation"],
            "profileSha256": record["profile_sha256"],
            "credentialUri": record["credential_uri"],
            "luksUuid": descriptor["luksUuid"],
            "deviceBytes": descriptor["diskBytes"],
            "headerSha256": descriptor["headerSha256"],
            "headerBytes": descriptor["headerBytes"],
            "dataOffsetBytes": HEADER_BYTES,
            "filesystem": descriptor["filesystem"],
            "source": source,
            "files": descriptor["files"],
            "verity": {
                "root": descriptor["verityRoot"],
                "salt": descriptor["veritySalt"],
                "hashAlgorithm": descriptor["hashAlgorithm"],
                "blockBytes": descriptor["blockBytes"],
                "hashOffsetBytes": descriptor["hashOffsetBytes"],
                "dataBytes": descriptor["dataBytes"],
            },
        }
    )
    validate_manifest(raw, record)
    return raw


def approve(authority, volume_id, raw):
    """Trusted administrator operation, never selected by a guest request.

    New releases require new records/keys and explicit workload policy selection.
    An existing record can never be updated to another image/root, even after
    close. Revocation blocks new openings; it cannot erase an already loaded key.
    """
    with authority._transaction() as db:
        record = authority._load(db, volume_id)
        binding = record.get("mount_binding") or {}
        if (
            record["revoked"]
            or binding.get("access") != "ro"
            or not supports("ro", record["profile_sha256"], binding.get("destination"))
            or record.get("initialization_approval")
            or record.get("initialization_steps")
        ):
            raise Denied("publication requires a bound uninitialized read-only model")
        manifest = validate_manifest(raw, record)
        approved = {
            "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "header_sha256": manifest["headerSha256"],
            "source": manifest["source"],
            "verity_root": manifest["verity"]["root"],
        }
        previous = record.get("publication_approval")
        if previous is not None:
            if previous != approved or record["state"] != "Ready":
                raise Denied("published model approval is immutable")
            return record
        if record["state"] != "Uninitialized" or record["owner"] is not None:
            raise Denied("published model requires a fresh registration")
        record.update(
            state="Ready",
            publication_approval=approved,
            header_sha256=approved["header_sha256"],
            manifest_sha256=approved["manifest_sha256"],
        )
        authority._save(db, record, "approve-published-model")
        return record


def require_ready(record, header, manifest):
    approved = record.get("publication_approval")
    binding = record.get("mount_binding") or {}
    if (
        record["state"] != "Ready"
        or not approved
        or binding.get("access") != "ro"
        or not supports("ro", record["profile_sha256"], binding.get("destination"))
        or record.get("initialization_approval")
        or record.get("initialization_steps")
        or approved["header_sha256"] != header
        or approved["manifest_sha256"] != manifest
    ):
        raise Denied("published model is not approved for this exact manifest")
