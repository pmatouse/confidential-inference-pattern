"""Exact guest profile catalog. Never accept crypto arguments from requests."""

import hashlib
from pathlib import Path
import re

PROFILES = Path(__file__).resolve().parents[1] / "confidential-storage-guest/profiles"


def destination(value):
    if not isinstance(value, str) or len(value) > 256 or not value.startswith("/"):
        return False
    parts = value[1:].split("/")
    return (
        1 <= len(parts) <= 8
        and parts[0] in {"models", "data", "checkpoints"}
        and all(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}", p) for p in parts)
    )


def profile_digest(name):
    if name not in {
        "rw-luks2-v1",
        "rw-luks2-v2",
        "ro-luks2-verity-v1",
        "ro-luks2-verity-v2",
    }:
        raise ValueError("unsupported compiled profile")
    return hashlib.sha256((PROFILES / (name + ".json")).read_bytes()).hexdigest()


def supports(access, digest, path):
    if access not in {"ro", "rw"} or not destination(path):
        return False
    stem, legacy_path = (
        ("ro-luks2-verity", "/models") if access == "ro" else ("rw-luks2", "/data")
    )
    return (digest == profile_digest(stem + "-v1") and path == legacy_path) or (
        digest == profile_digest(stem + "-v2")
    )
