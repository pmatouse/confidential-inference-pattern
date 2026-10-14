"""Administrator CLI: release only a journal-proven unstarted initialization.

Not exposed by the HTTPS gateway. First stop the failed guest, retain a database
backup and inspect converter readiness. This never recovers an issued step.
"""

import argparse
from pathlib import Path

from authority import Authority


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--volume-id", required=True)
    parser.add_argument("--activation-id", required=True)
    parser.add_argument("--evidence-sha256", required=True)
    args = parser.parse_args()
    if not args.database.is_file() or args.database.is_symlink():
        raise ValueError("Existing retained authority database required")
    authority = Authority(args.database)
    result = authority.release_unstarted_initialization(
        args.volume_id, args.activation_id, args.evidence_sha256
    )
    print("Unstarted initialization released; old session retired; history retained")
    assert result["state"] == "Uninitialized" and result["owner"] is None


if __name__ == "__main__":
    main()
