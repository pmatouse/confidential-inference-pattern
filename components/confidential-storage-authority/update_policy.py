"""Administrator-only policy upgrade. Requires closed Ready retained volumes."""

import argparse
from pathlib import Path
from authority import Authority


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--volume-id", action="append", required=True)
    parser.add_argument("--old-policy", required=True)
    parser.add_argument("--new-policy", required=True)
    parser.add_argument("--evidence-sha256", required=True)
    args = parser.parse_args()
    if not args.database.is_file() or args.database.is_symlink():
        raise ValueError("Existing retained database required")
    Authority(args.database).update_workload_policy(
        args.volume_id, args.old_policy, args.new_policy, args.evidence_sha256
    )
    print("Policy updated atomically; disk identities and history retained")


if __name__ == "__main__":
    main()
