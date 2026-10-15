"""Administrator-only reapproval of unchanged, never-started blank storage."""
import argparse
from pathlib import Path
from authority import Authority


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--database", type=Path, required=True)
    p.add_argument("--volume-id", required=True)
    p.add_argument("--policy", required=True)
    p.add_argument("--previous-plan", required=True)
    p.add_argument("--evidence-sha256", required=True)
    a = p.parse_args()
    if not a.database.is_file() or a.database.is_symlink():
        raise ValueError("Existing retained database required")
    r = Authority(a.database).rebind_unstarted_initialization(
        a.volume_id, a.policy, a.previous_plan, a.evidence_sha256)
    print(r["initialization_approval"]["plan_sha256"])


if __name__ == "__main__":
    main()
