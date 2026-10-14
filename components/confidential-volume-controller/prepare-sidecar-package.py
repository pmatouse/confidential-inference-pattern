#!/usr/bin/env python3
"""Package reviewed public sidecar output for signing; never deploy or authorize keys."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import tomllib

from controller import MAX_BYTES, parse, validate_artifacts


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--request", type=Path, required=True)
    p.add_argument("--workload", type=Path, required=True)
    p.add_argument("--configuration", type=Path, required=True)
    p.add_argument("--runtime", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    request = parse(args.request.read_bytes(), MAX_BYTES)
    if request.get("kind") == "ConfigMap":
        request = parse(request["data"]["request.json"], MAX_BYTES)
    workload = parse(args.workload.read_bytes(), MAX_BYTES)
    configuration = parse(args.configuration.read_bytes(), MAX_BYTES)
    raw = configuration["data"]["initdata.toml"]
    data = tomllib.loads(raw)["data"]
    guest = json.loads(data["storage-sidecar.json"])["service"]
    guest["authority"].update(
        init_data=hashlib.sha256(raw.encode()).hexdigest(),
        policy_sha256=hashlib.sha256(data["policy.rego"].encode()).hexdigest(),
    )
    for v in guest["volumes"]:
        v["expected"]["policy_sha256"] = guest["authority"]["policy_sha256"]
    predictor = copy.deepcopy(workload["spec"]["predictor"])
    next(v for v in predictor["volumes"] if v["name"] == "configuration")["configMap"][
        "name"
    ] = ("cv-sidecar-" + guest["authority"]["init_data"][:48])
    # Resource quantities are strings in Kubernetes API responses; default TCP
    # explicitly so repeat reconciliation does not fight API serialization.
    for c in predictor["containers"]:
        for direction in ["requests", "limits"]:
            if direction in c.get("resources", {}):
                c["resources"][direction] = {
                    k: str(v) for k, v in c["resources"][direction].items()
                }
        for port in c.get("ports", []):
            port.setdefault("protocol", "TCP")
    metadata = {k: workload["metadata"].get(k, {}) for k in ["labels", "annotations"]}
    metadata["annotations"] = {
        k: v
        for k, v in metadata["annotations"].items()
        if not k.startswith("kubectl.kubernetes.io/")
        and not k.startswith("storage.confidentialcontainers.org/")
    }
    artifacts = {
        "guest-config.json": json.dumps(guest, separators=(",", ":")),
        "initdata.toml": raw,
        "runtime.json": args.runtime.read_text(),
        "sidecar-deployment.json": json.dumps(
            {"predictor": predictor, "metadata": metadata}, separators=(",", ":")
        ),
    }
    validate_artifacts(artifacts, request)
    args.output.mkdir(mode=0o755)  # Refuse replacing an existing reviewed package.
    for name, text in artifacts.items():
        (args.output / name).write_text(text)
    print("Public package validated; no signing, enrollment or deployment performed")


if __name__ == "__main__":
    main()
