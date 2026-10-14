"""Build a narrowly reviewed stock-agent policy profile from public OCI fixtures."""

import copy
import json
from pathlib import Path
import re


def settings(request):
    request = copy.deepcopy(request)
    process = request["OCI"]["Process"]
    mounts = request["OCI"]["Mounts"]
    for mount in mounts:
        source = mount["source"]
        if source.startswith("/run/kata-containers/shared/containers/"):
            match = re.fullmatch(
                r"/run/kata-containers/shared/containers/[a-f0-9]{64}-[a-f0-9]{16}-([A-Za-z0-9_.-]+)",
                source,
            )
            if not match:
                raise ValueError("Unexpected shared-file locator")
            mount["source"] = "shared:" + re.escape(match[1])
    images = [s for s in request["storages"] if s["driver"] == "image_guest_pull"]
    if len(images) != 1:
        raise ValueError("Exactly one guest image required")
    return {
        "image": images[0]["source"],
        "args": process["Args"],
        "uid": process["User"]["UID"],
        "gid": process["User"]["GID"],
        "additionalGroups": [process["User"]["AdditionalGids"]],
        "noNewPrivileges": process["NoNewPrivileges"],
        "readonlyRoot": request["OCI"]["Root"]["Readonly"],
        "environment": sorted(set(process["Env"])),
        "requiredEnvironment": sorted(set(process["Env"])),
        "capabilities": sorted(
            set(c for v in process["Capabilities"].values() for c in v)
        ),
        "mounts": mounts,
        "ephemeralStorages": [
            s for s in request["storages"] if s["driver"] == "ephemeral"
        ],
        "rawDevices": [
            d["container_path"] for d in request["devices"] if d["type_"] == "scsi"
        ],
    }


def render(profile):
    # Keep lines bounded for stock policy engines, including long CUDA env/code.
    raw = json.dumps(profile, sort_keys=True, separators=(",", ":"))
    chunks = [raw[n : n + 256] for n in range(0, len(raw), 256)]
    expression = (
        'json.unmarshal(concat("", [\n'
        + ",\n".join(json.dumps(c) for c in chunks)
        + "\n]))"
    )
    return (
        Path(__file__)
        .with_name("policy.rego.in")
        .read_text()
        .replace("__PROFILE_JSON__", expression)
    )
