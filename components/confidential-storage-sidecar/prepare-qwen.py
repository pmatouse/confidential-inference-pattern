#!/usr/bin/env python3
"""Render the stock-Kata Qwen migration; never changes a cluster or authority."""
import argparse
import base64
import copy
import gzip
import hashlib
import json
from pathlib import Path
import re
import tomllib

import yaml
from policy import render, settings

RENDEZVOUS = """import socket, time
_storage = socket.socket(socket.AF_UNIX)
_deadline = time.monotonic() + 600
while True:
    try:
        _storage.connect('/rendezvous/storage.sock')
        break
    except (FileNotFoundError, ConnectionRefusedError):
        if time.monotonic() >= _deadline:
            raise RuntimeError('storage supervisor unavailable')
        time.sleep(0.25)
_storage.settimeout(600)
_ready = b''
while len(_ready) < 6:
    _part = _storage.recv(6 - len(_ready))
    if not _part:
        raise RuntimeError('storage supervisor disconnected')
    _ready += _part
if _ready != b'READY\\n':
    raise RuntimeError('storage supervisor rejected startup')
_storage.close()
del _storage, _ready, _part, _deadline
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current-public-directory", type=Path, required=True)
    parser.add_argument("--kserve-manifest", type=Path, required=True)
    parser.add_argument("--bootstrap-configmap", type=Path, required=True)
    parser.add_argument("--sidecar-image", required=True)
    parser.add_argument("--sidecar-build-name", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", args.sidecar_image):
        parser.error("Pin the reviewed public sidecar image by digest")
    directory = args.current_public_directory
    service = json.loads((directory / "guest-public.json").read_text())
    workload = json.loads((directory / "workload.json").read_text())
    if service["schema_version"] != 2 or len(service["volumes"]) != 2:
        raise ValueError("This example requires the reviewed two-volume Qwen binding")
    source = list(yaml.safe_load_all(args.kserve_manifest.read_text()))
    inference = copy.deepcopy(
        next(p for p in source if p["kind"] == "InferenceService")
    )
    if inference["metadata"]["name"] != "qwen-storage":
        raise ValueError("Only the newer qwen-storage workload may be migrated")
    predictor = inference["spec"]["predictor"]
    application = predictor["containers"][0]
    if application["image"] != workload["image"]:
        raise ValueError("Application image changed")
    application["command"] = [
        "/usr/bin/python3",
        "-c",
        RENDEZVOUS + workload["args"][2],
    ]
    application["readinessProbe"] = {
        "httpGet": {"path": "/health", "port": 8000},
        "periodSeconds": 5,
        "timeoutSeconds": 2,
        "failureThreshold": 3,
    }
    transports = application.pop("volumeDevices")
    application["volumeMounts"] = [
        {"name": name, "mountPath": target}
        for name, target in [
            ("rendezvous", "/rendezvous"),
            ("model-target", "/models/qwen"),
            ("data-target", "/data"),
            ("shm", "/dev/shm"),
        ]
    ]
    helper = {
        "name": "storage-sidecar",
        "image": args.sidecar_image,
        "command": ["python3", "/opt/storage-sidecar/runtime.py"],
        "env": [{"name": "INFERENCE_SERVICE_NAME", "value": "qwen-storage"}],
        "securityContext": {"runAsUser": 0, "privileged": True},
        "resources": {
            "requests": {"cpu": "1", "memory": "2Gi"},
            "limits": {"cpu": "2", "memory": "4Gi"},
        },
        "volumeDevices": transports,
        "volumeMounts": [
            {"name": "configuration", "mountPath": "/configuration", "readOnly": True},
            {"name": "rendezvous", "mountPath": "/rendezvous"},
        ],
    }
    predictor.update(
        serviceAccountName="storage-sidecar",
        runtimeClassName="kata-cc-nvidia-gpu",
        shareProcessNamespace=True,
        securityContext={"fsGroup": 1001},
        terminationGracePeriodSeconds=180,
        hostname="qwen-storage-sidecar",
        containers=[application, helper],
    )
    configuration_name = "qwen-storage-sidecar-configuration"
    predictor["volumes"] += [
        {"name": "configuration", "configMap": {"name": configuration_name}},
        *[
            {"name": name, "emptyDir": {"medium": "Memory", "sizeLimit": size}}
            for name, size in [
                ("rendezvous", "4Mi"),
                ("model-target", "4Mi"),
                ("data-target", "4Mi"),
                ("shm", "4Gi"),
            ]
        ],
    ]
    fixtures = (
        Path(__file__).resolve().parents[2]
        / "tests/confidential-storage/stock-agent-sidecar/fixtures"
    )
    profile = {
        "namespace": inference["metadata"]["namespace"],
        "gpuCount": 1,
        **{
            role: settings(json.loads((fixtures / (role + ".json")).read_text()))
            for role in ["pause", "helper", "application"]
        },
    }
    h, a = profile["helper"], profile["application"]
    h.update(
        image=args.sidecar_image,
        args=helper["command"],
        additionalGroups=[[0, 1001], [1001, 0], [1001]],
        rawDevices=[d["devicePath"] for d in transports],
    )
    h["environment"] = [
        e if not e.startswith("HOSTNAME=") else "HOSTNAME=qwen-storage-sidecar"
        for e in h["environment"]
    ]
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", args.sidecar_build_name):
        raise ValueError("Invalid reviewed OpenShift build name")
    h["environment"] = [
        (
            e
            if not e.startswith("OPENSHIFT_BUILD_NAME=")
            else "OPENSHIFT_BUILD_NAME=" + args.sidecar_build_name
        )
        for e in h["environment"]
    ]
    h["environment"] = sorted(
        set(h["environment"]) | {"INFERENCE_SERVICE_NAME=qwen-storage"}
    )
    h["requiredEnvironment"] = h["environment"]
    # These are the stock runtime's guest-memory mount requests, observed with
    # the same fsGroup. No host filesystem is used for plaintext destinations.
    rendezvous = next(m for m in a["mounts"] if m["destination"] == "/rendezvous")
    h["mounts"].append(copy.deepcopy(rendezvous))
    h["ephemeralStorages"] = [
        copy.deepcopy(s)
        for s in a["ephemeralStorages"]
        if s["mount_point"].endswith("/rendezvous")
    ]
    a["args"] = application["command"]
    bootstrap = tomllib.loads(
        json.loads(args.bootstrap_configmap.read_text())["data"]["initdata.toml"]
    )
    data = {k: bootstrap["data"][k] for k in ["aa.toml", "cdh.toml"]}
    data["policy.rego"] = render(profile)
    # Derived hashes are filled only AFTER the stock AA verifies all InitData
    # against SNP HOST_DATA, avoiding self-referential policy hashes.
    service["authority"]["policy_sha256"] = ""
    service["authority"]["init_data"] = ""
    for volume in service["volumes"]:
        volume["expected"]["policy_sha256"] = ""
    data["storage-sidecar.json"] = json.dumps(
        {
            "schemaVersion": 1,
            "service": service,
            "consumerArgs": application["command"],
        },
        separators=(",", ":"),
    )
    raw = 'version = "0.1.0"\nalgorithm = "sha256"\n[data]\n' + "".join(
        json.dumps(k) + " = " + json.dumps(v) + "\n" for k, v in sorted(data.items())
    )
    if len(raw.encode()) > 65536:
        raise ValueError("InitData exceeds the reviewed 64 KiB service limit")
    init_hash = hashlib.sha256(raw.encode()).hexdigest()
    policy_hash = hashlib.sha256(data["policy.rego"].encode()).hexdigest()
    configuration_name += "-" + init_hash[:12]
    next(v for v in predictor["volumes"] if v["name"] == "configuration")["configMap"][
        "name"
    ] = configuration_name
    predictor["annotations"] = {
        "openshift.io/required-scc": "confidential-storage-sidecar",
        "io.katacontainers.config.hypervisor.cc_init_data": base64.b64encode(
            gzip.compress(raw.encode(), mtime=0)
        ).decode(),
        "io.katacontainers.config.hypervisor.kernel_params": "agent.log=warn agent.guest_components_procs=confidential-data-hub",
        "io.katacontainers.config.hypervisor.default_memory": "65536",
        "io.katacontainers.config.hypervisor.default_vcpus": "8",
        "io.katacontainers.config.runtime.create_container_timeout": "300",
    }
    configmap = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": configuration_name, "namespace": profile["namespace"]},
        "immutable": True,
        "data": {"initdata.toml": raw},
    }
    args.output.mkdir(parents=True, exist_ok=True)
    for name, obj in [
        ("kserve.json", inference),
        ("configuration.json", configmap),
        ("profile.json", profile),
    ]:
        (args.output / name).write_text(json.dumps(obj, indent=2) + "\n")
    (args.output / "initdata.toml").write_text(raw)
    (args.output / "policy.rego").write_text(data["policy.rego"])
    (args.output / "identity.json").write_text(
        json.dumps(
            {
                "policy_sha256": policy_hash,
                "init_data": init_hash,
                "sidecar_image": args.sidecar_image,
                "application_image": application["image"],
                "status": "rendered-only-not-approved-or-deployed",
            },
            indent=2,
        )
        + "\n"
    )
    print(f"Rendered {len(raw.encode())} bytes of InitData; no cluster changes")


if __name__ == "__main__":
    main()
