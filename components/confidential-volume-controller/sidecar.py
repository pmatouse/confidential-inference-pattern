"""Approved stock-Kata sidecar deployment; no keys or authority mutation."""

import base64
import copy
import gzip
import hashlib
import json
import tomllib

from compiler import (
    ANNOTATION,
    API,
    canonical,
    digest,
    fields,
    name,
    parse,
    require,
    uid,
)

OWNER = "storage.confidentialcontainers.org/confidential-workload-uid"
MODE = "stock-kata-sidecar/v1"
EXTRA = "sidecar-deployment.json"


def desired(obj, declarations):
    """Compile user intent, never the controller's generated KServe predictor."""
    fields(obj["spec"], {"template"}, {"adoptExistingUID"})
    source = obj["spec"]["template"]
    fields(source, {"metadata", "spec"})
    fields(source["metadata"], {"name"}, {"annotations", "labels"})
    fields(source["spec"], {"predictor"})
    ns = obj["metadata"]["namespace"]
    owner = uid(obj["metadata"]["uid"])
    target = name(source["metadata"]["name"])
    if "adoptExistingUID" in obj["spec"]:
        uid(obj["spec"]["adoptExistingUID"])
    out = {
        "apiVersion": "serving.kserve.io/v1beta1",
        "kind": "InferenceService",
        "metadata": {
            **copy.deepcopy(source["metadata"]),
            "namespace": ns,
            "uid": owner,
        },
        "spec": copy.deepcopy(source["spec"]),
    }
    p = out["spec"]["predictor"]
    require(len(p.get("containers", [])) == 1, "one application required")
    app = p["containers"][0]
    require(not app.get("volumeDevices"), "raw devices are controller-owned")
    bindings = parse(p.get("annotations", {}).get(ANNOTATION, ""), 32768)
    require(type(bindings) is list and 1 <= len(bindings) <= 8, "invalid bindings")
    p.setdefault("volumes", [])
    app["volumeDevices"] = []
    for i, binding in enumerate(bindings):
        d = declarations[name(binding["confidentialVolume"])]["spec"]
        p["volumes"].append(
            {
                "name": name(binding["volume"]),
                "persistentVolumeClaim": {
                    "claimName": d["claimRef"]["name"],
                    "readOnly": d["access"] == "ReadOnly",
                },
            }
        )
        app["volumeDevices"].append(
            {"name": binding["volume"], "devicePath": f"/dev/coco-volume-{i}"}
        )
    out["_sidecarOwner"] = obj
    return out


def request_binding(workload):
    obj = workload["_sidecarOwner"]
    return {
        "mode": MODE,
        "ownerName": obj["metadata"]["name"],
        "ownerUID": obj["metadata"]["uid"],
        "adoptExistingUID": obj["spec"].get("adoptExistingUID"),
        "desired": obj["spec"]["template"],
    }


def validate(artifacts, request, guest, runtime):
    import re

    binding = request["deployment"]
    require(binding["mode"] == MODE, "unsupported deployment mode")
    package = parse(artifacts[EXTRA], 256 * 1024)
    fields(package, {"predictor", "metadata"})
    fields(package["metadata"], {"annotations", "labels"})
    for values in package["metadata"].values():
        require(
            type(values) is dict
            and all(type(k) is str and type(v) is str for k, v in values.items()),
            "invalid metadata",
        )
    p = package["predictor"]
    require(
        p["runtimeClassName"] == runtime["runtimeClassName"] == "kata-cc-nvidia-gpu",
        "stock GPU runtime required",
    )
    require(
        p.get("shareProcessNamespace") is True
        and p.get("automountServiceAccountToken") is False,
        "guest PID and token boundary",
    )
    require(
        not any(
            p.get(k)
            for k in [
                "hostPID",
                "hostIPC",
                "hostNetwork",
                "initContainers",
                "ephemeralContainers",
            ]
        ),
        "unsafe pod namespace or containers",
    )
    require(
        p.get("serviceAccountName") == "storage-sidecar", "dedicated identity required"
    )
    require(
        p.get("minReplicas") == p.get("maxReplicas") == 1
        and p.get("deploymentStrategy") == {"type": "Recreate"},
        "single-owner rollout required",
    )
    containers = p["containers"]
    require(
        len(containers) == 2
        and [c["name"] for c in containers] == ["kserve-container", "storage-sidecar"],
        "invalid container roles",
    )
    app, helper = containers
    require(
        app["image"] == request["contract"]["workload"]["image"],
        "application image changed",
    )
    sc = app["securityContext"]
    require(
        sc.get("runAsUser") == sc.get("runAsGroup") == 1001
        and sc.get("runAsNonRoot") is True
        and sc.get("privileged") is False
        and sc.get("allowPrivilegeEscalation") is False
        and sc.get("readOnlyRootFilesystem") is True
        and sc.get("capabilities") == {"drop": ["ALL"]}
        and not app.get("volumeDevices"),
        "application must remain unprivileged",
    )
    require(
        helper.get("securityContext") == {"runAsUser": 0, "privileged": True}
        and re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", helper["image"]),
        "pinned guest helper required",
    )
    encoded = p["annotations"]["io.katacontainers.config.hypervisor.cc_init_data"]
    # Bound decompression; never allocate arbitrary attacker-supplied gzip output.
    import io

    with gzip.GzipFile(
        fileobj=io.BytesIO(base64.b64decode(encoded, validate=True))
    ) as stream:
        raw = stream.read(65537)
    require(
        raw == artifacts["initdata.toml"].encode() and len(raw) <= 65536,
        "deployment InitData mismatch",
    )
    data = tomllib.loads(raw.decode())["data"]
    config = json.loads(data["storage-sidecar.json"])
    require(config["consumerArgs"] == app["command"], "consumer command mismatch")
    service = copy.deepcopy(config["service"])
    service["authority"].update(
        init_data=runtime["initDataSha256"],
        policy_sha256=hashlib.sha256(data["policy.rego"].encode()).hexdigest(),
    )
    for v in service["volumes"]:
        v["expected"]["policy_sha256"] = service["authority"]["policy_sha256"]
    require(service == guest, "guest configuration is not measured")
    entries = request["contract"]["volumes"]
    devices = {d["name"]: d["devicePath"] for d in helper["volumeDevices"]}
    claims = {
        v["name"]: v["persistentVolumeClaim"]
        for v in p["volumes"]
        if "persistentVolumeClaim" in v
    }
    require(
        len(devices) == len(entries) == len(helper["volumeDevices"])
        and set(claims) == set(devices),
        "unexpected storage attachment",
    )
    mounts = {m["mountPath"]: m["name"] for m in app.get("volumeMounts", [])}
    volumes = {v["name"]: v for v in p["volumes"]}
    require(len(volumes) == len(p["volumes"]), "duplicate volume")
    for e in entries:
        require(
            devices[e["bindingId"]] == e["devicePath"]
            and claims[e["bindingId"]]
            == {
                "claimName": e["claimRef"]["name"],
                "readOnly": e["access"] == "ReadOnly",
            },
            "attachment differs from declaration",
        )
        require(
            volumes[mounts[e["mountPath"]]].get("emptyDir", {}).get("medium")
            == "Memory",
            "plaintext target must be guest memory",
        )
    config_name = "cv-sidecar-" + runtime["initDataSha256"][:48]
    require(
        volumes["configuration"].get("configMap") == {"name": config_name},
        "configuration reference mismatch",
    )
    for v in p["volumes"]:
        require(
            "persistentVolumeClaim" in v
            or (v["name"] == "configuration" and "configMap" in v)
            or v.get("emptyDir", {}).get("medium") == "Memory",
            "unsupported volume",
        )
    return package, config_name


def deploy(api, workload, request, artifacts, runtime, approval_sha, allowed_targets):
    """Create/adopt/update only the approved target; retain the owner on renewal."""
    obj = workload["_sidecarOwner"]
    ns = obj["metadata"]["namespace"]
    target = workload["metadata"]["name"]
    require(target in allowed_targets, "target not enabled for deployment")
    guest = parse(artifacts["guest-config.json"])
    package, config_name = validate(artifacts, request, guest, runtime)
    from controller import ensure, configmap

    cm = configmap(
        ns,
        "sidecar",
        runtime["initDataSha256"],
        {"initdata.toml": artifacts["initdata.toml"]},
    )
    cm["metadata"]["name"] = config_name
    ensure(api, cm)
    current = api.get("InferenceService", target)
    metadata = copy.deepcopy(package["metadata"])
    metadata.update(name=target, namespace=ns)
    metadata["labels"][OWNER] = obj["metadata"]["uid"]
    metadata["annotations"][
        "storage.confidentialcontainers.org/approval-sha256"
    ] = approval_sha
    owner = {
        "apiVersion": API,
        "kind": "ConfidentialWorkload",
        "name": obj["metadata"]["name"],
        "uid": obj["metadata"]["uid"],
        "controller": True,
        "blockOwnerDeletion": False,
    }
    metadata["ownerReferences"] = [owner]
    wanted = {
        "apiVersion": "serving.kserve.io/v1beta1",
        "kind": "InferenceService",
        "metadata": metadata,
        "spec": {"predictor": package["predictor"]},
    }
    if current is None:
        api.create_workload(wanted)
        return "Created"
    require(not current["metadata"].get("deletionTimestamp"), "target terminating")
    owned = current["metadata"].get("labels", {}).get(OWNER) == obj["metadata"][
        "uid"
    ] and owner in current["metadata"].get("ownerReferences", [])
    require(
        owned
        or (
            current["metadata"]["uid"] == obj["spec"].get("adoptExistingUID")
            and not current["metadata"].get("ownerReferences")
        ),
        "target belongs to someone else",
    )
    # Preserve API bookkeeping, unrelated metadata and status; own the full spec.
    body = copy.deepcopy(current)
    for k in ["labels", "annotations"]:
        body["metadata"].setdefault(k, {}).update(metadata[k])
    body["metadata"]["ownerReferences"] = [owner]
    body["spec"] = wanted["spec"]
    if body != current:
        api.update_workload(body)
        return "Updated"
    return "Unchanged"
