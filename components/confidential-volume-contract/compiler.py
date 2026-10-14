#!/usr/bin/env python3
"""Compile explicit volume declarations into a bounded APPROVAL REQUEST.

No cluster access, signer, key lookup, formatting or runtime activation occurs.
The output is not an approved guest configuration. The authority/build pipeline
must independently resolve and approve profile/content/lifecycle identities.
JSON input avoids implicit YAML types and rejects duplicate object members.
"""

import argparse
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re

API = "storage.confidentialcontainers.org/v1alpha1"
ANNOTATION = "storage.confidentialcontainers.org/bindings"
MAX_VOLUMES = 8
MAX_CONTRACT = 32768  # Reserve space within 64 KiB InitData for agent policy.
MAX_INPUT = 1024 * 1024
NAME = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
UUID = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
URI = r"kbs:///[a-z0-9][a-z0-9-]{0,62}/[a-z0-9][a-z0-9-]{0,62}/[a-z0-9][a-z0-9-]{0,62}"
# Deliberately narrow roots for the first integration. Arbitrary root paths would
# let a storage mount shadow binaries, controls or runtime configuration.
ROOTS = {"model", "models", "data", "checkpoints"}


class Invalid(ValueError):
    """Fixed error descriptions must not reflect input resource/secret values."""


def require(condition, message):
    if not condition:
        raise Invalid(message)


def fields(value, required, optional=()):
    require(type(value) is dict, "expected an object")
    require(set(required) <= value.keys(), "missing required field")
    require(value.keys() <= set(required) | set(optional), "unknown field")


def name(value):
    require(type(value) is str and re.fullmatch(NAME, value), "invalid name")
    return value


def uid(value):
    require(type(value) is str and re.fullmatch(UUID, value), "invalid UID")
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON member")
        value[key] = item
    return value


def parse(data, maximum=MAX_INPUT):
    require(len(data) <= maximum, "input too large")
    try:
        return json.loads(
            data,
            object_pairs_hook=no_duplicates,
            parse_constant=lambda _: (_ for _ in ()).throw(Invalid("invalid number")),
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise Invalid("invalid JSON") from error


def metadata(obj, namespace):
    meta = obj.get("metadata", {})
    require(type(meta) is dict, "invalid metadata")
    require(meta.get("namespace") == namespace, "cross-namespace reference")
    return name(meta.get("name"))


def size(value):
    # Bound and normalize only the exact integer/binary quantities used by this
    # implementation. Refuse lossy floats, unknown suffixes and expansion.
    require(type(value) is str and len(value) <= 24, "invalid capacity")
    match = re.fullmatch(r"([1-9][0-9]*)(Ki|Mi|Gi)?", value)
    if match:
        result = (
            int(match[1])
            * {None: 1, "Ki": 1024, "Mi": 1024**2, "Gi": 1024**3}[match[2]]
        )
    else:
        # The API serializes some integral quantities as e.g. 2.147483648e+09.
        # Decimal avoids a lossy float conversion; exponents/input are bounded.
        require(
            re.fullmatch(r"[1-9][0-9]*(?:\.[0-9]+)?[eE][+-]?[0-9]{1,2}", value),
            "unsupported capacity notation",
        )
        exact = Decimal(value)
        require(exact == exact.to_integral_value(), "fractional byte capacity")
        result = int(exact)
    require(
        64 * 1024**2 <= result <= 64 * 1024**3 and result % 4096 == 0,
        "unsupported capacity",
    )
    return result


def destination(value):
    require(type(value) is str and len(value) <= 256, "invalid destination")
    parts = value.split("/")
    require(
        2 <= len(parts) <= 9 and parts[0] == "" and parts[1] in ROOTS,
        "unsupported destination root",
    )
    require(
        all(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}", p) for p in parts[1:]),
        "invalid destination component",
    )
    return value


def overlap(a, b):
    return (
        a == "/" or b == "/" or a == b or a.startswith(b + "/") or b.startswith(a + "/")
    )


def declaration(obj, namespace):
    fields(obj, {"apiVersion", "kind", "metadata", "spec"}, {"status"})
    require(
        obj["apiVersion"] == API and obj["kind"] == "ConfidentialVolume",
        "unexpected declaration kind",
    )
    declared_name = metadata(obj, namespace)
    spec = obj["spec"]
    fields(
        spec,
        {"claimRef", "access", "profile", "initialization", "keyResource"},
        {"content"},
    )
    fields(spec["claimRef"], {"name", "uid"})
    name(spec["claimRef"]["name"])
    uid(spec["claimRef"]["uid"])
    require(
        type(spec["keyResource"]) is str and re.fullmatch(URI, spec["keyResource"]),
        "invalid key resource",
    )
    init = spec["initialization"]
    if spec["access"] == "ReadOnly":
        require(spec["profile"] == "luks-verity-v1", "invalid model profile")
        fields(init, {"policy"})
        require(init["policy"] == "Never", "models cannot initialize")
        require("content" in spec, "model approval reference required")
        fields(spec["content"], {"approvedManifestRef"})
        name(spec["content"]["approvedManifestRef"])
    elif spec["access"] == "ReadWrite":
        require(
            spec["profile"] == "luks-integrity-v1" and "content" not in spec,
            "invalid writable profile",
        )
        fields(init, {"policy", "filesystem", "owner"})
        require(
            init["policy"] in {"Never", "OnceIfApproved"}
            and init["filesystem"] == "ext4",
            "invalid initialization policy",
        )
        fields(init["owner"], {"uid", "gid"})
        require(
            all(type(x) is int and 0 < x <= 2147483647 for x in init["owner"].values()),
            "non-root integer ownership required",
        )
    else:
        raise Invalid("invalid access")
    return declared_name, spec


def indexed(objects, namespace, kind):
    require(
        type(objects) is list and len(objects) <= MAX_VOLUMES, "invalid object list"
    )
    result = {}
    for obj in objects:
        require(type(obj) is dict and obj.get("kind") == kind, "unexpected object kind")
        key = metadata(obj, namespace)
        require(key not in result, "duplicate resource name")
        result[key] = obj
    return result


def compile_contract(bundle):
    fields(bundle, {"namespace", "workload", "declarations", "claims"})
    namespace = name(bundle["namespace"])
    workload = bundle["workload"]
    require(type(workload) is dict, "invalid workload")
    workload_name = metadata(workload, namespace)
    if workload.get("apiVersion") == "v1" and workload.get("kind") == "Pod":
        pod = workload.get("spec", {})
        annotations = workload["metadata"].get("annotations", {})
    elif (
        workload.get("apiVersion") == "serving.kserve.io/v1beta1"
        and workload.get("kind") == "InferenceService"
    ):
        pod = workload.get("spec", {}).get("predictor", {})
        annotations = pod.get("annotations", {})
    else:
        raise Invalid("unsupported workload kind")
    require(type(pod) is dict and type(annotations) is dict, "invalid pod template")
    raw = annotations.get(ANNOTATION)
    require(type(raw) is str, "explicit binding annotation required")
    bindings = parse(raw, MAX_CONTRACT)
    require(
        type(bindings) is list and 1 <= len(bindings) <= MAX_VOLUMES,
        "invalid binding count",
    )
    declarations = indexed(bundle["declarations"], namespace, "ConfidentialVolume")
    claims = indexed(bundle["claims"], namespace, "PersistentVolumeClaim")
    require(
        not pod.get("initContainers") and not pod.get("ephemeralContainers"),
        "additional consumers unsupported",
    )
    containers = pod.get("containers", [])
    require(
        type(containers) is list and len(containers) == 1,
        "one explicit consuming container required",
    )
    container = containers[0]
    require(type(container) is dict, "invalid container")
    consumer = name(container.get("name"))
    image = container.get("image")
    require(
        type(image) is str and re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", image),
        "pinned application image required",
    )
    volumes = pod.get("volumes", [])
    require(type(volumes) is list and len(volumes) <= 32, "invalid pod volume list")
    volumes_by_name = {}
    for volume in volumes:
        require(type(volume) is dict, "invalid pod volume")
        n = name(volume.get("name"))
        require(n not in volumes_by_name, "duplicate pod volume")
        volumes_by_name[n] = volume
    devices = container.get("volumeDevices", [])
    require(
        type(devices) is list and len(devices) == len(bindings),
        "unbound or missing block attachment",
    )
    devices_by_name = {}
    paths = set()
    for device in devices:
        fields(device, {"name", "devicePath"})
        n, path = name(device["name"]), device["devicePath"]
        require(
            type(path) is str and re.fullmatch(r"/dev/coco-volume-[0-7]", path),
            "invalid transport attachment",
        )
        require(n not in devices_by_name and path not in paths, "duplicate attachment")
        devices_by_name[n] = path
        paths.add(path)
    mounts = container.get("volumeMounts", [])
    require(type(mounts) is list and len(mounts) <= 32, "invalid mount list")
    entries, destinations, used_decl, used_claim, used_volume, used_keys = (
        [],
        [],
        set(),
        set(),
        set(),
        set(),
    )
    for binding in bindings:
        fields(binding, {"volume", "confidentialVolume", "container", "mountPath"})
        n, declaration_name = name(binding["volume"]), name(
            binding["confidentialVolume"]
        )
        require(binding["container"] == consumer, "consumer mismatch")
        path = destination(binding["mountPath"])
        require(
            not any(overlap(path, old) for old in destinations),
            "overlapping destinations",
        )
        require(
            declaration_name in declarations
            and n in devices_by_name
            and n in volumes_by_name,
            "unresolved binding",
        )
        require(
            declaration_name not in used_decl and n not in used_volume,
            "duplicate binding",
        )
        _, spec = declaration(declarations[declaration_name], namespace)
        claim_ref = spec["claimRef"]
        require(claim_ref["name"] in claims, "unresolved claim")
        claim = claims[claim_ref["name"]]
        require(
            claim.get("apiVersion") == "v1"
            and claim["metadata"].get("uid") == claim_ref["uid"],
            "claim incarnation mismatch",
        )
        require(
            claim_ref["uid"] not in used_claim and spec["keyResource"] not in used_keys,
            "duplicate claim or credential",
        )
        pvc_spec = claim.get("spec", {})
        require(
            pvc_spec.get("volumeMode") == "Block"
            and pvc_spec.get("accessModes") == ["ReadWriteOncePod"],
            "exclusive block claim required",
        )
        requested_bytes = size(
            pvc_spec.get("resources", {}).get("requests", {}).get("storage")
        )
        fields(volumes_by_name[n], {"name", "persistentVolumeClaim"})
        attachment = volumes_by_name[n]["persistentVolumeClaim"]
        fields(attachment, {"claimName"}, {"readOnly"})
        readonly = attachment.get("readOnly", False)
        require(
            type(readonly) is bool and readonly == (spec["access"] == "ReadOnly"),
            "attachment access mismatch",
        )
        require(
            attachment["claimName"] == claim_ref["name"], "attachment claim mismatch"
        )
        for mount in mounts:
            require(
                type(mount) is dict and type(mount.get("mountPath")) is str,
                "invalid existing mount",
            )
            existing = mount["mountPath"]
            require(
                (
                    existing.startswith("/")
                    and "\\" not in existing
                    and not any(ord(c) < 32 for c in existing)
                    and all(
                        part not in {".", "..", ""} for part in existing[1:].split("/")
                    )
                    if existing != "/"
                    else True
                ),
                "noncanonical existing mount",
            )
            require(
                mount.get("name") != n
                and not overlap(path, mount["mountPath"].rstrip("/") or "/"),
                "filesystem mount conflicts with confidential binding",
            )
        used_decl.add(declaration_name)
        used_claim.add(claim_ref["uid"])
        used_volume.add(n)
        used_keys.add(spec["keyResource"])
        destinations.append(path)
        entries.append(
            {
                "bindingId": n,
                "declaration": declaration_name,
                "declarationSpecSha256": digest(spec),
                "claimRef": claim_ref,
                "requestedBytes": requested_bytes,
                "devicePath": devices_by_name[n],
                "container": consumer,
                "mountPath": path,
                "access": spec["access"],
                "profile": spec["profile"],
                "initialization": spec["initialization"],
                "keyResource": spec["keyResource"],
                **({"content": spec["content"]} if "content" in spec else {}),
            }
        )
    require(
        used_decl == declarations.keys() and len(used_claim) == len(claims),
        "unused declaration or claim",
    )
    # This only binds compiler input to later policy generation. A trusted build
    # step must verify the exact generated/mutated OCI spec and reference values.
    result = {
        "schemaVersion": 1,
        "purpose": "confidential-volume-approval-request/v1",
        "namespace": namespace,
        "workload": {
            "apiVersion": workload["apiVersion"],
            "kind": workload["kind"],
            "name": workload_name,
            "container": consumer,
            "image": image,
        },
        "podTemplateSha256": digest(pod),
        "volumes": sorted(entries, key=lambda x: x["bindingId"]),
    }
    require(len(canonical(result)) <= MAX_CONTRACT, "contract exceeds size budget")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with args.input.open("rb") as stream:
        bundle = parse(stream.read(MAX_INPUT + 1))
    contract = compile_contract(bundle)
    # Exclusive creation prevents accidental replacement of an approved artifact.
    with args.output.open("xb") as stream:
        stream.write(canonical(contract) + b"\n")
    print("approval-request-sha256=" + digest(contract))
    print(
        "runtime-activation=false; independent approval and guest integration required"
    )


if __name__ == "__main__":
    main()
