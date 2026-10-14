#!/usr/bin/env python3
"""Namespace-scoped reconciliation; no keys, signing, formatting or pod mutation."""
import argparse
import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "confidential-volume-contract")
)
from compiler import (  # noqa: E402
    ANNOTATION,
    API,
    Invalid,
    canonical,
    compile_contract,
    declaration,
    digest,
    fields,
    name,
    parse,
    require,
    size,
    uid,
)
from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PublicKey,
)  # noqa: E402

GROUP = "storage.confidentialcontainers.org"
MANAGED = GROUP + "/controller"
MAX_BYTES = 768 * 1024
KINDS = {
    "ConfidentialWorkload": "/apis/" + API + "/namespaces/{ns}/confidentialworkloads",
    "ConfidentialVolume": "/apis/" + API + "/namespaces/{ns}/confidentialvolumes",
    "EncryptedModelSource": "/apis/" + API + "/namespaces/{ns}/encryptedmodelsources",
    "PersistentVolumeClaim": "/api/v1/namespaces/{ns}/persistentvolumeclaims",
    "ConfigMap": "/api/v1/namespaces/{ns}/configmaps",
    "InferenceService": "/apis/serving.kserve.io/v1beta1/namespaces/{ns}/inferenceservices",
    "Pod": "/api/v1/namespaces/{ns}/pods",
}
ARTIFACTS = {"guest-config.json", "initdata.toml", "runtime.json"}


class APIError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__("Kubernetes API request failed")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward the projected token to another origin.


class Kubernetes:
    def __init__(self, namespace, origin, ca, token):
        self.namespace = name(namespace)
        url = urllib.parse.urlsplit(origin)
        require(
            url.scheme == "https"
            and url.hostname
            and not url.username
            and not url.password
            and url.path in ("", "/")
            and not url.query
            and not url.fragment,
            "invalid API origin",
        )
        self.origin = origin.rstrip("/")
        self.token = Path(token)
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca)),
        )

    def path(self, kind, resource=None):
        path = KINDS[kind].format(ns=self.namespace)
        return path if resource is None else path + "/" + name(resource)

    def call(self, method, path, obj=None):
        token = self.token.read_text().strip()  # Re-read rotating projected token.
        require(token and "\n" not in token and "\r" not in token, "invalid API token")
        req = urllib.request.Request(
            self.origin + path,
            data=canonical(obj) if obj is not None else None,
            method=method,
            headers={
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json",
            },
        )
        try:
            with self.opener.open(req, timeout=20) as response:
                return parse(response.read(8 * 1024**2 + 1), 8 * 1024**2)
        except urllib.error.HTTPError as error:
            raise APIError(error.code) from None
        except (OSError, urllib.error.URLError):
            raise APIError(0) from None

    def list(self, kind):
        result, cursor = [], ""
        for _ in range(100):
            query = urllib.parse.urlencode({"limit": 100, "continue": cursor})
            page = self.call("GET", self.path(kind) + "?" + query)
            require(type(page.get("items")) is list, "invalid API list")
            version = (
                "v1"
                if kind in {"Pod", "PersistentVolumeClaim", "ConfigMap"}
                else "serving.kserve.io/v1beta1" if kind == "InferenceService" else API
            )
            for item in page["items"]:
                require(type(item) is dict, "invalid list item")
                # Built-in typed lists omit TypeMeta on each item. Restore it
                # from the fixed endpoint, never override contradictory metadata.
                require(
                    item.get("kind", kind) == kind
                    and item.get("apiVersion", version) == version,
                    "unexpected list item type",
                )
                item.setdefault("kind", kind)
                item.setdefault("apiVersion", version)
                result.append(item)
            cursor = page.get("metadata", {}).get("continue", "")
            if not cursor:
                return result
        raise Invalid("resource inventory exceeds limit")

    def get(self, kind, resource):
        try:
            return self.call("GET", self.path(kind, resource))
        except APIError as error:
            if error.code == 404:
                return None
            raise

    def create(self, obj):
        return self.call("POST", self.path("ConfigMap"), obj)

    def intent_status(self, obj, status):
        body = copy.deepcopy(obj)
        body["status"] = status
        return self.call(
            "PUT",
            self.path("ConfidentialWorkload", obj["metadata"]["name"]) + "/status",
            body,
        )

    def create_workload(self, obj):
        return self.call("POST", self.path("InferenceService"), obj)

    def update_workload(self, obj):
        return self.call(
            "PUT", self.path("InferenceService", obj["metadata"]["name"]), obj
        )

    def status(self, obj, status):
        # PUT /status with resourceVersion prevents stale reconciliation winning.
        body = copy.deepcopy(obj)
        body["status"] = status
        return self.call(
            "PUT",
            self.path("ConfidentialVolume", obj["metadata"]["name"]) + "/status",
            body,
        )


def resource_name(prefix, sha):
    return "cv-" + prefix + "-" + sha[:48]


def sha256(value):
    require(
        type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "invalid digest"
    )
    return value


def active(obj):
    require(
        not obj.get("metadata", {}).get("deletionTimestamp"), "resource terminating"
    )


def template(workload):
    return (
        workload["spec"]["predictor"]
        if workload["kind"] == "InferenceService"
        else workload["spec"]
    )


def referenced(workload):
    annotations = (
        template(workload).get("annotations", {})
        if workload["kind"] == "InferenceService"
        else workload["metadata"].get("annotations", {})
    )
    raw = annotations.get(ANNOTATION)
    if raw is None:
        return []
    bindings = parse(raw, 32768)
    require(type(bindings) is list and 1 <= len(bindings) <= 8, "invalid bindings")
    return [name(b["confidentialVolume"]) for b in bindings]


def request_for(namespace, cluster_id, workload, declarations, claims, sources):
    active(workload)
    workload_uid = uid(workload["metadata"].get("uid"))
    names = referenced(workload)
    require(names and len(set(names)) == len(names), "duplicate bindings")
    selected = [declarations[n] for n in names]
    pvc_names = [d["spec"]["claimRef"]["name"] for d in selected]
    pvcs = [claims[n] for n in pvc_names]
    declaration_ids, claim_facts, source_facts = [], [], []
    for d, pvc in zip(selected, pvcs):
        active(d)
        active(pvc)
        declaration(d, namespace)
        require(pvc.get("status", {}).get("phase") == "Bound", "claim not bound")
        p = pvc["spec"]
        require(
            p.get("volumeName") and p.get("storageClassName"), "claim not provisioned"
        )
        declaration_ids.append(
            {"name": d["metadata"]["name"], "uid": uid(d["metadata"].get("uid"))}
        )
        claim_facts.append(
            {
                "name": pvc["metadata"]["name"],
                "uid": uid(pvc["metadata"].get("uid")),
                "storageClassName": p["storageClassName"],
                "volumeName": p["volumeName"],
                "dataSourceRef": p.get("dataSourceRef"),
            }
        )
        source_ref = p.get("dataSourceRef")
        if source_ref:
            fields(source_ref, {"apiGroup", "kind", "name"}, {"namespace"})
            require(
                source_ref["apiGroup"] == GROUP
                and source_ref["kind"] == "EncryptedModelSource"
                and source_ref.get("namespace", namespace) == namespace,
                "unsupported source",
            )
            source = sources[source_ref["name"]]
            active(source)
            require(
                source["metadata"]["namespace"] == namespace, "cross-namespace source"
            )
            fields(
                source["spec"],
                {"format", "repository", "manifestDigest", "diskDigest", "diskBytes"},
            )
            require(
                source["spec"]["format"] == "luks-verity-v1"
                and d["spec"]["access"] == "ReadOnly"
                and source["spec"]["diskBytes"]
                == size(p["resources"]["requests"]["storage"]),
                "source profile or size mismatch",
            )
            for field in ("manifestDigest", "diskDigest"):
                require(
                    re.fullmatch(r"sha256:[0-9a-f]{64}", source["spec"][field]),
                    "invalid source digest",
                )
            source_facts.append(
                {
                    "name": source_ref["name"],
                    "uid": uid(source["metadata"].get("uid")),
                    "spec": source["spec"],
                }
            )
    contract = compile_contract(
        {
            "namespace": namespace,
            "workload": workload,
            "declarations": selected,
            "claims": pvcs,
        }
    )
    request = {
        "schemaVersion": 1,
        "purpose": "confidential-volume-reconcile-request/v1",
        "clusterId": cluster_id,
        "workloadUID": workload_uid,
        "contract": contract,
        "declarations": sorted(declaration_ids, key=lambda x: x["name"]),
        "claims": sorted(claim_facts, key=lambda x: x["name"]),
        "sources": sorted(source_facts, key=lambda x: x["name"]),
    }
    if "_sidecarOwner" in workload:
        from sidecar import request_binding

        request["deployment"] = request_binding(workload)
    require(len(canonical(request)) <= 65536, "request exceeds size budget")
    return request


def validate_artifacts(artifacts, request):
    """Check public package/binding shape; independent signer approves semantics."""
    fields(
        artifacts,
        ARTIFACTS | ({"sidecar-deployment.json"} if "deployment" in request else set()),
    )
    require(
        all(
            type(v) is str and 0 < len(v.encode()) <= 256 * 1024
            for v in artifacts.values()
        ),
        "invalid public artifact",
    )
    guest = parse(artifacts["guest-config.json"].encode(), MAX_BYTES)
    runtime = parse(artifacts["runtime.json"].encode(), MAX_BYTES)
    fields(
        runtime,
        {"runtimeClassName", "guestImageSha256", "launchMeasurement", "initDataSha256"},
    )
    name(runtime["runtimeClassName"])
    sha256(runtime["guestImageSha256"])
    sha256(runtime["initDataSha256"])
    require(
        re.fullmatch(r"[0-9a-f]{96}", runtime["launchMeasurement"]),
        "invalid SNP measurement",
    )
    require(
        hashlib.sha256(artifacts["initdata.toml"].encode()).hexdigest()
        == runtime["initDataSha256"],
        "InitData hash mismatch",
    )
    require(
        guest.get("schema_version") == 2
        and guest.get("purpose") == "confidential-storage-guest/v2",
        "unsupported guest configuration",
    )
    require(
        guest.get("authority", {}).get("init_data") == runtime["initDataSha256"],
        "guest InitData mismatch",
    )
    require(
        guest.get("kbs", {}).get("provider") == "private-cdh", "private CDH required"
    )
    entries = request["contract"]["volumes"]
    volumes = guest.get("volumes", [])
    require(
        type(volumes) is list and len(volumes) == len(entries),
        "guest volume count mismatch",
    )
    by_id = {v["binding_id"]: v for v in volumes}
    require(len(by_id) == len(volumes), "duplicate guest binding")
    resources = guest["kbs"].get("resources", {})
    require(
        set(resources) == {v["keyResource"] for v in entries}, "guest resource mismatch"
    )
    for item in entries:
        v = by_id[item["bindingId"]]
        e = v["expected"]
        require(
            v["transport_path"] == item["devicePath"]
            and e["container_name"] == item["container"]
            and e["destination"] == item["mountPath"]
            and e["access"] == {"ReadOnly": "ro", "ReadWrite": "rw"}[item["access"]],
            "guest binding mismatch",
        )
        require(
            resources[item["keyResource"]] in ("lower-hex64", "raw32"),
            "invalid credential encoding",
        )
        sha256(e["profile_sha256"])
        require(
            e["policy_sha256"] == guest["authority"]["policy_sha256"],
            "guest policy mismatch",
        )
    if "deployment" in request:
        from sidecar import validate

        validate(artifacts, request, guest, runtime)
    # No heuristic secret scrubbing: the trusted packager must supply public-only files.
    # This controller never accepts server.json, authority DB or credentials as inputs.


def verify_approval(raw, request, public_keys, now):
    envelope = parse(raw, MAX_BYTES)
    fields(envelope, {"keyId", "payload", "signature"})
    key = public_keys[envelope["keyId"]]
    payload = envelope["payload"]
    fields(payload, {"purpose", "requestSha256", "issuedAt", "expiresAt", "artifacts"})
    require(
        payload["purpose"] == "confidential-volume-deployment-approval/v1"
        and payload["requestSha256"] == digest(request),
        "approval request mismatch",
    )
    issued, expiry = payload["issuedAt"], payload["expiresAt"]
    require(
        type(issued) is int
        and type(expiry) is int
        and issued <= now < expiry
        and 0 < expiry - issued <= 7 * 86400,
        "approval expired or invalid lifetime",
    )
    try:
        sig = base64.b64decode(envelope["signature"], validate=True)
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
            sig, canonical(payload)
        )
    except (InvalidSignature, ValueError, TypeError):
        raise Invalid("invalid approval signature") from None
    validate_artifacts(payload["artifacts"], request)
    return envelope


def configmap(namespace, kind, sha, data):
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": resource_name(kind, sha),
            "namespace": namespace,
            "labels": {
                MANAGED: "confidential-volume-controller",
                GROUP + "/artifact": kind,
            },
            "annotations": {GROUP + "/sha256": sha},
        },
        "immutable": True,
        "data": data,
    }


def ensure(api, obj):
    old = api.get("ConfigMap", obj["metadata"]["name"])
    if old is None:
        try:
            return api.create(obj)
        except APIError as error:
            if error.code != 409:
                raise
            old = api.get("ConfigMap", obj["metadata"]["name"])
    require(
        old
        and not old.get("metadata", {}).get("deletionTimestamp")
        and old.get("immutable") is True
        and old.get("data") == obj["data"]
        and old.get("metadata", {}).get("labels", {}).get(MANAGED)
        == "confidential-volume-controller"
        and old.get("metadata", {}).get("annotations", {}).get(GROUP + "/sha256")
        == obj["metadata"]["annotations"][GROUP + "/sha256"],
        "artifact name conflict",
    )
    return old


def condition(kind, good, reason, generation, now, previous):
    value = {
        "type": kind,
        "status": "True" if good else "False",
        "reason": reason,
        "observedGeneration": generation,
        "lastTransitionTime": datetime.fromtimestamp(now, timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
    }
    for old in previous:
        if old.get("type") == kind and old.get("status") == value["status"]:
            value["lastTransitionTime"] = old["lastTransitionTime"]
    return value


class Controller:
    def __init__(
        self,
        api,
        namespace,
        cluster_id,
        public_keys,
        include_pods=False,
        sidecar_targets=(),
    ):
        self.api, self.namespace = api, name(namespace)
        self.cluster_id = name(cluster_id)
        require(
            type(public_keys) is dict and len(public_keys) <= 8,
            "invalid approval keyring",
        )
        for key_id, key in public_keys.items():
            name(key_id)
            sha256(key)  # Ed25519 public keys are 32 bytes, represented as hex.
        self.keys, self.include_pods = public_keys, include_pods
        self.sidecar_targets = {name(n) for n in sidecar_targets}

    def reconcile(self, now):
        declarations = {
            d["metadata"]["name"]: d for d in self.api.list("ConfidentialVolume")
        }
        claims = {
            c["metadata"]["name"]: c for c in self.api.list("PersistentVolumeClaim")
        }
        sources = {
            s["metadata"]["name"]: s for s in self.api.list("EncryptedModelSource")
        }
        workloads = self.api.list("InferenceService")
        if self.include_pods:
            workloads += [
                p
                for p in self.api.list("Pod")
                if p["metadata"].get("labels", {}).get(MANAGED) == "standalone"
                and not p["metadata"].get("ownerReferences")
            ]
        consumers = {n: [] for n in declarations}
        failed_inventory = False
        if self.sidecar_targets:
            from sidecar import desired

            for intent in self.api.list("ConfidentialWorkload"):
                if intent.get("metadata", {}).get("deletionTimestamp"):
                    continue
                try:
                    workloads.append(desired(intent, declarations))
                except (Invalid, KeyError, TypeError, ValueError):
                    failed_inventory = True
                    blocked = {
                        "observedGeneration": intent["metadata"].get("generation", 1),
                        "phase": "Blocked",
                        "reason": "InvalidInputs",
                    }
                    if intent.get("status") != blocked:
                        self.api.intent_status(intent, blocked)
        for workload in workloads:
            try:
                refs = referenced(workload)
            except (Invalid, KeyError, TypeError, ValueError):
                # Cannot safely assign a malformed annotation to particular volumes.
                failed_inventory = True
                continue
            if not refs:
                continue
            ref = {
                "kind": (
                    "ConfidentialWorkload"
                    if "_sidecarOwner" in workload
                    else workload["kind"]
                ),
                "name": workload.get("_sidecarOwner", workload)["metadata"]["name"],
                "uid": workload["metadata"].get("uid", ""),
                "phase": "Blocked",
                "reason": "InvalidInputs",
            }
            try:
                request = request_for(
                    self.namespace,
                    self.cluster_id,
                    workload,
                    declarations,
                    claims,
                    sources,
                )
                sha = digest(request)
                req_cm = configmap(
                    self.namespace,
                    "request",
                    sha,
                    {"request.json": canonical(request).decode()},
                )
                ensure(self.api, req_cm)
                ref.update(
                    requestSha256=sha,
                    requestConfigMap=req_cm["metadata"]["name"],
                    phase="AwaitingApproval",
                    reason="ApprovalMissing",
                )
                approval = self.api.get("ConfigMap", resource_name("approval", sha))
                if approval is not None:
                    active(approval)
                    ref.update(phase="Blocked", reason="InvalidApproval")
                    envelope = verify_approval(
                        approval["data"]["approval.json"].encode(),
                        request,
                        self.keys,
                        now,
                    )
                    approval_sha = digest(envelope)
                    artifact = configmap(
                        self.namespace,
                        "approved",
                        approval_sha,
                        {
                            **envelope["payload"]["artifacts"],
                            "approval.json": canonical(envelope).decode(),
                            "request.json": canonical(request).decode(),
                        },
                    )
                    ref.update(reason="ArtifactConflict")
                    ensure(self.api, artifact)
                    ref.update(
                        phase="Approved",
                        reason="SignedConfigurationPublished",
                        artifactConfigMap=artifact["metadata"]["name"],
                        approvalSha256=approval_sha,
                        expiresAt=envelope["payload"]["expiresAt"],
                    )
                    if "_sidecarOwner" in workload:
                        from sidecar import deploy

                        ref.update(phase="Blocked", reason="DeploymentBlocked")
                        action = deploy(
                            self.api,
                            workload,
                            request,
                            envelope["payload"]["artifacts"],
                            parse(envelope["payload"]["artifacts"]["runtime.json"]),
                            approval_sha,
                            self.sidecar_targets,
                        )
                        ref.update(
                            phase="Approved",
                            reason="ApprovedWorkloadApplied",
                            deploymentAction=action,
                        )

            except (Invalid, KeyError, TypeError, ValueError):
                pass  # Only fixed categories enter status; never input or exception strings.
            if "_sidecarOwner" in workload:
                intent = workload["_sidecarOwner"]
                desired_status = {
                    **ref,
                    "observedGeneration": intent["metadata"].get("generation", 1),
                }
                if intent.get("status") != desired_status:
                    self.api.intent_status(intent, desired_status)
            for n in set(refs):
                if n in consumers:
                    consumers[n].append(copy.deepcopy(ref))
        updated = 0
        for n, obj in declarations.items():
            if obj["metadata"].get("deletionTimestamp"):
                continue  # No finalizer, disk/key deletion or authority mutation.
            resolved, reason, claim_uid = False, "InvalidClaim", ""
            try:
                declaration(obj, self.namespace)
                pvc = claims[obj["spec"]["claimRef"]["name"]]
                active(pvc)
                require(
                    pvc["metadata"]["uid"] == obj["spec"]["claimRef"]["uid"],
                    "claim changed",
                )
                require(
                    pvc["spec"].get("volumeMode") == "Block"
                    and pvc["spec"].get("accessModes") == ["ReadWriteOncePod"],
                    "invalid claim",
                )
                size(pvc["spec"]["resources"]["requests"]["storage"])
                claim_uid = pvc["metadata"]["uid"]
                resolved = pvc.get("status", {}).get("phase") == "Bound"
                reason = "ClaimResolved" if resolved else "ClaimPending"
            except (Invalid, KeyError, TypeError, ValueError):
                pass
            refs = sorted(consumers[n], key=lambda x: (x["kind"], x["name"]))
            overflow = len(refs) > 32
            approved = (
                resolved
                and bool(refs)
                and not failed_inventory
                and not overflow
                and all(r["phase"] == "Approved" for r in refs)
            )
            phase = (
                "Approved"
                if approved
                else (
                    "Blocked"
                    if failed_inventory
                    or overflow
                    or not resolved
                    or any(r["phase"] == "Blocked" for r in refs)
                    else "AwaitingApproval" if refs else "WaitingForConsumer"
                )
            )
            approval_reason = (
                "SignedConfigurationPublished"
                if approved
                else (
                    "InventoryInvalid"
                    if failed_inventory or overflow
                    else "ApprovalPending"
                )
            )
            generation = obj["metadata"].get("generation", 1)
            previous = obj.get("status", {}).get("conditions", [])
            status = {
                "observedGeneration": generation,
                "phase": phase,
                "resolvedClaimUID": claim_uid,
                "consumers": refs[:32],
                "conditions": [
                    condition("Resolved", resolved, reason, generation, now, previous),
                    condition(
                        "Approved", approved, approval_reason, generation, now, previous
                    ),
                    condition(
                        "ConfigurationPublished",
                        approved,
                        approval_reason,
                        generation,
                        now,
                        previous,
                    ),
                ],
            }
            if obj.get("status") != status:
                self.api.status(obj, status)
                updated += 1
        return {
            "declarations": len(declarations),
            "statusUpdates": updated,
            "workloads": len(workloads),
            "invalidInventory": failed_inventory,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--cluster-id", required=True)
    parser.add_argument("--keys", required=True)
    parser.add_argument("--api-origin", default="https://kubernetes.default.svc")
    parser.add_argument(
        "--ca", default="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    )
    parser.add_argument(
        "--token", default="/var/run/secrets/kubernetes.io/serviceaccount/token"
    )
    parser.add_argument("--interval", type=int, default=15)
    parser.add_argument("--include-pods", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--sidecar-workload", action="append", default=[])
    args = parser.parse_args()
    require(2 <= args.interval <= 60, "invalid reconciliation interval")
    api = Kubernetes(args.namespace, args.api_origin, args.ca, args.token)
    controller = Controller(
        api,
        args.namespace,
        args.cluster_id,
        parse(Path(args.keys).read_bytes(), 8192),
        args.include_pods,
        args.sidecar_workload,
    )
    while True:
        try:
            result = controller.reconcile(int(time.time()))
            print(json.dumps({"event": "Reconciled", **result}), flush=True)
            Path("/tmp/cv-controller-ready").touch()
        except (APIError, Invalid, OSError, KeyError, TypeError, ValueError):
            print('{"event":"ReconciliationFailed"}', flush=True)
            if args.once:
                raise SystemExit(1) from None
        if args.once:
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
