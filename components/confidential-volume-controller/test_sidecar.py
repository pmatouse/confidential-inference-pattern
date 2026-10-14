"""Signed sidecar rollout and failure boundaries; no storage credentials."""

import base64
import copy
import gzip
import hashlib
import json
import unittest

from controller import Controller, GROUP, canonical, digest, parse, resource_name
from approve import sign
from sidecar import OWNER
from test_controller import setup


def fixture():
    api, old, key = setup()
    template = copy.deepcopy(api.objects["InferenceService"][0])
    app = template["spec"]["predictor"]["containers"][0]
    app.pop("volumeDevices")
    template["spec"]["predictor"]["volumes"] = []
    app["volumeMounts"] = []
    target = template["metadata"]["name"]
    cw = {
        "apiVersion": "storage.confidentialcontainers.org/v1alpha1",
        "kind": "ConfidentialWorkload",
        "metadata": {
            "name": "intent",
            "namespace": old.namespace,
            "uid": "30000000-0000-4000-8000-000000000000",
            "generation": 1,
            "resourceVersion": "1",
        },
        "spec": {"template": {"metadata": {"name": target}, "spec": template["spec"]}},
    }
    api.objects["InferenceService"] = []
    api.objects["ConfidentialWorkload"] = [cw]
    api.create_workload = api.create

    def update(body):
        api.objects["InferenceService"] = [copy.deepcopy(body)]
        api.writes.append(("update", "InferenceService", body["metadata"]["name"]))

    api.update_workload = update

    def status(obj, status):
        api.objects["ConfidentialWorkload"][0]["status"] = copy.deepcopy(status)

    api.intent_status = status
    c = Controller(
        api, old.namespace, old.cluster_id, old.keys, sidecar_targets=[target]
    )
    return api, c, key


def approve_sidecar(api, c, key):
    c.reconcile(1000)
    cm = next(v for v in api.objects["ConfigMap"] if "request.json" in v["data"])
    req = parse(cm["data"]["request.json"])
    entries = req["contract"]["volumes"]
    app = {
        "name": "kserve-container",
        "image": req["contract"]["workload"]["image"],
        "command": ["python3", "-c", "consumer"],
        "securityContext": {
            "runAsUser": 1001,
            "runAsGroup": 1001,
            "runAsNonRoot": True,
            "privileged": False,
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
        },
        "volumeMounts": [],
    }
    helper = {
        "name": "storage-sidecar",
        "image": "example/helper@sha256:" + "e" * 64,
        "securityContext": {"runAsUser": 0, "privileged": True},
        "volumeDevices": [],
    }
    guest = {
        "schema_version": 2,
        "purpose": "confidential-storage-guest/v2",
        "authority": {"init_data": "", "policy_sha256": ""},
        "kbs": {"provider": "private-cdh", "resources": {}},
        "volumes": [],
    }
    volumes = []
    for i, e in enumerate(entries):
        guest["kbs"]["resources"][e["keyResource"]] = "raw32"
        guest["volumes"].append(
            {
                "binding_id": e["bindingId"],
                "transport_path": e["devicePath"],
                "expected": {
                    "container_name": e["container"],
                    "destination": e["mountPath"],
                    "access": "ro" if e["access"] == "ReadOnly" else "rw",
                    "profile_sha256": "a" * 64,
                    "policy_sha256": "",
                },
            }
        )
        helper["volumeDevices"].append(
            {"name": e["bindingId"], "devicePath": e["devicePath"]}
        )
        volumes += [
            {
                "name": e["bindingId"],
                "persistentVolumeClaim": {
                    "claimName": e["claimRef"]["name"],
                    "readOnly": e["access"] == "ReadOnly",
                },
            },
            {"name": f"target-{i}", "emptyDir": {"medium": "Memory"}},
        ]
        app["volumeMounts"].append({"name": f"target-{i}", "mountPath": e["mountPath"]})
    data = {
        "policy.rego": "package agent_policy",
        "storage-sidecar.json": json.dumps(
            {"consumerArgs": app["command"], "service": guest}
        ),
    }
    raw = 'version="0.1.0"\n[data]\n' + "".join(
        json.dumps(k) + "=" + json.dumps(v) + "\n" for k, v in data.items()
    )
    init = hashlib.sha256(raw.encode()).hexdigest()
    policy = hashlib.sha256(data["policy.rego"].encode()).hexdigest()
    guest["authority"].update(init_data=init, policy_sha256=policy)
    for v in guest["volumes"]:
        v["expected"]["policy_sha256"] = policy
    volumes.append(
        {"name": "configuration", "configMap": {"name": "cv-sidecar-" + init[:48]}}
    )
    p = {
        "runtimeClassName": "kata-cc-nvidia-gpu",
        "shareProcessNamespace": True,
        "automountServiceAccountToken": False,
        "serviceAccountName": "storage-sidecar",
        "minReplicas": 1,
        "maxReplicas": 1,
        "deploymentStrategy": {"type": "Recreate"},
        "containers": [app, helper],
        "volumes": volumes,
        "annotations": {
            "io.katacontainers.config.hypervisor.cc_init_data": base64.b64encode(
                gzip.compress(raw.encode())
            ).decode()
        },
    }
    artifacts = {
        "initdata.toml": raw,
        "guest-config.json": canonical(guest).decode(),
        "runtime.json": canonical(
            {
                "runtimeClassName": "kata-cc-nvidia-gpu",
                "guestImageSha256": "a" * 64,
                "launchMeasurement": "b" * 96,
                "initDataSha256": init,
            }
        ).decode(),
        "sidecar-deployment.json": canonical(
            {"predictor": p, "metadata": {"annotations": {}, "labels": {}}}
        ).decode(),
    }
    env = sign(req, artifacts, key, "release-v1", 1000, 2000)
    approval = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": resource_name("approval", digest(req)),
            "namespace": c.namespace,
        },
        "data": {"approval.json": canonical(env).decode()},
    }
    api.objects["ConfigMap"].append(approval)
    return req, env, approval


class SidecarTests(unittest.TestCase):
    def test_no_deployment_without_signed_approval(self):
        api, c, key = fixture()
        c.reconcile(1000)
        self.assertEqual(api.objects["InferenceService"], [])
        self.assertEqual(
            api.objects["ConfidentialWorkload"][0]["status"]["phase"],
            "AwaitingApproval",
        )

    def test_create_reconcile_restart_and_recreate_keep_request_stable(self):
        api, c, key = fixture()
        req, _, _ = approve_sidecar(api, c, key)
        c.reconcile(1001)
        live = api.objects["InferenceService"][0]
        live["metadata"]["uid"] = "40000000-0000-4000-8000-000000000000"
        original = copy.deepcopy(live)
        for t in [1002, 1003]:
            c.reconcile(t)
        self.assertEqual(api.objects["InferenceService"][0], original)
        self.assertEqual(
            len(
                [
                    x
                    for x in api.objects["ConfigMap"]
                    if x["metadata"]["name"].startswith("cv-request-")
                ]
            ),
            1,
        )
        api.objects["InferenceService"] = []
        c.reconcile(1004)
        self.assertEqual(len(api.objects["InferenceService"]), 1)
        self.assertEqual(
            api.objects["ConfidentialWorkload"][0]["status"]["reason"],
            "ApprovedWorkloadApplied",
        )

    def test_exact_uid_adoption_and_drift_repair(self):
        api, c, key = fixture()
        target = next(iter(c.sidecar_targets))
        old_uid = "40000000-0000-4000-8000-000000000000"
        api.objects["ConfidentialWorkload"][0]["spec"]["adoptExistingUID"] = old_uid
        approve_sidecar(api, c, key)
        api.objects["InferenceService"] = [
            {
                "apiVersion": "serving.kserve.io/v1beta1",
                "kind": "InferenceService",
                "metadata": {
                    "name": target,
                    "namespace": c.namespace,
                    "uid": old_uid,
                    "resourceVersion": "7",
                },
                "spec": {"predictor": {}},
            }
        ]
        c.reconcile(1001)
        live = api.objects["InferenceService"][0]
        self.assertEqual(live["metadata"]["uid"], old_uid)
        self.assertIn(OWNER, live["metadata"]["labels"])
        live["spec"]["predictor"]["runtimeClassName"] = "runc"
        c.reconcile(1002)
        self.assertEqual(
            api.objects["InferenceService"][0]["spec"]["predictor"]["runtimeClassName"],
            "kata-cc-nvidia-gpu",
        )

    def test_adoption_does_not_steal_an_existing_owner(self):
        api, c, key = fixture()
        old_uid = "40000000-0000-4000-8000-000000000000"
        api.objects["ConfidentialWorkload"][0]["spec"]["adoptExistingUID"] = old_uid
        approve_sidecar(api, c, key)
        api.objects["InferenceService"] = [
            {
                "kind": "InferenceService",
                "metadata": {
                    "name": next(iter(c.sidecar_targets)),
                    "uid": old_uid,
                    "ownerReferences": [{"uid": "another-owner"}],
                },
                "spec": {"predictor": {}},
            }
        ]
        c.reconcile(1001)
        self.assertEqual(
            api.objects["ConfidentialWorkload"][0]["status"]["reason"],
            "DeploymentBlocked",
        )

    def test_tampering_or_expiry_blocks_recreation(self):
        for expiry in [False, True]:
            api, c, key = fixture()
            _, env, cm = approve_sidecar(api, c, key)
            if not expiry:
                env["payload"]["artifacts"]["sidecar-deployment.json"] += " "
                cm["data"]["approval.json"] = canonical(env).decode()
            c.reconcile(2001 if expiry else 1001)
            self.assertFalse(api.objects["InferenceService"])
            self.assertEqual(
                api.objects["ConfidentialWorkload"][0]["status"]["phase"], "Blocked"
            )

    def test_unrelated_workload_cannot_be_adopted(self):
        api, c, key = fixture()
        req, _, _ = approve_sidecar(api, c, key)
        old = {
            "kind": "InferenceService",
            "metadata": {
                "name": req["contract"]["workload"]["name"],
                "uid": "40000000-0000-4000-8000-000000000000",
            },
            "spec": {"predictor": {}},
        }
        api.objects["InferenceService"] = [copy.deepcopy(old)]
        c.reconcile(1001)
        self.assertEqual(api.objects["InferenceService"], [old])
        self.assertEqual(
            api.objects["ConfidentialWorkload"][0]["status"]["reason"],
            "DeploymentBlocked",
        )

    def test_changed_intent_claim_or_disabled_target_cannot_use_old_approval(self):
        for change in ["intent", "claim", "target"]:
            api, c, key = fixture()
            approve_sidecar(api, c, key)
            if change == "intent":
                api.objects["ConfidentialWorkload"][0]["spec"]["template"]["spec"][
                    "predictor"
                ]["containers"][0]["image"] = ("example/changed@sha256:" + "e" * 64)
            elif change == "claim":
                api.objects["PersistentVolumeClaim"][0]["metadata"][
                    "uid"
                ] = "40000000-0000-4000-8000-000000000000"
            else:
                c.sidecar_targets = {"another-target"}
            c.reconcile(1001)
            self.assertFalse(api.objects["InferenceService"])

    def test_signed_privilege_or_measurement_mismatch_is_rejected(self):
        from controller import verify_approval, Invalid

        for field in ["privilege", "initdata", "raw"]:
            api, c, key = fixture()
            req, env, _ = approve_sidecar(api, c, key)
            p = json.loads(env["payload"]["artifacts"]["sidecar-deployment.json"])
            if field == "privilege":
                p["predictor"]["containers"][0]["securityContext"]["privileged"] = True
            elif field == "initdata":
                p["predictor"]["annotations"][
                    "io.katacontainers.config.hypervisor.cc_init_data"
                ] = base64.b64encode(gzip.compress(b"wrong")).decode()
            else:
                p["predictor"]["containers"][0]["volumeDevices"] = [
                    {"name": "bad", "devicePath": "/dev/bad"}
                ]
            env["payload"]["artifacts"]["sidecar-deployment.json"] = canonical(
                p
            ).decode()
            with self.assertRaises(Invalid):
                sign(req, env["payload"]["artifacts"], key, "release-v1", 1000, 2000)


if __name__ == "__main__":
    unittest.main()
