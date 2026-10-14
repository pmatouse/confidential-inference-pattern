"""Reconciliation, approval and race tests without storage keys or formatting."""

import copy
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from controller import (
    APIError,
    ARTIFACTS,
    Controller,
    GROUP,
    Invalid,
    Kubernetes,
    MANAGED,
    canonical,
    digest,
    parse,
    resource_name,
)
from approve import sign
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "confidential-volume-contract")
)
from test_compiler import fixture  # noqa: E402


class FakeAPI:
    def __init__(self, bundle):
        self.objects = {
            "ConfidentialVolume": bundle["declarations"],
            "PersistentVolumeClaim": bundle["claims"],
            "InferenceService": [bundle["workload"]],
            "EncryptedModelSource": [],
            "Pod": [],
            "ConfigMap": [],
        }
        self.writes = []
        self.conflict = False

    def list(self, kind):
        return copy.deepcopy(self.objects[kind])

    def get(self, kind, name):
        return next(
            (
                copy.deepcopy(v)
                for v in self.objects[kind]
                if v["metadata"]["name"] == name
            ),
            None,
        )

    def create(self, obj):
        if self.get(obj["kind"], obj["metadata"]["name"]):
            raise APIError(409)
        self.objects[obj["kind"]].append(copy.deepcopy(obj))
        self.writes.append(("create", obj["kind"], obj["metadata"]["name"]))
        return obj

    def status(self, obj, status):
        if self.conflict:
            self.conflict = False
            raise APIError(409)
        live = next(
            v
            for v in self.objects["ConfidentialVolume"]
            if v["metadata"]["name"] == obj["metadata"]["name"]
        )
        if live["metadata"]["resourceVersion"] != obj["metadata"]["resourceVersion"]:
            raise APIError(409)
        live["status"] = copy.deepcopy(status)
        live["metadata"]["resourceVersion"] = str(
            int(live["metadata"]["resourceVersion"]) + 1
        )
        self.writes.append(("status", "ConfidentialVolume", obj["metadata"]["name"]))


def setup():
    b = fixture()
    for i, d in enumerate(b["declarations"]):
        d["metadata"].update(
            uid=f"10000000-0000-4000-8000-{i:012d}", generation=1, resourceVersion="1"
        )
    for i, p in enumerate(b["claims"]):
        p["status"] = {"phase": "Bound"}
        p["spec"].update(storageClassName="lvms-vg1", volumeName=f"pv-{i}")
    b["workload"]["metadata"]["uid"] = "20000000-0000-4000-8000-000000000000"
    api = FakeAPI(b)
    key = Ed25519PrivateKey.generate()
    keys = {"release-v1": key.public_key().public_bytes_raw().hex()}
    return api, Controller(api, b["namespace"], "test-cluster", keys), key


def request(api):
    cm = next(v for v in api.objects["ConfigMap"] if "request.json" in v["data"])
    return parse(cm["data"]["request.json"])


def artifacts(req):
    initdata = (
        'version = "0.1.0"\n'  # Synthetic test package, never a deployable guest.
    )
    init_sha = hashlib.sha256(initdata.encode()).hexdigest()
    guest = {
        "schema_version": 2,
        "purpose": "confidential-storage-guest/v2",
        "authority": {"init_data": init_sha, "policy_sha256": "a" * 64},
        "kbs": {"provider": "private-cdh", "resources": {}},
        "volumes": [],
    }
    for item in req["contract"]["volumes"]:
        guest["kbs"]["resources"][item["keyResource"]] = "lower-hex64"
        guest["volumes"].append(
            {
                "binding_id": item["bindingId"],
                "transport_path": item["devicePath"],
                "expected": {
                    "container_name": item["container"],
                    "destination": item["mountPath"],
                    "access": "ro" if item["access"] == "ReadOnly" else "rw",
                    "policy_sha256": "a" * 64,
                    "profile_sha256": "b" * 64,
                },
            }
        )
    return {
        "guest-config.json": canonical(guest).decode(),
        "initdata.toml": initdata,
        "runtime.json": canonical(
            {
                "runtimeClassName": "kata-candidate",
                "guestImageSha256": "c" * 64,
                "launchMeasurement": "d" * 96,
                "initDataSha256": init_sha,
            }
        ).decode(),
    }


def approve(api, key, now=1000):
    req = request(api)
    env = sign(req, artifacts(req), key, "release-v1", now, now + 300)
    api.objects["ConfigMap"].append(
        {
            "kind": "ConfigMap",
            "metadata": {
                "name": resource_name("approval", digest(req)),
                "namespace": "gpu-workload",
            },
            "data": {"approval.json": canonical(env).decode()},
        }
    )
    return env


class ReconcileTests(unittest.TestCase):
    def test_four_volumes_one_request_idempotent_no_workload_mutation(self):
        api, c, _ = setup()
        original = copy.deepcopy(api.objects["InferenceService"])
        c.reconcile(1000)
        self.assertEqual(len(api.objects["ConfigMap"]), 1)
        self.assertTrue(
            all(
                v["status"]["phase"] == "AwaitingApproval"
                for v in api.objects["ConfidentialVolume"]
            )
        )
        self.assertEqual(c.reconcile(1001)["statusUpdates"], 0)
        self.assertEqual(api.objects["InferenceService"], original)
        self.assertTrue(all(w[0] in ("create", "status") for w in api.writes))

    def test_signed_approval_publishes_immutable_public_config(self):
        api, c, key = setup()
        c.reconcile(1000)
        approve(api, key)
        c.reconcile(1001)
        self.assertTrue(
            all(
                v["status"]["phase"] == "Approved"
                for v in api.objects["ConfidentialVolume"]
            )
        )
        published = next(
            v
            for v in api.objects["ConfigMap"]
            if v["metadata"]["name"].startswith("cv-approved-")
        )
        self.assertTrue(published["immutable"])
        self.assertEqual(
            set(published["data"]), ARTIFACTS | {"approval.json", "request.json"}
        )
        self.assertEqual(c.reconcile(1002)["statusUpdates"], 0)

    def test_expiry_withdraws_status_without_deleting_artifacts_or_workloads(self):
        api, c, key = setup()
        c.reconcile(1000)
        approve(api, key)
        c.reconcile(1001)
        count = len(api.objects["ConfigMap"])
        c.reconcile(1300)
        self.assertTrue(
            all(
                v["status"]["phase"] == "Blocked"
                for v in api.objects["ConfidentialVolume"]
            )
        )
        self.assertEqual(count, len(api.objects["ConfigMap"]))
        self.assertNotIn(
            "artifactConfigMap",
            api.objects["ConfidentialVolume"][0]["status"]["consumers"][0],
        )

    def test_removed_approval_and_consumer_clear_old_status(self):
        api, c, key = setup()
        c.reconcile(1000)
        approve(api, key)
        c.reconcile(1001)
        api.objects["ConfigMap"] = [
            v
            for v in api.objects["ConfigMap"]
            if not v["metadata"]["name"].startswith("cv-approval-")
        ]
        c.reconcile(1002)
        self.assertEqual(
            api.objects["ConfidentialVolume"][0]["status"]["phase"], "AwaitingApproval"
        )
        api.objects["InferenceService"] = []
        c.reconcile(1003)
        self.assertEqual(
            api.objects["ConfidentialVolume"][0]["status"]["phase"],
            "WaitingForConsumer",
        )

    def test_claim_replacement_or_pending_never_publishes(self):
        for mutate in [
            lambda p: p["metadata"].update(uid="30000000-0000-4000-8000-000000000000"),
            lambda p: p.update(status={"phase": "Pending"}),
            lambda p: p["metadata"].update(deletionTimestamp="now"),
            lambda p: p["spec"].update(volumeMode="Filesystem"),
        ]:
            api, c, _ = setup()
            mutate(api.objects["PersistentVolumeClaim"][0])
            c.reconcile(1000)
            self.assertEqual(api.objects["ConfigMap"], [])
            self.assertEqual(
                api.objects["ConfidentialVolume"][0]["status"]["phase"], "Blocked"
            )

    def test_deleted_claim_and_unknown_declaration_block_existing_bindings(self):
        for kind in ["PersistentVolumeClaim", "ConfidentialVolume"]:
            api, c, _ = setup()
            api.objects[kind].pop(0)
            c.reconcile(1000)
            self.assertEqual(api.objects["ConfigMap"], [])
            self.assertTrue(
                all(
                    v["status"]["phase"] == "Blocked"
                    for v in api.objects["ConfidentialVolume"]
                )
            )

    def test_workload_or_declaration_recreation_requires_new_approval(self):
        for kind in ["InferenceService", "ConfidentialVolume"]:
            api, c, key = setup()
            c.reconcile(1000)
            approve(api, key)
            c.reconcile(1001)
            api.objects[kind][0]["metadata"][
                "uid"
            ] = "30000000-0000-4000-8000-000000000000"
            c.reconcile(1002)
            self.assertTrue(
                all(
                    v["status"]["phase"] == "AwaitingApproval"
                    for v in api.objects["ConfidentialVolume"]
                )
            )

    def test_process_change_needs_new_approval(self):
        api, c, key = setup()
        c.reconcile(1000)
        approve(api, key)
        c.reconcile(1001)
        api.objects["InferenceService"][0]["spec"]["predictor"]["containers"][0][
            "command"
        ] = ["other"]
        c.reconcile(1002)
        self.assertTrue(
            all(
                v["status"]["phase"] == "AwaitingApproval"
                for v in api.objects["ConfidentialVolume"]
            )
        )

    def test_untrusted_status_cannot_approve(self):
        api, c, _ = setup()
        for d in api.objects["ConfidentialVolume"]:
            d["status"] = {"phase": "Approved", "consumers": [], "conditions": []}
        c.reconcile(1000)
        self.assertTrue(
            all(
                d["status"]["phase"] == "AwaitingApproval"
                for d in api.objects["ConfidentialVolume"]
            )
        )

    def test_approval_tamper_unknown_signer_expiry_and_cluster_replay(self):
        for mutate in [
            lambda e: e["payload"].update(requestSha256="f" * 64),
            lambda e: e["payload"].update(expiresAt=999),
            lambda e: e.update(keyId="unknown"),
            lambda e: e.update(signature="invalid"),
            lambda e: e["payload"]["artifacts"].update(**{"initdata.toml": "changed"}),
        ]:
            api, c, key = setup()
            c.reconcile(1000)
            envelope = approve(api, key)
            mutate(envelope)
            api.objects["ConfigMap"][-1]["data"]["approval.json"] = canonical(
                envelope
            ).decode()
            c.reconcile(1001)
            self.assertTrue(
                all(
                    v["status"]["phase"] == "Blocked"
                    for v in api.objects["ConfidentialVolume"]
                )
            )
        api, c, key = setup()
        c.reconcile(1000)
        approve(api, key)
        c.cluster_id = "other-cluster"
        c.reconcile(1001)
        self.assertEqual(
            api.objects["ConfidentialVolume"][0]["status"]["phase"], "AwaitingApproval"
        )

    def test_bad_signed_bindings_rejected(self):
        api, c, key = setup()
        c.reconcile(1000)
        req = request(api)
        art = artifacts(req)
        guest = parse(art["guest-config.json"])
        guest["volumes"][0]["expected"]["destination"] = "/data/other"
        art["guest-config.json"] = canonical(guest).decode()
        with self.assertRaises(Invalid):
            sign(req, art, key, "release-v1", 1000, 1200)

    def test_immutable_name_conflict_refused(self):
        api, c, key = setup()
        c.reconcile(1000)
        api.objects["ConfigMap"][0]["data"]["request.json"] = "changed"
        c.reconcile(1001)
        self.assertTrue(
            all(
                v["status"]["phase"] == "Blocked"
                for v in api.objects["ConfidentialVolume"]
            )
        )
        self.assertEqual(api.objects["ConfigMap"][0]["data"]["request.json"], "changed")

    def test_conflict_retry_is_idempotent(self):
        api, c, _ = setup()
        api.conflict = True
        with self.assertRaises(APIError):
            c.reconcile(1000)
        c.reconcile(1001)
        self.assertEqual(len(api.objects["ConfigMap"]), 1)
        self.assertTrue(
            all(
                v["status"]["phase"] == "AwaitingApproval"
                for v in api.objects["ConfidentialVolume"]
            )
        )

    def test_controller_restart_reuses_artifacts_and_status(self):
        api, c, key = setup()
        c.reconcile(1000)
        approve(api, key)
        c.reconcile(1001)
        fresh = Controller(api, c.namespace, c.cluster_id, c.keys)
        self.assertEqual(fresh.reconcile(1002)["statusUpdates"], 0)
        self.assertEqual(len(api.objects["ConfigMap"]), 3)

    def test_bad_annotation_blocks_without_logging_input(self):
        api, c, _ = setup()
        api.objects["InferenceService"][0]["spec"]["predictor"]["annotations"][
            GROUP + "/bindings"
        ] = '{"secret":"never log"'
        result = c.reconcile(1000)
        self.assertTrue(result["invalidInventory"])
        self.assertNotIn(
            "never log", canonical(api.objects["ConfidentialVolume"]).decode()
        )
        self.assertEqual(api.objects["ConfigMap"], [])

    def test_source_digest_and_incarnation_are_bound(self):
        api, c, _ = setup()
        source = {
            "kind": "EncryptedModelSource",
            "apiVersion": GROUP + "/v1alpha1",
            "metadata": {
                "name": "base-source",
                "namespace": c.namespace,
                "uid": "40000000-0000-4000-8000-000000000000",
            },
            "spec": {
                "format": "luks-verity-v1",
                "repository": c.namespace + "/model",
                "manifestDigest": "sha256:" + "a" * 64,
                "diskDigest": "sha256:" + "b" * 64,
                "diskBytes": 2 * 1024**3,
            },
        }
        api.objects["EncryptedModelSource"].append(source)
        api.objects["PersistentVolumeClaim"][0]["spec"]["dataSourceRef"] = {
            "apiGroup": GROUP,
            "kind": "EncryptedModelSource",
            "name": "base-source",
        }
        c.reconcile(1000)
        first = request(api)
        self.assertEqual(first["sources"][0]["spec"], source["spec"])
        source["spec"]["diskDigest"] = "sha256:" + "c" * 64
        c.reconcile(1001)
        self.assertEqual(len(api.objects["ConfigMap"]), 2)
        source["metadata"]["namespace"] = "other"
        c.reconcile(1002)
        self.assertTrue(
            all(
                v["status"]["phase"] == "Blocked"
                for v in api.objects["ConfidentialVolume"]
            )
        )

    def test_resource_versions_and_status_do_not_change_request(self):
        api, c, _ = setup()
        c.reconcile(1000)
        for kind in ["ConfidentialVolume", "PersistentVolumeClaim", "InferenceService"]:
            for obj in api.objects[kind]:
                obj["metadata"]["resourceVersion"] = "900"
        c.reconcile(1001)
        self.assertEqual(len(api.objects["ConfigMap"]), 1)

    def test_api_pagination(self):
        client = object.__new__(Kubernetes)
        client.namespace = "test"
        pages = [
            {"items": [{"id": 1}], "metadata": {"continue": "a+b"}},
            {"items": [{"id": 2}], "metadata": {}},
        ]
        with patch.object(client, "call", side_effect=pages) as call:
            self.assertEqual(
                [item["id"] for item in client.list("ConfidentialVolume")], [1, 2]
            )
            self.assertIn("continue=a%2Bb", call.call_args[0][1])

    def test_typed_kubernetes_lists_restore_only_missing_typemeta(self):
        client = object.__new__(Kubernetes)
        client.namespace = "test"
        with patch.object(
            client, "call", return_value={"items": [{"metadata": {"name": "disk"}}]}
        ):
            result = client.list("PersistentVolumeClaim")[0]
            self.assertEqual(result["apiVersion"], "v1")
            self.assertEqual(result["kind"], "PersistentVolumeClaim")
        with patch.object(client, "call", return_value={"items": [{"kind": "Secret"}]}):
            with self.assertRaises(Invalid):
                client.list("PersistentVolumeClaim")

    def test_api_failure_does_not_treat_missing_inventory_as_deleted(self):
        api, c, key = setup()
        c.reconcile(1000)
        approve(api, key)
        c.reconcile(1001)
        before = copy.deepcopy(api.objects)
        with patch.object(api, "list", side_effect=APIError(403)):
            with self.assertRaises(APIError):
                c.reconcile(1002)
        self.assertEqual(before, api.objects)

    def test_standalone_pods_explicit_opt_in_no_generated_pods(self):
        api, c, _ = setup()
        template = api.objects["InferenceService"][0]["spec"]["predictor"]
        pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "standalone",
                "namespace": c.namespace,
                "uid": "50000000-0000-4000-8000-000000000000",
                "annotations": template["annotations"],
                "labels": {MANAGED: "standalone"},
            },
            "spec": {k: v for k, v in template.items() if k != "annotations"},
        }
        api.objects["InferenceService"] = []
        api.objects["Pod"] = [pod]
        c.include_pods = True
        c.reconcile(1000)
        self.assertEqual(len(api.objects["ConfigMap"]), 1)
        pod["metadata"]["ownerReferences"] = [{"uid": "owned"}]
        c.reconcile(1001)
        self.assertTrue(
            all(
                v["status"]["phase"] == "WaitingForConsumer"
                for v in api.objects["ConfidentialVolume"]
            )
        )


if __name__ == "__main__":
    unittest.main()
