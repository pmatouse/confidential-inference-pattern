"""Contract validation tests: no cluster, key material or privileged operation."""

import copy
import json
import unittest

from compiler import (
    ANNOTATION,
    API,
    Invalid,
    canonical,
    compile_contract,
    digest,
    parse,
    size,
)


def fixture():
    declarations, claims, volumes, devices, bindings = [], [], [], [], []
    for index, (n, path, access) in enumerate(
        [
            ("base", "/models/qwen", "ReadOnly"),
            ("embedding", "/models/embedding", "ReadOnly"),
            ("data", "/data", "ReadWrite"),
            ("checkpoints", "/checkpoints", "ReadWrite"),
        ]
    ):
        model = access == "ReadOnly"
        identity = f"00000000-0000-4000-8000-{index:012d}"
        spec = {
            "claimRef": {"name": n, "uid": identity},
            "access": access,
            "profile": "luks-verity-v1" if model else "luks-integrity-v1",
            "initialization": (
                {"policy": "Never"}
                if model
                else {
                    "policy": "OnceIfApproved",
                    "filesystem": "ext4",
                    "owner": {"uid": 1001, "gid": 1001},
                }
            ),
            "keyResource": f"kbs:///default/volume-keys/{n}",
        }
        if model:
            spec["content"] = {"approvedManifestRef": n + "-v1"}
        declarations.append(
            {
                "apiVersion": API,
                "kind": "ConfidentialVolume",
                "metadata": {"namespace": "gpu-workload", "name": n},
                "spec": spec,
            }
        )
        claims.append(
            {
                "apiVersion": "v1",
                "kind": "PersistentVolumeClaim",
                "metadata": {"namespace": "gpu-workload", "name": n, "uid": identity},
                "spec": {
                    "volumeMode": "Block",
                    "accessModes": ["ReadWriteOncePod"],
                    "resources": {"requests": {"storage": "2Gi" if model else "1Gi"}},
                },
            }
        )
        volumes.append(
            {"name": n, "persistentVolumeClaim": {"claimName": n, "readOnly": model}}
        )
        devices.append({"name": n, "devicePath": f"/dev/coco-volume-{index}"})
        bindings.append(
            {
                "volume": n,
                "confidentialVolume": n,
                "container": "kserve-container",
                "mountPath": path,
            }
        )
    workload = {
        "apiVersion": "serving.kserve.io/v1beta1",
        "kind": "InferenceService",
        "metadata": {"namespace": "gpu-workload", "name": "qwen-storage"},
        "spec": {
            "predictor": {
                "annotations": {ANNOTATION: json.dumps(bindings)},
                "containers": [
                    {
                        "name": "kserve-container",
                        "image": "example.invalid/vllm@sha256:" + "a" * 64,
                        "command": ["vllm", "serve", "/models/qwen"],
                        "volumeDevices": devices,
                    }
                ],
                "volumes": volumes,
            }
        },
    }
    return {
        "namespace": "gpu-workload",
        "workload": workload,
        "declarations": declarations,
        "claims": claims,
    }


def edit_binding(bundle, action):
    annotations = bundle["workload"]["spec"]["predictor"]["annotations"]
    bindings = json.loads(annotations[ANNOTATION])
    action(bindings)
    annotations[ANNOTATION] = json.dumps(bindings)


class CompilerTests(unittest.TestCase):
    def test_api_scientific_capacity_is_exact_and_bounded(self):
        self.assertEqual(size("2.147483648e+09"), size("2Gi"))
        self.assertEqual(size("1.073741824E9"), size("1Gi"))
        for value in [
            "2.1474836481e+09",
            "1e99",
            "1e999",
            "1e-99",
            "NaN",
            "inf",
            "2.5Gi",
            "1e+09",
        ]:
            with self.subTest(value=value), self.assertRaises(Invalid):
                size(value)

    def test_four_volumes_compile_deterministically_without_approval(self):
        source = fixture()
        original = copy.deepcopy(source)
        compiled = compile_contract(source)
        self.assertEqual(source, original)
        self.assertEqual(
            canonical(compiled), canonical(compile_contract(parse(canonical(source))))
        )
        self.assertEqual(compiled["purpose"], "confidential-volume-approval-request/v1")
        self.assertEqual(
            [v["bindingId"] for v in compiled["volumes"]],
            ["base", "checkpoints", "data", "embedding"],
        )
        self.assertEqual(
            {v["access"] for v in compiled["volumes"]}, {"ReadOnly", "ReadWrite"}
        )
        self.assertNotIn("approved", compiled)

    def test_status_cannot_supply_approval_or_change_request(self):
        source = fixture()
        expected = compile_contract(source)
        for item in source["declarations"]:
            item["status"] = {"phase": "Ready", "approved": True, "key": "not-trusted"}
        for item in source["claims"]:
            item["status"] = {"phase": "Bound"}
        self.assertEqual(expected, compile_contract(source))
        self.assertNotIn("not-trusted", canonical(compile_contract(source)).decode())

    def test_claim_recreation_and_namespace_substitution_rejected(self):
        for field in ["uid", "namespace"]:
            source = fixture()
            source["claims"][0]["metadata"][field] = "replaced"
            with self.subTest(field=field), self.assertRaises(Invalid):
                compile_contract(source)

    def test_role_swap_rejected(self):
        source = fixture()
        source["workload"]["spec"]["predictor"]["volumes"][0]["persistentVolumeClaim"][
            "claimName"
        ] = "data"
        with self.assertRaises(Invalid):
            compile_contract(source)

    def test_unbound_or_duplicate_devices_rejected(self):
        for duplicate in [False, True]:
            source = fixture()
            devices = source["workload"]["spec"]["predictor"]["containers"][0][
                "volumeDevices"
            ]
            if duplicate:
                devices[1]["devicePath"] = devices[0]["devicePath"]
            else:
                devices.append({"name": "extra", "devicePath": "/dev/coco-volume-4"})
            with self.subTest(duplicate=duplicate), self.assertRaises(Invalid):
                compile_contract(source)

    def test_unsafe_and_overlapping_destinations_rejected(self):
        for path in [
            "/",
            "/dev",
            "/proc/x",
            "/run/coco",
            "/usr/bin",
            "/data/../models",
            "/data//cache",
            "/data/",
            "/data",
            "/data/cache",
        ]:
            source = fixture()
            edit_binding(source, lambda b: b[0].update(mountPath=path))
            with self.subTest(path=path), self.assertRaises(Invalid):
                compile_contract(source)

    def test_host_mount_collision_rejected(self):
        for path in ["/models", "/models/qwen/config", "/"]:
            source = fixture()
            source["workload"]["spec"]["predictor"]["containers"][0]["volumeMounts"] = [
                {"name": "host", "mountPath": path}
            ]
            with self.subTest(path=path), self.assertRaises(Invalid):
                compile_contract(source)

    def test_model_cannot_format_and_rw_cannot_change_profile(self):
        for index, change in [
            (0, {"initialization": {"policy": "OnceIfApproved"}}),
            (2, {"profile": "luks-verity-v1"}),
            (2, {"content": {"approvedManifestRef": "other"}}),
        ]:
            source = fixture()
            source["declarations"][index]["spec"].update(change)
            with self.subTest(index=index, change=change), self.assertRaises(Invalid):
                compile_contract(source)

    def test_invalid_owner_and_key_redirection_rejected(self):
        for owner in [0, -1, True, "1001"]:
            source = fixture()
            source["declarations"][2]["spec"]["initialization"]["owner"]["uid"] = owner
            with self.subTest(owner=owner), self.assertRaises(Invalid):
                compile_contract(source)
        for resource in [
            "https://other/key",
            "kbs://other/a/b/c",
            "kbs:///a/b/../c",
            "kbs:///a/b/c?x=y",
        ]:
            source = fixture()
            source["declarations"][0]["spec"]["keyResource"] = resource
            with self.subTest(resource=resource), self.assertRaises(Invalid):
                compile_contract(source)

    def test_duplicate_keys_claims_and_unknown_spec_fields_rejected(self):
        for mutate in [
            lambda s: s["declarations"][1]["spec"].update(
                keyResource=s["declarations"][0]["spec"]["keyResource"]
            ),
            lambda s: s["declarations"][1]["spec"].update(
                claimRef=s["declarations"][0]["spec"]["claimRef"]
            ),
            lambda s: s["declarations"][0]["spec"].update(formatIfMissing=True),
        ]:
            source = fixture()
            mutate(source)
            with self.assertRaises(Invalid):
                compile_contract(source)

    def test_workload_and_key_changes_change_the_proposal_digest(self):
        source = fixture()
        previous = digest(compile_contract(source))
        source["workload"]["spec"]["predictor"]["containers"][0]["command"] = [
            "different"
        ]
        self.assertNotEqual(previous, digest(compile_contract(source)))
        source = fixture()
        source["declarations"][0]["spec"][
            "keyResource"
        ] = "kbs:///default/volume-keys/changed"
        self.assertNotEqual(previous, digest(compile_contract(source)))

    def test_extra_consumers_and_mutable_images_rejected(self):
        for key in ["containers", "initContainers", "ephemeralContainers"]:
            source = fixture()
            pod = source["workload"]["spec"]["predictor"]
            pod.setdefault(key, []).append({"name": "sidecar"})
            with self.subTest(key=key), self.assertRaises(Invalid):
                compile_contract(source)
        source = fixture()
        source["workload"]["spec"]["predictor"]["containers"][0][
            "image"
        ] = "example.invalid/vllm:latest"
        with self.assertRaises(Invalid):
            compile_contract(source)

    def test_duplicate_json_fields_and_oversized_input_rejected(self):
        for data in [b'{"x":1,"x":2}', b'{"x":NaN}', b"{" * 3000]:
            with self.subTest(data=data[:30]), self.assertRaises(Invalid):
                parse(data)
        with self.assertRaises(Invalid):
            parse(b" " * 20, maximum=10)

    def test_existing_mounts_cannot_hide_overlap_with_traversal(self):
        for path in ("/data/../models/qwen", "/models//qwen", "/models/./qwen", "/"):
            bundle = fixture()
            bundle["workload"]["spec"]["predictor"]["containers"][0]["volumeMounts"] = [
                {"name": "other", "mountPath": path}
            ]
            with self.assertRaises(Invalid):
                compile_contract(bundle)


if __name__ == "__main__":
    unittest.main()
