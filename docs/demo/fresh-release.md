# Fresh release preparation

Prerequisites and inputs: [setup](setup.md), [input contract](../inputs.md).
This is the current **operator-orchestrated** release path. It produces fresh keys,
ciphertext and PVCs; copying an existing deployment is not a fresh-run test.

## 1. Trusted preparation environment

Install `charts/model-publisher` in a separate trusted enrollment namespace. Set
workload namespace, model/helper ImageStream names and a dedicated reader account.
The chart provides a restricted CPU-only publisher, memory-backed scratch, registry
CA and projected push token. It uses software QEMU, not host devices or a privileged pod.

The reader lives outside the workload namespace and has `get` only on the named
helper `imagestreams/layers`; the publisher has `get/update` only on its model stream.
Do not grant anonymous pulls. Stage public tool sources in `/build`.

Generate distinct 32-byte model/data keys privately. Model key input below is a
private file; transfer keys through protected stdin/files, never arguments with key
bytes, ConfigMaps or Git. Retain keys in the trusted backend after enrollment.

```sh
python3 components/model-publisher/fetch_tools.py --work /build/tools-fetch
python3 components/encrypted-model-populator/fetch_qwen.py --model /build/qwen
python3 components/encrypted-model-populator/prepare.py \
  --tools /build/tools-fetch/tools --model /build/qwen \
  --key /build/model.key --work /build/encrypted
python3 components/encrypted-model-populator/publish.py \
  --disk /build/encrypted/volume.raw --work /build/oci \
  --registry https://image-registry.openshift-image-registry.svc:5000 \
  --repository WORKLOAD_NAMESPACE/MODEL_STREAM \
  --ca /registry-ca/service-ca.crt --token /registry-auth/token
```

Preparation verifies pinned source files, builds LUKS + dm-verity over ciphertext
including its header, reopens RO and checks all files. Retain the public descriptor
and digest receipt. Remove plaintext scratch and the key-bearing appliance after
successful publication. Only ciphertext and public metadata enter OCI.

## 2. Declare and bind storage

Set `demo.source` from the publisher receipt and run `make demo-provision VALUES=...`.
The populator fills the model claim through a prime PVC; the data claim is blank.
The binding Job verifies Bound claims and records actual PVC UIDs in immutable
ConfidentialVolumes. The workload controller publishes its approval request.

## 3. Derive the measured release

Instantiate the [runtime profile](../../profiles/README.md) with the publisher's
file inventory, new run identity and public site inputs. Use the
[release commands](../../components/inference-release/README.md) in this order:

1. `render.py`: request + reviewed compatibility profile → exact workload policy.
2. `enroll.py plan/apply`: register RO identity and approve explicitly new RW claim
   UIDs against that policy. `charts/storage-enrollment` runs this without workload
   raw devices or volume keys against retained authority state.
3. `package.py`: enrollment + authority trust pins + AA/CDH configuration + expected
   runtime identity → InitData, its hash and public deployment artifacts.

Bootstrap the authority once. `trust.py` creates a CA, a separate non-CA TLS leaf,
receipt signer and approval signer; keep private files in the trusted domain.
Subsequent serving/enrollment must retain history and use
`fsGroupChangePolicy: OnRootMismatch` to preserve private database permissions.

Set CDH `authenticated_registry_credentials_uri` to the third Trustee resource
containing the scoped helper reader's Docker auth JSON. InitData contains only its
URI and public registry CA. Token renewal is currently manual.

## 4. Enroll trust before activation

Through the **existing CoCo Trustee owner**, install exact launch/InitData bindings
for all three resource tags, preserving CPU/GPU appraisal and unrelated bindings.
Then run `key_enrollment.py` with the private file map, encodings, reviewed live
policy hash and private journal. It uses scoped Vault authentication, CAS patch and
ESO verification; it refuses conflicting existing tags. See [backend bootstrap](vault-bootstrap.md).

Verify resources in the **running** KBS. Its operator copies Secret files at startup;
a pod replacement may be needed. A restart annotation alone is not evidence: check
replacement UID and loaded filenames without printing values. The resource-policy
binding map must be pretty-printed; Regorus limits each line to 1,024 columns.

Start authority serving with exact policy/InitData. Sign the public package using
`confidential-volume-controller/approve.py`, then apply its ConfigMap. The controller
verifies the signature and reconciles the KServe predictor and sidecar automatically.

## 5. Verify and retain

Deploy chat and run [both acceptance phases](acceptance.md): initial inference and
fresh-VM reopen. Compare initialization step IDs/hashes; no second format is allowed.
Keep authority history, keys and retained claims together. Missing close/uncertain
ownership requires diagnosis, not an automatic reset.

A policy change requires new measured configuration and Trustee/authority approval.
`update_policy.py` normally requires closed Ready volumes. Its explicit
`--allow-never-started` option additionally allows approved blanks with **zero
operation history**. Before formatting such a migrated blank, use
`reapprove_initialization.py` to CAS-reapprove unchanged geometry against the new
policy, then regenerate InitData with the new plan hash. Superseded approval is
retained; existing or previously attempted disks cannot use this path.
