# Fresh encrypted Qwen release

This guide describes the new installation path, including trusted preparation.
Use it with [setup](setup.md), [Vault bootstrap](vault-bootstrap.md) and the
[release command reference](../../components/inference-release/README.md).
A fresh add-on namespace, new keys, a freshly encrypted model and new PVCs on an
existing configured CoCo cluster are not a reinstallation of that cluster.
The current qualified target is stock OSC SNP with NVIDIA GPU passthrough;
other hardware profiles require their own qualification.

## Platform and one-time installations

1. Install CoCo VP and configure its stock confidential GPU RuntimeClass, standard
   Trustee, CPU/GPU verification and reference values. Install the compatible
   KServe controller. Supply a CSI class supporting raw Block, ReadWriteOncePod
   and Immediate binding. Do not install a second copy of these services.
2. Build/pin the add-on controller, populator, sidecar and authority images. The
   helper image includes the storage client/service and cryptographic tools;
   neither Kata nor vLLM needs a rebuilt image. Keep the image metadata and stock
   runtime compatibility profile together: environment, mount shape and working
   directory are enforced by the measured agent policy.
3. Install the add-on CRDs, namespace-scoped controllers, admission rules and
   dedicated helper SCC using `make install-addon VALUES=...`. The SCC permits the
   storage helper inside Kata; vLLM remains UID/GID 1001, no capabilities, no
   privilege escalation, read-only root filesystem and no raw devices.
4. Establish a trusted enrollment namespace and the scoped Vault identity from
   the bootstrap guide. The controller and populator receive no key provisioning
   credential. Establish repository-scoped GitOps access if using the private repo.
5. Bootstrap retained authority history once using the storage-authority chart.
   Use a separate CA and CA-signed server leaf, plus fresh receipt-signing and
   approval identities. The guest pins the CA; do not serve the CA certificate
   itself as the server leaf, which Rust TLS verification rejects. `trust.py` separates
   public pins from private files. Keep the same history and namespace ownership
   range on subsequent starts. The authority is an add-on; it does not replace
   Trustee or hold the volume decryption keys.

Set `base.gpuResourceName` to the device plugin's advertised resource. The stock
sandbox plugin on the edge example exposes `nvidia.com/pgpu`, not
`nvidia.com/gpu`. The renderer explicitly sets `/` as the working directory and
opts out of generic InitData injection with `coco.io/skip-initdata: "true"` because
it supplies its own signed, measured InitData. This does not disable agent policy.

## Publish a new encrypted model

Install `charts/model-publisher` into the trusted enrollment namespace. Set
`workloadNamespace`, a fresh `modelImageStream`, and a dedicated `readerName`.
The chart creates a restricted publisher pod with memory-backed scratch, a
projected short-lived push credential and the registry CA. Its software QEMU
appliance runs without host devices or privileged container access. It is a
trusted data producer, not the confidential inference VM.

The reader account lives outside the workload namespace to avoid OpenShift's
implicit same-project image-puller grant. Its role permits only `get` on the
helper's named image stream. The publisher has `get/update` only on its model
stream. Do not grant anonymous registry access.

Stage the public source files into `/build` and run in the publisher:

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

Generate a fresh 32-byte model key in the trusted producer environment and transfer
it through private stdin or an equivalent protected channel, never a ConfigMap,
command argument or Git. Generate a distinct data key. Preparation verifies the
pinned Qwen files, creates LUKS, builds dm-verity over the ciphertext including the
LUKS header, reopens read-only and verifies all files. Only the ciphertext disk
and public metadata enter OCI. Keep the publisher descriptor and digest receipt
for enrollment; discard plaintext scratch and the key-bearing appliance after
successful publication. Retain the keys in the trusted backend.

## Declare and approve storage

Put the returned OCI source digests in site values and run `make demo-provision`.
The model PVC uses `dataSourceRef: EncryptedModelSource`; the populator imports
ciphertext through a prime PVC, verifies it and rebinds the PV. The data PVC has
no data source. A binding Job checks Bound claims and creates ConfidentialVolumes
bound to the actual claim UIDs. The ConfidentialWorkload controller then publishes
its public request and waits for approval.

Render a draft from that request and the reviewed runtime/image profile. Include
`startupChecks` with the producer's file inventory, `/model`, `/data` and a fresh
run identity. Create the enrollment plan from the reviewed publisher descriptor
and explicit list of new blank data claim UIDs. `charts/storage-enrollment` runs
`enroll.py apply` as a restricted, tokenless Job against the retained authority
claim. It only registers metadata and first-use permission; it has no volume key,
raw workload device or formatter. Repeated identical enrollment preserves history.

Both authority and enrollment use `fsGroupChangePolicy: OnRootMismatch`. This
prevents a later OpenShift mount from recursively widening the private database
permissions. Existing incorrect permissions require a separate owner-checked
migration, not automatic permission repair at every startup.

Package the public enrollment result, authority pins, AA/CDH settings and runtime
measurement. In the stock CDH `[image]` configuration, set
`authenticated_registry_credentials_uri` to a dedicated Trustee resource holding
a Docker auth JSON credential for the helper image. The public InitData contains
the resource URI and registry CA, never the token. Token lifetime must cover the
run and subsequent fresh VM launches; the current six-hour demo credential needs
explicit renewal for longer use. Automatic registry credential renewal is not
implemented.

The Trustee Helm template must pretty-print the binding map: Regorus rejects
a single policy line longer than 1,024 columns. Expanding the map must preserve
its exact contents and existing deny-by-default rules.

Install exact launch/InitData bindings for the model key, data key and helper pull
credential through the existing CoCo Trustee GitOps owner. Preserve its CPU and
GPU appraisal requirements and all unrelated workload bindings. Run
`key_enrollment.py` with the private key-file map, explicit encodings, runtime,
reviewed live resource-policy hash and a private journal. It uses a short-lived
scoped Vault login, a compare-and-set JSON merge patch, and verifies ESO output.
It refuses existing resource tags rather than silently rotating them.

The current standard Trustee operator copies resource Secret files in an init
container. After ESO updates, verify filenames in the running repository; a pod
replacement may be required. A Deployment restart annotation can be reverted by
its operator before any pod is replaced. Verify the replacement pod UID, loaded
resource names and mounted policy hash; never print the key contents.

Configure and start the authority using the packaged InitData and exact policy
hash. Only after all trusted bindings are verified, sign the four-file deployment
package with `approve.py` and apply its public ConfigMap. The controller creates
the KServe predictor with the stock application and storage helper.

## Acceptance gates

The sidecar attests through stock guest services, obtains authorized keys from
standard Trustee, verifies model metadata and dm-verity, and initializes the
blank data volume once under journaled authority permission. It installs the
mounts into vLLM's mount namespace before releasing the startup rendezvous.

Require all of the following, not just a Ready pod:

- Model files match the producer's hashes; `/model` is read-only.
- `/data` is writable, initialized as LUKS plus keyed dm-integrity, and the
  application's persistence canary was flushed.
- The application reports no capabilities/private devices and a passing CUDA
  computation; the authority reports affirming CPU and GPU appraisals.
- A real OpenAI-compatible inference request returns Qwen output. Deploy the
  separate chat chart and send a request through it too.
- Administrator `oc exec` is rejected by the measured agent policy.
- Gracefully replace the predictor pod, confirm a different guest boot ID, and
  verify the same canary and inference. No second format permit may be issued.

The demo startup check intentionally requires a fresh VM when it sees an existing
canary; an application-only restart in the same VM does not count as persistence
qualification. Missing Close/retained ownership requires explicit diagnosis; do
not reset the authority or delete PVCs to make a restart pass.

A strict profile correction requires renewed measured configuration, Trustee
bindings and authority policy approval. `update_policy.py --allow-never-started`
can additionally migrate an explicitly approved blank volume only if no operation
has ever been recorded. It preserves the original initialization identity and
rejects owned, revoked or previously attempted records. Before first formatting
a migrated blank, explicitly reapprove its unchanged plan against the new policy
with `reapprove_initialization.py`, then regenerate and approve InitData with the
new plan hash. The guest deliberately rejects an old-policy formatting approval.
The administrator command checks the previous plan hash and zero operation history
transactionally, retains the superseded approval, and changes no geometry or keys. Normal initialized-volume
migration still requires closed Ready state. This is an administrator CLI with
no guest-accessible route.
