# Inputs and generated artifacts

## Supply before starting

Copy [the input template](../overrides/sites/demo-inputs.example.yaml) to a site
override; it merges over [values-global.yaml](../values-global.yaml). These are the
**current** input locations; there is not yet a single file covering trusted preparation.
Names, resource URIs and public digests may go in Git. Credentials and key bytes may not.
You supply authentication/authorization; the demo generates its own encryption keys.

| Input | Location / requirement |
| --- | --- |
| Cluster access | `KUBECONFIG` outside Git; installer needs CRD/RBAC/SCC/admission and namespace permissions. Trusted enrollment additionally needs scoped backend access. |
| Installation identity | `installation.name`, `.namespace`, `.clusterIdentity`; stable and unique. Do not change identity when reopening retained volumes. |
| Hardware profile | `installation.profile`; currently only `osc-snp-nvidia-x86_64-v1`. CoCo CPU/GPU attestation must already work. |
| Existing platform | `base.*`: RuntimeClass/handler, GPU resource, raw Block StorageClass, KServe version/location, Trustee name/namespace, GitOps namespace. Defaults require verification. |
| Images | `images.controller`, `.populator`, `.sidecar`; application/Python defaults are pinned. Authority image and trusted preparation image are separate chart values. Build/publish for your registry; edge internal URLs are not portable. |
| Registry | `registry.origin` HTTPS endpoint and CA (`injectServiceCA` for OpenShift). Model repository must be in the workload namespace. Scoped publisher push and helper pull identities are required. |
| Demo choice | `demo.name`, PVC sizes, `/model` and `/data`, served model name, distinct model/data KBS resource URIs, manifest reference. Fetcher uses a pinned Qwen source manifest. |
| Trustee integration | Trusted operator supplies KBS URL/CA, AS signing certificate, approved CPU/GPU reference values and access to the existing policy owner. Registry credential gets a third KBS URI. |
| Backend enrollment | Vault namespace/pod, Kubernetes auth mount/role/ServiceAccount, trusted namespace and ESO projection names: `key_enrollment.py` arguments. Current adapter expects `secret/data/hub/modelKeys`; this is a site-specific integration. |
| Release trust | Authority hostname/state claim and private Secret reference: `charts/storage-authority`. Approval signer stays in the trusted domain; its **public** key goes in `approvalKeys`. |
| Exposure | `chat.enabled`, `serviceType`, `port`; explicit `nodePort` for VPN exposure. Default ClusterIP uses local port-forward. No automatic DNS, public ingress or TLS. |
| Optional GitOps | `gitops.enabled`, repository, full commit, values path; separately provision repository-scoped access for a private repo. |

Tooling: Python 3.12+, pinned `requirements.txt`, Helm 3 and `oc`.
The trusted build/publisher also needs access to pinned images, source/model files,
registry and required attestation/certificate services, or equivalent approved mirrors.

## Generate during preparation; do not copy from the lab

| Output | Produced by / consumed by |
| --- | --- |
| Fresh 32-byte model and data keys | Trusted producer/enrollment; retained in Trustee's backend, never in PVC/ConfigMap/Git |
| Authority CA + TLS leaf, receipt and approval keys | `trust.py`; private material stays trusted, public pins enter release configuration |
| LUKS UUID, verity root/salt, header/file hashes, OCI manifest/disk digests | Publisher; populate `demo.source` and reviewed descriptor |
| Actual PVC UIDs and volume identities | Binding Job + enrollment; immutable bindings, not user guesses |
| Workload policy and initialization-plan hash | Release renderer + authority enrollment; bind current workload and explicitly new data volume |
| InitData SHA-256 | `package.py`; computed from exact public AA/CDH, policy and storage configuration |
| Signed deployment approval | Trusted signer after Trustee bindings and enrollment are verified; controller consumes it |
| Registry reader token | Scoped identity; kept as a Trustee resource, renewal currently manual |

Current manual runtime inputs: reviewed stock initrd hash, expected SNP launch
measurement for the exact boot configuration, Kubernetes Service IP, image/build
metadata and the [compatibility profile](../profiles/README.md). Packaging computes
InitData; **the installer does not yet discover or calculate the launch measurement**.
Authority TLS defaults to a 30-day certificate; certificate/approval/credential
renewal is an operational input, not an automatic feature.

## Reproducibility contract

- **Demonstrated:** fresh encryption, keys, claims and authority state on an existing
  CoCo cluster; inference and persistence across two VMs. The cluster itself was not reinstalled.
- **Repeatable today:** staged commands with matching pinned artifacts and trusted
  inputs. Manual orchestration remains; installation alone does not produce a chat endpoint.
- **Expected differences:** fresh keys, UUIDs, ciphertext/OCI digests, PVC UIDs and
  InitData. Reproducibility means the same verified behavior, not identical ciphertext.
- **Preserve on retry:** keys, authority history, claim UIDs, enrollment journal and
  already approved storage identities. Never “retry” by resetting retained disks/history.

See [automation boundary](automation.md) for the install-and-run target.
