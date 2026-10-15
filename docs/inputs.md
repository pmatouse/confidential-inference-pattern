# Inputs and generated artifacts

## Supply before starting

The [automatic stock-pattern bootstrap](demo/stock-bootstrap.md) accepts the same
site YAML plus external Git SSH and Vault administrator credential-file references.
It establishes the previously manual Vault/ESO/Trustee integration. Administrator
credentials are never retained by the release controller.

For either the manual Make or controller path, copy [quickstart.example.yaml](../overrides/sites/quickstart.example.yaml).
It merges over [values-global.yaml](../values-global.yaml) and covers public
preparation, Trustee-owner and backend references in `quickstart.*`.
The [quickstart](demo/quickstart.md) generates images, keys, measurements and release
artifacts. Authentication remains external; never put tokens, keys or kubeconfig in YAML.
The lower-level [demo-inputs template](../overrides/sites/demo-inputs.example.yaml)
remains available for already-prepared artifacts. Full lifecycle GitOps remains planned.

| Input | Location / requirement |
| --- | --- |
| Cluster access | `KUBECONFIG` outside Git; installer needs CRD/RBAC/SCC/admission and namespace permissions. Trusted enrollment additionally needs scoped backend access. |
| Installation identity | `installation.name`, `.namespace`, `.clusterIdentity`; stable and unique. Do not change identity when reopening retained volumes. |
| Hardware profile | `installation.profile`; currently only `osc-snp-nvidia-x86_64-v1`. CoCo CPU/GPU attestation must already work. |
| Existing platform | `base.*`: RuntimeClass/handler, GPU resource, raw Block StorageClass, KServe version/location, Trustee name/namespace, GitOps namespace. Defaults require verification. |
| Images | `images.controller`, `.populator`, `.sidecar`; application/Python defaults are pinned. `qs-build` builds all five add-on images; `qs-push` resolves their digests automatically. Edge internal URLs are not portable. |
| Registry | `registry.origin` HTTPS endpoint and CA (`injectServiceCA` for OpenShift). Model repository must be in the workload namespace. Scoped publisher push and helper pull identities are required. |
| Demo choice | `demo.name`, PVC sizes, `/model` and `/data`, served model name, distinct model/data KBS resource URIs, manifest reference. Fetcher uses a pinned Qwen source manifest. |
| Trustee integration | Trusted operator supplies KBS URL/CA, AS signing certificate, approved CPU/GPU reference values and access to the existing policy owner. Registry credential gets a third KBS URI. |
| Backend enrollment | Vault namespace/pod, Kubernetes auth mount/role/ServiceAccount, trusted namespace and ESO projection names: `quickstart.vault.*` (or direct `key_enrollment.py` arguments). Current adapter expects `secret/data/hub/modelKeys`; this is a site-specific integration. |
| Release trust | Authority hostname/state claim and private Secret reference: `charts/storage-authority`. Approval signer stays in the trusted domain; its **public** key goes in `approvalKeys`. |
| Exposure | `chat.enabled`, `serviceType`, `port`; explicit `nodePort` for VPN exposure. Default ClusterIP uses local port-forward. No automatic DNS, public ingress or TLS. |
| Integration bootstrap | `quickstart.integrations`: enable, owner topology file, parent Argo application and application key; external `CI_GIT_SSH_KEY_FILE`, `CI_GIT_KNOWN_HOSTS_FILE`, `CI_VAULT_ADMIN_TOKEN_FILE` |
| Controller Git credential | External `inference-release-git` Secret in the trusted namespace: repository-only SSH deploy key + pinned `known_hosts` (recommended), or repository-scoped HTTPS token. Used only by enrollment to update the existing Trustee owner repository; see [setup](demo/controller.md#repository-scoped-git-credential). |
| GitOps | Current opt-in: `gitops.enabled`, repository and full commit; separately provision repository-scoped access. Bootstrap snapshots resolved values into the Application; `gitops.valuesFile` is not currently watched. Full lifecycle GitOps is the target default. |

Tooling: Python 3.12+, pinned `requirements.txt`, Helm 3 and `oc`.
The trusted build/publisher also needs access to pinned images, source/model files,
registry and required attestation/certificate services, or equivalent approved mirrors.

## Generate during preparation

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

`qs-build` verifies installed stock firmware/kernel/initrd against the reviewed
artifact lock. `qs-measure` calculates the expected SNP launch measurement and
resolves Service IP/build metadata; `qs-enroll` packages the exact InitData.
This calculation is qualified only for the pinned [runtime profile](../profiles/README.md).
Authority TLS defaults to a 30-day certificate; certificate/approval/credential
renewal is an operational input, not an automatic feature.

## Reproducibility contract

- **Demonstrated:** fresh encryption, keys, claims and authority state on an existing
  CoCo cluster; inference and persistence across two VMs. The cluster itself was not reinstalled.
- **Manual path:** `qs-*` targets or `quickstart-all` run preparation, installation
  and verification from the public site YAML and external access. Argo release
  orchestration and credential renewal remain separate work.
- **Expected differences:** fresh keys, UUIDs, ciphertext/OCI digests, PVC UIDs and
  InitData. Reproducibility means the same verified behavior, not identical ciphertext.
- **Preserve on retry:** keys, authority history, claim UIDs, enrollment journal and
  already approved storage identities. Never “retry” by resetting retained disks/history.

See [automation boundary](automation.md) for the install-and-run target.
