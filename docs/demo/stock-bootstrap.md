# Stock CoCo pattern → controller-driven Qwen

Supply a site YAML, cluster access, a repository-scoped SSH deploy key and a Vault
administrator token file. `make controller-demo` configures the missing Vault/ESO
and Trustee policy integration, builds the add-on and submits one `InferenceRelease`.
The controller then publishes encrypted Qwen, populates `/model`, initializes
encrypted `/data`, serves chat and tests persistence across a new confidential VM.

**Platform prerequisite:** an installed CoCo Validated Pattern with working CPU/GPU
attestation, the qualified OSC SNP/NVIDIA runtime, Vault Kubernetes authentication,
ESO/ClusterSecretStore, Argo automated sync, cert-manager, a working internal
registry and compatible CSI storage. This does not install or qualify different
hardware, enable GPU confidential mode, or manufacture trusted hardware reference
values. See [runtime pins](../../profiles/runtime/osc-snp-nvidia-artifacts.json).

## Inputs

Start from [quickstart.example.yaml](../../overrides/sites/quickstart.example.yaml).
Fill the cluster/node/StorageClass/Trustee fields, then verify this integration block:

```yaml
quickstart:
  integrations:
    enabled: true
    topologyFile: values-baremetal.yaml
    parentApplication: coco-pattern-baremetal
    applicationKey: trustee
  allowTrusteeRestart: true
  vault:
    namespace: vault
    pod: vault-0
    enrollmentNamespace: confidential-inference-enrollment
    serviceAccount: confidential-inference-enroller
    authMount: hub
    role: confidential-inference-enroller
    backendPath: secret/data/hub/modelKeys
    externalSecret: model-keys-eso
    projectionSecret: model-keys
  trustee:
    # Keep origin, deployment and public certificate references from the template.
    owner:
      namespace: vp-gitops
      application: trustee
      repository: git@github.com:YOUR_ORG/YOUR_COCO_PATTERN.git
      branch: main
      valuesFile: overrides/values-confidential-inference.yaml
```

`topologyFile` must contain `clusterGroup.applications.<applicationKey>` for the
actual Trustee application. `parentApplication` is the Argo application that
reconciles it. Use the exact repository URL and branch declared by that application.
The branch must accept direct pushes by the deploy key. Bootstrap appends the new
values file to Trustee's `extraValueFiles`; do not create this wiring manually.
Use fresh enrollment names or an identity already owned by this installation.

| External input | Required access / lifetime |
| --- | --- |
| `KUBECONFIG` | Administrator installation access; same permissions as the existing quickstart |
| `CI_GIT_SSH_KEY_FILE` | Private SSH deploy key, write access only to the CoCo owner repository |
| `CI_GIT_KNOWN_HOSTS_FILE` | Pinned SSH host keys, obtained through a trusted channel |
| `CI_VAULT_ADMIN_TOKEN_FILE` | Bootstrap policy/role configuration and initial KV creation; administrator credential stays outside cluster release state |

All three credential files must have private permissions (`0600`). The installer
does not discover a root token or read an installer credential Secret. Only the
repository deploy key is copied into `inference-release-git` for later enrollment.
No Vault administrator token enters Git, an image, a Kubernetes Secret created by
the add-on, or the controller's retained state PVC. Vault commands receive it on
stdin with captured output; it is not passed in process arguments.

## Run

Prerequisites on the workstation: Python 3.12+, Helm 3, `oc`, Git and curl.
No local Docker or Vault CLI is needed; Vault CLI runs in the declared existing
Vault Pod. Obtain the deploy key as described in the [controller runbook](controller.md#repository-scoped-git-credential).

```sh
git clone https://github.com/pmatouse/confidential-inference-pattern.git
cd confidential-inference-pattern
export KUBECONFIG=/private/path/cluster.kubeconfig
export VALUES=overrides/sites/my-cluster.yaml
cp overrides/sites/quickstart.example.yaml "$VALUES"
# Edit site fields before starting; keep the same inputs for this run.
export QUICKSTART_CACHE="$HOME/.cache/confidential-inference"
export CI_GIT_SSH_KEY_FILE=/private/path/deploy-key
export CI_GIT_KNOWN_HOSTS_FILE=/private/path/known_hosts
export CI_VAULT_ADMIN_TOKEN_FILE=/private/path/vault-bootstrap-token
chmod 600 "$CI_GIT_SSH_KEY_FILE" "$CI_GIT_KNOWN_HOSTS_FILE" \
  "$CI_VAULT_ADMIN_TOKEN_FILE"

make controller-demo VALUES="$VALUES" PYTHON=python3
```

Expected bootstrap sequence:

```text
ToolsReady → DependenciesReady → PlatformReady → IntegrationsReady
→ BootstrapReady → BuildsComplete → ImagesPinned → FoundationReady
→ ControllerBootstrapReady → release submitted
```

Observe the run, substituting the names from your YAML:

```sh
oc -n confidential-inference-trusted get inferencerelease qwen-demo-001 -w
# Expected final state: Ready / E2EPassed; eight completed stage receipts.
oc -n confidential-inference port-forward svc/qwen-demo-001-chat 8766:8080
# Open http://127.0.0.1:8766/
```

The bootstrap command stops on failure. Keep private state and inspect its gate;
do not reset retained keys/history or run manual release stages after controller
handover. Bootstrap is still an administrator command, not a cluster controller
holding an administrator credential. The eight release stages need no local process.

## What bootstrap changes

```mermaid
sequenceDiagram
  participant U as Site YAML + external credentials
  participant B as Administrator bootstrap
  participant V as Existing Vault
  participant G as CoCo owner Git repository
  participant A as Existing Argo
  participant T as Existing ESO / Trustee
  participant C as Release controller
  U->>B: Explicit cluster, Git and Vault access
  B->>B: Validate owner, pinned chart and rendered policy/ESO
  B->>V: Create exact enrollment ACL/role; CAS-create missing KV record
  B->>G: Commit chart adapter, preserved secret list and values wiring
  G->>A: Existing automated reconciliation
  A->>T: Reconcile model-key ESO, KbsConfig and fail-closed policy
  B->>T: Verify exact live policy, KbsConfig mapping and Ready ESO
  B->>C: Foundation, scoped identity, Git Secret and release intent
  C->>G: Exact per-release CPU launch and InitData bindings
  C->>V: Short-lived scoped login; CAS-patch new keys
  V->>T: ESO projection; verified resource loading
```

| Component | Automated change |
| --- | --- |
| Enrollment identity | Create its namespace/ServiceAccount and exact Vault ACL/role; reuse matching objects, reject conflicting permissions |
| Vault record | Preserve an existing `secret/data/hub/modelKeys`; create a missing record with CAS=0 and a public `bootstrap-marker`, never replacement keys |
| ESO | Add `model-keys` to the existing chart's `kbs.secretResources`; chart creates `model-keys-eso` and registers the Secret with KbsConfig |
| Git owner | Preserve other applications, resources and bindings; append the integration values file; refresh the existing parent and Trustee Applications |
| Stock Trustee chart | Materialize the pinned 0.10.2 chart under `charts/addons/confidential-inference-trustee` in the owner repository; change only `templates/resource-policy.yaml` |
| Existing compatible chart | Reuse its policy renderer; do not replace its attestation configuration or chart |
| Credentials | Install only the provided repository deploy key and host pins in the trusted namespace; Vault admin remains local |

The stock chart currently lacks a per-model binding hook. The generated **chart
adapter is an add-on**, not a claim that the stock chart already has this feature.
All other runtime chart files, including attestation policies and KbsConfig, are copied
unchanged and recorded by SHA-256 in its provenance file. Trustee, Kata and vLLM
binaries remain unchanged. Development metadata (including the upstream package’s
nested `.git` directory) is excluded from the materialized chart. This adapter is a candidate for an upstream chart hook.

The new stock adapter denies every unbound `default/model-keys/<tag>`. Bound tags
require affirmative CPU and GPU claims, exact SNP launch/InitData, non-debug and
non-migratable CPU evidence, and successful NVIDIA secure-boot/non-debug evidence.
The stock non-model resource rules are preserved. The public initialization marker
has no binding and cannot be released through the model-key rule.

## Scope and remaining gaps

- Only the reviewed stock chart and recognized compatible local charts are accepted.
  Unknown local charts, conflicting backend mappings, inline resource-list overrides
  and differing Vault privileges stop bootstrap instead of being overwritten.
- Existing Vault Kubernetes auth and ESO ClusterSecretStore configuration stay owned
  by CoCo. Auth-mount creation, Vault initialization/unseal and hardware attestation
  configuration are outside this add-on.
- The current key adapter uses the shared `hub/modelKeys` KV document. Vault grants
  apply to the entire document; per-installation KV paths remain future work.
- The generated policy binds new model resources; unrelated existing bindings and
  resources are retained. Existing compatible charts keep their existing behavior.
- Chart upgrades, credential/certificate renewal, full lifecycle GitOps and prompt
  TLS inside the guest remain separate work.

Validation: stock single/multi-source owner transformation, unchanged chart-file
hashes, conflict/credential boundaries and 17 OPA allow/deny cases are tested.
The earlier [fresh controller E2E](../../tests/evidence/2026-10-15/controller-fresh-e2e.json)
predates this bootstrap extension and does not by itself qualify the new stock
installation path. The live `qwen-controller-007` integration test reused the existing compatible
Trustee chart, created a new scoped Vault enrollment identity, preserved the existing
KV record, and verified Git/Argo policy reconciliation and Ready ESO. The stock
chart conversion is locally tested; a fresh stock-chart cluster has not yet been
qualified with this extension.
