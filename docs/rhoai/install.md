# CoCo installation to confidential Qwen chat

This branch implements the RHOAI preview path. The earlier custom storage stack
is not part of this installation. Start with the normal CoCo Validated Pattern,
then apply this extension. The source lock and image digests are in this
repository; generated secrets and per-cluster measurements belong to the
installer's private state directory and the trusted CoCo configuration owner.

## Installation contract

Provide an OpenShift cluster, an AMD SEV-SNP-capable host and a supported NVIDIA
confidential-computing GPU. Enable the required firmware/IOMMU settings and GPU
confidential mode. For this lab the platform is OpenShift 4.22.15, OSC 1.13.0,
Trustee 1.2.0 and an RTX PRO 6000 Blackwell Server Edition. This hardware/version
combination is the tested target, not a claim of general hardware certification.

The normal pattern owns GPU setup, the confidential runtime, Trustee, Vault/ESO
and block storage. The extension needs one free `nvidia.com/pgpu`, a 64 GiB guest,
8 vCPUs, a storage class supporting raw Block and `ReadWriteOncePod`, and enough
pod capacity for the RHOAI serving controllers. Disable optional sample workloads
on a small single-node cluster. Do not install a second KServe controller.

On the administrator workstation install OpenShift CLI, Helm **3**, Git,
Python 3.11+ with PyYAML, curl and OpenSSL. The normal pattern installer also
uses Podman. Supply registry credentials entitled to the RHOAI 3.6 EA2 images.
The cluster must reach Red Hat registries, the pinned Hugging Face model revision
and the CPU/GPU attestation collateral endpoints (or use the pattern's documented
collateral caches). DNS and HTTPS ingress must be reachable by the demo audience.

## Dependencies and GitOps ownership

Install the configured CoCo pattern once. Its ClusterGroup includes the CoCo
operators and configuration plus the `rhoai-platform` Argo CD Application. RHOAI
is enabled during bootstrap, before model-specific preparation. There is no
separate administrator installation of the RHOAI operator.

Validated Patterns represents operators with OLM subscriptions and configuration
with Argo CD applications. This extension keeps the RHOAI Subscription,
OperatorGroup and DataScienceCluster together in the existing `rhoai-platform`
chart, with one GitOps owner. Do not also declare `rhods-operator` under
`clusterGroup.subscriptions`: that would give the same Subscription two owners.
CoCo is the base pattern being extended, rather than a second nested Pattern
installation or a second copy of its shared operators.

Argo CD performs the following sequence automatically:

1. Create the RHOAI namespace, OperatorGroup, restricted bootstrap RBAC and
   Subscription.
2. Run a bounded Sync hook alongside the Subscription. Keep OLM approval set to
   `Manual`, but automatically approve the plan only when its entire CSV list
   matches the single pinned `rhods-operator.3.6.0-ea.2` release. A changed release,
   additional bundle or existing different RHOAI version stops the hook for
   explicit review. `startingCSV` alone would not prevent future upgrades.
3. Wait for the CSV to succeed and the DataScienceCluster v2 API to be served.
4. Apply the DataScienceCluster with KServe enabled, then wait for Ready and the
   required LLMInferenceService APIs. The hooks use a stock Red Hat UBI Python
   image and embedded scripts; they add no operator or derivative image.

The operator approval hook shares the Subscription's sync wave to avoid waiting
for approval before the approval hook can run. DataScienceCluster uses a later
wave and skips dry-run only while its CRD is absent. Readiness checks supplement
ordering; merely creating a Subscription is not proof that serving is usable.

| Automatic pattern dependencies | Explicit model/site preparation |
|---|---|
| CoCo operators, runtime, Trustee and storage from the normal base configuration | Hardware/firmware setup, entitlement and normal CoCo secret/reference inputs |
| RHOAI operator installation, pinned initial approval and serving configuration | Build the derivative image or provide its reviewed digest |
| Argo CD reconciliation of the configured application | Enroll keys, publish the encrypted model, generate and commit the measured binding and site values |

The application and model publisher remain disabled for a new site until
`rhoai-configure-owner.sh ready` publishes their inputs. Bootstrap reruns preserve
already-enabled applications. The temporary dependency hooks are removed on
success; their completion is recorded in the Argo sync operation. Later RHOAI
upgrades still require an explicit Git change and review of the version pin.

Framework references: [ClusterGroup subscriptions and applications](https://validatedpatterns.io/learn/clustergroup-in-values-files/)
and [sequencing with sync waves and hooks](https://validatedpatterns.io/blog/2024-11-07-clustergroup-sequencing/).

## Ordered workflow

Use a private state directory. Set `KUBECONFIG` to the intended cluster and review
the current context before starting. A resumed installation must use the same
state directory: replacing the LUKS key will make an existing volume unreadable.

```bash
export KUBECONFIG=/secure/path/cluster.kubeconfig
export STATE_DIR="$PWD/.private/rhoai"
export HELM=helm
export DEMO_NAMESPACE=rhoai-confidential-qwen
export PUBLISHER_NAMESPACE=rhoai-model-publisher
export STORAGE_CLASS=lvms-vg1
export REGISTRY_AUTH_FILE=/secure/path/registry-auth.json
```

1. Fork and configure the normal CoCo pattern for the hardware. Use its existing
   secret generation, reference calculation and installation workflow. Set `COCO_CHECKOUT` and run `scripts/rhoai-configure-owner.sh bootstrap`.
   This installs the Trustee configuration adapter through the existing owner,
   reserves the demo key class before enrollment, disables competing sample
   inference applications and enables RHOAI as a platform dependency. The model
   publisher and Qwen application stay disabled until their values are ready.
   Commit and push that fork. Existing installations must orphan the
   old KServe Applications before retiring their owner: deleting their CRDs can
   destroy RHOAI resources. The adapter targets the pinned 0.10.x Trustee chart;
   review its configuration when rebasing onto a newer normal CoCo pattern.
   Set `COCO_CHECKOUT` to the checkout and run
   `scripts/rhoai-demo.sh foundation`, which installs the normal pattern and waits
   for its RHOAI dependency. For an existing CoCo installation,
   `scripts/rhoai-demo.sh preflight` checks the necessary objects and detects a
   competing upstream KServe deployment.
2. Check the `rhoai-platform` Argo Application is Synced/Healthy. Optionally run
   `scripts/rhoai-demo.sh platform` to wait for the pinned CSV, DataScienceCluster
   and serving API. This command is read-only; Argo CD performs the installation
   and guarded approval automatically. The demo has no external inference
   gateway; the chat proxy accesses vLLM over guest loopback.
3. Run `scripts/rhoai-demo.sh build`. OpenShift builds the small initializer
   derivative from the exact Red Hat base digest plus merged KServe PR 6219. The
   resulting immutable digest is saved in `STATE_DIR/initializer-image`.
4. Set `CHAT_HOST` if the standard application domain is not the intended browser
   hostname. Run `scripts/rhoai-enroll.sh`. It preserves existing keys, creates a
   demo CA and guest TLS certificate when absent, and writes model/LUKS/TLS and
   narrowly scoped image-pull credentials to the normal Vault backend. It uses
   the standard CoCo bootstrap handoff or `VAULT_ADMIN_TOKEN_FILE`. Neither
   credentials nor private keys are committed to Git.
5. Set `MODEL_KEY_FILE="$STATE_DIR/model-key.json"` and run
   `scripts/rhoai-demo.sh publish`. The trusted publisher downloads the exact
   Qwen revision, verifies the file inventory, creates compact JWE files using
   the pinned reference utility and serves only the resulting encrypted archive.
   Publisher plaintext is temporary trusted preparation data; it is not a
   confidential workload and is not protected from the publisher administrator.
6. Set `SNP_LAUNCH_MEASUREMENT` to the independently computed stock GPU guest
   identity for the chosen vCPU count and runtime artifacts. Use the CoCo
   reference-collection workflow, never a measurement copied from a quote just
   because it was observed. Run `scripts/rhoai-prepare.sh`. It verifies membership
   in the CoCo-owned reference store and generates the measured guest policy,
   public site values and exact Trustee binding. A command, script, model hash,
   image, namespace or KBS endpoint change requires regeneration and approval
   through the trusted owner.
7. Run `scripts/rhoai-configure-owner.sh ready`, then commit and push the CoCo
   fork. It publishes the measured binding and public site values, enables the
   model publisher and Qwen Applications while retaining the already-enabled
   RHOAI platform Application, and keeps Trustee under its existing owner. Set the
   Pattern's Git revision to that branch using the normal pattern installer.
   Wait for the ExternalSecret, RVPS and resource policy to converge, then the
   confidential application. If updating an existing guest identity, restart
   Trustee after its configuration reconciles so the new reference is loaded. During development,
   `scripts/rhoai-demo.sh deploy` renders and applies the same chart.
8. Set `CHAT_CA_FILE="$STATE_DIR/chat-ca.crt"` and run
   `scripts/rhoai-demo.sh verify`. It checks that both servers are in one ready
   confidential pod, then sends a real chat request with TLS certificate
   verification. Open the reported URL from the demo network and verify a
   browser conversation. Trust the demonstration CA on the presentation client,
   or replace the leaf certificate with one signed by the organization's CA.

`ADDON_REPO` and `ADDON_REVISION` select the extension source (default: this
checkout's origin and `rhoai-confidential-qwen`). The generated owner files are
public configuration; never copy the rest of `STATE_DIR` into either repository.
For an existing lab, `TRUSTEE_CHART_PATH=charts/hub/trustee-edge` retains that
chart location. A new site defaults to `charts/hub/rhoai-trustee`.

When migrating an existing Pattern from an SSH repository URL to public HTTPS,
remove stale `spec.gitSpec.tokenSecret` and `tokenSecretNamespace` references if
its status reports `invalid auth method`. Keep the credential Secret itself for
rollback. The standard installer merges the Pattern and preserves those old
fields. A new public-HTTPS installation has no such credential references.

When reusing a cluster from the earlier custom storage demo, retire that
installation's orphaned SCCs along with its owner. An OLM-managed operator can
otherwise select an old `MustRunAs: 0` importer SCC and conflict with its own
`runAsNonRoot: true`, even though the confidential demo itself is healthy. Check
the failed pod's `openshift.io/scc` annotation and remove only constraints owned
by the retired installation; keep the standard platform SCCs.

The scripts stop on failures. They do not erase old model volumes, rotate keys
implicitly, approve a different RHOAI CSV, or retire unrelated applications.
The retained block claim and Vault data are required for a safe rerun.

## Trustee ownership

The site's existing Trustee chart remains the single owner of KbsConfig,
resource policy, reference values and ExternalSecrets. The small extension adds:

- A `rhoai-qwen-secrets` resource backed by `secret/data/hub/rhoaiQwen` in Vault.
  Values are Base64 encoded in Vault and decoded by ESO, including the raw
  32-byte model key. The publisher's JWK and Trustee's raw key describe the same
  key, as required by the RHOAI initializer.
- An exact `confidentialGuestBindings` entry for this resource class, requiring
  the approved SNP launch and initdata digests, affirming CPU/GPU results, debug
  and migration disabled, GPU secure boot and successful GPU measurements.
- The generated initdata digest in the normal RVPS policy. Generic Trustee
  resource access must explicitly exclude this protected resource class.

The registry pull token is a revocable ServiceAccount token with image-puller
access only in the demo namespace. It avoids an expiring development token and
is delivered through KBS rather than mounted into application containers. Rotate
it by replacing the token Secret and rerunning enrollment. Keep all trusted keys
in the chosen trusted backend; a single-cluster demo still trusts its Trustee
administrator.

## Persistence and acceptance

Qualification requires a fresh blank raw volume, successful CPU/GPU attestation,
eight verified model files, a real chat response and a browser conversation.
Restart the entire pod and verify that the initializer reports
`MODEL_PERSISTENCE_HASHES_PASS`, with different first/current guest boot IDs,
then repeat chat. A successful RHOAI Ready condition alone is insufficient.

Run `tests/rhoai/streaming_cluster.sh` for the 2 GiB regression and tampered-tag
check in the actual built image with a 512 MiB limit. Run
`tests/rhoai/reject_unapproved_guest.sh` for hardware key-denial evidence (requires
a second free passthrough GPU). It alters only the initdata identity, uses no
model PVC, and removes its temporary pod afterwards. `make test-rhoai` exercises
command/image/environment injection, private-path writes, GPU device constraints,
policy replacement and the Trustee decision matrix. A live `oc exec ... -- true`
against the final guest must fail with `ExecProcessRequest is blocked by policy`. Record the exact
image digests, source commits and test results. The final validation record must
distinguish fresh CoCo installation, reconciliation of an existing foundation,
fresh application/volume installation and a restart; they are different tests.

## Preview status and troubleshooting

Confidential model loading in RHOAI 3.6 EA2 is an Early Access/Developer Preview
feature. The initializer derivative is a demo build. PR 6219 fixes full-file JWE
memory consumption; it does not change Red Hat support limits or remove disk
capacity requirements. Keep the original and patched image provenance visible.

The stock GPU kernel command line starts CDH's local resource endpoint. Do not
carry forward the older demo's `guest_components_procs=confidential-data-hub`
override: that configuration did not expose the HTTP API needed by this path.
On this Blackwell target, the selected Red Hat vLLM build is tested with the
Triton attention backend after FlashAttention crashed during its first request.
Do not substitute another inference image without repeating the real-chat test.
