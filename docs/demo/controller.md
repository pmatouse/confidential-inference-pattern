# Controller-driven Qwen release

The trusted `InferenceRelease` controller runs the shared quickstart operations as
sequential Kubernetes Jobs. The namespace CV/CW controller still creates KServe;
the new controller orchestrates publication, binding, measurement, enrollment,
approval and acceptance. Kata, vLLM and shared CoCo services stay stock.

**Scope:** one immutable fresh demo per installation. Administrator bootstrap
builds/installs the foundation and seeds verified stock artifacts and trust state.
Applying one release intent then runs the eight remaining stages without Make
or a local process. This is not yet automatic renewal, arbitrary retained-volume
upgrades, or full foundation lifecycle GitOps. The controller-driven path passed
hardware E2E on the qualified AMD SEV-SNP/NVIDIA profile.

## Recorded validation

[Controller E2E evidence](../../tests/evidence/2026-10-15/controller-e2e.json),
2026-10-15: `qwen-controller-001` reached **Ready / E2EPassed**, with eight completed
stage receipts. The run started with new add-on namespaces, encrypted model,
keys, PVCs and authority history on an existing OpenShift + CoCo installation.
Compatible shared dependencies were reused; the cluster was not reinstalled.

| Check | Observed result |
| --- | --- |
| Serving | Stock NVIDIA vLLM / Qwen3-0.6B through KServe; chat HTTP 200 and `7 plus 5 equals 12.` on both VMs |
| RO model | OCI-populated encrypted Block PVC; producer file hashes verified; read-only `/model` |
| RW data | Blank PVC initialized in the guest; canary survived a new VM/boot; same claims and initialization history |
| Attestation | Standard Trustee CPU/GPU appraisal; both authority EAR markers affirming |
| Isolation | CUDA on RTX PRO 6000 Blackwell Server Edition; unprivileged application; cluster-administrator exec blocked by guest policy |
| Recovery | Explicit retry resumed the existing replacement VM; controller restart retained all stage Jobs/receipts and the tested predictor |
| Git access | Repository-only SSH deploy key; strict host verification and in-cluster fetch/push dry-run passed; broad token removed |
| Other workloads | Separate `confidential-inference-demo` predictor UID unchanged |

The initial qualification exposed integration bugs and required fixes plus explicit
retries. Completed stages, keys and authority history were retained. Corrections
covered Lease timestamps, scoped RBAC apply ordering, executor profile packaging,
named Trustee Deployment reads, delayed Pod garbage collection and PVC alias
resolution. The final executor passed persistence/report and restart checks;
a second completely fresh release with that final image has not been run.
139 Python tests pass. [Bootstrap evidence](../../tests/evidence/2026-10-15/controller-bootstrap.json)
is the earlier intermediate snapshot, not the final outcome.

Fresh repetition `qwen-controller-002` exposed a shared-CRD ownership bug during
bootstrap, before any release started ([failure record](../../tests/evidence/2026-10-15/controller-002-bootstrap-failed.json)).
The installer now reuses the validated shared API without adopting it. A new
installation will qualify this correction; the failed attempt is not counted as E2E.

## Bootstrap once

Use the [quickstart inputs](quickstart.md), but a new run and new namespaces.
Supply the existing scoped Vault identity and permission for exact Trustee-owner
updates. The operator performs these steps once:

```sh
export KUBECONFIG=/private/path/cluster.kubeconfig
export VALUES=overrides/sites/my-controller.yaml
make qs-tools qs-dependencies qs-preflight qs-bootstrap qs-build qs-push qs-install VALUES="$VALUES"
# Register a repository-only deploy key using the commands below, then:
oc -n <trusted-namespace> create secret generic inference-release-git \
  --from-file=ssh-privatekey=/private/path/deploy-key \
  --from-file=known_hosts=/private/path/known_hosts
make release-controller-image VALUES="$VALUES"
make release-controller-install VALUES="$VALUES"
# The credential Secret is required before start; install can seed state without it.
make release-controller-start VALUES="$VALUES"
make release-controller-status VALUES="$VALUES"
```

Expected: `ControllerBootstrapReady`, followed by stage progress and eventually
`Ready / E2EPassed`. The release intent is also written as public
`output/quickstart/<run>/inference-release.json`; it can be owned by Argo instead
of applying `release-controller-start`. Do not give both owners competing specs.
The installation's exact site digest is administrator-authorized; changing it
requires a new installation or an explicit migration, not editing live claims.

The bootstrap retains `.private` trust material and public receipts on a new
filesystem PVC, together with hash-verified stock boot artifacts for measurement.
The executor image contains public source and pinned Linux clients, not those
secrets. The local run is marked controller-owned after transfer: ordinary
mutating Make stages refuse it. A serving manual release cannot be adopted through
this initial bootstrap path.

## Repository-scoped Git credential

The enrollment Job writes exact attestation bindings to the **existing Trustee
owner repository**, then asks Argo to refresh it. This is not the add-on source
repository. Keys and credentials never enter either repository.

For GitHub, create a dedicated write deploy key. GitHub restricts it to that one
repository; it can write any permitted branch in that repository, so branch
protection still matters. Register the public key using a repository administrator
session; only the new private key goes into the cluster Secret above.

```sh
export TRUSTEE_REPO=<owner/repository>
umask 077
mkdir -p /private/path
ssh-keygen -q -t ed25519 -N '' -C inference-release -f /private/path/deploy-key
jq -n --rawfile key /private/path/deploy-key.pub \
  '{title:"inference-release",key:$key,read_only:false}' |
  gh api --method POST "repos/$TRUSTEE_REPO/keys" --input - \
    --jq '{id,title,read_only}'
# Retrieve host keys over authenticated HTTPS; SSH fails closed on a mismatch.
gh api meta --jq '.ssh_keys[] | "github.com " + .' > /private/path/known_hosts
```

Expected: a deploy-key ID and `read_only: false`. Record the ID for revocation.
The Secret contains `ssh-privatekey` and `known_hosts`, **no token**. For rotation,
register a new key, replace those Secret fields, verify access, then revoke the
old deploy-key ID. Do not run Git maintenance while an enrollment Job is active.

Only `enroll` mounts the credential. The worker copies the key into its ephemeral
`/tmp` with mode `0600` (OpenShift Secret mounts may be group-readable), disables
ambient credential helpers and requires pinned SSH host verification. The private
copy disappears with the worker Pod. Trusted-namespace administrators can read
the Secret. Repository-scoped HTTPS tokens remain an alternative (`token` field);
supply exactly one credential type. The add-on does not mint or renew tokens.

## API and execution

```yaml
apiVersion: inference.confidentialcontainers.org/v1alpha1
kind: InferenceRelease
metadata:
  name: qwen-controller-001
  namespace: inference-trusted
spec:
  siteConfigRef:
    name: qwen-controller-001-site
    key: values.json
    sha256: <canonical-merged-site-sha256>
  acceptance:
    mode: FreshDemo
    allowTestVMReplacement: true
```

This is an add-on API. The immutable ConfigMap contains the normal merged public
site values. The bootstrap computes its digest and pins it in the controller's
administrator-owned grant. Neither release nor status contains credentials.

```mermaid
sequenceDiagram
  participant O as Administrator bootstrap
  participant A as Argo or operator
  participant C as Release controller
  participant J as Sequential stage Jobs
  participant P as Retained orchestration PVC
  participant W as Existing workload controller / KServe
  O->>P: Seed fresh trust state, foundation receipts and verified boot artifacts
  O->>C: Pinned image + exact site grant + scoped identities
  A->>C: Immutable InferenceRelease / explicit test replacement
  C->>C: Acquire per-release Lease; verify site digest
  loop model through report
    C->>J: Deterministic stage Job / no automatic Job retries
    J->>P: Lock run; validate release UID; reuse committed receipts
    J->>W: Shared tools drive publication, enrollment and deployment
    J->>P: Commit private/public durable stage state
    J-->>C: Immutable public receipt bound to release/spec/site/Job UID
  end
  C->>C: Check tested Pod/PVC identities and readiness
  C-->>A: Ready only after first/fresh-VM E2EPassed
```

| Stage | Shared operation | Completion |
| --- | --- | --- |
| `model` | Trusted publisher → encrypted OCI | `ModelPublished` |
| `volumes` | Source/PVC/CW creation; populator and UID binder | `VolumesBound` |
| `measure` | Approved stock artifacts → launch/policy/initialization plan | `ReleaseMeasured` |
| `enroll` | Authority metadata; exact Trustee-owner bindings; scoped Vault/ESO resources | `TrustReady` |
| `deploy` | Serve authority; sign package; CV controller → KServe; chat | `Serving` |
| `test-first` | Model hashes, CUDA, first RW canary, attestation, exec denial and chat | `FirstBootPassed` |
| `test-reopen` | Replace only this test predictor once; repeat inference/persistence checks | `FreshVMPersistencePassed` |
| `report` | Verify retained claims/history and current replacement | `E2EPassed` |

## Observe and use the result

```sh
oc -n <trusted-namespace> get inferencerelease <run>
# Inspect current phase/reason and the eight completed receipt references:
oc -n <trusted-namespace> get inferencerelease <run> -o jsonpath='{.status}'
oc -n <workload-namespace> port-forward svc/<run>-chat 8766:8080 --address=127.0.0.1
# Open http://127.0.0.1:8766/ and send a prompt.
```

Use the configured chat Service port if it differs from `8080`. For the recorded
run, namespaces are `ci-controller-001-trusted` / `ci-controller-001`, and the
service is `qwen-controller-001-chat`. The final report is in the immutable
ConfigMap named by the `report` stage's `receipt` field (`data.e2e-report.json`).
`qs-chat` expects local manual-run receipts; use the direct Service port-forward
for a controller-owned run. This endpoint remains localhost HTTP; it does not
provide TLS inside the confidential VM.

## Ownership and retries

The controller uses a per-release Kubernetes Lease. Job names are deterministic;
API create conflicts are reconciled. Workers additionally hold the retained run's
filesystem lock. Jobs have `backoffLimit: 0`; uncertain failure stops progression.
A committed stage receipt survives a lost worker acknowledgement, so retry publishes
the missing public acknowledgement without repeating completed effects.

Status is not the only history. The private executor PVC, authority database,
backend keys and application PVCs are separate retained assets. Completed Jobs and
immutable public receipts are retained; successful worker Pods can be removed to
release scheduling capacity. No owner reference garbage-collects retained storage.
Deletion of the release does not retire an already running predictor or erase keys.

After fixing the cause of a blocked stage, explicitly request a new attempt:

```sh
oc -n <trusted-namespace> annotate inferencerelease <run> \
  inference.confidentialcontainers.org/retry=retry-1 --overwrite
```

The reconciler waits for the previous attempt's active Pods to finish.
The fresh-VM test accepts deletion of the old Pod or a terminating `Succeeded`
Pod with the exact old UID and every container exited successfully; delayed API
garbage collection alone does not block it. A different VM/boot, persistent
canary, unchanged initialization history and closed old authority owner are
still mandatory. It never
clears authority ownership or discards disk/initialization history. Keep failure
logs private; the API exposes bounded reason codes, not raw subprocess errors.
Worker exceptions are retained at `/state/private/<run>/worker-<job>.error.log`,
alongside private stage logs; inspect them through an authorized operator session.
A controller restart/resync does not replace the VM again. Ready checks continue
to compare the tested Pod/PVC identities and Pod readiness; replacement loses
Ready and needs a deliberate validation workflow.

## Executor image maintenance

For a reviewed fix, rebuild and explicitly upgrade the orchestrator:

```sh
make release-controller-image VALUES="$VALUES"
make release-controller-upgrade VALUES="$VALUES"
```

Maintenance verifies the existing grant; only the pinned executor image may change.
It stops this controller and refuses to proceed while any stage worker remains
active. If refused, it stays paused: let the stage finish, inspect its result, then
repeat the upgrade. It installs a new immutable grant and restarts the controller,
retaining the same intent, PVCs, keys, receipts and authority history. Failed stages
still require the explicit retry annotation above. This does not upgrade a running
confidential workload, rotate credentials or re-seed retained state.

## Privilege and trusted-service boundary

The controller has release/status, Job, Lease and receipt access in its trusted
namespace, plus read-only predictor/PVC health access in the workload namespace.
It cannot directly read Secrets. Its ability to create executor Jobs makes it a
**trusted orchestrator**; this is not a sandbox against a compromised controller.

Controller, seed and stage Pods explicitly require OpenShift `restricted-v2`;
they do not inherit the root-only importer SCC. The guest storage sidecar retains
its separately scoped guest privileges.

The stage identity has namespace administrator access only in its two dedicated
namespaces, explicit storage/KServe APIs, cluster inventory reads, and scoped
cross-namespace integration grants: Vault Pod exec, named Vault TokenRequest,
named Trustee Secret/config reads, Trustee Pod verification/restart, and refresh
of the declared Argo owner Application. It does not receive cluster-admin or
machine-config-daemon exec. Stock artifacts are fetched and verified by the
administrator during bootstrap. The current Vault exec/Trustee integration is
powerful and backend-specific; replacing it with narrower authenticated service
interfaces is a remaining hardening task.

Authority metadata enrollment occurs before this installation's authority starts
serving. Concurrent enrollment into a shared serving authority is intentionally
unsupported. Automatic renewal, multiple releases sharing authority/history,
retirement/handover, generic backend adapters and portable prepublished images
remain separate work. Existing scoped key/policy and initialization checks are
unchanged; unattended execution does not turn unknown measurements into trust.

## Argo health

Use the chart's [health.lua](../../charts/inference-release-controller/health.lua)
as the custom health check for
`inference.confidentialcontainers.org/InferenceRelease`. Configure it through the
existing Argo owner's settings; do not overwrite operator-managed configuration.
`Blocked` maps to Degraded; missing/stale/in-progress status maps to Progressing;
only the current generation's `Ready=True / E2EPassed` maps to Healthy. Argo Sync
or a completed Job alone is not acceptance.
