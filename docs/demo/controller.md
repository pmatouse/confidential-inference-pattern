# Controller-driven Qwen release

The trusted `InferenceRelease` controller runs the shared quickstart operations as
sequential Kubernetes Jobs. The namespace CV/CW controller still creates KServe;
the new controller orchestrates publication, binding, measurement, enrollment,
approval and acceptance. Kata, vLLM and shared CoCo services stay stock.

**Scope:** one immutable fresh demo per installation. Administrator bootstrap
builds/installs the foundation and seeds verified stock artifacts and trust state.
Applying one release intent then runs the eight remaining stages without Make
or a local process. This is not yet automatic renewal, arbitrary retained-volume
upgrades, or full foundation lifecycle GitOps. Hardware qualification is pending
until the controller's own E2E evidence is recorded.

## Recorded validation

[Bootstrap evidence](../../tests/evidence/2026-10-15/controller-bootstrap.json),
2026-10-15: fresh isolated foundation and executor images built; controller Running
under `restricted-v2`; retained orchestration PVC seeded; CRD and release intent
accepted by API server dry-run; the other Qwen predictor retained its original UID.
131 Python tests cover contracts, ownership, failed Jobs, identity checks and
lost-acknowledgement recovery. Linux image build checks `oc`, Helm and shared imports.

The release has **not started**: the external Git credential Secret is pending.
No controller-driven encrypted-model/inference/persistence E2E result is claimed.
The manual quickstart's existing qualification does not substitute for this test.

## Bootstrap once

Use the [quickstart inputs](quickstart.md), but a new run and new namespaces.
Supply the existing scoped Vault identity and permission for exact Trustee-owner
updates. The operator performs these steps once:

```sh
export KUBECONFIG=/private/path/cluster.kubeconfig
export VALUES=overrides/sites/my-controller.yaml
make qs-tools qs-dependencies qs-preflight qs-bootstrap qs-build qs-push qs-install VALUES="$VALUES"
# Existing, repository-scoped credential; never put its value into YAML or arguments.
oc -n <trusted-namespace> create secret generic inference-release-git \
  --from-file=token=/private/path/git-token
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

The reconciler waits for the previous attempt's active Pods to finish. It never
clears authority ownership or discards disk/initialization history. Keep failure
logs private; the API exposes bounded reason codes, not raw subprocess errors.
A controller restart/resync does not replace the VM again. Ready checks continue
to compare the tested Pod/PVC identities and Pod readiness; replacement loses
Ready and needs a deliberate validation workflow.

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
