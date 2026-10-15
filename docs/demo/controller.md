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

The [integration-bootstrap run](../../tests/evidence/2026-10-15/integration-bootstrap.json)
also passed `qwen-controller-007` after automatic Vault/ESO/Trustee setup: eight
initial Jobs, fresh-VM persistence and no stage intervention. It reused a compatible
Trustee chart; [stock-chart coverage and bootstrap limits](stock-bootstrap.md#recorded-validation)
are recorded separately.

[Fresh unattended E2E evidence](../../tests/evidence/2026-10-15/controller-fresh-e2e.json),
2026-10-15: `qwen-controller-006` reached **Ready / E2EPassed** from source
`c273861`. A single bootstrap invocation built six new images and installed the
add-on in new namespaces. After applying one `InferenceRelease`, all eight
first-attempt Jobs completed without manual fixes, retry annotations, per-stage
Make commands or controller restarts.

The starting platform was **OpenShift + CoCo already installed**. Compatible shared
CRDs, KServe, Trustee and the cluster registry were reused. Model ciphertext,
keys, claims, authority history and release state were new. This qualifies a fresh
add-on installation on that platform, not an OpenShift/CoCo reinstall or every
shared-dependency installation path.

| Check | Observed result |
| --- | --- |
| Orchestration | Eight initial stage Jobs; one pinned executor image; zero failed stage Jobs; controller UID/image/restart count unchanged |
| Serving | Stock vLLM / Qwen3-0.6B through KServe; real CUDA inference and chat HTTP 200 before and after VM replacement |
| RO model | Newly encrypted OCI artifact → populated Block PVC → read-only `/model`; producer file hashes verified |
| RW data | New blank PVC initialized in the guest; canary survived a different VM/boot; same claims and unchanged initialization history |
| Attestation | Standard Trustee CPU/GPU appraisal; exact workload bindings; both authority EAR markers affirming |
| Isolation | Unprivileged application; cluster-administrator exec denied by guest policy |
| Git access | Dedicated write SSH deploy key limited to the Trustee owner repository; no broad token installed |
| Other workloads | Separate `confidential-inference-demo` predictor UID unchanged |

The acceptance workflow intentionally replaces its own predictor once to test
persistence. That replacement is an automated test stage, not an operator repair.
All six builds also completed on their first attempts; no automatic transfer
retry was needed. These counts and results describe the recorded `006` run;
subsequent changes and bootstrap coverage are recorded in the `007` evidence.

### Qualification history

Fresh attempts `002`–`005` were retained as failures and never repaired or retried
into a passing result. Each correction was committed and tested before a new attempt.

| Attempt | Failure and correction | Evidence |
| --- | --- | --- |
| `001` | Initial integration qualification needed explicit fixes/retries; also tested controller restart recovery | [Earlier E2E](../../tests/evidence/2026-10-15/controller-e2e.json) |
| `002` | Bootstrap tried to adopt an already validated shared release CRD; installer now reuses it | [Record](../../tests/evidence/2026-10-15/controller-002-bootstrap-failed.json) |
| `003` | Enrollment raced the owner-managed Trustee rollout; wait for a unique healthy Pod and verify exact key hashes before any authorized restart | [Record](../../tests/evidence/2026-10-15/controller-003-enrollment-failed.json) |
| `004` | Stock-initrd binary transfer failed; bounded read-only transport recovery preserves pinned-hash verification | [Record](../../tests/evidence/2026-10-15/controller-004-bootstrap-failed.json) |
| `005` | Compiled-binary transfer failed; existing verified receive loop now also handles transport exceptions | [Record](../../tests/evidence/2026-10-15/controller-005-bootstrap-failed.json) |

Transport recovery accepts only complete bytes matching the expected digest.
A failed stage Job still blocks the release; it is never silently retried.

## Bootstrap once

Use the same [site template and external credentials](stock-bootstrap.md#inputs)
as the manual quickstart, with a fresh run and namespaces. The normal entry point is:

```sh
make controller-demo VALUES="$VALUES" PYTHON=python3
make release-controller-status VALUES="$VALUES" \
  PYTHON="${QUICKSTART_CACHE:-$PWD/.cache/quickstart}/venv/bin/python"
```

The expanded sequence is useful for inspecting the foundation before handover:

```sh
make quickstart-foundation VALUES="$VALUES" PYTHON=python3
export PYTHON="${QUICKSTART_CACHE:-$PWD/.cache/quickstart}/venv/bin/python"
make release-controller-image VALUES="$VALUES" PYTHON="$PYTHON"
make release-controller-install VALUES="$VALUES" PYTHON="$PYTHON"
make release-controller-start VALUES="$VALUES" PYTHON="$PYTHON"
```

`quickstart-foundation` is shared with the manual path and includes
`qs-integrations`; it installs the repository-scoped Git Secret automatically when
integrations are enabled. Run expanded commands sequentially. Do not list dependent
Make targets together under `make -j`.

If integrations were configured externally, set `quickstart.integrations.enabled: false`
before starting and follow [external bootstrap](vault-bootstrap.md). In that
mode, create the Git Secret after the foundation and before controller start:

```sh
oc -n <trusted-namespace> create secret generic inference-release-git \
  --from-file=ssh-privatekey=/private/path/deploy-key \
  --from-file=known_hosts=/private/path/known_hosts
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
session; only the new private key goes into the cluster Secret (automatically
during enabled integration bootstrap).

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
  name: qwen-controller-006
  namespace: inference-trusted
spec:
  siteConfigRef:
    name: qwen-controller-006-site
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
run, namespaces are `ci-controller-006-trusted` / `ci-controller-006`, and the
service is `qwen-controller-006-chat`. The final report is in the immutable
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
