# Manual E2E quickstart: implementation specification

**Acceptance specification for the implemented manual path.** Use the
[executable quickstart](quickstart.md) for current commands, qualification and limits.
The [controller path](controller.md) is also implemented and uses the same stage
handlers. Both installers share `quickstart-foundation`; automatic integration
bootstrap and current credentials are described in [stock bootstrap](stock-bootstrap.md).

## Starting and finishing states

Agreed starting boundary: installed OpenShift + CoCo VP on a qualified CPU/GPU,
with cluster access. Start with **no add-on namespace, image builds, encrypted
model, keys, approvals, claims or authority history**. An empty local cache must work.
OpenShift provisioning and hardware/firmware enablement are platform prerequisites,
not actions hidden inside an inference Make target. List and check their exact
versions. Reuse compatible shared services; document installation commands for
any missing supported dependency, especially KServe and registry/storage setup.

Finish with a reachable chat → KServe → stock vLLM → confidential GPU, verified
RO `/model`, persistent encrypted RW `/data`, standard Trustee CPU/GPU-gated keys,
denied administrator exec and first/fresh-VM E2E receipts. No new release
orchestrator is required; the existing populator and volume/workload controllers
remain installed. See the [two-path plan](../full-lifecycle-implementation-plan.md).

## Files to deliver

- `make/quickstart.mk`, included by the root Makefile: small, sequential targets.
- `scripts/quickstart.py`: configuration validation, shared stage invocations,
  receipt inspection, output handling and safe resume; no embedded site credentials.
- One complete public site template, including build/preparation, authority,
  backend/Trustee-owner mapping, reviewed runtime/profile and exposure inputs.
- A succinct `docs/demo/quickstart.md`: numbered commands, expected output, next
  step and one troubleshooting pointer per stage. All required commands are inline
  or executable targets; no “prepare the files” or “configure Trustee” omissions.
- Pinned build recipes/contexts for every add-on image, with public input inventories.
- Manual-path E2E evidence from a fresh run; CI tests of stage contracts/retries.

Use the same operation API and receipt schema as the release controller. Make runs
commands rather than relying on file timestamps as proof of external completion.
Completed steps are verified before skipping. Local private state uses a mode-0700
run directory with mode-0600 files; generated public output is separate. Both are
ignored by Git. Keys/signers also retain their required durable backend identity.

## Operator command sequence

The finished how-to must provide these commands and checks. Names below record the original acceptance contract; the executable guide lists
the implemented result names.
All targets take `VALUES=overrides/sites/my-site.yaml RUN=qwen-demo-001`.

| Command | Must do | Expected result / follow-up |
| --- | --- | --- |
| `make qs-tools` | Check/install documented client dependencies; create pinned Python environment; verify Helm 3, oc and local build prerequisites | `ToolsReady`; print versions and any exact missing-tool installation command |
| `make qs-dependencies` | Inventory shared services; install only explicitly enabled, pinned missing dependencies such as KServe; configure the internal registry/storage through the supported site recipe | `DependenciesReady`; print reused/installed versions and owners; reject incompatible existing installations |
| `make qs-preflight` | Check kubecontext, qualified runtime/CPU/GPU, free GPU capacity, registry CA/storage, CSI raw Block/RWOP/Immediate, KServe and namespace ownership | `PlatformReady`; otherwise name failed prerequisite and its setup instructions; never evict another workload |
| `make qs-integrations` | Configure scoped Vault role/backend and Git-owned ESO/Trustee integration, or record externally supplied integrations | `IntegrationsReady` / `ExternalIntegrationsReused`; verify policy and ESO convergence |
| `make qs-bootstrap` | Create isolated workload/build/trusted namespaces and scoped identities; provision public registry/CA references and stable authority/signing credentials through authorized admin access | `BootstrapReady`; print public identities and private-state location, never secrets |
| `make qs-build` | Fetch verified source/tool inputs; compile/package all add-on images using the qualified Linux environment; build in OpenShift where appropriate | `BuildsComplete`; code/context hashes and actual OpenShift build metadata |
| `make qs-push` | Publish or verify build outputs in the selected registry; resolve manifest digests, pull permissions and CA trust; create resolved values automatically | `ImagesPinned`; public image lock with each `repository@sha256:...`; rerun preserves completed artifacts |
| `make qs-install` | Install admission/RBAC/controllers, retained authority bootstrap and required supported dependencies in ownership-safe order | `FoundationReady`; authority identity preserved, existing CoCo services reused |
| `make qs-model` | Fetch pinned Qwen, generate-or-retrieve model/data keys, encrypt/verify model disk and push ciphertext OCI; clean plaintext scratch after success | `ModelPublished`; descriptor, verity root, OCI digest and inventory; no plaintext/key in publication |
| `make qs-volumes` | Render model source, RO/data claims and workload request; wait for population/binding; capture actual UIDs | `VolumesBound`; populated model + newly created blank data claim; unexpected existing/replaced claims fail |
| `make qs-measure` | Resolve verified stock boot artifacts and expected launch identity; instantiate profile; render exact policy and first-use enrollment plan | `ReleaseMeasured`; artifact, launch/policy hashes and explicit new claim UID list; unsupported calculation fails closed |
| `make qs-enroll` | Register authority metadata/plans; package InitData; update exact bindings through Trustee owner; enroll keys/reader credential; verify loaded KBS resources | `TrustReady`; policy/InitData/resource receipts; controlled shared reload only under explicit site authorization |
| `make qs-deploy` | Start authority serving, validate/sign package, submit to workload controller; wait for KServe; install chat | `Serving`; predictor identity and chat service/access command; readiness alone is not E2E proof |
| `make qs-test-first` | Run real chat/inference, GPU, file/mount/isolation/exec checks; collect scoped CPU/GPU appraisal and authority journal evidence | `FirstPass`; first receipt and four completed initialization steps |
| `make qs-test-reopen` | Gracefully replace only the run's predictor; require successful close; verify new VM, unchanged claims/canary/format history and actual chat | `ReopenPass`; new Pod/boot IDs, same persistent data and no repeated initialization |
| `make qs-report` | Validate the full receipt chain against this run and current identities; emit sanitized summary | `E2EPassed`; code/image/input digests, evidence paths and endpoint/access command |
| `make qs-chat` | Foreground port-forward for default ClusterIP, or print explicitly selected VPN endpoint | Open printed URL; send another prompt; explain tunnel lifetime and HTTP limitation |

The manual path does not require Argo to own its release resources. The GitOps
path additionally requires the existing OpenShift GitOps instance; never deploy a
second shared operator to satisfy a missing dependency.

`make quickstart-all` runs the sequence through `qs-report`, excluding the foreground
chat tunnel. It must stop at the first failed gate. Steps needing localhost access
start and clean up their own scoped port-forward. `make qs-status` reports the last
verified stage and next command; rerunning a stage resumes safely. An explicit
resume target may run remaining steps without resetting successful state.

The final guide begins with clone/checkout of a reviewed release, `oc login` or
private `KUBECONFIG`, site-template copy/edit and dependency setup. It lists every
required external credential/reference and public input before the first mutation.
No generated field is an operator copy/paste task. Secret inputs never appear in
shell history, command arguments, Helm values, printed output or Git.

## Image creation and registry coverage

| Image/artifact | Build requirements that the quickstart must include |
| --- | --- |
| Volume/workload controller | Public source/Containerfile, pinned base/dependencies, scoped binary BuildConfig/context, registry output and resolved digest |
| Populator/importer | Pinned Go/compiler inputs, locked source, Linux binary build, runtime image and digest; do not assume a local compiled binary |
| Storage helper | Verify/copy unchanged AA/CDH from the approved stock GPU initrd; fetch/hash-check tools/modules; stage pinned upstream protocol definitions; locked Rust build with `trustee-rcar`; public-only payload/image context |
| Authority | Fetch hash-pinned Python wheels; run `prepare-authority-build.py`; build without TLS/receipt/signing keys or retained state in context |
| Preparation runner | Package pinned model fetch/encryption/publication/release tools and dependencies; scoped CPU-only build environment with bounded plaintext scratch |
| Stock application/runtime | Verify pinned vLLM and boot artifacts; document authenticated registry access or approved mirroring; do not rebuild or patch them |
| Encrypted model | Separate publication from image builds; verify LUKS + verity including header, source inventory, ciphertext digest and importer receipt |

Use tags only as build outputs, then pin digests in resolved configuration. Capture
actual build name/namespace because the helper policy binds injected build metadata.
OpenShift builds may push automatically: `qs-push` verifies the existing publication
rather than building/pushing a second different image. Document proxy/CA settings,
private-registry authentication, CPU/RAM/disk requirements and network downloads.
Never disable TLS verification or grant anonymous registry access to simplify setup.

## Follow-ups, failures and completion

Every failed target prints the failed gate, sanitized evidence location and exact
next command. Do not suggest deleting authority state/PVCs, accepting observed
measurements as trusted, broadening attestation policy or repeating format.

Provide commands for status/log inspection, credential renewal, reopening retained
volumes, stopping disposable compute and explicit retirement. Keep destructive
retirement separate from `clean`; local build-cache cleanup must not remove keys,
receipts, authority history or PVCs. Explain that changed measured configuration
can require explicit policy migration rather than an ordinary rerun.

The how-to is complete only after another execution starts from an empty add-on
installation/cache and reaches `E2EPassed` using its commands alone. Also test a
second invocation, failed build/push, interrupted enrollment and lost controller/Job
responses. Retrying must preserve resource identities and completed initialization.
Repeat equivalent gates through the controller path with a separate fresh identity.
