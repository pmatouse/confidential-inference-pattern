# Status and gaps

[Manual quickstart E2E receipt](../tests/evidence/2026-10-15/manual-quickstart-e2e.json), 2026-10-15:
new add-on namespaces, five image builds, encrypted Qwen publication, keys, PVCs
and authority history on an **existing** CoCo cluster. Compatible shared CRDs were
reused; no cluster reinstall. This receipt qualifies the isolated add-on installation,
not every possible clean-cluster dependency installation path.

| Area | Result |
| --- | --- |
| Installation | Separate repo; isolated controllers, CRDs/admission/SCC, restricted GitOps project; Synced/Healthy |
| RO model | Fresh LUKS + verity OCI artifact → populated Block PVC → `/model`; all producer file hashes verified |
| RW data | Blank PVC initialized once; four completed steps retained unchanged after a fresh VM reopened the canary |
| Inference | Stock vLLM/Qwen via KServe; CUDA and chat succeeded before/after VM replacement |
| Trust | Standard Trustee CPU/GPU appraisal; exact launch/InitData bindings; scoped Vault/ESO enrollment |
| Isolation | Unprivileged vLLM; raw devices/private CDH only in guest helper; administrator exec denied |
| Reproducibility | `qs-*`, `quickstart-all` and resume; generated launch/policy/InitData, retained receipts, fresh-VM E2E |

The independent [controller E2E receipt](../tests/evidence/2026-10-15/controller-e2e.json)
qualifies the same model/storage/inference path through eight sequential release
Jobs. The final status is `Ready / E2EPassed`; controller restart preserved the
verified VM and claims. Initial qualification needed explicit fixes/retries, as
recorded in the [controller runbook](demo/controller.md).

## Remaining integration work

- **Release automation:** the initial [InferenceRelease controller](demo/controller.md)
  now integrates publication, binding, measurement, enrollment, signing and acceptance
  as sequential Jobs and passed hardware E2E on the qualified profile. One immutable
  fresh demo per installation is supported; general lifecycle reconciliation is not.
- **Full lifecycle GitOps:** administrator bootstrap, mutable retained-volume upgrades,
  renewal and retirement are not reconciled by the initial immutable release API.
- **Portability:** publish portable images; qualify additional hardware/runtime/CSI
  profiles. Only the tested OSC SNP/NVIDIA configuration is qualified.
- **Credential lifecycle:** automate helper pull-token, approval and certificate
  renewal; parameterize the current shared Vault/ESO mapping.
- **Operations:** protected authority backup/rollback handling, uncertain-owner
  recovery and coordinated key/state retention. No general RW snapshot anti-replay.
- **Prompt transport:** TLS terminating inside the guest; current chat is HTTP.

See [automation design](automation.md), [architecture](architecture.md) and
[required inputs](inputs.md). `make test lint` checks contracts; hardware acceptance
must run on every newly qualified profile. Historical build/bootstrap receipts
are intermediate evidence, not substitutes for the final E2E receipt.
