# Status and gaps

[Fresh E2E receipt](../tests/evidence/2026-10-15/fresh-qwen-e2e.json), 2026-10-15:
new encrypted Qwen publication, keys, PVCs and authority history on an **existing**
CoCo cluster. No cluster reinstall. Original Qwen remained healthy and unchanged.

| Area | Result |
| --- | --- |
| Installation | Separate repo; isolated controllers, CRDs/admission/SCC, restricted GitOps project; Synced/Healthy |
| RO model | Fresh LUKS + verity OCI artifact → populated Block PVC → `/model`; all producer file hashes verified |
| RW data | Blank PVC initialized once; four completed steps retained unchanged after a fresh VM reopened the canary |
| Inference | Stock vLLM/Qwen via KServe; CUDA and chat succeeded before/after VM replacement |
| Trust | Standard Trustee CPU/GPU appraisal; exact launch/InitData bindings; scoped Vault/ESO enrollment |
| Isolation | Unprivileged vLLM; raw devices/private CDH only in guest helper; administrator exec denied |
| Reproducibility | Pinned builds, public profile template, staged release tools and executable acceptance checks |

## Remaining integration work

- **Full lifecycle GitOps:** Argo currently owns the foundation. Watched site YAML,
  a trusted release reconciler, expected launch measurement, publication/enrollment,
  signing and acceptance health gates remain to be integrated.
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
