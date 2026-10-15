# Implementation ledger

The fresh add-on E2E passed on 2026-10-15; see the [receipt](../tests/evidence/2026-10-15/fresh-qwen-e2e.json)
and [repeatable acceptance commands](demo/acceptance.md). The existing cluster was
not reinstalled. The original Qwen workload remained Ready with its pod UID unchanged.

| Work | Current state |
| --- | --- |
| Separate private repository, license, source provenance, CI | Implemented |
| Generic values schema and site override | Implemented; first profile only |
| Existing-platform preflight and ownership guards | Implemented and exercised on edge |
| Isolated controller/populator installation and admission ordering | Installed successfully in `confidential-inference-demo` |
| Root GitOps chart and restricted project | Implemented; edge Application reached Synced/Healthy |
| Controller `/model` support | Implemented, unit-tested; new image built in isolated namespace |
| RO source/PVC and blank RW PVC chart | Implemented |
| Actual PVC UID binding Job | Implemented; edge Job bound two new PVC UIDs successfully |
| Unprivileged KServe workload intent and chat chart | Passed: new KServe Qwen and separate chat on VPN NodePort 31865 |
| Standalone Qwen source manifest | Extracted pinned model/file identities; no dependency on old producer AST |
| Create-once authority history bootstrap | Implemented and tested; two-mode authority chart added; fresh bootstrap and retained serving passed on a new PVC |
| Generic measured sidecar release renderer | Implemented and qualified on the first OSC SNP/NVIDIA profile; reusable public template included |
| Trusted metadata enrollment and package generation | Implemented; multi-volume/retry/retained-owner tests pass; fresh two-volume metadata enrollment passed |
| Scoped Vault authentication | Approved one-time edge bootstrap completed; projected JWT login and least-privilege capability checks passed; new release keys subsequently enrolled using the scoped role |
| Scoped key enrollment and Trustee owner integration | CAS merge-patch writer implemented and verified through Vault/ESO; three exact measured bindings installed through the base Trustee owner |
| Portable helper/populator/authority image release | Controller, helper, authority and standalone populator built in the new project; separate fresh PVC import passed with the new populator image; public cross-registry distribution remains future work |
| Fresh model publication → population → guest mount | Passed: new Qwen ciphertext OCI artifact, populated RO PVC, guest verification and all file hashes |
| Blank RW first-format through stock sidecar → fresh VM reopen | Passed: four first-use steps completed once, then same canary and unchanged step IDs/hashes in a different VM |
| Real Qwen/GPU/chat and negative security E2E | Passed: CUDA on RTX PRO 6000, real chat before/after VM replacement, exact measured exec denial |
| Second TEE/site and WFFC qualification | Pending |

Run `make test lint` for control-plane contracts. Each new platform must repeat the
hardware gates. This result qualifies the demonstrated profile, not arbitrary
CoCo installations or production operational recovery.

The model root allowlist was extended consistently in the compiler, authority and
Rust guest library. The newly built/pinned helper and authority now passed `/model`; an older helper
digest does not gain this support from a controller upgrade alone.

Build/bootstrap receipts are in [the evidence directory](../tests/evidence/2026-10-15/).
The edge example now pins the tested helper and standalone populator. The earlier
ABI smoke test is supplemental; the fresh E2E receipt contains the hardware result.

Remaining integration gaps: automatic scoped registry-token renewal, trusted release
review/enrollment/signing orchestration, production authority backup/recovery,
portable image distribution, additional hardware/CSI profiles, and TLS terminating
inside the guest. No blanket admission, exec, image-pull or attestation bypass was
introduced to obtain the passing result.
