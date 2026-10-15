# Implementation ledger

The earlier Qwen workload remains separate from this new installation. Its passing
hardware evidence is not a new clean-install result.

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
| Unprivileged KServe workload intent and chat chart | Implemented; fresh inference pending |
| Standalone Qwen source manifest | Extracted pinned model/file identities; no dependency on old producer AST |
| Create-once authority history bootstrap | Implemented and tested; two-mode authority chart added; fresh bootstrap and retained serving passed on a new PVC |
| Generic measured sidecar release renderer | New offline draft/package renderer added with synthetic contract tests; measured stock runtime profile deployed; full hardware qualification pending |
| Trusted metadata enrollment and package generation | Implemented; multi-volume/retry/retained-owner tests pass; fresh two-volume metadata enrollment passed |
| Scoped Vault authentication | Approved one-time edge bootstrap completed; projected JWT login and least-privilege capability checks passed; new release keys subsequently enrolled using the scoped role |
| Scoped key enrollment and Trustee owner integration | CAS merge-patch writer implemented and verified through Vault/ESO; three exact measured bindings installed through the base Trustee owner |
| Portable helper/populator/authority image release | New helper and authority images built in isolated project; stock protocol/no-CPU-fallback tests pass; guest qualification pending; edge override still uses existing lab artifacts |
| Fresh model publication → population → guest mount | Fresh Qwen encryption, ciphertext/verity verification, local OCI publication and population passed; guest mount pending |
| Blank RW first-format through stock sidecar → fresh VM reopen | Pending; cannot substitute prior reopened data for this gate |
| Real Qwen/GPU/chat and negative security E2E | Pending for new installation |
| Second TEE/site and WFFC qualification | Pending |

Run `make test lint` for the implemented control-plane contracts. Hardware access,
workload capacity and qualified trust inputs are needed for the remaining E2E
gates. Do not report the overall implementation complete until those gates pass.

The model root allowlist was extended consistently in the compiler, authority and
Rust guest library. Existing helper images predate this change: `/model` requires
a newly built/pinned helper and authority image. Do not assume the updated
controller alone changes guest mount support. `/models/qwen` remains the previously
tested lab path.

Build/bootstrap receipts are in [the evidence directory](../tests/evidence/2026-10-15/).
Candidate helper/authority digests are kept separate from the active site image pins.
The helper ABI/non-root-denial smoke test passed; it is not a confidential GPU test.
