# Implementation ledger

The earlier Qwen workload remains separate from this new installation. Its passing
hardware evidence is not a new clean-install result.

| Work | Current state |
| --- | --- |
| Separate private repository, license, source provenance, CI | Implemented |
| Generic values schema and site override | Implemented; first profile only |
| Existing-platform preflight and ownership guards | Implemented and exercised on edge |
| Isolated controller/populator installation and admission ordering | Installed successfully in `confidential-inference-demo` |
| Root GitOps chart and restricted project | Implemented; live sync validation pending |
| Controller `/model` support | Implemented, unit-tested; new image built in isolated namespace |
| RO source/PVC and blank RW PVC chart | Implemented |
| Actual PVC UID binding Job | Implemented; live populated-claim integration pending |
| Unprivileged KServe workload intent and chat chart | Implemented; fresh inference pending |
| Standalone Qwen source manifest | Extracted pinned model/file identities; no dependency on old producer AST |
| Create-once authority history bootstrap | Implemented and tested; chart/backend integration pending |
| Generic measured sidecar release renderer | Pending; legacy renderer still depends on old prepared lab inputs |
| Scoped trusted key enrollment and Trustee owner integration | Pending; no root-token harvesting imported into installer |
| Portable helper/populator/authority image release | Pending; edge override still uses some existing lab artifacts |
| Fresh model publication → population → guest mount | Pending new repository E2E |
| Blank RW first-format through stock sidecar → fresh VM reopen | Pending; cannot substitute prior reopened data for this gate |
| Real Qwen/GPU/chat and negative security E2E | Pending for new installation |
| Second TEE/site and WFFC qualification | Pending |

Run `make test lint` for the implemented control-plane contracts. Hardware access,
workload capacity and qualified trust inputs are needed for the remaining E2E
gates. Do not report the overall implementation complete until those gates pass.
