# Install-and-run demo: automation boundary

**Target:** after CoCo installation and one administrator bootstrap, provide site
values + a supported profile; the add-on prepares the model, derives measurements,
enrolls trust, deploys Qwen/chat and emits an E2E receipt. This orchestrator is **not
implemented yet**. Current tools provide its building blocks.

| Stage | Available today | Needed for unattended execution |
| --- | --- | --- |
| Platform discovery | Checks RuntimeClass, CSI binding mode, KServe, Trustee and ownership | Verify eligible node/GPU/firmware/guest artifacts against a versioned profile; fail unsupported configurations |
| Release images | Pinned build contexts and tested site digests | Publish a portable, versioned image/profile bundle with verified provenance |
| Trusted bootstrap | Scoped Vault role, authority chart, credential generator | One-time administrator-selected backend mapping, policy-owner integration and signer identity |
| Model preparation | Trusted fetch/encrypt/publish tools | Job orchestration, generated keys, durable receipts and cleanup; retries preserve the same keys |
| Measurements | InitData/policy hashes computed; launch measurement supplied | Compute expected SNP launch identity from verified boot artifacts + exact VM parameters; compare with fresh evidence |
| Enrollment | CAS key writer, authority journal, exact binding checks | Reconcile through the existing Trustee owner; verify policy/resources loaded before activation; renew credentials |
| Deployment | Binder + signed-package controller automatically create KServe | Trusted runner generates/signs packages under a preauthorized profile; workload controller never receives the signer or keys |
| Acceptance | Startup probes and `verify-demo.py` | Run initial inference, graceful VM replacement, unchanged-journal/persistence checks and chat test; publish Ready only after all pass |

```mermaid
sequenceDiagram
    participant Admin
    participant Runner as Proposed trusted release runner
    participant Platform as Existing CoCo / Trustee owner
    participant Controller as Existing add-on controllers
    participant VM as Stock VM + sidecar + vLLM
    Admin->>Runner: Site values + approved profile + scoped identity
    Runner->>Platform: Discover and verify platform artifacts
    Runner->>Runner: Publish encrypted model; derive expected measurements
    Runner->>Controller: Create model/data PVCs and workload intent
    Controller-->>Runner: Bound PVC identities and approval request
    Runner->>Platform: Install exact bindings; enroll keys; verify readiness
    Runner->>Runner: Approve first-use plan and sign measured package
    Runner->>Controller: Publish signed package
    Controller->>VM: Reconcile KServe workload
    VM->>Platform: Fresh CPU/GPU evidence; request keys
    Runner->>VM: Inference, graceful replacement, persistence checks
    Runner-->>Admin: Chat URL + verified E2E receipt
```

“Measure automatically” must not mean trusting whatever a host reports. Expected
values come from approved artifact identities and configuration; attestation must
match them. Discovery cannot authorize a new firmware/image version, an existing
disk wipe, or an unknown model generation. Reject deviations instead of widening policy.

Implement the runner in the **trusted preparation domain**, with persisted step
receipts and explicit states. Separate administrator bootstrap from routine release
execution. Ordinary retries must not regenerate keys, rerun completed formatting,
replace authority history or take over an uncertain writer. No upstream Kata/vLLM
modification is required for this orchestration.
