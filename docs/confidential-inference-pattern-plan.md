# Confidential inference add-on: design and integration plan

This separate repository installs after OpenShift + the CoCo Validated Pattern.
Its implemented manual path builds an encrypted Qwen release and serves it through
KServe with stock Kata and vLLM. The [workload walkthrough](workload-walkthrough.md)
is the current architecture reference; the [component map](components.md) describes
each source directory, process, interface and trust role.

## Delivered design

- A trusted publisher prepares a pinned model in a LUKS2 + dm-verity disk and
  publishes only encrypted bytes/public metadata to the internal OCI registry.
- `EncryptedModelSource` and a custom volume populator populate an ordinary raw
  Block PVC through existing CSI. A separate blank PVC supplies RW storage.
- `ConfidentialVolume` binds immutable claim identity to crypto/access/initialization
  intent; `ConfidentialWorkload` binds these declarations to a consumer and paths.
- The namespace controller publishes a request, verifies a separately signed
  deployment package and reconciles KServe plus measured public InitData.
- A privileged guest storage sidecar uses stock private AA/CDH, standard Trustee
  and an independent retained lifecycle authority. It opens RO model storage,
  initializes explicitly approved blank RW storage once, then reopens it on later VMs.
- The helper transfers filesystem mounts into unprivileged stock vLLM. No custom
  Kata agent, patched vLLM image, host decryptor or custom CSI is needed for the
  qualified topology.
- Make performs the trusted release operations; existing Argo ownership handles
  platform/foundation configuration. Full lifecycle GitOps remains planned.

## Integration boundaries

| Boundary | Existing contract | Work still needed |
| --- | --- | --- |
| Runtime portability | Reviewed stock bytes, OCI request profile, InitData, CPU/GPU verifier | Qualify additional TEE/GPU/runtime versions without weakening policy |
| Storage portability | Block/RWOP, Immediate binding, approved crypto geometry | Additional CSI/topology/WFFC and larger RW volumes require explicit support/tests |
| Trustee owner | Exact per-resource launch/InitData bindings, standard KBS/AS, scoped Vault/ESO enrollment | Portable chart/backend interface; automatic token/certificate renewal |
| Release controller | Public requests, deterministic tools and signed approval envelope | Trusted reconciler, retained state, retries, approval renewal and Argo health integration |
| Authority operations | Exclusive owner and durable four-step initialization history | Production fencing, protected backups, rollback handling and migrations |
| Network privacy | Current HTTP proxy outside TEE | TLS termination inside guest and authenticated client trust |

## Delivery paths

1. **Manual, implemented:** [quickstart](demo/quickstart.md), public site YAML,
   explicit credential references, fresh image builds/publication/enrollment and
   first-boot/fresh-VM tests. [Recorded acceptance](../tests/evidence/2026-10-15/manual-quickstart-e2e.json).
2. **Controller/GitOps, planned:** [automation contract](automation.md) and
   [detailed lifecycle implementation plan](full-lifecycle-implementation-plan.md).
   Reuse the same deterministic tools and authorization boundary; do not give an
   untrusted namespace reconciler the release signer or volume credentials.

Qualification currently covers AMD SNP + NVIDIA RTX PRO 6000 Blackwell Server
Edition on the documented OSC/KServe/storage profile. Generic API shape is not
proof of arbitrary hardware support. Installation starts with CoCo already working;
firmware enablement, base cluster provisioning and storage/network topology belong
to the platform owner. See [inputs](inputs.md) and [status](implementation-status.md).
