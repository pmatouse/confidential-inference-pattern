# Repeatable Qwen demonstration: scope and acceptance

The executable instructions are the [manual Make quickstart](demo/quickstart.md).
Start with OpenShift + CoCo already installed, the qualified CPU/GPU runtime,
raw-block storage and the documented trusted backend. “Clean” means fresh add-on
namespaces, run identity, images, encrypted publication, keys, PVCs and retained
authority history; compatible shared CRDs/services can be reused.

## Sequence and evidence

| Phase | Operation | Required evidence |
| --- | --- | --- |
| Platform | Check dependencies, ownership and free GPU/pod capacity | Qualified runtime/storage/backend; no implicit eviction or shared-service replacement |
| Build | Fetch pinned inputs, compile/test, build/push five images | Digests and source/runtime provenance; no private material in build contexts |
| Publish | Prepare Qwen disk with private LUKS credential; publish ciphertext OCI | OCI/disk digests, approved verity root, model inventory; plaintext scratch removed |
| Allocate | Populate RO PVC, allocate blank RW PVC, resolve declarations | Actual Bound claim UIDs, source identity, deterministic workload request |
| Authorize | Calculate launch/policy/InitData; enroll authority/Trustee; sign package | Exact trust bindings, loaded resources, retained journal, valid deployment approval |
| First boot | Controller creates KServe sidecar workload; attest, mount, serve | RO hashes/mode, four RW initialization steps, canary write, CPU/GPU appraisal, CUDA, real chat, denied exec |
| Fresh VM | Gracefully replace predictor using same claims | New Pod/boot IDs; same canary/header/manifest and initialization history; new attested owner; repeated inference |
| Repeat | Resume completed stages and inspect status | No key rotation, disk format, identity replacement or duplicate import on exact retry |

[Committed E2E evidence](../tests/evidence/2026-10-15/manual-quickstart-e2e.json)
records this sequence on the qualified SNP/NVIDIA profile. The missing-KServe
installation branch is available but was not exercised by this hardware run.
Synthetic/negative fixtures are distinct from hardware acceptance; a generic
runtime profile or unit-test result alone cannot claim hardware qualification.

The [workload walkthrough](workload-walkthrough.md) explains the data/control/key
paths and YAML bindings. The [component map](components.md) identifies what is
installed and what is reused. For per-step commands, expected outputs, retry and
retention rules use the quickstart; for deeper individual release commands see
[fresh release preparation](demo/fresh-release.md).

Keep retained authority history, volume credentials and PVCs together through
recovery/retention. Namespace deletion is not a reset procedure. The current chat
is an HTTP proxy outside the TEE; persistent storage does not imply prompt TLS or
persistent chat history. Full RW snapshot anti-replay is not provided.
