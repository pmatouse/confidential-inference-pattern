# ConfidentialVolume and workload controller

Namespace-scoped Python reconciler for `ConfidentialVolume` and
`ConfidentialWorkload`. It deploys an approved stock-Kata sidecar package through
KServe; it never derives permission to decrypt/format from a CR alone.

Every scan resolves actual Bound Block/RWOP claims and immutable source/workload
identities, compiles a deterministic request, and publishes
`cv-request-<digest-prefix>`. It looks for `cv-approval-<request-prefix>`, verifies
Ed25519 signature/expiry/exact request, validates the four public artifacts and
publishes immutable approved configuration. With `controller.sidecarWorkloads`
explicitly enabled, it creates/updates only the permitted KServe targets and the
InitData ConfigMap. Adoption requires an explicitly approved existing UID.
Publication-only mode is available without workload reconciliation.

The four package files are `guest-config.json`, `initdata.toml`, `runtime.json`
and `sidecar-deployment.json`. `approve.py` signs them in the trusted release
environment; the controller receives public verification keys only. The request
binds cluster, CW/CV/PVC/source identities and the desired template, preventing a
same-name replacement from reusing another object's approval.

Conditions `Resolved`, `Approved`, `ConfigurationPublished` describe configuration,
not guest mount/key readiness. Expiry or changed inputs withdraw current approved
status; they do not terminate a running workload or revoke a cached key. Deleted
generated workloads can be recreated while approval is valid. There are no disk
reset/delete finalizers or automatic initialization approvals.

RBAC permits scoped input reads, status updates, ConfigMap publication and allowed
InferenceService operations; admission also bounds create targets. No Secret
read, PVC write, exec, Trustee administration or private approval signer is given
to the controller. Polling/immutable artifacts allow safe repeated reconciliation.

Install with [`charts/vendor/confidential-volumes`](../../charts/vendor/confidential-volumes/).
Apply reviewed CRD updates explicitly: ordinary Helm upgrades do not update `crds/`.
Run contract/controller tests via `make test`. The quickstart prepares measurements,
enrolls authority/Trustee and signs before this reconciler deploys; an autonomous
trusted release controller remains separate future work.

See the [component map](../../docs/components.md) and [runtime walkthrough](../../docs/workload-walkthrough.md). Build/deploy through the [manual quickstart](../../docs/demo/quickstart.md).
