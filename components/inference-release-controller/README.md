# Trusted inference release controller

Orchestrates the shared quickstart's eight post-bootstrap stages as sequential,
non-privileged Jobs. It is separate from the namespace ConfidentialVolume
controller, which verifies a signed package and deploys KServe.

- `controller.py`: exact administrator-granted site identity, per-release Lease,
  deterministic Jobs, immutable bound receipts, bounded status and live identity checks.
- `worker.py`: retained run lock/UID binding, shared stage execution, recovery of
  committed stages without replay, public receipt publication after durable state.
- `git-askpass.py`: read an externally provisioned repository credential only for
  Git authentication; no token in command arguments or public status.
- `Containerfile`: public source, pinned base/oc/Helm, Python dependencies; no live
  keys, kubeconfig or prepared model bundled into the image.

[Controller runbook](../../docs/demo/controller.md) explains bootstrap, API, retries,
RBAC and current limits. [Chart](../../charts/inference-release-controller/) contains
CRD, scoped identities, Deployment, retained state claim and Argo health adapter.
`make test` includes reconciliation/restart/failed-Job/receipt/identity tests.
The controller and executor are trusted; creating a Job that can mount signing
state is authority even though the controller does not itself read Secrets.
