# Confidential inference pattern

Experimental add-on installed **after CoCo Validated Pattern**. Qwen3-0.6B runs
through KServe on a confidential GPU VM, with an OCI-populated encrypted RO
`/model`, guest-initialized encrypted RW `/data`, and a chat frontend.

**Stock Kata and vLLM; unprivileged application.** Added components are the volume
populator, ConfidentialVolume/workload controller, privileged guest storage
sidecar, lifecycle authority, trusted release tools and chat frontend. Standard
Trustee releases keys after CPU/GPU attestation and exact workload bindings.

**Status:** fresh resources and two-VM E2E passed on the tested AMD SEV-SNP +
RTX PRO 6000 Blackwell Server Edition configuration. [Evidence](tests/evidence/2026-10-15/fresh-qwen-e2e.json).
This is a staged, reproducible workflow on installed CoCo; **not yet a one-command
unattended demo**, a cross-hardware qualification, or an official VP support tier.

| Read | Contents |
| --- | --- |
| [Architecture](docs/architecture.md) | Components, data paths, trust boundaries, diagram, exact tested stack |
| [Inputs](docs/inputs.md) | What to supply first, what is generated, credentials and reproducibility |
| [Demo setup](docs/demo/setup.md) | One-time installation and release sequence |
| [Acceptance](docs/demo/acceptance.md) | Inference, fresh-VM persistence and negative checks |
| [GitOps target](docs/automation.md) | One site YAML, Argo ownership, trusted release lifecycle and remaining work |
| [Implementation plan](docs/full-lifecycle-implementation-plan.md) | Milestones, release API, integration gaps and completion gates |
| [Status](docs/implementation-status.md) | Verified result and open integration gaps |

Start by filling site values, then run:

```sh
./pattern.sh make demo-preflight VALUES=overrides/sites/my-site.yaml
./pattern.sh make install-addon VALUES=overrides/sites/my-site.yaml
```

These commands install the foundation; follow the release sequence to deploy Qwen.
Keep kubeconfig, keys, credentials, retained authority state and approvals out of Git.
The current HTTP chat frontend is outside the TEE; prompt TLS is a separate gap.

## Provenance

Apache-2.0. Imported add-on source/charts are recorded in
[provenance/import.json](provenance/import.json); vendor images/binaries retain their
own redistribution terms. Yuval's repository informed the deployment separation;
its source was not copied. [Original design](docs/confidential-inference-pattern-plan.md)
and [original runbook specification](docs/qwen-clean-cluster-demo-plan.md) are historical plans.
