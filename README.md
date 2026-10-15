# Confidential inference pattern

Experimental add-on installed **after CoCo Validated Pattern**. Qwen3-0.6B runs
through KServe on a confidential GPU VM, with an OCI-populated encrypted RO
`/model`, guest-initialized encrypted RW `/data`, and a chat frontend.

**Stock Kata and vLLM; unprivileged application.** Added components are the volume
populator, ConfidentialVolume/workload controller, privileged guest storage
sidecar, lifecycle authority, trusted release tools and chat frontend. Standard
Trustee releases keys after CPU/GPU attestation and exact workload bindings.

**Status:** the [manual Make quickstart](docs/demo/quickstart.md) passed fresh-add-on
and fresh-VM E2E on AMD SEV-SNP + RTX PRO 6000 Blackwell Server Edition.
[Manual evidence](tests/evidence/2026-10-15/manual-quickstart-e2e.json). The
[controller path](docs/demo/controller.md) passed a completely fresh add-on run:
six first-attempt image builds, then `Ready / E2EPassed` through eight initial
stage Jobs, with no manual fixes/retries and fresh-VM persistence
([fresh controller evidence](tests/evidence/2026-10-15/controller-fresh-e2e.json)).
The existing OpenShift + CoCo platform and compatible shared APIs were reused.
Full lifecycle GitOps, other hardware qualification and production credential/authority
lifecycle remain open.

| Read | Contents |
| --- | --- |
| [Workload walkthrough](docs/workload-walkthrough.md) | CR/PVC examples, approval, attestation, mount transfer, disk I/O, inference and shutdown |
| [Component map](docs/components.md) | Every source directory, running process, interface and key holder |
| [Architecture](docs/architecture.md) | Components, data paths, trust boundaries, diagram, exact tested stack |
| [Security model](docs/security-model.md) | InitData, attestation coverage, key release, trust boundaries and residual threats |
| [Hardware porting](docs/hardware-porting.md) | CPU-only and Intel TDX paths, platform-specific code, bring-up order and qualification gates |
| [Inputs](docs/inputs.md) | What to supply first, what is generated, credentials and reproducibility |
| [Demo setup](docs/demo/setup.md) | One-time installation and release sequence |
| [Acceptance](docs/demo/acceptance.md) | Inference, fresh-VM persistence and negative checks |
| [GitOps target](docs/automation.md) | One site YAML, Argo ownership, trusted release lifecycle and remaining work |
| [Implementation plan](docs/full-lifecycle-implementation-plan.md) | Manual-first delivery, then controller/GitOps; shared operations and completion gates |
| [Stock-pattern bootstrap](docs/demo/stock-bootstrap.md) | Site YAML + explicit credentials; automatic Vault/ESO/policy setup and controller submission |
| [Controller release](docs/demo/controller.md) | One-time bootstrap, InferenceRelease API, sequential Jobs, retries and Argo health |
| [Manual quickstart](docs/demo/quickstart.md) | Site inputs, image builds/pushes, all Make stages, expected results and recovery |
| [Status](docs/implementation-status.md) | Verified result and open integration gaps |

Start with OpenShift + CoCo installed. Configure the site YAML and explicit
credentials in [stock-pattern bootstrap](docs/demo/stock-bootstrap.md), then run:

```sh
make controller-demo VALUES=overrides/sites/my-site.yaml PYTHON=python3
```

For the stage-by-stage alternative, follow the [manual quickstart](docs/demo/quickstart.md).
The new Vault/ESO bootstrap has live integration coverage; fresh stock-chart E2E
qualification remains open.

Keep kubeconfig, keys, credentials, retained authority state and approvals out of Git.
The current HTTP chat frontend is outside the TEE; prompt TLS is a separate gap.

## Provenance

Apache-2.0. Imported add-on source/charts are recorded in
[provenance/import.json](provenance/import.json); vendor images/binaries retain their
own redistribution terms. Installation and architecture documentation are contained
in this repository; provenance records are for source/license traceability.
