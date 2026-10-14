# Confidential inference pattern

A separately installed, experimental add-on for an existing Confidential
Containers Validated Pattern. It reuses stock Kata, stock vLLM, KServe, Trustee,
GitOps and CSI; it does not reinstall or take ownership of those shared services.

The target is Qwen served through KServe and a chat application, with an
OCI-populated encrypted model volume at `/model` and a guest-initialized encrypted
read/write volume at `/data`. The application stays unprivileged. A trusted,
privileged storage sidecar inside its confidential VM owns device access and
mount transfer. Keys require approved CPU/GPU evidence at Trustee; a separate
storage authority manages volume lifecycle authorization.

**Implementation status:** the separate repository, installer, GitOps chart,
preflight, controller/populator packaging, declaration binder, chat chart and
create-once authority bootstrap, trusted metadata enrollment and public release
packaging are implemented. The controllers were installed
in an isolated namespace on the edge cluster. The full fresh-install workflow,
scoped key provisioning, qualified release profiles and first-format sidecar E2E test
are **not yet qualified**. Do not treat the earlier lab workload as proof that
this repository can already reproduce it from zero.

## Start here

- [Current executable setup and component ownership](docs/demo/setup.md)
- [Trusted Vault bootstrap prerequisite](docs/demo/vault-bootstrap.md)
- [Implementation status and remaining release gates](docs/implementation-status.md)
- [Detailed design](docs/confidential-inference-pattern-plan.md)
- [Planned complete E2E acceptance procedure](docs/qwen-clean-cluster-demo-plan.md)

The design documents describe the full target, including commands not implemented
yet. `./pattern.sh make` and the current setup guide are the executable interface.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
make test lint
# Supply your own site values; the edge override is a lab-specific example.
./pattern.sh make demo-preflight VALUES=overrides/sites/my-site.yaml
./pattern.sh make render VALUES=overrides/sites/my-site.yaml
./pattern.sh make install-addon VALUES=overrides/sites/my-site.yaml
```

Set `KUBECONFIG` through your private environment. Never commit credentials,
private keys, authority history, filled secrets files or signed lab approvals.

## Boundaries

- Qualified runtime target for the first release: AMD SEV-SNP, NVIDIA confidential
  GPU, stock OSC, Immediate raw Block CSI. Cross-TEE qualification is pending.
- Read-only models: LUKS ciphertext with dm-verity authentication rooted in an
  approved manifest. Importers only handle ciphertext.
- Read/write data: guest-side LUKS with keyed integrity, explicit first-use
  authorization and retained authority state. Storage is untrusted.
- The helper is privileged **inside the confidential VM**. The vLLM container has
  no elevated capabilities, raw devices, Kubernetes token or key-service socket.
- `ConfidentialVolume` references are not key authorization. The binder resolves
  actual PVC UIDs; the existing controller requires a signed deployment package.
- HTTPS terminated at an OpenShift router would protect browser-to-router traffic,
  not establish end-to-end prompt confidentiality into the TEE.
- This is an experimental add-on using the pattern conventions; it has not acquired
  an official Validated Patterns support tier.

## Sources and ownership

The selected reusable components/charts were imported from
`pmatouse/coco-pattern-edge-rtx6k@ebfaf34`, with original file hashes in
[provenance/import.json](provenance/import.json). This repository is their new
integration/development location; `charts/vendor` records the import boundary.
The root chart packages those charts as local dependencies rather than recreating
parallel implementations. Refresh packages with `helm dependency build
charts/confidential-inference` after chart changes.

No source from Yuval's unlicensed repository was copied. Its separated
trusted-service/inference-cluster arrangement informed the design. No patched
Kata build or existing vLLM source changes are part of this add-on.

Licensed under Apache-2.0; preserve upstream notices and separately qualify
redistribution rights for vendor images, guest modules and bundled binaries.
