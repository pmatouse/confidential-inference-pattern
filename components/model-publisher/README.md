# Publisher and helper tool preparation

Public build inputs for the trusted model preparation image and storage helper:
`source-lock.json`, `packages.txt` and `tools-inventory.json` pin sources/tools;
`fetch_tools.py` and `bundle-tools.py` assemble verified userspace tools;
`extract-kernel-modules.py` extracts matching modules from the approved package.
No model, storage credential or private cluster state belongs here.

The actual publication programs are in
[`encrypted-model-populator`](../encrypted-model-populator/README.md).
[`charts/model-publisher`](../../charts/model-publisher/) runs them in a trusted,
CPU-only restricted Pod using software QEMU and memory-backed scratch. It needs
scoped registry push access and a private model unlock credential, supplied by
the release owner. It publishes only ciphertext/public metadata, then preparation
scratch is removed. It is not part of the serving Pod or an attestation service.

`qs-build` creates the preparation image; `qs-model` runs a fresh publication and
records the descriptor/digests. This separation lets an untrusted importer later
populate model PVCs without receiving the model key.

See the [component map](../../docs/components.md) and [runtime walkthrough](../../docs/workload-walkthrough.md). Build/deploy through the [manual quickstart](../../docs/demo/quickstart.md).
