# Encrypted model publication and population

This directory contains two separate roles. **Trusted publication** sees plaintext
and a model unlock credential. **Population** transports ciphertext and needs no
model key. The OCI disk artifact is distinct from the vLLM/helper container images.

| Entry point | Role |
| --- | --- |
| `fetch_qwen.py` | Fetch and verify pinned Qwen3-0.6B inputs |
| `prepare.py`, `publisher-init` | Build LUKS2 disk + ciphertext verity tree in software QEMU; reopen and verify files |
| `publish.py` | Package encrypted disk/public metadata and push to OCI by digest |
| Go controller/importer | Watch PVC dataSourceRef, create prime PVC/importer, verify streamed bytes/flush/readback, remove writer and rebind PV |
| `third_party/lib-volume-populator` | Pinned population machinery with documented opt-in same-namespace extension |

Install the source CRD and controller from
[`charts/vendor/encrypted-model-populator`](../../charts/vendor/encrypted-model-populator/).
The fixed registry origin is controller configuration; a source cannot choose an
arbitrary endpoint. Completed Bound claims are reused without importing again.
A new claim is a new population and authorization identity.

Importer RBAC/device access permits ciphertext writing only. No plaintext model,
credential or key-bearing preparation appliance enters the registry artifact.
A successful digest check/Bound PVC proves transport, not trusted freshness or
permission to decrypt; the guest separately verifies authority-approved content.

The same Go image runs controller/importer with separate modes and identities.
`qs-build` builds and tests it with pinned Go dependencies; `qs-volumes` exercises
real population. The trusted publisher Job is configured by `charts/model-publisher`.

See the [component map](../../docs/components.md) and [runtime walkthrough](../../docs/workload-walkthrough.md). Build/deploy through the [manual quickstart](../../docs/demo/quickstart.md).
