# Encrypted model population

Development implementation of trusted LUKS/verity publication and untrusted
ciphertext transport from the internal OCI registry into a CSI raw-block PVC.
The [guide](../../docs/confidential-storage/model-populator.md) explains the
layout, permissions, lifecycle and reproduction commands.

- `fetch_qwen.py`: verify the existing pinned Qwen3-0.6B revision.
- `prepare.py` / `publisher-init`: create and verify an encrypted model disk in a
  disposable software VM, without granting host privileges to the publisher pod.
- `publish.py`: package ciphertext and public metadata, then push by digest.
- Go controller/importer: prime PVC, strict streaming import, flush/readback,
  writer removal, PV rebind and cleanup.
- `third_party/lib-volume-populator`: pinned Apache-2.0 upstream library plus a
  documented opt-in same-namespace extension.

Run `go test -race github.com/kubernetes-csi/lib-volume-populator/v3/populator-machinery ./...`
and `python3 -m unittest -v test_publish.py` here. The local TLS tests need loopback
listener permission. The actual cluster population test is
[`validate_population.py`](../../tests/confidential-storage/validate_population.py).

No application container or attested guest key-delivery implementation is supplied
by this component. A Bound PVC and unsigned publisher descriptor do not authorize
decryption or establish model freshness. Never package a publisher key, plaintext
filesystem or key-bearing initramfs into the registry layer.
