# Private CDH storage adapter

This add-on consumes an opaque, short-lived authority permit before calling the
unchanged stock CDH `GetResource` API over its root-private Unix socket. The
application receives neither that socket nor a key-fetch API. Keys are held in
zeroizing allocations, and a response arriving after permit expiry is rejected.

The adapter accepts only explicitly configured raw 32-byte or lowercase hex
64-byte resources. It rejects alternate endpoints, traversal, implicit encoding
fallbacks and application access to the private directory. CDH and stock AA perform
CPU/GPU attestation against the existing standard Trustee; the adapter does not
manufacture evidence. CDH may reuse its attested session until upstream expiry,
so a successful resource request alone is not proof of fresh attestation.

The older CPU-only direct KBS protocol client was removed from this repository.
There is no CPU fallback and no patched upstream KBS protocol dependency. The
service rejects legacy CPU-provider configuration. The old research implementation
remains in the source repository recorded in `provenance/import.json`.

Use `../confidential-storage-sidecar/stage-service.py` to stage the pinned,
unchanged CoCo `protos` crate and these add-on libraries. Build and test with the
`trustee-rcar` service feature. This creates our add-on executable; it does not
rebuild or change Kata, AA, CDH, vLLM or Trustee.

The protocol source currently comes from the exact guest-components revision
used by the original compatibility test. That is a versioned interface dependency,
not a claim that arbitrary stock releases work. Guest AA/CDH binaries are copied
unchanged from the qualified installed initrd, and their protocol compatibility
still needs testing whenever the profile changes.
