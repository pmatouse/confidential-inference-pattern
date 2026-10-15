# Private CDH key adapter

Rust library linked into the storage service. It consumes an opaque, short-lived
authority permit, then calls unchanged stock CDH `GetResource` on a root-private
Unix socket. The application receives neither the socket nor a key API.

The adapter allows only configured resource URIs and explicit `raw32` or
`lower-hex64` encoding. It rejects endpoint/path substitutions and encoding
fallbacks, stores keys in zeroizing allocations and rejects responses after permit
expiry. Stock CDH/AA perform resource attestation against standard Trustee. CDH
may reuse its session; key retrieval is distinct from fresh lifecycle attestation.

Build through the sidecar's `stage-service.py` with the `trustee-rcar` feature.
Only pinned, unchanged upstream protocol definitions are compiled into this
add-on. No patched KBS client, CPU-only fallback or Trustee server is supplied.

See the [component map](../../docs/components.md) and [runtime walkthrough](../../docs/workload-walkthrough.md). Build/deploy through the [manual quickstart](../../docs/demo/quickstart.md).
