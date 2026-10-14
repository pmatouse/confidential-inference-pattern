# Private storage KBS provider

Development library for the measured guest system service. It retrieves a
32-byte storage credential only after the authority client issues an opaque,
short-lived permit. There is no listener, application RPC, generic resource-fetch
method, token-export method or configurable AA endpoint.

This reuses CoCo's KBS RCAR and encrypted-response implementation, also used by
CDH, from guest-components fork commit
`0ab1fb1be6e46293f29600085f929ae035ca3739`. It does **not** retrofit grant enforcement
into the installed CDH daemon or deploy any key policy. The isolated CPU RO and RW E2Es passed; the new multi-volume/GPU integration
is not installed. See the [implementation checkpoint](../../docs/confidential-storage/multi-volume-implementation.md).

## Authorization and lifecycle

- RO model access: the authority has approved an immutable publisher manifest.
  `AuthorityClient::authorize_reopen_key` verifies the fresh signed reopen grant
  and known RO/RW profile, returning that grant and a non-cloneable `KeyPermit`.
  Authenticate the exact manifest, profile and sealed header with the opener
  **before** calling `SnpCpuKbs::retrieve`. The eventual provider/lifecycle wiring
  must preserve this order and use the matching grant/device context.
- RW first use: after acquiring initialization ownership,
  `authorize_initialization_key` fetches fresh signed metadata and requires the
  same session/operation with state Initializing. An approved but unowned plan,
  Ready record or read-only profile cannot use this path. This permits key
  retrieval, **not formatting**; each disk effect still needs its one-shot journal
  decision. Keep the key inside the trusted executor across the four steps.
- The provider consumes the permit and checks its retained session, workload
  policy, exact credential allowlist and expiry before access and again before
  returning bytes. Expiry during retrieval discards the result. It exposes no
  method to create a permit from an arbitrary URI or caller-supplied receipt.
- In the legacy `SnpCpuKbs` provider, each retrieval creates a new KBS protocol client, private TEE key and cookie
  jar. No token or volume key is cached between calls. The returned `KeyMaterial`
  has no Debug/Clone/serialization implementation; its owned allocation is wiped
  on drop. Caller copies, process dumps, swapping and tracing still need guest
  hardening; this wrapper cannot guarantee erasure of every transient copy.

The permit is checked in trusted guest code. KBS separately attests that guest
and applies its resource policy; it does not interpret the custom authority
journal or enforce its activation ID. This design therefore requires the KBS
policy to admit only the measured guest service/configuration that enforces the
permit. No application-accessible CDH GetResource route, AA quote/token oracle,
host-visible key output or alternate broker client may bypass that service.
The production artifact/InitData loader must enforce this before key policies
are enabled. The current library and synthetic tests do not prove that isolation.

## Explicit CPU test scope

`SnpCpuKbs` supports the isolated **SNP CPU** test profile. It forwards negotiated
SHA-256/384/512 report-data digests to the fixed private AA client without
rehashing and advertises no additional device evidence. `require_gpu=true` is a
configuration error; there is no GPU-to-CPU fallback. This must not replace the
existing model policy requiring CPU and GPU attestation. Composite GPU runtime
binding and real hardware interoperability remain separate acceptance gates.

The endpoint, dedicated TLS CA, optional fixed address, full InitData and exact
allowed resource IDs must be loaded from measured configuration. The raw InitData
digest must equal the authority client's pinned digest. SHA-256/384/512 is selected
by that administrator-pinned digest length, independently of the KBS-negotiated
runtime-data hash. Trustee parses the TOML algorithm and verifies the resulting
InitData against hardware evidence. The actual diagnostic guest uses SHA-256;
the former hardcoded SHA-384 assumption would incorrectly reject it. Configuration construction
alone is not a measured-boot loader; host annotations must not supply these values.

TLS requires 1.3, verifies the configured hostname, trusts only the dedicated CA,
and disables redirects and environment proxies. Each request has a 10-second
timeout; retrieval has a 25-second deadline. KBS IDs permit exactly three path
segments under `kbs:///`, with no alternate authority/plugin, query, encoding or
traversal. All response bodies are bounded to 256 KiB before parsing.

The staged library accepts only a 32-byte AES-GCM payload with a P-256
ECDH-ES+A256KW envelope, 40-byte wrapped CEK, 12-byte IV and 16-byte tag. It validates
curve-coordinate lengths before upstream crypto calls and rejects external AAD.
This intentionally makes the staged client unsuitable for arbitrary CDH resources.

## Reproduce

`prepare.py` reads the exact pinned Git revision and verifies its original lock
hash. It creates a separate build tree, applies the small HTTP/body/envelope
changes there, then copies the local guest/client/provider libraries. It never
modifies the source checkout. Review the generated changes as part of the guest
artifact; these changes are not an upstream release or installed cluster feature.

```sh
python3 components/confidential-storage-kbs/prepare.py \
  --upstream /path/to/guest-components-at-pinned-commit \
  --output /new/storage-kbs-build --with-test-fixtures
cd /new/storage-kbs-build/components/confidential-storage-kbs
cargo +1.94.1 fmt --check
cargo +1.94.1 build --locked --lib
cargo +1.94.1 clippy --locked --all-targets --features test-fixture -- -D warnings
cargo +1.94.1 build --locked --features test-fixture --example key_fixture
```

The committed Cargo.lock pins this composition. Do not run an unreviewed
dependency update during deployment. Four deprecation warnings originate in the
pinned upstream crypto dependency; the local crate passes strict Clippy.

The optional `--with-test-fixtures` switch copies the authority test component
and two public model-populator descriptors. Omit it for a library-only staging
tree. Install the authority's pinned Python test requirements, then run:

```sh
python3 -m pip install -r ../confidential-storage-authority/requirements.txt
STORAGE_CLIENT_FIXTURE="$PWD/target/debug/examples/key_fixture" \
  python3 -m unittest -v test_keys.py
```

This fixture uses real TLS, ECDSA/Ed25519 signatures, RCAR message binding,
ECDH/AES key wrapping and AES-GCM decryption with disposable test keys. Hardware
evidence and AS decisions are synthetic. **Never enable `test-fixture`, install
`key_fixture`, or approve its measurement in a secret-bearing guest.**

Evidence and remaining gates are in
[the private key-delivery checkpoint](../../docs/confidential-storage/private-key-delivery.md).

## Existing CDH adapter (opt-in, not live validated)

Feature `private-cdh` adds a provider using only the fixed root-private CDH ttRPC
socket. The service selects `provider: private-cdh` with a measured resource map
and explicit `raw32` or `lower-hex64` encoding. It consumes the same opaque permit
and checks expiry before and after retrieval. There is no fallback to the CPU
provider, alternate endpoint or encoding autodetection.

CDH may reuse its own KBS attestation session. A fresh authority permit does not
mean fresh CPU/GPU evidence was collected for every key request. Approve the
actual GPU CDH/AA configuration, resource policies and acceptable session age
before enabling this provider. Authority operation authentication is handled by
the separate [standard Trustee RCAR adapter](../../docs/confidential-storage/standard-trustee-adapter.md).
That implementation has passed unit tests and live TLS `/auth`; full composite
hardware acceptance remains a separate gate.
