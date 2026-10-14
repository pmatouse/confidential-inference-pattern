# Trusted guest authority client

Development library for the privileged **guest system service**, not the
application container. No listener, public RPC, disk operation or key-byte delivery API is provided.
Opaque key permits are consumed by the separate private KBS provider. The isolated
CPU RO/RW integrations are tested; the combined GPU storage guest is not deployed.

The legacy direct-AS mode implements this authority TLS protocol:

1. Load endpoint, dedicated TLS CA, exact workload policy/InitData binding and
   Ed25519 receipt verifier from measured guest configuration.
2. Generate a dedicated in-memory P-256 session signing key. Derive the same
   session hash as the authority; never reuse a CDH/KBC decryption key.
3. Obtain a challenge for the exact initialization, reopen or close request. Check its audience,
   nonce, request hash and lifetime before collecting evidence.
4. Canonically serialize the challenge and public key binding; ask the private
   attestation agent for evidence over its SHA-256. The authority relays and
   verifies that evidence through its pinned Trustee AS.
5. Sign the domain-separated proof covering audience, challenge, request and AS
   token. Submit it over TLS. A reopen result becomes `VerifiedGrant` only after
   signature, session, nonce, profile, volume and mount binding checks.
6. Call close only after proven quiescence, unmount and mapper teardown. A network
   error never implies that ownership has been released.

TLS is restricted to version 1.3 and the supplied certificate trust store.
Hostname verification stays enabled with optional administrator-pinned address
resolution. Environment proxies and redirects are disabled. Each request has a
10-second total timeout; responses require bounded Content-Length and JSON
content type, with no compression or transfer encoding. Typed responses reject
unknown or duplicate fields. Error strings omit request/token/response contents.

Use this blocking client on the guest service's blocking worker, including
construction and disposal. The caller creates and retains a random request nonce
and operation ID. Exact retries reuse those values and the same client/session
key; there are no automatic retries. Losing the process/key requires explicit
recovery and cannot take ownership from the old session.

## Private AA collector

`PrivateAa` invokes only `/usr/bin/storage-aa-client`, the hash-pinned client from
`attestation-build-lock.json` in the authority component. Install it root:root
0700. The AA socket directory must be root:root 0700; the socket must be root
owned. The collector fails if these requirements or the binary hash differ.
It does not use the application's public CDH/AA HTTP endpoint.

The pinned CLI takes standard base64 encoding of the raw 32-byte runtime digest.
The SNP attester pads it to report_data; do not hash it again. Collection has an
8-second deadline, a 144 KiB output limit, no stderr forwarding, no core dumps,
and a private process group for timeout cleanup. No socket or executable path
can be chosen by a request.

The collector is now hardware-validated in the isolated
[RO](../../docs/confidential-storage/native-model-serving.md) and
[RW](../../docs/confidential-storage/native-rw-storage.md) SNP guests.
Earlier no-secret diagnostic initrds remain ineligible for keys.

## Reproduce transport tests

On Linux with Rust 1.94.1 and Python 3.11+, first stage the pinned upstream sources
with [prepare.py](../confidential-storage-kbs/prepare.py), including
`--with-test-fixtures`. The optional private AA dependency resolves through that
staged tree even when its feature is disabled. Run these commands from the staged
`components/confidential-storage-client` directory:

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --example transport_fixture
python3 -m pip install -r ../confidential-storage-authority/requirements.txt
STORAGE_CLIENT_FIXTURE="$PWD/target/debug/examples/transport_fixture" \
  python3 -m unittest discover -v -s ../confidential-storage-authority -p test_transport.py
```

The fixture opens a temporary loopback TLS listener. It verifies actual Rust
ECDSA proofs and Python Ed25519 receipts against durable SQLite transitions.
Its evidence/AS claims are explicitly synthetic; no model key or disk is used.
The `transport_fixture` example is a test-only binary and must never be installed
in a measured production guest. A missing fixture binary skips Python tests;
that is not a passing interoperability run.

The isolated native integration now connects trusted disk execution, real KBS,
device resolution and agent lifecycle callbacks. Both requested E2Es pass;
production deployment and operational recovery remain separate work.

## Initialization journal

`initialization` adds signed Plan/Begin/Step/Complete/Ready operations over the
same authenticated channel. A verified opaque record pins the approved plan;
one-shot execute permits expire and cannot be cloned/deserialized. A Started
retry requires reconciliation and Ready never grants another format decision.
See [the full timeline and manifest recovery contract](../../docs/confidential-storage/guest-initialization-protocol.md).
The fixture tests these messages with synthetic completion data, not real disks.

## Private key authorization

`keys` creates non-cloneable, expiring permits only from fresh authority responses.
`authorize_reopen_key` returns the verified grant and its permit for a supported
RO/RW profile. `authorize_initialization_key` requires an already owned Initializing
record; it cannot grant formatting. The consumer checks the retained session,
policy and exact credential allowlist before and after retrieval. See the
[private KBS provider](../confidential-storage-kbs/README.md) for the real encrypted
response integration, CPU-only test scope and remaining deployment gates.

## Standard Trustee mode

Feature `private-rcar-aa` adds a composite collector using the existing private AA
ttRPC interface. `AuthorityClient::new_rcar` requires an explicit RCAR challenge
and SHA-384 selection; it cannot fall back to the legacy CPU collector. The guest
collects NVIDIA evidence first and binds its exact bytes into the SNP runtime
digest. The request proof and signed receipt checks remain in place.

See the [protocol, configuration and validation checkpoint](../../docs/confidential-storage/standard-trustee-adapter.md).
Five client tests pass with this feature, four without it. Full hardware RCAR
interoperability in the combined GPU guest remains untested.
