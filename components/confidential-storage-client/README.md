# Guest authority client

Rust library linked into the storage service. It establishes TLS 1.3 sessions to
the pinned authority and verifies signed initialization/reopen/close decisions.
It does not format disks or serve an application endpoint.

The active `trustee-rcar` path:

1. Generate an in-memory P-256 signing key and a fresh request identity.
2. Obtain a challenge associated with a standard Trustee RCAR exchange.
3. Ask private stock AA for NVIDIA additional evidence and SNP evidence binding
   the challenge/session public key and additional evidence.
4. Submit evidence and the guest's proof through the authority's fixed KBS relay.
5. Verify the Ed25519 result against pinned issuer/key, request, session, nonce,
   volume, generation, policy/profile and mount binding before yielding a grant.
6. Derive an opaque, expiring key permit for the exact approved resource.

TLS verifies the configured CA and hostname; redirects/proxies and unbounded
responses are rejected. Private AA socket permissions and identity are checked.
A Started initialization step is not returned as another execute grant. Session
loss cannot take over the old owner; expiry of an admission receipt is not a lease
that revokes an existing mount or key.

`initialization.rs` implements journal messages; `keys.rs` implements permits;
`private_rcar_aa.rs` collects composite evidence through unchanged AA ttRPC.
The supported adapter currently requires SNP and NVIDIA; general protocol types
or test fixtures do not establish other hardware support.

See the [component map](../../docs/components.md) and [runtime walkthrough](../../docs/workload-walkthrough.md). Build/deploy through the [manual quickstart](../../docs/demo/quickstart.md).
