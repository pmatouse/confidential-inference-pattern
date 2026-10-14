# Signed authorization and guest mount lifecycle core

This library implements receipt verification and the lifecycle controller intended
for the privileged **guest system service**. It has no daemon, public RPC, real CDH
adapter or production Kata namespace integration. It now includes
[authenticated RW header preparation](profiles/README.md) using Linux memfd seals
and a [Linux reopen/close primitive](../../docs/confidential-storage/guest-opener.md)
that passes those sealed bytes to cryptsetup, plus a
[Linux lifecycle backend](../../docs/confidential-storage/guest-mount-backend.md)
for private guest staging mounts with injected trusted providers.
The [consumer manager](../../docs/confidential-storage/consumer-namespace.md) now owns
the application bind using retained namespace/root descriptors; production Kata
callbacks and attested providers remain unfinished. The Kata experiment's
activation gate remains closed. **This is not working encrypted persistent storage.**

The paired [Python authority](../confidential-storage-authority/README.md) now issues
signed reopen receipts after committing ownership. Rust verifies those signatures
and the request binding before the controller can invoke its backend. The tests
use synthetic peers and an injected storage backend; they do not simulate a TEE
and present it as attestation evidence.

## Authorization contract

An administrator registers immutable target-container, destination, access and
manifest-URI bindings alongside the policy/profile digests and credential URI.
The initialization commit records both authenticated header and exact manifest
SHA-256 digests. Bound records cannot become `Ready` without both. A retry cannot
replace either digest. Legacy records lacking these fields cannot get a receipt.

`ReceiptIssuer.reopen` checks those bindings, then calls the authority's transactional
`begin` operation. A hash of the request's nonce, binding and profile is stored with
the owner. The exact retry can obtain the same activation; a changed nonce or
binding cannot reuse that operation. Signing occurs only after ownership commits.
A signing/delivery failure leaves that durable ownership available to an exact
retry, rather than granting another owner.

Receipts use compact JWS with the fully specified `Ed25519` algorithm from
[RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html#section-2.2). The guest pins
the public key, issuer and key ID through measured configuration. It accepts only
that algorithm, the expected token type and audience, known fields and canonical
base64url. It never follows `jku`, `x5u` or an embedded `jwk`.

| Signed field | Binding |
| --- | --- |
| Volume and generation | Exact registered persistent volume generation |
| Policy/profile digests | Approved workload policy and crypto/filesystem profile |
| Manifest URI and digest | Exact approved manifest bytes and retrieval location |
| Header digest | Exact copied header bytes authorized at initialization |
| Credential URI | Versioned Trustee resource; never a plaintext key |
| Container, destination, access | Fixed application filesystem exposure |
| Session, operation, activation | Verified guest session and durable authority owner |
| Nonce | Guest-generated 256-bit request challenge, retained for exact retries |
| Issuer, audience, type, times | Protocol separation and a maximum 60-second admission window |

The guest verifier returns a `VerifiedGrant` that cannot be constructed or
deserialized directly by other crates. It compares every locally expected field
and checks the pinned signature. `authenticate_manifest` and `authenticate_header`
verify exact bytes before parsing; their returned borrowed byte views cannot be
mutated through safe Rust while in use. Hashing is not validation of a LUKS profile:
the disk backend must still validate its algorithms, layout and integrity mode.

`Expected` values must be assembled by the guest from measured policy and its
own pending request, not copied from an untrusted host or from the receipt being
verified. The session digest must bind the guest-held channel key, and the nonce
must originate in that authenticated guest context. **There is no attestation
verifier or channel-establishment implementation in this checkpoint.** The Python
`AttestedPeer` remains trusted adapter input, not proof that hardware was attested.

## Lifecycle and failure behavior

One controller owns the guest's activation registry. It serializes work per
activation and allows only one active owner per volume and per resolved major:minor
device. This first implementation is exclusive even for read-only access; sharing
and reference counting are not implemented. Applications receive only the guest
mount path, never a raw mapper path or key.

```text
signed receipt verified
  -> reserve volume/device/activation
  -> record NeedsClose before opening any mapping
  -> record NeedsUnmount before attempting a mount
  -> Mounted
  -> unmount all application binds and the guest mount
  -> close every mapping in the stack
  -> acknowledge teardown to authority
  -> Closed tombstone
```

| Failure | Retained state and permitted next action |
| --- | --- |
| Open fails after partial effects | Attempt close; retain `NeedsClose` if cleanup fails |
| Mount fails after partial effects | Attempt unmount, then close; stop at the first failure |
| Unmount is busy | Keep `NeedsUnmount`; do not close mappings or release ownership |
| Mapping close fails | Keep `NeedsClose`; retry close without repeating a successful unmount |
| Authority close acknowledgement fails | Keep `NeedsRelease`; retry only the acknowledgement |
| Caller cancels or loses its response | Service-owned worker finishes; exact retry/close finds retained state |
| Backend panics | Phase was recorded before the call; cleanup state remains available |
| Worker starts after receipt expiry | Release unused ownership; do not open a device |
| Closed activation is replayed | Reject reopening; old close cannot affect a newer activation |

An activation retry never restarts a failed open or implicitly formats anything.
There is no format method on the backend interface. Failed activation cleanup may
leave ownership retained; the caller must inspect the phase and retry close.
Cancellation does not automatically tear down a successfully mounted activation,
because a lost response is ambiguous. The agent must explicitly close it on a
failed container creation or final container removal.

The registry keeps closed activation IDs to reject local replay, and has a capacity
limit instead of silently evicting those records. It is in guest memory. A daemon
crash does not prove kernel mappings disappeared; a guest crash does not justify
releasing the authority owner. Restart/recovery needs a fresh attested session and
an explicit reconciliation design. Do not construct a replacement controller with
an old session and replay old grants. Check capacity before acquiring new authority
ownership in the eventual service adapter.

The admission timeout is not a lease: expiry does not revoke an already released
key or an active mount. Revocation blocks new receipts; an already issued, unused
receipt can remain admissible until its 60-second window expires. Nonce/session binding and durable ownership are required
alongside time checks. The controller rechecks a monotonic admission deadline before
starting disk effects, rather than relying solely on a check before task scheduling.
None of this detects rollback of an entire writable disk or VM snapshot, revokes
cached keys, or fences a hostile host. Authority database rollback protection is
also outside this core.

## Required production backend

The `Backend` trait is a trusted implementation boundary, not a security sandbox.
A deliberately incorrect backend could violate its contract. Before enabling the
Kata gate, implement and test it inside the guest CDH/agent service:

1. Verify fresh hardware/workload evidence and bind the authority channel to a
   guest-held key. Load the public signing key and allowlist from measured policy.
   The authority needs independently managed durable storage and administrative
   authentication. It must not accept client JSON as `AttestedPeer`.
2. Resolve and retain the guest block device safely. Fetch the exact manifest via
   CDH and use `PreparedHeader::prepare` to bind its key reference/profile, authenticate
   the complete header, validate the narrow RW metadata profile and seal the copy.
   Pass that same sealed descriptor to cryptsetup. No unverified
   disk-header parsing, fallback cipher or format-on-open-failure is permitted.
3. Use activation-specific mapping names and enforce the journaled integrity profile
   in both metadata and the effective kernel stack. Include compatible cryptsetup
   and kernel support in the new guest artifact. The existing prototype's
   `luks2-integrity-rw` name is not proof that these requirements are enforced.
4. Mount with the approved fixed flags, place only the filesystem bind in the
   application namespace, and retain mount ownership across container lifecycle
   callbacks. Remove all app binds before closing the stack. A successful cleanup
   return must establish absence, including after partial command failures; merely
   checking whether a `/dev/mapper` pathname exists is insufficient.
5. Keep storage management on a private guest-service socket. Do not export it via
   api-server-rest, a pod port, a sidecar or an application-mounted Unix socket.
   Review generic CDH resource endpoints too: they must not let the application
   fetch a volume key directly and bypass the intended storage-service boundary.
6. Keep guest state on any cleanup error and call authority `close` only after
   actual teardown. Backend errors exposed through this library use static codes,
   not command output that might contain keys. Test CDH process death, VM death,
   partial device-mapper closes and recovery before a production rollout.

First-use initialization still needs its separate durable `Initializing` protocol.
The current receipt issuer only grants reopening already initialized volumes.
The standalone `Opener` now handles descriptor-based reopening, effective-stack
checks and explicit mapping cleanup. `LinuxBackend` now connects it to the
lifecycle controller, private ext4 staging mounts and a retained application bind.
Production Kata callbacks, the device resolver and attested CDH key provider remain
unfinished. Its
per-handle state is not a substitute for the controller's global activation/device
reservation and tombstones. Never expose it directly through an application API.

No host CSI code gets a decryption key, and no application storage capabilities
are added by this library.

## Reproduce tests

The Rust dependency graph is pinned by `Cargo.lock`. Tests were compiled on AMD64
with Rust 1.94.1 in the same disposable unprivileged compiler defined in
[the Kata experiment](../confidential-storage-kata/README.md).

```sh
cd components/confidential-storage-guest
cargo test --locked --all-targets
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
```

From the pattern repository, with the pinned Python dependency installed in your
development environment:

```sh
python3 -m pip install -r components/confidential-storage-authority/requirements.txt
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s components/confidential-storage-authority -v
```

The checked-in receipt fixture contains public keys and signatures for synthetic
records only. It contains no private signing key, encryption key or live credential.
To regenerate it, the helper creates a fresh signing key only in memory:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 \
  components/confidential-storage-authority/generate_receipt_fixture.py \
  components/confidential-storage-guest/tests/receipt-fixture.json
```

The tests verify Python-to-Rust signature interoperability, altered fields and
bytes, wrong keys/sessions/nonces, expiration, duplicate claims, concurrency,
cancellation, panic and failure cleanup. The original lifecycle backend effects
are injected test doubles; those tests have no real disk or TEE operations. Their evidence lives under
`tests/confidential-storage/evidence/2026-10-13/lifecycle/`.

The separate `kernel_opener_lab` example exercises real block operations with the
new opener inside the disposable non-TEE guest. It generates synthetic signatures
in memory and uses the lab's random test key. See the
[opener guide](../../docs/confidential-storage/guest-opener.md) for reproduction,
negative cases and remaining production prerequisites.
The example also tests the Linux lifecycle backend with synthetic providers,
including authentication before key retrieval, busy unmount, release ordering
and acknowledgement retry. See the [mount backend guide](../../docs/confidential-storage/guest-mount-backend.md).

The [trusted-agent coordinator](../../docs/confidential-storage/agent-lifecycle.md)
now reserves ownership before paused namespace creation and serializes verified
bind attachment, application startup and teardown. It connects to `LinuxBackend`
but still requires real Kata callbacks and attested providers. The lab runtime is
synthetic; this is not an installed agent integration.

The RO profile and sealed-header validator now consume the [approved published-model manifest](../../docs/confidential-storage/published-model-approval.md). `RoOpener` and the common Linux backend implement the read-only verity/LUKS stack and `/models` consumer bind. Live attested providers and production runtime integration remain unfinished.
