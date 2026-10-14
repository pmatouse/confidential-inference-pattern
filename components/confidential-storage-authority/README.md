# Private-volume authority core

This component implements durable storage transition rules and an authenticated
TLS gateway. The isolated CPU RO/RW path has passed hardware tests. The new
standard-Trustee GPU adapter is not deployed; this service is not a key broker.
Run its tests with Python 3.9+ and the pinned signing-library dependency:

```sh
cd components/confidential-storage-authority
python3 -m pip install -r requirements.txt
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v
```

`Authority` uses SQLite `BEGIN IMMEDIATE` transactions and `synchronous=FULL`.
The volume record, ownership, consumed operation IDs and event are committed in
one transaction before returning an authorization decision. Parallel callers
cannot obtain two different owners. Use an independently administered, private
directory on durable local storage; sharing the database through an ordinary
workload PVC would invalidate the authority's trust boundary.

| Call | Caller and effect |
| --- | --- |
| `register` | Trusted administrator records immutable volume, policy/profile digests and versioned KBS reference; duplicate registration fails |
| `approve_published_model` | Administrator approves an immutable publisher manifest for RO `/models`; no initialization grant |
| `approve_initialization` | Administrator authorizes an immutable first-use plan for a new disposable RW volume |
| `begin(initialize)` | Verified guest obtains ownership and `plan-initialization` after durable `Initializing`; no disk operation yet |
| `begin_initialization_step` | Records `Started` before a single `execute` decision; retries return `reconcile` or `complete` |
| `complete_initialization_step` | Records adapter-verified result and evidence digest for the same step/activation; conflicting retry fails |
| Retry of initialization | Same session/operation gets `resume-initialization`, never a new format grant; another session must stop for recovery |
| `commit_ready` | Requires all four steps complete and matching final header/manifest digests; then records `Ready` |
| `begin(reopen)` | Only for `Ready`; returns the recorded header/profile/key reference; never initializes |
| `close` | Same activation/session confirms teardown, then releases ordinary ownership |
| `revoke` | Administrator denies future operations; previously released keys remain usable |

An initialization retry after `Ready` returns `open`, not permission to format.
The same operation ID cannot acquire ownership again after close. There is no
automatic owner expiry, force takeover, database reset, or recovery format API.
Incomplete initialization stays owned until an explicit recovery protocol is
implemented. This intentionally sacrifices availability on ambiguous failure.

`AttestedPeer` contains trusted inputs. Constructing this dataclass does **not**
validate evidence. The development gateway below verifies signed AS results and
guest-key proofs, but a real guest/evidence/transport adapter is still required.
Never deserialize an untrusted HTTP body directly into `AttestedPeer` and treat
it as authenticated. Administrative methods need separate authentication.

Before deployment, implement and test:

- Real hardware interoperability for the AS-result verifier and authenticated
  session transport, including the required GPU runtime binding.
- Hardware validation of the signed, challenge-bound initialization/reopen
  responses; raw library dictionaries remain trusted internal results.
- Guest receipts that bind durable initialization phases/header/profile to the
  same activation; this library cannot verify that a guest actually flushed disk.
- Measured guest policy binding target container, destination and device contract.
- Fresh Trustee key retrieval bound to the approved volume/profile. This library
  stores only resource identifiers and never handles key material.
- Independent authority recovery/epoch protection. Restoring an old SQLite
  backup can restore old authorization; SQLite durability does not prevent this.
- Guest mount lifecycle and failure cleanup. `close` trusts the adapter's teardown
  assertion and does not establish fencing against a malicious host.

The original state tests cover transaction/state rules, not cryptography, disk integrity,
attestation, application isolation, writable rollback resistance or hardware E2E.

## Signed reopen receipts

`receipts.py` adds an internal Ed25519 receipt issuer for the
[guest lifecycle core](../confidential-storage-guest/README.md). Install the pinned
`requirements.txt` dependency before running the complete test suite. The original
state core still has no network endpoint or hardware verifier.

New registration may include an immutable `mount_binding` with `manifest_uri`,
`container_name`, `destination` and `access`. For these records, `commit_ready`
requires `manifest_sha256` as well as the header digest. Both digests are immutable
on retries. The issuer refuses legacy/unbound/uninitialized records. Existing
records are not silently upgraded or reset.

The issuer checks the requested binding and profile, commits a nonce-bound reopen
operation, and signs a short-lived receipt containing the session, activation,
resource identities and mount constraints. Changed request nonces cannot reuse
an existing operation; exact retries retain its activation ID. A signing or delivery
failure does not roll back committed ownership. Signing keys are supplied by the
trusted administrator; tests generate them in memory and retain only public
signature fixtures. No real authority key was created or deployed.

This implements signed response construction, not the missing attested transport,
attested first-use execution/completion, signing-key distribution/rotation,
private CDH socket, disk backend or privileged guest mount integration. Keep the
Kata activation gate closed until those pieces pass their respective tests.

## First-use initialization journal

[The initialization guide](../../docs/confidential-storage/first-use-initialization.md)
describes the explicit approval, four durable steps, failure timeline and remaining
guest work. `initialization.py` is an internal protocol library; it executes no
formatting command and does not issue signed format capabilities. A missing LUKS
header never influences authorization.

New and legacy unbound records cannot begin initialization without approval.
Approval requires a bound RW `/data` record and an explicit new-volume plan.
Old Ready records without completed initialization history cannot obtain signed
reopen receipts. This is a deliberate development-protocol change, not an automatic
migration of existing storage. The test fixtures are synthetic; no production
authority database has been upgraded or deployed.

## Trusted initialization coordinator

`executor.py` serializes a bound backend through the four journal steps. It requires
fresh administrative approval, checks the device/profile/key binding, commits each
Started decision before invoking the backend and validates completion before the
next operation. A failed/consumed executor cannot be retried; a restarted executor
refuses existing ownership/history instead of repeating destructive operations.
It does not automatically recover, clean up mappings or release ownership.

The concrete backend is currently the non-TEE QEMU test driver. No production
guest daemon or attested RPC adapter has been installed. The coordinator itself
needs only the Python standard library; receipt signing and the full unit suite
still require the pinned cryptography dependency. See
[execution contract and tests](../../docs/confidential-storage/initialization-executor.md).

## Attested request boundary

`attestation.py` verifies pinned ES256 Trustee EAR results, exact measured InitData,
configured CPU/GPU appraisals and a fresh request binding. `gateway.py` verifies
proof of possession of the dedicated guest key, atomically consumes a one-use
challenge and invokes only reopen/close. It constructs the internal `AttestedPeer`;
the request cannot supply one or invoke administrator/format/key-delivery methods.

The tests use real signatures and the SQLite core with synthetic EAR claims. No
hardware attestation or production key is involved. The custom
`storage-binding` runtime extension still needs a measured guest/AS integration;
the inspected NVIDIA result does not export the required binding. GPU-required
requests remain denied instead of falling back to CPU-only authorization.

See [the gateway guide](../../docs/confidential-storage/attested-authority-gateway.md)
for the protocol, retry behavior, pinned upstream source inspection, limitations
and remaining deployment gates. Kata activation remains disabled.

`serve.py` now provides a bounded TLS 1.3 listener and a fixed-policy loopback
Trustee relay. It exposes challenge/attest/execute only; administrator operations,
initialization and key delivery are absent. See [HTTPS setup and private guest
integration](../../docs/confidential-storage/authority-https.md). Ninety tests pass,
including real TLS transport and synthetic AS interoperability. The pinned real
AS and private ttRPC client build successfully; installed guest diagnostics found
the public attestation API disabled. Neither storage E2E has passed yet.

The [published-model approval guide](../../docs/confidential-storage/published-model-approval.md) describes the separate immutable RO path and its replay limits.

## Signed guest initialization API

`initialization_api.py` now exposes the approved first-use journal through the
existing attested TLS gateway. Each response is Ed25519-signed and bound to the
fresh challenge, exact request, session and workload policy. The Rust guest
client checks all bindings and reconstructs the immutable plan/manifest before
accepting metadata. Started retries return reconciliation, never a second execute
decision. See [protocol and evidence](../../docs/confidential-storage/guest-initialization-protocol.md).

The guest API has no administrator, reset, key or disk endpoints. Physical disk
completion remains a trusted guest-executor responsibility; the current network
tests use synthetic evidence and no disks. The full authority suite has 106
passing tests at this checkpoint, and the cross-language TLS suite has 16. Real
hardware attestation, private CDH key delivery and Kata activation are unfinished.

## Standard Trustee RCAR mode

`kbs_rcar.py` and `rcar_gateway.py` authenticate operations through the standard
KBS `/auth` and `/attest` endpoints. Configure `trustee_rcar` instead of
`as_loopback_port`; ambiguous configuration is rejected. The new mode requires
both SNP and NVIDIA appraisals. Each request retains its own fresh KBS handshake,
and execution requires its exact verified token plus the guest's signing proof.
No resource request, policy mutation or AS private signing key is involved.

See [configuration, security checks and evidence](../../docs/confidential-storage/standard-trustee-adapter.md).
The authority suite now passes 121 tests. Live verified TLS `/auth` passed;
composite hardware `/attest` acceptance still needs the candidate guest.


## Explicit recovery after a stopped Ready-volume owner

`recover_fenced_reopen.py` is an offline administrator tool, not a network route.
It requires independently established fencing of the old VM/storage access and
SHA-256 digests of the exact current records. It releases only unchanged,
non-revoked **Ready / reopen** owners, permanently retires their sessions using
the existing authority session-denial list, and records the old owner and evidence
hash in a transaction. Keys, headers, manifests, generation and initialization
history remain unchanged. It refuses uninitialized/initializing records and never
issues a formatting permit. Default operation is a dry run; applying requires
`--apply-after-external-fencing`.

An evidence hash is an audit reference, not proof that a hostile host destroyed a
VM. The lab exercised explicit administrator recovery after proving no old sandbox
or sidecar VM remained. Production use requires independent fencing; timeouts and
host statements alone are insufficient. See the
[sidecar shutdown result](../../docs/confidential-storage/stock-kata-qwen-storage-addon.md).
