# Retained storage authority

Trusted Python TLS service for volume identity, exclusive ownership and first-use
initialization. It is **not a key broker**: standard Trustee holds/releases storage
credentials. The authority keeps approved metadata, SQLite history, a TLS key and
an Ed25519 receipt signer in a trusted administration domain.

See the [component map](../../docs/components.md),
[workload walkthrough](../../docs/workload-walkthrough.md) and
[deployment chart](../../charts/storage-authority/README.md).

## Interfaces and enforcement

| Interface | Caller / behavior |
| --- | --- |
| Offline bootstrap and metadata enrollment | Trusted release tools; register exact volume/generation/profile/key URI and container/path/access; approve a published RO manifest or explicit new RW plan |
| TLS challenge/attest/execute | Measured guest; standard Trustee RCAR verifies CPU/GPU evidence and session binding; guest proof authorizes the exact request |
| Signed lifecycle result | Commits ownership/history before issuing a nonce/session/request-bound receipt; no key bytes |
| Offline recovery tools | Administrator with independent fencing/recovery evidence; never a guest reset or format endpoint |

`kbs_rcar.py` permits only standard KBS `/auth` and `/attest`, not resource/admin
calls. `attestation.py` validates the pinned signed EAR (Entity Attestation Result),
expected InitData and CPU/GPU appraisals; `rcar_gateway.py` verifies guest proof and
fresh challenge binding before constructing the internal authenticated peer.
Network JSON is never accepted directly as a trusted `AttestedPeer`.

`authority.py` commits record/owner/operation/event changes in one SQLite
`BEGIN IMMEDIATE` transaction with `synchronous=FULL`. It never returns a second
owner merely because a previous request timed out. Administrative registration,
policy changes and secret-backend access are not exposed on the guest listener.

## First use, reopen and close

| State/action | Permitted behavior |
| --- | --- |
| Registered RO model | Open only the approved manifest/header/root/generation; no initialization grant |
| Uninitialized RW + explicit approval | Acquire owner and immutable plan; no format permission inferred from missing header |
| `begin_initialization_step` | Persist Started before one execute decision; duplicate Started requires reconciliation |
| `complete_initialization_step` | Record bound result/evidence digest; reject conflicting retry |
| `commit_ready` | Require four completed steps and matching header/manifest; then Ready |
| Ready reopen | New attested owner receives recorded identities; never formats |
| Close | Same session/activation confirms teardown before ordinary ownership is released |
| Revoke | Deny future authorizations; cannot erase a key already released to a running guest |

The four steps are `luks-format`, `integrity-initialize`, `filesystem-create`,
`durability-barrier`. The trusted guest executor establishes physical completion;
the authority authenticates/binds and journals the assertion, not the disk itself.
Signed reopen receipts bind volume/generation, policy/profile, credential URI,
manifest/header, container/destination/access, session/operation/activation and
nonce, with a short admission window. Expiry is not an ownership lease.

## Retention and recovery

Bootstrap is one-time; serve/enroll must verify and preserve the same retained
identity/database. Back up history, trust/signing identities and enrollment records
together. The authority PVC is not an application data PVC. Same-cluster placement
does not protect it from that cluster's administrator, and SQLite durability is
not rollback protection.

No automatic owner timeout/takeover exists. An uncertain VM/storage teardown
retains ownership. `recover_fenced_reopen.py` is an offline dry-run-first tool:
it requires independently established fencing and hashes of unchanged Ready
records, retires old sessions and does not change headers/keys/initialization.
A digest of evidence is an audit reference, not proof a hostile host destroyed a VM.
Unstarted/initialization recovery tools have separate preconditions; they are not
a generic reset. Retained-state deletion is not a recovery procedure.

## Test and build

```sh
python3 -m pip install -r components/confidential-storage-authority/requirements.txt
python3 -m unittest discover -s components/confidential-storage-authority -v
```

Unit/transport fixtures include synthetic attestation inputs. Real hardware
qualification is recorded separately in the repository's
[manual quickstart receipt](../../tests/evidence/2026-10-15/manual-quickstart-e2e.json).
`qs-build` packages this service; `qs-install`, `qs-enroll` and `qs-deploy` bootstrap,
enroll and serve retained state in order.
