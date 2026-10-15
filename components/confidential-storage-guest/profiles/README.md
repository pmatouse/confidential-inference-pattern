# Storage profiles and authenticated headers

The release pins the exact profile bytes/hash, not merely the API alias:

| API alias | Current guest profile | Behavior |
| --- | --- | --- |
| `luks-verity-v1` | `ro-luks2-verity-v2.json` | ext4 RO, ciphertext/header verity, no format |
| `luks-integrity-v1` | `rw-luks2-v2.json` | ext4 RW, keyed integrity journal, UID/GID 1001 |

The qualified RW executor currently accepts 1 GiB geometry. V1 descriptors are
retained implementation inputs, not the current Qwen deployment profile. Profile
file whitespace/newlines participate in the hash; changing them needs review and
a new approval. [Runtime walkthrough](../../../docs/workload-walkthrough.md).

## Authenticate before parsing

```text
verified authority receipt + authenticated manifest
  -> match generation, device length, profile, key URI and header digest
  -> read complete 16 MiB header from retained device descriptor
  -> authenticate bytes before interpreting LUKS metadata
  -> validate narrow metadata/algorithm/layout allowlist
  -> seal copy in anonymous memfd against writing/resizing
  -> pass the same descriptor to cryptsetup
  -> verify effective kernel stack before exposing the filesystem
```

This prevents a host-supplied disk header from changing between verification and
cryptsetup parsing. The manifest binds UUID, generation, key URI, profile, device
length, header hash/size, data offset and filesystem. The RO manifest also pins
verity geometry/root/salt. Public manifest data comes from trusted enrollment or
signed initialization/reopen results; it is not trusted because it was stored next
to ciphertext. No secret is present in the manifest.

## Narrow accepted layout

Both profiles require LUKS2, matching metadata copies, SHA-256 header checksums,
one keyslot, no tokens/reencryption, AES-XTS and 4096-byte sectors. The complete
header/keyslot region is authenticated; no repair from one damaged copy or unknown
metadata extension is allowed. The unlock credential is distinct from LUKS's
internal encryption/integrity keys.

RW uses a 64-byte XTS key and 32-byte HMAC-SHA256 integrity key, bounded Argon2id
keyslot parameters, journal mode, and no discard/no-journal/recalculate bypass.
The opener checks effective dm-crypt/dm-integrity settings; a JSON profile name
alone proves nothing about the active stack. RO builds dm-verity over the LUKS
header and ciphertext, then read-only dm-crypt and ext4 `ro,noload`.
Both expose `nodev,nosuid,noexec` mounts to the approved destination.

These restrictions reject otherwise valid general-purpose LUKS volumes. Resizing,
keyslot changes and profile migrations need explicit supported lifecycle work;
they are not an automatic open fallback. Keyed integrity detects modification but
does not provide whole-disk snapshot freshness or general journal-tamper resistance.

Tests cover sealed-copy mutation, malformed/reauthorized unsafe metadata and stack
validation. Real storage/inference/persistence evidence is separate:
[qualified E2E](../../../tests/evidence/2026-10-15/manual-quickstart-e2e.json).
