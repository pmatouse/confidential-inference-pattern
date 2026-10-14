# Writable profile and authenticated header preparation

`rw-luks2-v1.json` is the exact byte descriptor hashed into `profileSha256`.
Its digest includes whitespace and the final newline. It describes a **candidate
profile**, not a profile validated on the confidential guest kernel. Do not register
it for a production key until the kernel stack and corruption/recovery gates pass.

The implemented path is:

```text
verified authority receipt + authenticated manifest
  -> compare volume/generation/key URI/profile/header digest/device length
  -> read exactly 16 MiB from the retained source fd, offset zero
  -> authenticate the complete copy before parsing any LUKS fields
  -> validate both LUKS2 binary headers, checksums and identical metadata
  -> enforce the narrow crypto/KDF/layout allowlist
  -> copy into an anonymous Linux memfd and seal against writes/resizing
  -> retain that exact descriptor for the future cryptsetup opener
```

`PreparedHeader::prepare` does not fetch a key, format, open a mapping or mount a
filesystem. It has no application RPC. Its `File` argument is deliberately usable
with regular files for isolated tests; the production caller still must resolve and
retain the intended guest block device and obtain its size from that same fd.
Receipt expiry is checked by the lifecycle admission path, not by this helper.

## Manifest contract

The manifest is retrieved through the future guest-only CDH adapter. The signed
receipt pins its exact bytes before JSON parsing. This is a separate, strict
contract from the upstream experimental `secure_volume` manifest; it cannot be
passed to that old API unchanged.

```json
{
  "schemaVersion": 1,
  "volumeId": "state-volume",
  "generation": 1,
  "profileSha256": "<sha256 of exact rw-luks2-v1.json bytes>",
  "credentialUri": "kbs:///storage/keys/state-v1",
  "luksUuid": "01234567-89ab-4cde-8123-456789abcdef",
  "deviceBytes": 1073741824,
  "headerSha256": "<sha256 of the complete 16 MiB header copy>",
  "headerBytes": 16777216,
  "dataOffsetBytes": 16777216,
  "filesystem": "ext4"
}
```

The displayed digests are explanatory placeholders, not deployable values.
Unknown/duplicate fields, another key URI, generation, profile, UUID syntax or
geometry fail validation. The fixed prefix holds both metadata copies and the
keyslot area; the integrity data region starts at 16 MiB. Once copied, that prefix
is treated as a detached header for future activation. Device length is pinned;
resize and alternate layouts are not supported by this version.

## What is enforced

| Area | Required behavior |
| --- | --- |
| Receipt/manifest | Signed digest, exact volume/generation/profile/key/header binding; RW `/data` only |
| Complete header | SHA-256 authentication before parsing; exactly 16 MiB including keyslot material |
| Binary metadata | LUKS2, two 16 KiB metadata areas, SHA-256 checksums, exact UUID, same nonzero sequence and JSON bytes |
| Repair/extension | No recovery from one damaged copy; no labels/subsystems, unknown JSON fields, extra slots or segments |
| Payload crypto | AES-XTS with 64-byte encryption key plus 32-byte HMAC-SHA256 key; 4096-byte sectors |
| Keyslot | One slot `0`, bounded Argon2id settings, AES-XTS keyslot encryption and SHA-256 AF splitter/digest |
| Flags/tokens | No persistent activation flags, tokens or reencryption requirements |
| Header lifetime | Anonymous memfd with WRITE/GROW/SHRINK/SEAL seals and close-on-exec |

These restrictions intentionally reject otherwise valid general-purpose LUKS
volumes. The code verifies the narrow profile rather than implementing cryptsetup's
full format/recovery behavior. Format definitions were checked against
[cryptsetup's LUKS2 specification](https://gitlab.com/cryptsetup/cryptsetup/-/blob/v2.8.1/docs/on-disk-format-luks2.pdf)
and source commit `9cfdd6ba068b375a2b6cda429b3f92388448dd67` (v2.8.1).

**Header metadata does not establish the live integrity mode.** In particular,
`journal_encryption: none` and `journal_integrity: none` are LUKS metadata values;
they do not prove that the dm-integrity journal is enabled or authenticated.
The opener must enforce journal mode, reject discard/no-journal/recalculate
bypasses, inspect the effective dm-crypt/dm-integrity stack, and test data/tag/journal
corruption and crash recovery before exposing `/data`. See the
[kernel dm-integrity contract](https://docs.kernel.org/admin-guide/device-mapper/dm-integrity.html).
No writable anti-rollback or journal-tamper-resistance claim follows from this code.

## Tests with real userspace tools

From the repository on Linux, with Rust and cryptsetup available:

```sh
cargo test --locked --manifest-path components/confidential-storage-guest/Cargo.toml
COCO_TEST_CRYPTSETUP=/usr/sbin/cryptsetup \
  scripts/confidential-storage/test-header-tools.sh
```

The tool test generates a disposable random key and an ordinary LUKS2 regular-file
image without dm-integrity. It proves the key unlocks that image using
`--test-passphrase`, then requires our profile to reject its header. The positive
parser fixture is synthetic: cryptsetup can parse its sealed metadata, but its
keyslot/data bytes do not describe a usable encrypted volume. Neither test creates
a device-mapper target. Files and the test key are removed on exit.

The Linux unit tests also verify that writes, truncate, growth and a shared writable
mapping cannot modify the sealed copy. Altering the source after preparation does
not change that copy. The profile tests cover reauthorized unsafe metadata as well
as simple digest mismatches: a valid authority signature cannot make an unsupported
cipher, CRC integrity, extra slot, token, duplicate field or oversized KDF acceptable.

Validated with Rust 1.94.1 and Debian cryptsetup 2.6.1 in an unprivileged compiler
pod with no GPU, PVC, host mount or service-account token. This is userspace/header
validation, **not encrypted-storage E2E** and not an attested VM test.
