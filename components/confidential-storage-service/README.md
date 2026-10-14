# Private guest storage service (development)

**Current status:** the v2 multi-volume service with private CDH and standard Trustee RCAR is deployed in the validated Qwen GPU guest. See the [current walkthrough](../../docs/confidential-storage/qwen-storage-walkthrough-and-gaps.md). Earlier deployment-status statements below are historical checkpoints.

This component connects the tested authority client, private SNP KBS client and
read-only LUKS/dm-verity opener and journaled RW initializer/opener. It is
**previous single-volume version is installed only in the isolated development guest**.
The new multi-volume version is compiled and tested, but not installed. Both
[model inference](../../docs/confidential-storage/native-model-serving.md) and
[RW first-use/reopen](../../docs/confidential-storage/native-rw-storage.md) passed.
RW configuration pins an immutable initialization-plan hash; Ready uses its signed
manifest, while only explicitly approved Uninitialized state can format.

The fixed, measured `/etc/confidential-storage/service.json` contains only public
trust roots, receipt verification key, endpoint pins, mount binding and an
approved RO manifest or RW initialization-plan hash. It contains no storage key. Runtime session key, nonce and
operation ID are generated inside the guest. A signed authority grant permits
only the configured resource; the copied LUKS header and manifest are validated
before the private client asks Trustee for an encrypted key reply. The legacy CPU
client establishes a new attestation session per retrieval; the opt-in CDH adapter
may reuse CDH's existing session.
The service decrypts/mounts the device and sends only the mount path to the agent.

The daemon accepts framed `activate` and `close` messages on a root-owned 0600
Unix socket under a 0700 directory. It checks root peer credentials and the peer
executable inode against the measured agent. This is additional enforcement
inside the trusted VM-root boundary, not a defense against arbitrary malicious
VM root or PID reuse. Applications must stay non-root, without capabilities,
private socket mounts or a public AA/CDH signing/key endpoint.

One container/device reservation lasts for the VM lifetime. Activation failures,
disconnects and uncertain effects retain ownership. Close unmounts normally,
closes the kernel mapping, then closes the authority owner; busy or failed cleanup
never becomes a force-unmount or lease takeover. The agent must destroy the
consumer first. Closed reservations cannot reactivate. Service state is currently
in-memory; guest loss requires conservative authority recovery, not ownership
expiry or automatic reformatting.

Failures log only a fixed activation-stage label. No request body, evidence,
receipt, key or underlying error text is logged. A denial retains ownership;
adding diagnostics does not introduce a retry or reformat path.

## Build and test

Use the pinned guest-components checkout recorded by the KBS wrapper:

```sh
python3 components/confidential-storage-kbs/prepare.py \
  --upstream /scratch/guest-components --output /scratch/storage-service \
  --with-service
cd /scratch/storage-service/components/confidential-storage-service
cargo +1.94.1 test --locked
cargo +1.94.1 build --locked --release
```

Eight service tests pass in both default and `private-cdh` builds: protocol
bounds, exact device bindings, configuration validation, group admission and
cleanup after partial failure. These do not substitute for live
service/agent/Trustee/PVC and failure-recovery testing. The release build requires
Linux glibc through 2.34, compatible with the recorded RHEL 10 guest base.

See the [native lifecycle experiment](../confidential-storage-kata/native-agent/README.md)
and [private guest packaging](../../tests/confidential-storage/native-guest/README.md).

## Version 2 configuration

`schema_version: 2`, `purpose: confidential-storage-guest/v2` selects up to eight
named `volumes`, with one shared authority and key-provider configuration. Each
entry has `binding_id`, `transport_path` (`/dev/coco-volume-0` through `-7`),
`expected`, `manifest` and optional `initialization_plan_sha256`. `expected` keeps
the authenticated volume/generation/profile/consumer/destination/access fields.
Every entry must name the same consumer. Legacy version 1 remains supported.

The private `activate-many` request resolves physical devices against these IDs.
All reservations precede activation; the agent receives mounts only after all
volumes succeed. An error does not roll back or erase an uncertain first-use
operation. Close attempts every child and reports success only after all close.
Closed or uncertain ownership cannot be used by a replacement consumer.

The new v2 guest profiles permit approved destinations beneath `/models`, `/data`
and `/checkpoints`. RW v2 formats for UID/GID 1001; legacy v1 remains UID/GID 1000
at `/data`. Existing profile bytes and hashes were not changed. Existing disks
need explicit approved metadata to change profile/binding; no automatic migration
or formatting is performed. Backend RW geometry remains 1 GiB.

The declarative compiler emits an approval request, not this configuration.
The authority resolver/approval packaging is still required. See the
[checkpoint and remaining gates](../../docs/confidential-storage/multi-volume-implementation.md).

## Opt-in standard Trustee authentication

Build with `--features trustee-rcar` and set measured
`authority.trustee_rcar: true` to select the existing KBS RCAR protocol for authority
operations. This feature includes `private-cdh` and the private composite AA
collector. Select the private CDH key provider explicitly in the measured key
configuration. A build without this feature rejects RCAR selection.

The feature is compiled and tested, not installed in Qwen. See the
[protocol and remaining hardware gates](../../docs/confidential-storage/standard-trustee-adapter.md).
