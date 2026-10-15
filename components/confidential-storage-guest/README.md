# Guest crypto and mount library

Rust library linked into the sidecar's storage service. It verifies authority
receipts and manifests, authenticates LUKS headers and executes the narrow approved
RO/RW disk profiles. It is not a replacement Kata agent, kernel or guest image.

| Module | Responsibility |
| --- | --- |
| `receipt.rs`, `binding.rs` | Signed exact volume/generation/policy/key/path/access/session bindings |
| `sealed_header.rs`, `profile.rs`, `ro_profile.rs` | Authenticate complete header before parsing; validate allowlisted metadata; seal memfd copy |
| `ro_opener.rs` | Approved ciphertext dm-verity → read-only dm-crypt → ext4 |
| `initializer.rs`, `opener.rs` | Explicitly authorized RW initialization and authenticated reopen; effective stack checks |
| `lifecycle.rs`, `linux_backend.rs`, `guest_mount.rs` | Reservations, private filesystem mounts and ordered cleanup |
| `consumer.rs`, `agent_lifecycle.rs` | Reusable coordination primitives; the installed sidecar handles actual consumer namespace transfer |

The current v2 profiles bind the destination through the authenticated grant;
RW ownership is UID/GID 1001 with 1 GiB supported geometry. API profile aliases
are resolved to exact profile bytes/hashes, not treated as sufficient authorization.
See [profile and header contract](profiles/README.md).

The backend marks possible effects before performing them. Busy unmount retains
NeedsUnmount; failed mapper close retains NeedsClose; a lost authority close
acknowledgement retains NeedsRelease. Closed activations cannot reopen. A crash,
expired receipt or failed unlock never authorizes formatting or another owner.

Storage keys are used only in the private guest execution path. Applications get
mounts, not mapper controls or keys. Storage availability, hostile-host fencing
and general writable-snapshot freshness are outside this library's guarantees.

Unit tests use synthetic receipts/backends as appropriate; the repository E2E
receipt separately demonstrates real populated/blank PVCs, attestation, inference
and fresh-VM persistence. Build the linked service through `make qs-build` so the
pinned upstream protocol dependencies and compiler are staged consistently.

See the [component map](../../docs/components.md) and [runtime walkthrough](../../docs/workload-walkthrough.md). Build/deploy through the [manual quickstart](../../docs/demo/quickstart.md).
