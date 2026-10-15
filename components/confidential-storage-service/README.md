# Private guest storage service

The Rust `confidential-storage-service` executable runs as a child of the sidecar.
It joins authority authorization, private CDH key delivery, disk validation and
mount lifecycle. It is not installed into or called by a modified Kata agent.

`--sidecar-parent` authenticates root peer credentials and the parent executable
inode on a 0600 Unix socket under a 0700 directory. The sidecar sends
`activate-many` and `close`; no network storage-management endpoint exists.
Measured v2 configuration holds up to eight named bindings, raw transport paths,
expected volume/profile/generation/consumer/path identities, approved manifests
or RW initialization-plan hashes, and shared authority/key-provider settings.
It contains no volume key.

All device reservations precede activation. Mount paths are returned only when
all volumes succeed. Partial or uncertain effects keep ownership; errors never
trigger implicit formatting. Close attempts all children and succeeds only after
mounts/mappings and authority owners have closed. Reservations and tombstones
are local to this VM; authority history persists outside it.

The qualified build selects `trustee-rcar` and the private CDH provider. The linked
`client` library authenticates authority decisions, `kbs` retrieves permitted
credentials, and `guest` executes the validated crypto/filesystem operations.
Diagnostics expose fixed stage labels rather than key/evidence bodies.

The retained agent-oriented library interfaces are not active deployment paths.
Use the sidecar staging/build flow; changing stock Kata is unnecessary.

See the [component map](../../docs/components.md) and [runtime walkthrough](../../docs/workload-walkthrough.md). Build/deploy through the [manual quickstart](../../docs/demo/quickstart.md).
