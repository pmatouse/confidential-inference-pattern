# Guest storage sidecar

`runtime.py` supervises encrypted storage inside a stock confidential Kata VM.
It is a privileged guest container; the application remains UID/GID 1001,
read-only-root, without capabilities, privilege escalation or raw storage devices.
The vLLM image is unchanged; the measured command waits for storage before exec.

1. Accept the application rendezvous after stock Kata attaches its GPU.
2. Start private, unchanged AA/CDH binaries extracted from the pinned stock initrd.
   AA verifies InitData against SNP HOST_DATA. Refuse the public guest REST API.
3. Load approved matching storage modules; start the Rust storage service with
   `--sidecar-parent` on its root-private socket.
4. Authenticate the consumer using SO_PEERCRED, exact command, UID/GID, capabilities
   and NoNewPrivs; retain pidfd, root and mount-namespace descriptors.
5. Activate all measured volume bindings. Clone private mounts with `open_tree`,
   enter the consumer namespace, attach using `move_mount`, enforce flags and send READY.
6. On shutdown, stop the consumer, remove its mounts, close storage, then release
   authority ownership. Uncertain cleanup retains ownership; supervisor failure
   kills the consumer rather than leaving it unsupervised.

The shared PID namespace is inside the guest, not the host. The rendezvous socket
returns readiness, not keys. AA/CDH and service sockets remain private to the helper.
The helper is trusted VM root; this design isolates storage privileges from the
app, not from malicious code running as guest root.

## Build interface

- `prepare-payload.py`: verify and extract stock AA/CDH, libraries and pinned tools/modules.
- `stage-service.py`, `build-service.sh`: stage unchanged upstream protocol definitions
  and build the add-on Rust executable with `trustee-rcar` (includes private CDH).
- `prepare-build.py`: package only the supervisor, executable and public payload.
- `policy.py`: render exact stock-agent request policy from reviewed runtime/image metadata.
- `test_runtime.py`: Linux supervisor/child shutdown regression.

No key, plaintext model or cluster credential belongs in the image. OpenShift build
metadata affects the measured environment, so rebuilding requires a fresh package
and approval. The SCC/admission guard restricts the service account to approved
images/runtime and prevents application privileges or host namespace access.

See the [component map](../../docs/components.md) and [runtime walkthrough](../../docs/workload-walkthrough.md). Build/deploy through the [manual quickstart](../../docs/demo/quickstart.md).
