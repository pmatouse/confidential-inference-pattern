# Confidential volume contract compiler

`compiler.py` is a deterministic Python library/CLI used by the namespace
controller. It validates a public workload/resource snapshot and emits an approval
request. It has no network client, signer, decryption key or disk access.

The contract resolves up to eight distinct Block/ReadWriteOncePod claims for one
consumer. It binds exact PVC UIDs, profiles, key URIs, access and destinations;
rejects conflicting/overlapping mounts, duplicate resources, mutable images and
model initialization. Names have no storage semantics. `luks-verity-v1` selects
RO/Never; `luks-integrity-v1` selects explicitly approved RW initialization/reopen.
The backend's narrower geometry/runtime limits still apply.

The request hash identifies intent, not trust. A release owner must resolve
approved model metadata, initialization plans, measurements and trust pins before
signing a deployable package. Changed immutable identities require a new request.

```sh
python3 -m unittest discover -s components/confidential-volume-contract
python3 components/confidential-volume-contract/compiler.py --input bundle.json --output request.json
```

`examples/four-volumes.json` is synthetic input showing two models and two data
volumes; its UIDs/digests are placeholders. CRD definitions live in
[`charts/vendor/confidential-volumes`](../../charts/vendor/confidential-volumes/crds/).

See the [component map](../../docs/components.md) and [runtime walkthrough](../../docs/workload-walkthrough.md). Build/deploy through the [manual quickstart](../../docs/demo/quickstart.md).
