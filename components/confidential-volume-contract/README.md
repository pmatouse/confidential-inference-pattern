# ConfidentialVolume approval-request compiler

The [ConfidentialVolume controller](../confidential-volume-controller/README.md) now invokes this compiler against live namespace resources. The standalone CLI remains available; neither compiler nor controller grants storage authorization.

Development tooling, not an operator or a runtime authorization service.
`compiler.py` takes a JSON snapshot containing one Pod or KServe InferenceService,
ConfidentialVolume declarations and actual Block PVC identities. It validates
one consumer with up to eight distinct volumes and emits a deterministic public
approval request. It never contacts Kubernetes, Trustee or a registry.

```sh
python3 -m unittest discover -s components/confidential-volume-contract
python3 components/confidential-volume-contract/compiler.py \
  --input bundle.json --output approval-request.json
```

The output must not be copied directly into guest configuration. It does not
contain a signed grant, approved manifest, initialization plan or approved
InitData. The independent authority/build integration must resolve these first.
The compiler's hash identifies the complete request; it does not confer trust.

`examples/four-volumes.json` is a synthetic offline example with two RO models
and two RW filesystems. Its registry digest, PVC UIDs and manifest names are
placeholders, not live deployment values. Paths explicitly bind each volume to
the same named consumer, independently of whether it stores a model or data.
A profile and initialization policy select behavior; names have no special meaning.

The initial schema accepts only exclusive Block/ReadWriteOncePod claims. It does
not implement shared-model access. CRD status is not used as approval. Replaced
claims, duplicate credentials/devices, overlapping mounts, mutable images and
model formatting requests are rejected.

The API aliases `luks-verity-v1` and `luks-integrity-v1` describe requested storage
behavior; they are not the guest profile file version or its authenticated hash.
The resolver must select an exact approved profile. The implemented guest's new
RW profile currently supports UID/GID 1001 and 1 GiB geometry; accepting another
owner/capacity in an approval request does not imply backend support.

See the [API proposal](../../docs/confidential-storage/confidential-volume-api-proposal.md)
and [component gap report](../../docs/confidential-storage/minimal-integration-and-stock-gaps.md).
