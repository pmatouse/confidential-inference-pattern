# Trusted public release renderer

`render.py` provides deterministic `draft(request, profile)` and
`package(request, draft, guest, aa, cdh, runtime)` functions. It does not sign,
read keys, enroll an authority or access a cluster. Inputs must come from the
trusted release pipeline, not arbitrary workload annotations.

Draft first: bind the controller request, select the qualified OCI compatibility
profile, render the helper and unprivileged consumer, and compute the policy hash.
Enroll RO manifests/RW initialization plans against that hash in the trusted domain.
Then package the resulting public guest configuration and AA/CDH settings into
InitData, derive its hash, and validate the four-file package with the same
controller verifier used at deployment. Trustee release configuration and signing
come after these public identities exist.

Synthetic tests cover request replacement, wrong images, relaxed application
profiles, deterministic output and controller acceptance. They do not establish
that a new runtime profile works on hardware. A qualified profile must bind actual
stock image metadata, guest ABI/mount shape, injected environment, launch identity
and NVIDIA evidence. An unrelated VM state or signed approval is not a valid substitute.

The draft wraps the declared application command in the sidecar rendezvous
protocol. Optional `startupChecks` verify model hashes, mount modes, application
isolation, CUDA and a flushed persistence canary across guest boot IDs. See the
[fresh release workflow](../../docs/demo/fresh-release.md) for the trusted steps.

## Trusted metadata enrollment and packaging

`enroll.py plan` matches approved publisher descriptors to the controller's exact
populated source, derives stable volume identities from cluster/namespace/PVC UID,
and requires an explicit list of every new writable claim UID. It creates public
metadata only. No name-based initialization or arbitrary existing-disk approval
is inferred from a PVC label.

`enroll.py apply` operates on already bootstrapped authority history in the trusted
domain. It verifies the bootstrap identity, prechecks existing registrations and
applies only missing registrations/approvals. Exact retries preserve initialization
plans and owners, including an attempt already in progress. Conflicting policy,
manifest, source, key reference or initialization geometry requires a separate
explicit migration; it never resets a record. A crash can leave partial enrollment,
which an identical retry completes. This command is not a controller API.

`package.py` checks the matching enrollment result, creates the multi-volume guest
configuration and delegates to the renderer/controller package validator. It takes
public AA/CDH settings, runtime identity, authority trust pins and resource encodings.
The output contains the four public approval artifacts. Use the existing
`../confidential-volume-controller/approve.py` only after the trusted administrator
has installed and verified the exact scoped Trustee release bindings. Signing does
not provision keys or authorize missing enrollment.

```sh
python3 components/inference-release/render.py \
  --request request.json --profile qualified-profile.json --output draft.json
python3 components/inference-release/enroll.py plan \
  --request request.json --draft draft.json --models reviewed-publishers.json \
  --blank-claim-uids approved-new-claim-uids.json --output enrollment-plan.json
python3 components/inference-release/enroll.py apply \
  --plan enrollment-plan.json --state /trusted/retained \
  --installation my-installation --output enrollment-result.json
python3 components/inference-release/package.py \
  --request request.json --draft draft.json --plan enrollment-plan.json \
  --enrollment enrollment-result.json --authority authority-public.json \
  --encodings resource-encodings.json --runtime qualified-runtime.json \
  --aa aa.toml --cdh cdh.toml --output release
```

`reviewed-publishers.json` maps each declared `approvedManifestRef` to
`{"descriptor": <publisher descriptor>, "source": <verified OCI source>}`.
The URI encodings map is `{"kbs:///repository/type/tag": "raw32"}` (or
`lower-hex64`, chosen explicitly). Authority public fields are `trustee_rcar: true`,
`audience`, DER CA byte array `certificate_der`, optional pinned `address`, 32-byte
`receipt_public_key`, `receipt_issuer`, and `receipt_key_id`. There are no private
keys in these files. Real compatibility profiles, trust pins and publisher metadata
are required; the synthetic fixtures in tests must never be deployed.

The [manual quickstart](../../docs/demo/quickstart.md) invokes these tools in order.
Its [E2E receipt](../../tests/evidence/2026-10-15/manual-quickstart-e2e.json) covers
fresh publication, initialized/reopened PVCs, attestation and real inference on
the qualified profile. See the [walkthrough](../../docs/workload-walkthrough.md)
for all runtime data flows and the [component map](../../docs/components.md) for
the distinction between release preparation and guest execution.
