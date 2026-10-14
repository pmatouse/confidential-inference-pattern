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
and NVIDIA evidence. No lab VM state or old signed approval is a valid substitute.

The current draft wraps the declared application command in the sidecar rendezvous
protocol. Startup filesystem/hash/CUDA/persistence evidence and trusted profile
publication still need integration before this is a complete E2E release path.
