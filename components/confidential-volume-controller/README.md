# ConfidentialVolume controller

Namespace-scoped reconciliation for the existing `ConfidentialVolume` API and
Pod/KServe binding format. It reuses the contract compiler; it never formats a
disk, reads a Secret, retrieves a volume key or signs an approval. It does not
write Pods directly. The opt-in sidecar deployment mode now creates and updates
approved KServe InferenceServices.

## Automatic stock-sidecar deployment (0.3.0)

Set `controller.sidecarWorkloads` to an explicit list of KServe target names and
install the new `ConfidentialWorkload` CRD. The declaration holds the desired
single-container application and ConfidentialVolume bindings; its generated
InferenceService contains the reviewed sidecar. Keeping these separate prevents
the controller's own injection from changing its approval request.

The request binds the declaration UID, cluster identity, template and exact volume
identities. A signed package adds `sidecar-deployment.json` to the original three
public artifacts. The controller validates the measured configuration, publishes
its immutable ConfigMap and creates/adopts/updates only an enabled KServe target.
Adoption requires an explicitly approved existing UID and no other owner. Repeated
reconciliation is idempotent; deleted generated workloads are recreated while the
approval is valid. Invalid/expired approval prevents deployment but does not revoke
keys or kill an existing workload.

This opt-in mode adds ConfidentialWorkload reads/status writes and restricted
InferenceService creation/update. A separate admission policy bounds creation to
the configured namespace and names; update/delete RBAC uses resourceNames.
Kubernetes requires delete permission on an existing dependent to set its owner
reference during adoption; the reconciler itself does not send DELETE requests. There is no
Secret read, PVC write, exec, signer or Trustee administration permission.

See the [deployment guide, one-time installation requirements and per-volume
approval steps](../../docs/confidential-storage/controller-sidecar-deployment.md).
The existing offline signer is retained; automatic trusted approval issuance and
renewal are not implemented by this change.

The sections below describe the retained **publication-only mode** and its original
approval contract. Workload-write restrictions there apply when
`controller.sidecarWorkloads` is empty. The full lab example and live controller
rollout evidence are linked from the deployment guide.

## Reconciliation

Every 15 seconds (configurable 2–60), the controller lists declarations, PVCs,
EncryptedModelSources and InferenceServices in its namespace. Full periodic
resync handles missed events and approval expiry without a watch cache. Only
InferenceServices with the existing binding annotation participate. Optional
standalone Pods require the label
`storage.confidentialcontainers.org/controller: standalone` and no owner reference;
KServe-generated Pods are not reconciled a second time.

For each consumer it:

1. Resolves all declared volumes, exact claim UIDs, Bound Block/RWOP claims and
   optional immutable OCI sources. Missing, replaced or terminating inputs block
   publication. The source CRD and KServe API must be installed.
2. Runs the existing deterministic compiler. The request also binds the configured
   cluster ID, workload UID, declaration UIDs, storage class, PV name and source
   UID/spec. Resource versions and statuses do not change its digest. Process or
   predictor configuration changes do.
3. Creates an immutable `cv-request-<digest-prefix>` ConfigMap with `request.json`.
   A conflicting object is never overwritten. Requests are not authorizations.
4. Looks for `cv-approval-<same-prefix>` containing `approval.json`. Verifies its
   Ed25519 signature against the configured public keyring, exact request digest
   and validity interval. Approvals last at most seven days. Empty keyrings allow
   request generation but cannot approve anything.
5. Publishes an immutable `cv-approved-<approval-digest-prefix>` ConfigMap containing
   the signed approval, request and three public files: `guest-config.json`,
   `initdata.toml` and `runtime.json`. Checks package hashes, volume/device/path
   bindings and resource allowlist consistency before publication.
6. Updates each declaration's `/status` with current conditions and per-consumer
   request/artifact references. Optimistic resourceVersion updates prevent lost
   updates; a controller restart repeats safely without replacing artifacts.

`Approved` / `ConfigurationPublished` mean that the current request has a valid
signed public deployment package. They **do not mean mounted, initialized, keys
released or application Ready**. Those are guest/authority/KServe decisions.
There is deliberately no `StorageReady` condition synthesized from PVC status.

If an approval expires, disappears or stops matching, the next successful scan
withdraws approved status and its current artifact reference. Previously published
immutable files remain for audit. This neither revokes keys already in a guest
nor stops a running workload. Old artifacts must not be deployed by trusting their
name alone: consumers must revalidate the signature, expiry and current request.

No finalizers or disk/key deletion are added. Deleting a CR does not erase storage
or its authority history. Public artifacts are retained without owner references;
reviewed garbage collection is future work.

## Approval boundary and current scope

The signing service/operator owns a separate Ed25519 **deployment-approval key**.
It is not a volume key, Trustee AS key or storage-authority receipt key. Keep its
private key outside the controller and its namespace. The controller receives only
public verification keys. Do not put a private key in chart values or ConfigMaps.

The signer independently reviews the full desired workload (the request includes
its template digest), resolves the release and initialization approvals, confirms
existing authority records and scoped Trustee policies, and packages the measured
public guest configuration. The signature binds that package to the exact request.
The supplied `approve.py` is a trusted offline signing interface for this boundary;
it does not perform authority enrollment or hardware measurement on behalf of the
reviewer. A future trusted approval service can emit exactly the same envelope.

The package must contain **only public configuration**, never `server.json`, an
SQLite database, TLS private keys or storage credentials. Package fields are
allowlisted; this is not a general file uploader. The signer remains responsible
for the approved policy and measured-image semantics. Basic shape/hash checks by
the controller do not establish the hardware measurements themselves.

The existing guest and authority remain the security enforcement boundary. This
controller's status and ConfigMap transport are not substitutes for their checks.
Changing the cluster ID, workload UID, declaration UID, claim/source identity or
predictor template requires a new signed deployment approval.

The controller closes the offline **discovery, compilation, signature verification,
publication and status** gap. It does not yet build guests, enroll authority records,
change Trustee policy or automatically roll KServe. Those actions have independent
approval and lifecycle requirements. Helm/GitOps consumes the reviewed published
package explicitly. The current workload-specific guest configuration still needs
packaging in its measured image; generic authenticated configuration delivery is
separate work. No unapproved workload is made runnable by this controller.

## Build and deploy

The chart is `charts/coco-supported/confidential-volumes`, version 0.2.0. Controller
and OpenShift image build are opt-in. Schema-only installation remains possible.
Helm does not upgrade files under `crds/` during an ordinary release upgrade; apply
the reviewed CRD update explicitly when adding the status subresource.

From the repository root, with credentials supplied privately:

```sh
python3 components/confidential-volume-controller/prepare-build.py \
  --wheels /private/path/locked-wheels --output /tmp/cv-controller-build.tar.gz
helm template confidential-volumes charts/coco-supported/confidential-volumes \
  -n confidential-storage-test --include-crds \
  --set openshift.buildEnabled=true > /tmp/cv-controller-build.yaml
oc apply -n confidential-storage-test --dry-run=server -f /tmp/cv-controller-build.yaml
oc apply -n confidential-storage-test -f /tmp/cv-controller-build.yaml
oc start-build confidential-volume-controller -n confidential-storage-test \
  --from-archive=/tmp/cv-controller-build.tar.gz --wait --follow
```

The build archive includes only allowlisted source and SHA-256-locked wheels. The
Containerfile reuses the pinned internal Python base of the authority build; other
clusters must review and supply their equivalent base. Unit tests run in the image
build before it succeeds. Take the resulting image **digest**, then render with:

```yaml
controller:
  enabled: true
  image: image-registry.openshift-image-registry.svc:5000/confidential-storage-test/confidential-volume-controller@sha256:<built-image-digest>
  clusterId: edge-rtx6k
  approvalKeys:
    storage-release-v1: <64-hex-character-Ed25519-public-key>
```

These are placeholders. Apply the rendered resources in the same namespace.
The Deployment uses a namespace-assigned non-root UID, read-only root, no added
capabilities, no host mounts and a projected service-account token. RBAC permits
only input reads, declaration status updates and ConfigMap creation/reads. It has
no PVC writes, Secret reads, workload writes, exec, cluster-wide privileges or
approval-signer access. Only one controller deployment should own a namespace;
Recreate avoids overlap on upgrades, and deterministic create/status operations
also tolerate races.

Create ConfidentialVolume declarations with actual PVC UIDs and use the documented
binding annotation on the desired InferenceService. Inspect progress:

```sh
oc get confidentialvolumes -n confidential-storage-test
oc get confidentialvolume qwen-gpu-model -n confidential-storage-test -o json
```

Each `status.consumers[]` entry exposes `requestConfigMap`, `requestSha256`, current
phase/reason and, after verification, `artifactConfigMap` / `approvalSha256` /
`expiresAt`. Conditions report `Resolved`, `Approved`, `ConfigurationPublished`.
Multiple consumers are reported separately; this does not grant concurrent access
to exclusive RWOP volumes. Ownership is still enforced by the storage authority.

## Publish a reviewed approval

Export the referenced request ConfigMap. In a trusted preparation environment,
place these files together:

- `guest-config.json`: public v2 service configuration, matching all bindings.
- `initdata.toml`: reviewed policy, contract and AA/CDH configuration.
- `runtime.json`: `runtimeClassName`, `guestImageSha256`, `launchMeasurement`
  (96 hex characters for this SNP profile), and `initDataSha256`.

Then sign with a separately held mode-0600 Ed25519 PEM key:

```sh
python3 components/confidential-volume-controller/approve.py \
  --request /private/path/request-configmap.json \
  --artifacts /private/path/public-package \
  --key /private/path/deployment-approval.pem \
  --key-id storage-release-v1 --lifetime 86400 \
  --output /private/path/public-approval-configmap.json
oc apply -n confidential-storage-test -f /private/path/public-approval-configmap.json
```

Only the public ConfigMap is sent to the cluster. An authorized issuer can renew
that input ConfigMap with a new signed expiry; the controller publishes a new
immutable artifact and updates status. Removing a verification key requires a
controller rollout (the chart hashes the keyring into its pod template). Production
approval issuance/renewal and revocation policy must be owned by the trusted
approval service, not an untrusted reconciler.

## Tests

```sh
python3 -m unittest discover -s components/confidential-volume-contract
python3 -m unittest discover -s components/confidential-volume-controller
helm lint charts/coco-supported/confidential-volumes
```

Tests exercise tampering/unknown signers, expiry and identity replay, replaced or
unbound claims, model-source changes, conflicting immutable artifacts, lost API
updates, restarts, malformed input, exact package bindings and status withdrawal.
