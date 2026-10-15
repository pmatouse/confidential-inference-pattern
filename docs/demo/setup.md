# Current add-on setup

This is the executable subset of the design. The initial isolated installation
uses existing, digest-pinned lab helper/populator images. A portable clean-cluster
release still needs reproducible image publication and trusted release automation.

## One-time platform prerequisites

Install CoCo VP, configure the confidential CPU/GPU runtime, and provide KServe,
Trustee and a raw Block CSI class. The installer creates the pinned upstream
volume-populator registration CRD if absent, or verifies an existing one. Existing
platform resources remain under their current owners. The installer checks the
stock GPU RuntimeClass handler, Immediate storage, available KServe version and
Trustee resource. Those checks do not prove attestation or hardware correctness.

Use Python 3.12+, Helm 3 and `oc`, with access to the target cluster. Install the
pinned Python dependencies from `requirements.txt`. Put private credentials outside
this repository and select your kubeconfig through the environment.

Copy `values-global.yaml` to a site override and set cluster identity, target
namespace, runtime/CSI names, Trustee resource identity, registry origin and exact
image digests. Empty generic inputs intentionally fail preflight. The edge values
are an example, not portable defaults.

```sh
./pattern.sh make demo-preflight VALUES=overrides/sites/my-site.yaml
./pattern.sh make render VALUES=overrides/sites/my-site.yaml
./pattern.sh make install-addon VALUES=overrides/sites/my-site.yaml
```

`install-addon` creates a separate owned namespace; compatible existing shared
CRDs are inspected but not rewritten. It checks all object ownership before
applying anything. Admission is installed and type-checked before granting helper
SCC access. Controller readiness is checked before success. Repeating the command
reconciles the same resources without modifying keys, disks or running Qwen.

For images in another OpenShift project, the installer grants only named image
stream pulls to the four add-on service accounts. These bootstrap RBAC objects
remain outside the workload GitOps project. External registry authentication and
vendor guest pull qualification are separate platform prerequisites.

## GitOps ownership

The same charts can be reconciled by the existing GitOps instance after the
bootstrap admission check. Configure a repository-scoped read-only credential
in that instance for this private repository. Pin `gitops.revision` to a reviewed
40-character commit, set `gitops.enabled: true`, then:

```sh
./pattern.sh make render-gitops VALUES=overrides/sites/my-site.yaml
./pattern.sh make enable-gitops VALUES=overrides/sites/my-site.yaml
```

The add-on creates its own restricted AppProject and root Application, with
pruning disabled. It manages the add-on controllers and security resources only.
It does not permit Secret, KataConfig, KbsConfig, Subscription or InferenceService
resources in that project. Existing shared CRDs are omitted from Helm sync;
upgrades need the current CRD owner's coordinated migration. Namespace bootstrap,
registry pull grants and binary-build resources remain explicit installer actions.

## Declare a model and writable volume

Set `demo.source` from a verified publisher receipt: `format`, `repository`,
`manifestDigest`, `diskDigest`, `diskBytes`. Supply key **resource identifiers** and
an approved manifest identifier; these values contain no decryption key.

```sh
./pattern.sh make demo-provision VALUES=overrides/sites/my-site.yaml
./pattern.sh make demo-status VALUES=overrides/sites/my-site.yaml
```

This creates the immutable EncryptedModelSource, model Block PVC with
`dataSourceRef`, a blank data Block PVC, a ConfidentialWorkload intent and a
restricted binding Job. The Job waits for Bound claims, verifies their source,
class, capacity and mode, then creates immutable ConfidentialVolumes containing
actual PVC UIDs. It has no Secret, signer, authority, disk, pod-exec or pod-update
access. Retry compares existing declarations; it never overwrites an identity.

The model uses `ReadOnly/luks-verity-v1/Never`; data uses
`ReadWrite/luks-integrity-v1/OnceIfApproved`. This is intent, not permission to
format. The controller publishes a request and waits for a separately signed
configuration. It does not deploy an arbitrary unapproved predictor.

`bind-volumes` is the equivalent operator-side troubleshooting command. A failed
binding Job is retained for diagnosis. Changed immutable inputs require a new run
identity, not deletion of retained claims.

## Trusted preparation still required

The [release renderer and metadata enrollment commands](../../components/inference-release/README.md)
are implemented and contract tested. Qualified runtime profiles, scoped key
enrollment, Trustee-owner integration and approval renewal are not wired into one
command yet. The [Vault bootstrap guide](vault-bootstrap.md) describes the
trusted-authentication prerequisite, now verified on the edge cluster; new sites
must configure their own scoped identity. The legacy `prepare-qwen.py` is retained
as source provenance and is not a clean-install interface. Do not copy the old lab's prepared state to make
this stage pass.

`components/confidential-storage-authority/bootstrap.py` creates a new authority
history directory exactly once in a trusted environment. Normal server restart
must verify retained state and must not rerun fresh initialization. Missing history,
partial bootstrap, symlinks or changed installation identity fail closed. The
[authority chart](../../charts/storage-authority/README.md) now separates explicit
bootstrap from normal retained-state verification. It consumes existing Secret
references; scoped backend provisioning and release enrollment remain separate.

## Chat

After a fully approved KServe backend is running, enable `chat.enabled` and run
`make demo-chat VALUES=...`. The chart deploys a non-root frontend without a service
account token and connects directly to the named KServe predictor. It has no
Kubernetes API fallback. The default is ClusterIP:

```sh
oc -n <namespace> port-forward service/<demo-name>-chat 8765:8080
```

Open `http://127.0.0.1:8765`. A site may explicitly configure a VPN NodePort.
Chat readiness only means its HTTP server is running; full E2E must verify the
actual backend pod, confidential GPU appraisal, encrypted mounts and persistence.

## Retention

No uninstall/destroy command is provided yet. Do not delete a populated namespace
as a routine retry. Claims and source declarations carry explicit Argo prune/delete
protection, independent of workload ownership. Preserve authority history and key
backend records together with retained ciphertext. Never reset authority ownership
to resolve an ordinary deployment error.

## Registry namespace contract

The current populator deliberately accepts only model repositories inside its own
workload namespace. Publish there or promote an already verified ciphertext image
by digest using an OpenShift ImageStreamTag before creating a new model source.
Cross-namespace registry sources now fail before any claim is created. Promotion
changes only the registry reference; verify the manifest digest is unchanged.
Reusing a published artifact is a population regression, not a fresh-publication
acceptance run.

The registration CRD is vendored from [the upstream validator project](https://github.com/kubernetes-csi/volume-data-source-validator),
with the exact source revision and file hash in `prerequisites/source-lock.json`.
The optional warning-event validator controller is not duplicated.
