# Qwen demo: installation sequence

**Outcome:** chat → KServe → stock vLLM on a confidential GPU; verified encrypted
RO `/model` and persistent encrypted RW `/data`. Start with the [inputs](../inputs.md)
and [qualified stack](../architecture.md#qualified-hardware-and-software).

## One-time setup

1. Install/configure CoCo VP's stock CPU/GPU runtime and standard Trustee. Provide
   KServe, GitOps, internal registry and an Immediate raw Block/RWOP CSI class.
2. Build/publish pinned controller, populator, sidecar and authority images. Copy
   [the input template](../../overrides/sites/demo-inputs.example.yaml) to a site override; edge registry URLs cannot be used on an unrelated cluster.
3. Set private `KUBECONFIG`; install Python 3.12+, Helm 3, `oc` and dependencies:

   ```sh
   python3 -m venv .venv
   . .venv/bin/activate
   python -m pip install -r requirements.txt
   ./pattern.sh make demo-preflight VALUES=overrides/sites/my-site.yaml
   ./pattern.sh make render VALUES=overrides/sites/my-site.yaml
   ./pattern.sh make install-addon VALUES=overrides/sites/my-site.yaml
   ```

4. Bootstrap the trusted enrollment identity ([Vault mapping](vault-bootstrap.md)),
   authority TLS/signing credentials and retained authority state. Bootstrap state
   **once**; normal serving verifies it. Supply the approval public key to the controller.
5. Optionally configure repository-scoped GitOps access, then `make enable-gitops
   VALUES=...` with a full commit pin. Its restricted project owns add-on resources;
   existing CoCo services and Trustee policies retain their original owner.

The installer checks namespace/resource ownership, reuses compatible shared CRDs,
installs admission before SCC access and waits for controllers. It does not enroll
keys, calculate SNP launch measurements, create a model release or prove hardware
attestation. The populator registration CRD is installed if absent; shared operators
are not duplicated.

## Each fresh demo release

| Order | Action | Result |
| --- | --- | --- |
| 1 | Trusted publisher fetches pinned Qwen, generates fresh model/data keys, encrypts and publishes | Ciphertext OCI digest + verified public descriptor |
| 2 | Set `demo.source`; run `make demo-provision VALUES=...` | RO model PVC, blank RW PVC, bound ConfidentialVolumes, workload request |
| 3 | Instantiate reviewed profile; render policy and enroll metadata | RO identity and explicitly approved first-use RW plan |
| 4 | Package InitData; install exact Trustee bindings through its owner; enroll keys | CPU/GPU + launch/InitData-gated resources, verified in running KBS |
| 5 | Start authority serving; sign/apply public deployment package | Controller automatically creates KServe + sidecar |
| 6 | Enable `chat.enabled`; run `make demo-chat VALUES=...`; execute acceptance | Chat response, CUDA, exec denial and fresh-VM persistence receipt |

Commands and checks: [release preparation](fresh-release.md),
[release tool reference](../../components/inference-release/README.md),
[acceptance](acceptance.md). Trusted steps are currently operator-orchestrated.
`make demo-status VALUES=...` reports resources; it is not E2E proof.

## Retention and access

Use a new identity/keys/claims for a **fresh** run. Reopen existing volumes with
unchanged keys, PVC identities and retained authority history. Initialization
permission is not inferred from a PVC name or label. Never reset ownership or
reformat to bypass a failed restart. Model sources/PVCs have GitOps deletion
protection; no automatic uninstall/destroy workflow exists.

Chat defaults to ClusterIP:

```sh
oc -n <namespace> port-forward service/<demo>-chat 8765:8080
```

Open `http://127.0.0.1:8765/`; a site can explicitly choose a private-network
NodePort. Frontend readiness does not prove backend inference or confidentiality.
