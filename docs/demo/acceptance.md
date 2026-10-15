# Repeatable encrypted Qwen acceptance test

Start from [fresh release preparation](fresh-release.md). Use a new demo identity,
model publication, model/data keys, model PVC and **blank** data PVC. Retain the
same authority history and scoped platform configuration for subsequent runs.
Do not reuse old signed deployment approvals or copy an old initialization journal.

The measured demo command checks every producer file hash, the read-only model
mount, writable data, absence of private devices/sockets, UID/GID 1001, zero
capabilities, NoNewPrivs, and CUDA integer addition before starting stock vLLM.
Its first run fsyncs a canary to `/data`; its next run requires a different VM
boot ID and the original canary. A container restart in the same VM does not pass.

## First VM

Select your kubeconfig and set the public inputs for your release:

```sh
export KUBECONFIG=/private/path/cluster.kubeconfig
NS=confidential-inference-demo
DEMO=qwen-demo-001
MODEL=qwen3-0.6b
CHAT=http://127.0.0.1:8765
INITDATA=$(python3 -c 'import json; print(json.load(open("release/runtime.json"))["initDataSha256"])')
VLLM='nvcr.io/nvidia/vllm@sha256:15f380ad9c32f0ac57ac16e4b778c6f733c88b9ffe3a936035d0a59ad17b1aab'
```

Enable the chat chart with `make demo-chat VALUES=...`. With default ClusterIP
exposure, run `oc -n "$NS" port-forward service/"$DEMO-chat" 8765:8080` in another
terminal. A private-network NodePort is an explicit site option. This frontend is
HTTP and runs outside the confidential VM; it does not establish protected prompt
transport or remote client attestation. HTTPS terminating inside the guest is a
separate integration task.

After KServe reports Ready:

```sh
python3 scripts/verify-demo.py --namespace "$NS" --workload "$DEMO" \
  --chat-url "$CHAT" --model "$MODEL" --expected-initdata "$INITDATA" \
  --expected-application-image "$VLLM" --phase first --output first.json
```

This sends a synthetic chat prompt and attempts `/bin/true` via `oc exec`; success
requires the exact measured `ExecProcessRequest` denial, not a network/RBAC error.
It does not read keys, edit workloads or replace pods.

Separately retain the authority's public journal and fixed appraisal markers:

- CPU **and** GPU EAR results are affirming for the same workload InitData.
- The data record has exactly four Complete steps: `luks-format`,
  `integrity-initialize`, `filesystem-create`, `durability-barrier`.
- Both model and data records are Ready; their owners belong to the current
  attested guest session. Record activation/step IDs and header/manifest hashes.
- OCI publication and population receipts refer to the exact ciphertext digest
  declared by the model PVC. No producer key or plaintext is in the importer.

Use the trusted authority administration environment to inspect its retained
metadata. Do not dump its credentials or full Trustee debug logs. Merely seeing a
KServe Ready condition or a successful chat is insufficient to prove these gates.

## Fresh VM and retained data

Keep the first receipt. Delete **only its predictor pod**, gracefully:

```sh
POD=$(python3 -c 'import json; print(json.load(open("first.json"))["pod"])')
oc -n "$NS" delete pod "$POD" --wait=false
```

Observe `SIDECAR_CONSUMER_MOUNTS_REMOVED` and `SIDECAR_STORAGE_CLOSED` in the old
helper log. KServe creates a replacement. Do not delete PVCs, force-release an
owner, reset the authority, or approve another format if close is uncertain.

When the replacement is Ready:

```sh
python3 scripts/verify-demo.py --namespace "$NS" --workload "$DEMO" \
  --chat-url "$CHAT" --model "$MODEL" --expected-initdata "$INITDATA" \
  --expected-application-image "$VLLM" --phase reopen \
  --previous first.json --output reopened.json
```

The verifier requires different pod and guest boot IDs, unchanged PVC UIDs and
InitData, the original canary, model hashes, CUDA, a real chat response and the
same exec denial. Compare authority journals: initialization step IDs/results and
header/manifest hashes must remain identical; reopen operations may increase,
format operations may not. Both tests must pass before labeling the run qualified.

## Workflow

```mermaid
sequenceDiagram
    participant Owner as Trusted release owner
    participant OCI as Internal OCI registry
    participant Pop as Volume populator / CSI
    participant Ctrl as ConfidentialVolume controller
    participant VM as Stock Kata VM + storage sidecar
    participant KBS as Standard Trustee
    participant Auth as Storage authority
    participant App as Unprivileged stock vLLM
    Owner->>OCI: Publish encrypted LUKS + verity model disk
    Owner->>Pop: Model PVC(dataSourceRef) + blank data PVC
    Pop->>Pop: Import and verify ciphertext; bind PVCs
    Owner->>Ctrl: ConfidentialVolumes + ConfidentialWorkload
    Ctrl-->>Owner: Request bound to actual PVC UIDs
    Owner->>Auth: Register model and approve first-use data plan
    Owner->>KBS: Enroll keys + exact CPU/GPU/InitData bindings
    Owner->>Ctrl: Signed measured deployment package
    Ctrl->>VM: KServe predictor, raw disks only to sidecar
    VM->>Auth: Fresh attestation; ownership / format-step requests
    VM->>KBS: CPU+GPU attested key retrieval via private CDH
    VM->>VM: Verify/open RO model; initialize or reopen RW data
    VM->>App: Transfer mounts into application namespace
    App->>App: Verify files, persistence and CUDA; start Qwen
    Note over App: Chat frontend → KServe → Qwen on GPU
    VM->>Auth: Close ownership on graceful shutdown
```
