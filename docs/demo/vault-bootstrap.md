# Trusted Vault enrollment bootstrap

The workload controller, populator, sidecar and chat receive **no Vault provisioning
identity**. Run enrollment in a trusted namespace/administration environment.
The current adapter uses the existing CoCo Trustee owner's ESO mapping from
`secret/data/hub/modelKeys`; it does not own or replace that mapping.

## One-time administrator action

Create this policy and bind a short-lived role to the dedicated enrollment
ServiceAccount. Substitute the existing Kubernetes auth mount and trusted namespace.

```hcl
path "secret/data/hub/modelKeys" {
  capabilities = ["patch"]
}
path "secret/metadata/hub/modelKeys" {
  capabilities = ["read"]
}
```

```sh
vault policy write confidential-inference-enroller enrollment-policy.hcl
vault write auth/hub/role/confidential-inference-enroller \
  bound_service_account_names=confidential-inference-enroller \
  bound_service_account_namespaces=TRUSTED_NAMESPACE \
  audience=vault token_policies=confidential-inference-enroller \
  token_no_default_policy=true token_ttl=900 token_max_ttl=3600
```

The runner requests a projected ServiceAccount token with audience `vault` and
exchanges it for the scoped token. Keep administrator credentials outside the
repository; no bootstrap root token is discovered by the installer.

**Scope limit:** Vault ACLs protect a KV document, not individual JSON fields. This
role can patch other entries in the shared record. Keep it trusted; per-installation
backend paths and corresponding owner-managed ESO mappings remain an integration gap.

## Per-release enrollment

1. Install and verify exact CPU/GPU, launch-measurement and InitData bindings for
   the new resource tags **before writing their keys**. The current base policy's
   generic model-key rule is insufficient for per-workload isolation.
2. Run `key_enrollment.py` with private key files, explicit encodings, reviewed
   runtime/policy and a private journal. It authenticates with the scoped role,
   uses versioned CAS merge-patch, refuses existing tags, and verifies ESO output.
3. Verify the running KBS contains the new resources. The operator's init-only
   resource copy may require replacement of its pod; verify the new pod UID and
   filenames, never print key contents.

The [bootstrap receipt](../../tests/evidence/2026-10-15/vault-bootstrap.json)
records authentication-only checks. Subsequent key publication and inference
passed in the [fresh E2E run](../../tests/evidence/2026-10-15/fresh-qwen-e2e.json).
For exact tool inputs see [release tools](../../components/inference-release/README.md)
and [input contract](../inputs.md).
