# Trusted Vault enrollment prerequisite

The installed volume controller and populator have no Vault credential. Key
provisioning runs in a separately trusted publisher/enrollment environment. The
current lab's existing Trustee ExternalSecret extracts `secret/data/hub/modelKeys`;
its owner is the base CoCo `trustee` Argo Application. The add-on must not become
a second owner of that Secret, ExternalSecret, resource policy or KbsConfig.

Before enrolling a live release, configure a short-lived Vault identity. The
approved one-time bootstrap was completed on the edge cluster on 2026-10-15.
Other installations must perform their own administrator bootstrap. The installed
policy is:

```hcl
# Allows JSON merge patch of the existing key record; no data read or deletion.
path "secret/data/hub/modelKeys" {
  capabilities = ["patch"]
}
# Read the version for compare-and-set; metadata contains no key values.
path "secret/metadata/hub/modelKeys" {
  capabilities = ["read"]
}
```

Vault ACLs apply to the whole KV document, not individual JSON properties. This
identity can therefore patch other entries in that shared record. It must remain
in the trusted administration domain. A dedicated per-installation Vault path
and corresponding owner-managed Trustee/ESO resource mapping is preferable for
separated deployments; that owner integration is still pending. Do not grant this
identity to the workload controller, importer, chat application or vLLM.

For a new installation, using an already authenticated Vault administrator, create
the policy and bind it to a dedicated ServiceAccount in the trusted namespace.
Substitute the existing auth mount and actual trusted namespace; the lab's mount
is `hub`:

```sh
vault policy write confidential-inference-enroller enrollment-policy.hcl
vault write auth/hub/role/confidential-inference-enroller \
  bound_service_account_names=confidential-inference-enroller \
  bound_service_account_namespaces=TRUSTED_NAMESPACE \
  audience=vault \
  token_policies=confidential-inference-enroller \
  token_no_default_policy=true token_ttl=900 token_max_ttl=3600
```

The trusted runner authenticates with a short-lived projected ServiceAccount JWT
for audience `vault`; no static Vault token belongs in Git or workload manifests.
Administrator credentials are needed only for the bootstrap above. The add-on
installer does not discover/read the base pattern's bootstrap root token.

Order matters: first prepare and verify the exact CPU/GPU and launch/InitData
bindings through the existing Trustee owner; only then provision keys. Unknown
`model-keys` tags in the current lab policy require CPU/GPU attestation but do not
have a per-workload InitData binding until that binding is installed. Publishing a
new key before its specific binding would expose it to other accepted guests.
Preserve all existing bindings and prove existing inference remains healthy.

A production writer must use versioned CAS, refuse conflicting existing tags,
recover uncertain writes without generating a replacement key, and keep key bytes
in the trusted producer/backend only. The patch-only bootstrap is not
that complete writer. Live key enrollment, owner integration and these failure
checks remain pending; do not treat an authority metadata enrollment as key
provisioning.

## Verified edge bootstrap

The policy and role are both named `confidential-inference-enroller`, under the
existing `hub` Kubernetes auth mount. The role is bound only to ServiceAccount
`confidential-inference-enroller` in the new `confidential-inference-enrollment`
namespace. That namespace enforces the restricted Pod Security profile. The
ServiceAccount disables automatic token mounting; no Kubernetes RoleBinding or
ClusterRoleBinding was added for it. A trusted runner must explicitly request a
short-lived token with audience `vault`.

Verification exercised a real Kubernetes TokenRequest and Vault login. The issued
Vault token had only this policy, a 900-second initial TTL, and no default policy;
the role limits token lifetime to 3,600 seconds. Capability checks confirmed
`patch` on the shared key record, `read` on its version metadata, and denial for an
unrelated secret, policy administration and role administration. The scoped token
successfully read version metadata and was then revoked by the bootstrap session.
No Vault token or administrator credential was saved in this repository.

The model-key record remained at version 3 throughout. No model/storage key
material was read or written. The original five protected Qwen, chat and authority
pods retained their identities and Ready status. The public
[bootstrap receipt](../../tests/evidence/2026-10-15/vault-bootstrap.json) records
these checks. This completes authentication setup only: safe key publication,
Trustee binding integration and fresh inference remain pending.

References: [Vault KV v2 API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2)
and [Kubernetes authentication API](https://developer.hashicorp.com/vault/api-docs/auth/kubernetes).
