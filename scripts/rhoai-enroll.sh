#!/usr/bin/env bash
# Trusted administrator setup. Private material stays in STATE_DIR and Vault.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
STATE_DIR=${STATE_DIR:-$ROOT/.private/rhoai}
DEMO_NAMESPACE=${DEMO_NAMESPACE:-rhoai-confidential-qwen}
: "${REGISTRY_AUTH_FILE:?Supply a private registry auth JSON file with Red Hat access}"
export ROOT STATE_DIR DEMO_NAMESPACE REGISTRY_AUTH_FILE
umask 077
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
trap 'rm -f "$STATE_DIR/vault-bootstrap.json" "$STATE_DIR/vault-token" "$STATE_DIR/registry-token-secret.json" "$STATE_DIR/vault-existing.json"' EXIT
host=${CHAT_HOST:-qwen-chat-$DEMO_NAMESPACE.$(oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}')}
export CHAT_HOST=$host
if [ ! -f "$STATE_DIR/model-key.bin" ]; then
  python3 - <<'PY'
import os,pathlib,base64,json
p=pathlib.Path(os.environ['STATE_DIR']);k=os.urandom(32)
(p/'model-key.bin').write_bytes(k)
(p/'model-key.json').write_text(json.dumps({'kty':'oct','k':base64.urlsafe_b64encode(k).decode().rstrip('=')}))
(p/'luks-passphrase').write_text(os.urandom(32).hex())
PY
fi
test -s "$STATE_DIR/model-key.json"
test -s "$STATE_DIR/luks-passphrase"
python3 - <<'PY'
import os,pathlib,base64,json,re
p=pathlib.Path(os.environ['STATE_DIR']);j=json.loads((p/'model-key.json').read_text())
assert j['kty']=='oct'
assert base64.urlsafe_b64decode(j['k']+'='*((-len(j['k']))%4)) == (p/'model-key.bin').read_bytes()
assert len((p/'model-key.bin').read_bytes())==32
assert re.fullmatch('[0-9a-f]{64}',(p/'luks-passphrase').read_text())
PY
if [ ! -f "$STATE_DIR/chat-ca.key" ]; then
  openssl req -x509 -newkey rsa:3072 -nodes -days 365 -subj '/CN=Confidential Qwen Demo CA' \
    -keyout "$STATE_DIR/chat-ca.key" -out "$STATE_DIR/chat-ca.crt" 2>"$STATE_DIR/cert-generation.log"
fi
if [ ! -f "$STATE_DIR/chat.key" ]; then
  openssl req -new -newkey rsa:2048 -nodes -subj '/CN=Confidential Qwen Demo' \
    -keyout "$STATE_DIR/chat.key" -out "$STATE_DIR/chat.csr" 2>>"$STATE_DIR/cert-generation.log"
  printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n' "$host" > "$STATE_DIR/chat.ext"
  openssl x509 -req -in "$STATE_DIR/chat.csr" -CA "$STATE_DIR/chat-ca.crt" -CAkey "$STATE_DIR/chat-ca.key" \
    -CAcreateserial -days 90 -extfile "$STATE_DIR/chat.ext" -out "$STATE_DIR/chat.crt" 2>>"$STATE_DIR/cert-generation.log"
fi
openssl verify -CAfile "$STATE_DIR/chat-ca.crt" "$STATE_DIR/chat.crt"
python3 - <<'PY'
import os,ssl,pathlib
cert=ssl._ssl._test_decode_cert(str(pathlib.Path(os.environ['STATE_DIR'])/'chat.crt'))
assert ('DNS',os.environ['CHAT_HOST']) in cert['subjectAltName'], 'Certificate hostname differs; rotate explicitly'
PY
oc create namespace "$DEMO_NAMESPACE" --dry-run=client -o yaml | oc apply -f -
oc create serviceaccount guest-image-puller -n "$DEMO_NAMESPACE" --dry-run=client -o yaml | oc apply -f -
# A revocable namespace-scoped pull token avoids an undocumented 48-hour expiry.
# It is never mounted into the workload or permitted to read model/KBS Secrets.
cat <<EOF | oc apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: guest-image-puller-token
  namespace: $DEMO_NAMESPACE
  annotations:
    kubernetes.io/service-account.name: guest-image-puller
type: kubernetes.io/service-account-token
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: guest-image-puller
  namespace: $DEMO_NAMESPACE
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:image-puller
subjects:
  - kind: ServiceAccount
    name: guest-image-puller
    namespace: $DEMO_NAMESPACE
EOF
for ((i=0; i<60; i++)); do
  oc get secret guest-image-puller-token -n "$DEMO_NAMESPACE" -o json > "$STATE_DIR/registry-token-secret.json"
  python3 -c 'import json,os,pathlib; assert json.loads((pathlib.Path(os.environ["STATE_DIR"])/"registry-token-secret.json").read_text()).get("data",{}).get("token")' 2>/dev/null && break
  sleep 2
done
python3 - <<'PY'
import base64,json,os,pathlib
p=pathlib.Path(os.environ['STATE_DIR']);source=json.loads(pathlib.Path(os.environ['REGISTRY_AUTH_FILE']).read_text())
auths={k:v for k,v in source['auths'].items() if k in ['registry.redhat.io','registry.connect.redhat.com']}
assert 'registry.redhat.io' in auths,'Red Hat registry access is required'
token=base64.b64decode(json.loads((p/'registry-token-secret.json').read_text())['data']['token']).decode()
auths['image-registry.openshift-image-registry.svc:5000']={'auth':base64.b64encode(('serviceaccount:'+token).encode()).decode()}
(p/'guest-registry.json').write_text(json.dumps({'auths':auths}))
data={k:base64.b64encode((p/v).read_bytes()).decode() for k,v in {'model-key':'model-key.bin','luks-passphrase':'luks-passphrase','tls-cert':'chat.crt','tls-key':'chat.key','registry':'guest-registry.json'}.items()}
(p/'vault-model-data.json').write_text(json.dumps(data))
PY
# The normal CoCo framework places its Vault bootstrap handoff here. An external
# administrator token can be supplied instead; neither token is echoed or saved.
if [ -n "${VAULT_ADMIN_TOKEN_FILE:-}" ]; then
  token_file=$VAULT_ADMIN_TOKEN_FILE
else
  oc get secret vaultkeys -n imperative -o json > "$STATE_DIR/vault-bootstrap.json"
  python3 - <<'PY'
import base64,json,os,pathlib
p=pathlib.Path(os.environ['STATE_DIR']);s=json.loads((p/'vault-bootstrap.json').read_text())
data=json.loads(base64.b64decode(s['data']['vault_data_json']))
(p/'vault-token').write_text(data['root_token'])
PY
  token_file=$STATE_DIR/vault-token
fi
# A new or incorrect state directory must not silently rotate persisted keys.
if { cat "$token_file"; printf '\n'; } | oc exec -i -n vault vault-0 -- sh -c 'set -eu; read -r VAULT_TOKEN; export VAULT_TOKEN; exec vault kv get -format=json secret/hub/rhoaiQwen' >"$STATE_DIR/vault-existing.json" 2>"$STATE_DIR/vault-read.log"; then
  python3 - <<'PY'
import os,pathlib,json
p=pathlib.Path(os.environ['STATE_DIR']);old=json.loads((p/'vault-existing.json').read_text())['data']['data'];new=json.loads((p/'vault-model-data.json').read_text())
assert all(old[k]==new[k] for k in ['model-key','luks-passphrase']), 'Existing Vault encryption keys differ: refusing implicit rotation'
PY
elif ! python3 -c 'import os,pathlib; assert "No value found" in (pathlib.Path(os.environ["STATE_DIR"])/"vault-read.log").read_text()'; then
  echo 'Could not verify existing Vault keys; no write performed.' >&2
  exit 1
fi
{
  cat "$token_file"; printf '\n'; cat "$STATE_DIR/vault-model-data.json"
} | oc exec -i -n vault vault-0 -- sh -c 'set -eu; read -r VAULT_TOKEN; export VAULT_TOKEN; exec vault kv put secret/hub/rhoaiQwen -' >/dev/null
rm -f "$STATE_DIR/vault-bootstrap.json" "$STATE_DIR/vault-token" "$STATE_DIR/registry-token-secret.json" "$STATE_DIR/vault-existing.json"
chmod 600 "$STATE_DIR"/*
echo 'Demo keys enrolled in Vault at secret/hub/rhoaiQwen. Configure the CoCo-owned ExternalSecret with Base64 decoding.'
