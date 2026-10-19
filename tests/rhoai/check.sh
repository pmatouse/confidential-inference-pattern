#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HELM=${HELM:-helm}
OPA=${OPA:-opa}
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
for file in "$ROOT"/tests/rhoai/*.sh "$ROOT"/scripts/rhoai-*.sh "$ROOT"/charts/rhoai-confidential-qwen/files/*.sh "$ROOT"/charts/rhoai-model-publisher/files/publish.sh; do bash -n "$file"; done
"$HELM" lint "$ROOT/charts/rhoai-platform"
"$HELM" lint "$ROOT/charts/rhoai-model-publisher"
"$HELM" lint "$ROOT/charts/rhoai-confidential-qwen" --set guest.initdata=render-test --set images.initializer=example.invalid/initializer@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
sed 's/__PROFILE__/data.test_profile/' "$ROOT/policies/rhoai-guest.rego.in" > "$scratch/policy.rego"
"$OPA" check "$scratch/policy.rego"
"$OPA" test "$scratch/policy.rego" "$ROOT/tests/rhoai/guest_policy_test.rego" -v
"$OPA" test "$ROOT/integration/trustee/files/resource-policy.rego" "$ROOT/tests/rhoai/trustee_policy_test.rego" -v
export HELM
python3 - "$ROOT" <<'PY'
from pathlib import Path
import hashlib,json,sys,subprocess,os,yaml
r=Path(sys.argv[1]);p=json.loads((r/'build/storage-initializer/provenance.json').read_text())
assert hashlib.sha256((r/'build/storage-initializer/jwe_decryptor.py').read_bytes()).hexdigest()==p['sha256']
assert '--no-enable-log-requests' in (r/'charts/rhoai-confidential-qwen/files/vllm.sh').read_text()
objects=list(yaml.safe_load_all(subprocess.check_output([os.environ['HELM'],'template','qwen',str(r/'charts/rhoai-confidential-qwen'),'--set','guest.initdata=render-test','--set','images.initializer=example.invalid/initializer@sha256:'+'a'*64],text=True)))
for obj in objects:
 if obj and obj['kind']=='ConfigMap':
  for name,value in obj['data'].items():
   assert value.encode()==(r/'charts/rhoai-confidential-qwen/files'/name).read_bytes(),f'Measured file bytes changed during rendering: {name}'
print('Pinned upstream decryptor and exact measured ConfigMap bytes verified')
platform=list(yaml.safe_load_all(subprocess.check_output([os.environ['HELM'],'template','rhoai',str(r/'charts/rhoai-platform')],text=True)))
sub=next(o for o in platform if o['kind']=='Subscription')
jobs={o['metadata']['name']:o for o in platform if o['kind']=='Job'}
def wave(o): return int(o['metadata']['annotations']['argocd.argoproj.io/sync-wave'])
assert wave(sub)==wave(jobs['rhoai-dependency-operator']), 'Manual approval would deadlock across waves'
dsc=next(o for o in platform if o['kind']=='DataScienceCluster')
assert wave(sub)<wave(dsc)<wave(jobs['rhoai-dependency-serving'])
assert dsc['metadata']['annotations']['argocd.argoproj.io/sync-options']=='SkipDryRunOnMissingResource=true'
for job in jobs.values():
 assert job['spec']['template']['spec']['containers'][0]['args'][0].rstrip()==(r/'charts/rhoai-platform/files/bootstrap.py').read_text().rstrip()
print('RHOAI operator approval, API readiness and serving configuration are sequenced')
PY
