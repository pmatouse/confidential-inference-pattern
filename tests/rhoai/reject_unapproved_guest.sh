#!/usr/bin/env bash
# Hardware negative test. Requires a second free passthrough GPU. No PVC is used.
set -euo pipefail
DEMO_NAMESPACE=${DEMO_NAMESPACE:-rhoai-confidential-qwen}
STATE_DIR=${STATE_DIR:?Supply the private qualification state directory}
export DEMO_NAMESPACE STATE_DIR
name=qwen-kserve-unapproved-guest
oc get pod "$name" -n "$DEMO_NAMESPACE" --ignore-not-found -o name | python3 -c 'import sys; assert not sys.stdin.read(), "Negative-test pod already exists"'
oc get pods -n "$DEMO_NAMESPACE" -l app.kubernetes.io/name=qwen-confidential -o json > "$STATE_DIR/negative-source.json"
python3 - <<'PY'
import os,pathlib,json,base64,gzip,copy,hashlib
p=pathlib.Path(os.environ['STATE_DIR']);pods=json.loads((p/'negative-source.json').read_text())['items']
live=[x for x in pods if x['status']['phase']=='Running' and not x['metadata'].get('deletionTimestamp')];assert len(live)==1
x=live[0];spec=copy.deepcopy(x['spec']);spec.pop('initContainers',None);spec['containers']=[c for c in spec['containers'] if c['name']=='main'];spec['restartPolicy']='Never'
for key in ['nodeName','hostname','subdomain']:spec.pop(key,None)
spec['volumes']=[v for v in spec['volumes'] if 'persistentVolumeClaim' not in v]
ann={k:v for k,v in x['metadata']['annotations'].items() if k.startswith('io.katacontainers.')}
key='io.katacontainers.config.hypervisor.cc_init_data';raw=gzip.decompress(base64.b64decode(ann[key]))
changed=raw+b'\n# unapproved identity: qualification negative test\n'
ann[key]=base64.b64encode(gzip.compress(changed,mtime=0)).decode()
pod={'apiVersion':'v1','kind':'Pod','metadata':{'name':'qwen-kserve-unapproved-guest','namespace':os.environ['DEMO_NAMESPACE'],'labels':{'coco.io/skip-initdata':'true'},'annotations':ann},'spec':spec}
(p/'negative-guest.json').write_text(json.dumps(pod))
(p/'negative-identities.json').write_text(json.dumps({'approved':hashlib.sha256(raw).hexdigest(),'unapproved':hashlib.sha256(changed).hexdigest()},indent=2))
PY
trap 'oc delete pod "$name" -n "$DEMO_NAMESPACE" --ignore-not-found --wait=false >/dev/null' EXIT
oc create -f "$STATE_DIR/negative-guest.json"
for ((i=0; i<120; i++)); do
  oc get pod "$name" -n "$DEMO_NAMESPACE" -o json > "$STATE_DIR/negative-status.json"
  if python3 - <<'PY'
import json,pathlib,os,re
p=pathlib.Path(os.environ['STATE_DIR']);x=json.loads((p/'negative-status.json').read_text())
for c in x['status'].get('containerStatuses',[]):
 if 'running' in c['state']:
  print('FAIL: unapproved guest unexpectedly started');raise SystemExit(2)
 message=c['state'].get('waiting',{}).get('message','')
 if re.search(r'kbs|attest|resource',message,re.I) and re.search(r'denied|forbidden|unauthorized|untrusted|401|403',message,re.I):
  (p/'negative-result.json').write_text(json.dumps({'result':'UNAPPROVED_GUEST_KEY_RELEASE_DENIED','podUID':x['metadata']['uid'],'reason':c['state']['waiting']['reason'],'identity':json.loads((p/'negative-identities.json').read_text())},indent=2));print('UNAPPROVED_GUEST_KEY_RELEASE_DENIED');raise SystemExit(0)
raise SystemExit(1)
PY
  then exit 0;else result=$?; [ "$result" -ne 2 ] || exit 2;fi
  sleep 5
done
echo 'No conclusive attestation/key-release denial observed; inspect the test status.' >&2
exit 1
