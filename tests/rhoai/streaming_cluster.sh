#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
STATE_DIR=${STATE_DIR:-$ROOT/.private/rhoai}
DEMO_NAMESPACE=${DEMO_NAMESPACE:-rhoai-confidential-qwen}
STORAGE_CLASS=${STORAGE_CLASS:-lvms-vg1}
export ROOT STATE_DIR DEMO_NAMESPACE STORAGE_CLASS
oc create configmap streaming-test -n "$DEMO_NAMESPACE" --from-file=verify.py="$ROOT/tests/rhoai/verify_streaming.py" --from-file=encrypt_model.py="$ROOT/charts/rhoai-model-publisher/files/encrypt_model.py" --dry-run=client -o yaml | oc apply -f -
python3 - <<'PY'
import os,pathlib,yaml
r=pathlib.Path(os.environ['ROOT']);p=pathlib.Path(os.environ['STATE_DIR']);j=yaml.safe_load((r/'tests/rhoai/streaming-job.yaml').read_text())
j['metadata']['namespace']=os.environ['DEMO_NAMESPACE'];j['spec']['template']['spec']['containers'][0]['image']=(p/'initializer-image').read_text().strip();j['spec']['template']['spec']['volumes'][1]['ephemeral']['volumeClaimTemplate']['spec']['storageClassName']=os.environ['STORAGE_CLASS']
(p/'streaming-job.yaml').write_text(yaml.safe_dump(j))
PY
# The completed Job and its synthetic-data claim remain as evidence until the
# administrator deletes the Job. A rerun of the same image rechecks its result.
oc apply -f "$STATE_DIR/streaming-job.yaml"
oc wait -n "$DEMO_NAMESPACE" --for=condition=Complete job/verify-streaming --timeout=15m
oc logs -n "$DEMO_NAMESPACE" job/verify-streaming > "$STATE_DIR/streaming-result.log"
python3 - "$STATE_DIR/streaming-result.log" <<'PY'
import pathlib,sys,json
s=pathlib.Path(sys.argv[1]).read_text();r=next(json.loads(x) for x in s.splitlines() if x.startswith('{') and 'STREAMING_2GIB_PASS' in x)
assert r['peakRssKiB'] < 512*1024
assert 'TAMPERED_JWE_REJECTED_WITH_ORIGINAL_FILES_PRESERVED' in s
print('2 GiB streaming and authenticated tamper rejection PASS; peak RSS KiB:',r['peakRssKiB'])
PY
