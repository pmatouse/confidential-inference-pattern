#!/usr/bin/env python3
"""Read-only demo checks plus synthetic inference and a denied-exec probe.

Does not replace pods, edit Trustee, inspect keys or reset retained state.
Authority journal/CPU+GPU appraisal evidence is checked separately.
"""
import argparse
import base64
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request


def require(ok, message):
    if not ok:
        raise ValueError(message)


def events(log):
    result = {}
    for line in log.splitlines():
        if line.startswith('{'):
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if item.get('event') in ('STORAGE_DATA_FIRST_WRITE_PASS',
                                     'STORAGE_DATA_FRESH_VM_REOPEN_PASS',
                                     'CUDA_GPU_PROBE_PASS'):
                result[item['event']] = item
    require('STORAGE_MODEL_RO_HASHES_PASS' in log, 'model hash/mount check missing')
    require('CUDA_GPU_PROBE_PASS' in result, 'CUDA check missing')
    return result


def persistence(event, phase, uid, previous):
    if phase == 'first':
        require('STORAGE_DATA_FIRST_WRITE_PASS' in event, 'fresh blank first write missing')
        return event['STORAGE_DATA_FIRST_WRITE_PASS']['boot']
    require(previous is not None, 'first-run receipt required')
    item = event.get('STORAGE_DATA_FRESH_VM_REOPEN_PASS', {})
    require(uid != previous['podUid'] and item.get('firstBoot') == previous['boot']
            and item.get('boot') and item['boot'] != previous['boot'],
            'same PVC canary in a different guest VM required')
    return item['boot']


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('namespace', 'workload', 'chat-url', 'model', 'expected-initdata',
                 'expected-application-image'):
        p.add_argument('--'+name, required=True)
    p.add_argument('--phase', choices=('first', 'reopen'), required=True)
    p.add_argument('--previous', type=Path)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    oc = ['oc', '-n', a.namespace]
    def read(*args):
        return json.loads(subprocess.check_output(oc+list(args)+['-o','json'], text=True))
    pods = read('get','pods','-l','serving.kserve.io/inferenceservice='+a.workload)['items']
    active = [x for x in pods if x['status']['phase']=='Running'
              and not x['metadata'].get('deletionTimestamp')
              and all(c['ready'] for c in x['status'].get('containerStatuses',[]))]
    require(len(active)==1, 'exactly one Ready predictor required')
    pod = active[0]; name = pod['metadata']['name']; spec = pod['spec']
    require(spec['runtimeClassName']=='kata-cc-nvidia-gpu', 'qualified runtime required')
    app = next(x for x in spec['containers'] if x['name']=='kserve-container')
    require(app['image']==a.expected_application_image, 'unexpected application image')
    sec = app['securityContext']
    require(sec['runAsUser']==sec['runAsGroup']==1001 and not sec.get('privileged',False)
            and sec['allowPrivilegeEscalation'] is False and sec['readOnlyRootFilesystem']
            and sec['capabilities']=={'drop':['ALL']} and not app.get('volumeDevices'),
            'application isolation mismatch')
    raw = gzip.decompress(base64.b64decode(pod['metadata']['annotations'][
        'io.katacontainers.config.hypervisor.cc_init_data']))
    require(hashlib.sha256(raw).hexdigest()==a.expected_initdata, 'unexpected InitData')
    log = subprocess.check_output(oc+['logs',name,'-c','kserve-container'],text=True)
    found = events(log)
    previous = json.loads(a.previous.read_text()) if a.previous else None
    boot = persistence(found,a.phase,pod['metadata']['uid'],previous)
    claims = {v['name']:v['persistentVolumeClaim']['claimName'] for v in spec['volumes']
              if 'persistentVolumeClaim' in v}
    pvc_ids = {n:read('get','pvc',v)['metadata']['uid'] for n,v in claims.items()}
    if previous:
        require(pvc_ids==previous['pvcUids'], 'PVC identities changed')
        require(a.expected_initdata==previous['initDataSha256'], 'measured configuration changed')
    probe = subprocess.run(oc+['exec',name,'-c','kserve-container','--','/bin/true'],
                           capture_output=True,text=True)
    require(probe.returncode!=0 and 'ExecProcessRequest is blocked by policy' in probe.stderr,
            'measured exec denial missing')
    request = urllib.request.Request(a.chat_url.rstrip('/')+'/api/chat',
        data=json.dumps({'messages':[{'role':'user','content':'What is 7 plus 5? Answer briefly. /no_think'}]}).encode(),
        headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=90) as response:
        require(response.status==200, 'chat request failed')
        reply = json.load(response)
    require(reply.get('model')==a.model and '12' in reply['choices'][0]['message']['content'],
            'unexpected model or synthetic inference response')
    result = dict(phase=a.phase,namespace=a.namespace,workload=a.workload,pod=name,
                  podUid=pod['metadata']['uid'],boot=boot,pvcUids=pvc_ids,
                  initDataSha256=a.expected_initdata,applicationImage=app['image'],
                  model=a.model,chatStatus=200,chatResponse=reply['choices'][0]['message']['content'],
                  modelHashesVerified=True,execDenied=True,gpu=found['CUDA_GPU_PROBE_PASS'],
                  scope='application, persistence, chat and exec checks; authority evidence separate')
    with a.output.open('x') as f:
        json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()
