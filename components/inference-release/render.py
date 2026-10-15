#!/usr/bin/env python3
"""Offline public configuration renderer. Never reads keys, enrolls or signs."""
import argparse
import base64
import copy
import gzip
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(Path(__file__).resolve().parent),str(ROOT/'components/confidential-volume-controller'),str(ROOT/'components/confidential-storage-sidecar')]
from controller import validate_artifacts
from policy import render as render_policy

WAIT='''import os, socket, time
s=socket.socket(socket.AF_UNIX)
end=time.monotonic()+600
while True:
    try:
        s.connect('/rendezvous/storage.sock')
        break
    except (FileNotFoundError,ConnectionRefusedError):
        if time.monotonic()>=end:raise RuntimeError('storage startup timeout')
        time.sleep(0.25)
s.settimeout(600)
ready=b''
while len(ready)<6:
    chunk=s.recv(6-len(ready))
    if not chunk:raise RuntimeError('storage supervisor disconnected')
    ready+=chunk
if ready!=b'READY\\n':raise RuntimeError('storage startup rejected')
s.close()
'''

def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'))
def sha(s):return hashlib.sha256(s.encode()).hexdigest()
def require(ok,message):
    if not ok:raise ValueError(message)

def draft(request,profile):
    require(request.get('purpose')=='confidential-volume-reconcile-request/v1','unexpected request')
    require(request.get('deployment',{}).get('mode')=='stock-kata-sidecar/v1','sidecar request required')
    require(profile['runtimeClassName']=='kata-cc-nvidia-gpu','unqualified stock runtime')
    template=copy.deepcopy(request['deployment']['desired'])
    ns=request['contract']['namespace'];name=template['metadata']['name']
    require(re.fullmatch('[a-z0-9][a-z0-9-]{0,44}',name),'workload name too long')
    p=template['spec']['predictor'];app=p['containers'][0]
    require(len(p['containers'])==1 and app['name']=='kserve-container','one unprivileged application required')
    require(app['image']==profile['application']['image'],'application image outside compatibility profile')
    a=profile['application'];h=profile['helper']
    require(a['uid']==a['gid']==1001 and a['noNewPrivileges'] and a['readonlyRoot'] and not a['capabilities'] and not a['rawDevices'],'profile relaxes application isolation')
    require(h['uid']==0,'helper must use the reviewed root profile')
    require(re.fullmatch(r'[^\s@]+@sha256:[a-f0-9]{64}',profile['helper']['image']),'helper digest required')
    command=app.get('command',[])+app.get('args',[])
    require(command and all(isinstance(x,str) for x in command),'explicit application command required')
    from startup import render as startup_checks
    checks=startup_checks(profile['startupChecks']) if 'startupChecks' in profile else ''
    consumer=[profile['applicationPython'],'-c',WAIT+checks+'os.execvp('+repr(command[0])+', '+repr(command)+')\n']
    app['command']=consumer;app.pop('args',None);app['workingDir']='/'
    app['securityContext']={'runAsUser':1001,'runAsGroup':1001,'runAsNonRoot':True,'privileged':False,'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}}
    app['ports']=[{'containerPort':8000,'protocol':'TCP'}]
    app['readinessProbe']={'httpGet':{'path':'/health','port':8000},'periodSeconds':5,'timeoutSeconds':2,'failureThreshold':3}
    entries=request['contract']['volumes']
    require(1<=len(entries)<=8,'unsupported volume count')
    require(all(e['container']=='kserve-container' for e in entries),'single consumer required')
    volumes=[];devices=[];mounts=[]
    for e in entries:
        role=e['bindingId'];target=role+'-target'
        volumes += [{'name':role,'persistentVolumeClaim':{'claimName':e['claimRef']['name'],'readOnly':e['access']=='ReadOnly'}},{'name':target,'emptyDir':{'medium':'Memory','sizeLimit':'4Mi'}}]
        devices.append({'name':role,'devicePath':e['devicePath']})
        mounts.append({'name':target,'mountPath':e['mountPath']})
    volumes += [{'name':'configuration','configMap':{'name':'pending-public-configuration'}},{'name':'rendezvous','emptyDir':{'medium':'Memory','sizeLimit':'4Mi'}},{'name':'shm','emptyDir':{'medium':'Memory','sizeLimit':'4Gi'}}]
    app['volumeMounts']=mounts+[{'name':'rendezvous','mountPath':'/rendezvous'},{'name':'shm','mountPath':'/dev/shm'}]
    helper={'name':'storage-sidecar','image':profile['helper']['image'],'command':['python3','/opt/storage-sidecar/runtime.py'],'workingDir':'/','securityContext':{'runAsUser':0,'privileged':True},'resources':{'requests':{'cpu':'1','memory':'2Gi'},'limits':{'cpu':'2','memory':'4Gi'}},'volumeDevices':devices,'volumeMounts':[{'name':'configuration','mountPath':'/configuration','readOnly':True},{'name':'rendezvous','mountPath':'/rendezvous'}]}
    p.update(labels={'coco.io/skip-initdata':'true'},minReplicas=1,maxReplicas=1,deploymentStrategy={'type':'Recreate'},serviceAccountName='storage-sidecar',runtimeClassName=profile['runtimeClassName'],shareProcessNamespace=True,automountServiceAccountToken=False,enableServiceLinks=False,hostname=name+'-sidecar',securityContext={'fsGroup':1001},terminationGracePeriodSeconds=180,containers=[app,helper],volumes=volumes)
    policy={'namespace':ns,'gpuCount':1,**{r:copy.deepcopy(profile[r]) for r in ('pause','helper','application')}}
    for role,container in [('helper',helper),('application',app)]:
        settings=policy[role];settings['args']=container['command'];settings['image']=container['image']
        env={}
        for item in settings['environment']:
            k,value=item.split('=',1)
            if k=='PATH' and value=='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin':continue
            env[k]=value
        env.update(HOSTNAME=name+'-sidecar',INFERENCE_SERVICE_NAME=name)
        host=profile['kubernetesServiceHost']
        require(re.fullmatch(r'[0-9.]+',host),'qualified IPv4 service environment required')
        env.update(KUBERNETES_SERVICE_HOST=host,KUBERNETES_PORT=f'tcp://{host}:443',KUBERNETES_PORT_443_TCP=f'tcp://{host}:443',KUBERNETES_PORT_443_TCP_ADDR=host)
        for e in container.get('env',[]):
            require(set(e)=={'name','value'},'environment must be public literal values')
            env[e['name']]=e['value']
        # Explicit image/profile environment avoids a previous pod's environment.
        container['env']=[{'name':k,'value':value} for k,value in sorted(env.items()) if k not in ('HOSTNAME','KUBERNETES_SERVICE_HOST','KUBERNETES_PORT','KUBERNETES_PORT_443_TCP','KUBERNETES_PORT_443_TCP_ADDR','KUBERNETES_SERVICE_PORT','KUBERNETES_SERVICE_PORT_HTTPS','KUBERNETES_PORT_443_TCP_PROTO','KUBERNETES_PORT_443_TCP_PORT')]
        settings['environment']=sorted([f'{k}={value}' for k,value in env.items()]+['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'])
        settings['requiredEnvironment']=settings['environment']
    h,a=policy['helper'],policy['application'];h['additionalGroups']=[[0,1001],[1001,0],[1001]];h['rawDevices']=[d['devicePath'] for d in devices]
    # The profile supplies the reviewed stock-runtime mount shape. Instantiate
    # only approved guest-memory targets; never authorize arbitrary host mounts.
    old=[m for m in a['mounts'] if m['destination'].startswith(('/models','/model','/data','/checkpoints'))]
    require(old,'profile has no guest memory target template')
    sample=copy.deepcopy(old[0]);a['mounts']=[m for m in a['mounts'] if m not in old]
    a['ephemeralStorages']=[x for x in a['ephemeralStorages'] if not x['mount_point'].endswith('-target')]
    for e in entries:
        target=e['bindingId']+'-target';m=copy.deepcopy(sample);m['destination']=e['mountPath'];m['source']='/run/kata-containers/sandbox/ephemeral/'+target;a['mounts'].append(m)
        a['ephemeralStorages'].append({'driver':'ephemeral','driver_options':[],'fs_group':None,'fstype':'tmpfs','mount_point':m['source'],'options':['fsgid=1001'],'shared':False,'source':'tmpfs'})
    rendezvous=next(m for m in a['mounts'] if m['destination']=='/rendezvous')
    h['mounts']=[m for m in h['mounts'] if m['destination']!='/rendezvous']+[copy.deepcopy(rendezvous)]
    h['ephemeralStorages']=[copy.deepcopy(x) for x in a['ephemeralStorages'] if x['mount_point'].endswith('/rendezvous')]
    raw=render_policy(policy)
    return {'schemaVersion':1,'requestSha256':sha(canonical(request)),'predictor':p,'metadata':template['metadata'],'policy':raw,'policySha256':sha(raw),'profile':policy}

def package(request,draft,guest,aa,cdh,runtime):
    require(draft['requestSha256']==sha(canonical(request)),'draft belongs to different request')
    require(draft['policySha256']==sha(draft['policy']),'draft policy changed')
    service=copy.deepcopy(guest)
    require(service['authority']['policy_sha256']==draft['policySha256'],'authority enrollment policy differs')
    service['authority']['init_data']='';service['authority']['policy_sha256']=''
    for v in service['volumes']:v['expected']['policy_sha256']=''
    p=copy.deepcopy(draft['predictor'])
    tomllib.loads(aa);tomllib.loads(cdh)
    data={'aa.toml':aa,'cdh.toml':cdh,'policy.rego':draft['policy'],'storage-sidecar.json':canonical({'schemaVersion':1,'service':service,'consumerArgs':p['containers'][0]['command']})}
    raw='version = "0.1.0"\nalgorithm = "sha256"\n[data]\n'+''.join(json.dumps(k)+' = '+json.dumps(v)+'\n' for k,v in sorted(data.items()))
    require(len(raw.encode())<=65536,'InitData exceeds the stock profile limit')
    initsha=sha(raw);runtime=copy.deepcopy(runtime);runtime['initDataSha256']=initsha
    next(v for v in p['volumes'] if v['name']=='configuration')['configMap']['name']='cv-sidecar-'+initsha[:48]
    p['annotations']={'openshift.io/required-scc':request['contract']['namespace']+'-storage-sidecar','io.katacontainers.config.hypervisor.cc_init_data':base64.b64encode(gzip.compress(raw.encode(),mtime=0)).decode(),'io.katacontainers.config.hypervisor.kernel_params':'agent.log=warn agent.guest_components_procs=confidential-data-hub','io.katacontainers.config.hypervisor.default_memory':'65536','io.katacontainers.config.hypervisor.default_vcpus':'8','io.katacontainers.config.runtime.create_container_timeout':'300'}
    guest=copy.deepcopy(guest);guest['authority']['init_data']=initsha
    for v in guest['volumes']:v['expected']['policy_sha256']=draft['policySha256']
    metadata={'labels':draft['metadata'].get('labels',{}),'annotations':draft['metadata'].get('annotations',{})}
    result={'guest-config.json':canonical(guest),'initdata.toml':raw,'runtime.json':canonical(runtime),'sidecar-deployment.json':canonical({'predictor':p,'metadata':metadata})}
    validate_artifacts(result,request)
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--request',type=Path,required=True);p.add_argument('--profile',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();request=json.loads(a.request.read_text())
    if request.get('kind')=='ConfigMap':request=json.loads(request['data']['request.json'])
    result=draft(request,json.loads(a.profile.read_text()))
    with a.output.open('x') as f:f.write(canonical(result)+'\n')
    print('Public policy draft created; no enrollment, signing or deployment performed.')
if __name__=='__main__':main()
