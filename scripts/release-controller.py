#!/usr/bin/env python3
"""Administrator bootstrap for the trusted release controller; stage execution is in Jobs."""
import argparse
import fcntl
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import yaml
import addon
from quickstart.core import ROOT, Run, require, write
from quickstart.build import archive, image_build


def image(r):
    r.require_stage('install')
    roots=['scripts','charts','profiles','prerequisites','values-global.yaml','values.schema.json','requirements-quickstart.txt','requirements.txt',
        'components/inference-release','components/confidential-volume-controller','components/confidential-volume-contract',
        'components/confidential-storage-authority','components/confidential-storage-sidecar','components/confidential-storage-guest/profiles']
    paths=subprocess.check_output(['git','-C',str(ROOT),'ls-files','-z','--',*roots],text=True).split('\0')
    extras=[p for folder in ('components/inference-release-controller','charts/inference-release-controller') for p in (ROOT/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts]
    entries={'source/'+name:ROOT/name for name in paths if name and (ROOT/name).is_file() and not (ROOT/name).is_symlink()}
    entries.update({'source/'+str(p.relative_to(ROOT)):p for p in extras})
    entries['source/scripts/release-controller.py']=Path(__file__).resolve()
    entries['Containerfile']=ROOT/'components/inference-release-controller/Containerfile'
    out=r.cache/'release-executor.tar.gz';archive(out,entries)
    receipt=image_build(r,'inference-release-executor',out)
    r.save('release-executor-image.json',receipt)
    return receipt


def configuration(r):
    im=r.read('release-executor-image.json')
    p={'namespace':r.trusted,'workloadNamespace':r.ns,'releaseName':r.name,
       'siteConfigMap':r.name+'-site','siteSha256':r.identity['siteSha256'],
       'image':im['image'],'stateClaim':r.name+'-release-state','stageServiceAccount':'inference-release-stage',
       'gitCredentialsSecret':'inference-release-git'}
    return {'policy':p,'site':r.v,'storageClassName':r.v['base']['storageClassName'],'stateSize':'20Gi','createIntent':False}


def install(r):
    r.require_stage('install')
    require(not r.receipt('model'),'bootstrap requires fresh unprepared release; explicit handover of serving releases is not implemented')
    require(r.get('inferencerelease',r.name,r.trusted) is None,'cannot bootstrap after release starts')
    cfg=configuration(r);p=cfg['policy']
    crd=yaml.safe_load((ROOT/'charts/inference-release-controller/crds/inferencereleases.yaml').read_text())
    old=r.get('crd',crd['metadata']['name'])
    require(not old or old['spec']['versions']==crd['spec']['versions'],'shared InferenceRelease CRD differs; reviewed upgrade required')
    if not old:r.apply(crd)
    r.oc('wait','--for=condition=Established','crd/'+crd['metadata']['name'],'--timeout=60s')
    # Explicit namespace scoping in the chart; never infer cluster scope from kind alone.
    objects=addon.helm(ROOT/'charts/inference-release-controller',cfg,r.trusted,'inference-release-controller')
    for obj in objects:
        if obj['kind']=='CustomResourceDefinition':
            # Helm includes crds/. The shared API was checked/created above;
            # never adopt it again under this installation's owner or namespace.
            require(obj['metadata']['name']==crd['metadata']['name'] and obj['spec']==crd['spec'],'unexpected release CRD in chart')
            continue
        if obj['kind'] not in ('ClusterRole','ClusterRoleBinding'):
            obj.setdefault('metadata',{}).setdefault('namespace',r.trusted)
        r.apply(obj)
    for account in ('inference-release-controller','inference-release-stage'):
        role=r.name+'-'+account+'-pull'
        r.apply({'apiVersion':'rbac.authorization.k8s.io/v1','kind':'Role','metadata':{'name':role,'namespace':r.ns},
            'rules':[{'apiGroups':['image.openshift.io'],'resources':['imagestreams/layers'],'resourceNames':['inference-release-executor'],'verbs':['get']}]})
        r.apply({'apiVersion':'rbac.authorization.k8s.io/v1','kind':'RoleBinding','metadata':{'name':role,'namespace':r.ns},
            'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':role},
            'subjects':[{'kind':'ServiceAccount','name':account,'namespace':r.trusted}]})
    r.save('release-controller-values.json',cfg)
    require(r.get('inferencerelease',r.name,r.trusted) is None,'cannot seed after release starts')
    seed=r.name+'-release-seed'
    r.apply({'apiVersion':'v1','kind':'Pod','metadata':{'name':seed,'namespace':r.trusted,'annotations':{'openshift.io/required-scc':'restricted-v2'}},'spec':{
        'serviceAccountName':'inference-release-stage','automountServiceAccountToken':False,'restartPolicy':'Never',
        'securityContext':{'runAsNonRoot':True,'fsGroupChangePolicy':'OnRootMismatch','seccompProfile':{'type':'RuntimeDefault'}},
        'containers':[{'name':'seed','image':p['image'],'command':['sleep','3600'],
            'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},
            'volumeMounts':[{'name':'state','mountPath':'/state'}]}],
        'volumes':[{'name':'state','persistentVolumeClaim':{'claimName':p['stateClaim']}}]}})
    r.oc('wait','-n',r.trusted,'--for=condition=Ready','pod/'+seed,'--timeout=300s',timeout=330)
    marker=r.oc('exec','-n',r.trusted,seed,'--','sh','-c','test ! -f /state/bootstrap-complete.json || cat /state/bootstrap-complete.json',sensitive=True)
    expected={'siteSha256':p['siteSha256'],'run':r.name,'executorImage':p['image']}
    if marker:require(json.loads(marker)==expected,'retained seed identity differs')
    else:
        # Keys/signers and receipts travel only through authenticated stdin, never build contexts or ConfigMaps.
        require(not (r.state/'executor-owner.json').exists(),'handover already started; inspect retained seed state')
        entries={}
        for prefix,folder in [('private',r.state),('output',r.out)]:
            for path in folder.rglob('*'):
                if path.is_file() and path.name!='lock':
                    require(not path.is_symlink(),'symlink in retained state')
                    entries[prefix+'/'+r.name+'/'+str(path.relative_to(folder))]=path
        for item in ('ovmf','kernel','initrd'):entries['cache/'+r.name+'/build/'+item]=r.cache/'build'/item
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w:gz') as tar:
            for name,path in entries.items():
                raw=path.read_bytes();info=tarfile.TarInfo(name);info.size=len(raw);info.mode=0o600;tar.addfile(info,io.BytesIO(raw))
        # Seed only into an empty state root; failed partial seed is blocked for explicit inspection.
        script="import os,sys,tarfile; from pathlib import Path; p=Path('/state/private'); assert not p.exists(); os.umask(0o077); tarfile.open(fileobj=sys.stdin.buffer,mode='r|gz').extractall('/state',filter='data')"
        r.oc('exec','-i','-n',r.trusted,seed,'--','python3','-c',script,body=data.getvalue(),binary=True,sensitive=True,timeout=600)
        owner={'executor':'controller','siteSha256':p['siteSha256']}
        script="import json,sys,os; from pathlib import Path; os.umask(0o077); x=json.load(sys.stdin); Path('/state/private/'+x['run']+'/executor-owner.json').write_text(json.dumps(x['owner'])); Path('/state/bootstrap-complete.json').write_text(json.dumps(x['marker']))"
        r.oc('exec','-i','-n',r.trusted,seed,'--','python3','-c',script,body=json.dumps({'run':r.name,'owner':owner,'marker':expected}),sensitive=True)
    write(r.state/'executor-owner.json',{'executor':'controller','siteSha256':p['siteSha256']})
    r.oc('delete','pod',seed,'-n',r.trusted,'--wait=true',timeout=120)
    r.save('controller-bootstrap.json',expected)
    print('ControllerBootstrapReady; apply the generated release intent or manage it through Argo')
    intent={'apiVersion':'inference.confidentialcontainers.org/v1alpha1','kind':'InferenceRelease',
            'metadata':{'name':r.name,'namespace':r.trusted,'annotations':{'argocd.argoproj.io/sync-options':'Prune=false,Delete=false'}},
            'spec':{'siteConfigRef':{'name':p['siteConfigMap'],'key':'values.json','sha256':p['siteSha256']},'acceptance':{'mode':'FreshDemo','allowTestVMReplacement':True}}}
    r.save('inference-release.json',intent)


def upgrade(r):
    """Explicit operator image maintenance; never seed, delete history or retry a Job."""
    require((r.out/'controller-bootstrap.json').is_file(),'bootstrap receipt missing')
    cfg=configuration(r);deployment=r.get('deployment','inference-release-controller',r.trusted)
    require(deployment and deployment['metadata'].get('labels',{}).get(addon.OWNER)==r.installation,'foreign controller')
    current_cm=next(v['configMap']['name'] for v in deployment['spec']['template']['spec']['volumes'] if v['name']=='configuration')
    current=json.loads(r.get('configmap',current_cm,r.trusted)['data']['policy.json'])
    require({k:v for k,v in current.items() if k!='image'}=={k:v for k,v in cfg['policy'].items() if k!='image'},'image maintenance cannot change site or grants')
    r.oc('patch','deployment/inference-release-controller','-n',r.trusted,'--type=merge','--field-manager=confidential-inference-quickstart','-p',json.dumps({'spec':{'replicas':0}}))
    r.wait('controller stopped',lambda:not [p for p in r.get('pods',ns=r.trusted)['items'] if p['metadata'].get('labels',{}).get('app')=='inference-release-controller'],timeout=120)
    jobs=[j for j in r.get('jobs',ns=r.trusted)['items'] if j['metadata'].get('labels',{}).get('inference.confidentialcontainers.org/release-uid')]
    require(not any(j.get('status',{}).get('active',0) for j in jobs),'stage still active; controller remains paused; retry maintenance after it finishes')
    uids={j['metadata']['uid'] for j in jobs}
    require(not any(p.get('status',{}).get('phase') not in ('Succeeded','Failed') and any(o['uid'] in uids for o in p['metadata'].get('ownerReferences',[])) for p in r.get('pods',ns=r.trusted)['items']),'stage Pod still active; controller remains paused')
    objects=addon.helm(ROOT/'charts/inference-release-controller',cfg,r.trusted,'inference-release-controller')
    # Only the content-addressed grant and controller Deployment change in maintenance.
    for obj in objects:
        if obj['kind']=='Deployment' or (obj['kind']=='ConfigMap' and 'policy.json' in obj.get('data',{})):
            if obj['kind']=='Deployment':obj['spec']['replicas']=0
            obj.setdefault('metadata',{}).setdefault('namespace',r.trusted);r.apply(obj)
    r.oc('patch','deployment/inference-release-controller','-n',r.trusted,'--type=merge','--field-manager=confidential-inference-quickstart','-p',json.dumps({'spec':{'replicas':1}}))
    r.oc('rollout','status','deployment/inference-release-controller','-n',r.trusted,'--timeout=180s',timeout=210)
    r.save('controller-upgrade-'+cfg['policy']['image'].split(':')[-1][:12]+'.json',{'previousImage':current['image'],'image':cfg['policy']['image'],'siteSha256':current['siteSha256'],'stateClaim':current['stateClaim']})
    print('ControllerImageUpdated; retained state unchanged; failed stages require explicit retry')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=['image','install','upgrade','start','status'])
    parser.add_argument('--values',type=Path,required=True);args=parser.parse_args()
    values=addon.load(args.values);r=Run(args.values,values['demo']['name'],exclusive=args.action=='install')
    if args.action in ('image','upgrade'):
        maintenance=(r.state/'release-maintenance.lock').open('a')
        fcntl.flock(maintenance,fcntl.LOCK_EX|fcntl.LOCK_NB)
    if args.action=='image':image(r)
    elif args.action=='upgrade':upgrade(r)
    elif args.action=='install':install(r)
    elif args.action=='start':
        require(r.get('secret','inference-release-git',r.trusted) is not None,'create external inference-release-git Secret with SSH deploy key and known_hosts, or scoped token, before starting the release')
        require((r.out/'controller-bootstrap.json').is_file(),'bootstrap receipt missing')
        r.apply(r.read('inference-release.json'))
    else:
        obj=r.get('inferencerelease',r.name,r.trusted)
        print(json.dumps((obj or {}).get('status',{'phase':'NotStarted'}),indent=2))
if __name__=='__main__':main()
