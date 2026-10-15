#!/usr/bin/env python3
"""Install isolated add-ons, reconcile immutable volume declarations; never enroll keys."""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import yaml
import jsonschema

ROOT = Path(__file__).resolve().parents[1]
GROUP = 'storage.confidentialcontainers.org'
OWNER = 'inference.confidentialcontainers.org/installation'
NAME = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
DIGEST = r'[^\s@]+@sha256:[a-f0-9]{64}'

from binding import Invalid
class UniqueLoader(yaml.SafeLoader): pass
def mapping(loader, node, deep=False):
    pairs = loader.construct_pairs(node, deep=deep)
    result = {}
    for k, v in pairs:
        if k in result: raise Invalid('duplicate YAML field')
        result[k] = v
    return result
UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)

def merge(a, b):
    out = copy.deepcopy(a)
    for k, value in b.items():
        out[k] = merge(out[k], value) if isinstance(value, dict) and isinstance(out.get(k), dict) else copy.deepcopy(value)
    return out

def load(path):
    base = yaml.load((ROOT/'values-global.yaml').read_text(), Loader=UniqueLoader)
    site = yaml.load(Path(path).read_text(), Loader=UniqueLoader)
    if not isinstance(site, dict): raise Invalid('values must be a mapping')
    v = merge(base, site)
    jsonschema.validate(v, json.loads((ROOT/'values.schema.json').read_text()))
    validate(v)
    return v

def validate(v, complete=False):
    for n in (v['installation']['name'], v['installation']['namespace'], v['demo']['name']):
        if not re.fullmatch(NAME, n): raise Invalid('invalid installation, namespace or run name')
    if len(v['demo']['name']) > 45: raise Invalid('run name too long for generated resources')
    if v['installation']['profile'] != 'osc-snp-nvidia-x86_64-v1': raise Invalid('unqualified hardware profile')
    if v['base']['runtimeClassName'] != 'kata-cc-nvidia-gpu' or v['base']['runtimeHandler'] != 'kata-snp-nvidia-gpu':
        raise Invalid('profile does not qualify this runtime')
    for image in v['images'].values():
        if image and not re.fullmatch(DIGEST, image): raise Invalid('images must be digest pinned')
    if complete:
        if not all(v['images'].values()): raise Invalid('all image digests are required')
        if not re.fullmatch(NAME, v['installation']['clusterIdentity']): raise Invalid('stable cluster identity required')
        if not v['base']['storageClassName']: raise Invalid('block storage class required')
        if not re.fullmatch(r'https://[a-zA-Z0-9.-]+(?::[0-9]+)?',v['registry']['origin']): raise Invalid('verified HTTPS registry origin required')
    paths=[v['demo']['modelMount'],v['demo']['dataMount']]
    if paths[0] not in ('/model','/models/qwen') or paths[1] != '/data': raise Invalid('unsupported mount profile')
    for k in ('modelSize','dataSize'):
        if not re.fullmatch(r'[1-9][0-9]*(Mi|Gi)',v['demo'][k]): raise Invalid('invalid claim size')
    for k in ('modelKeyResource','dataKeyResource'):
        if not re.fullmatch(r'kbs:///[a-z0-9-]+/[a-z0-9-]+/[a-z0-9-]+',v['demo'][k]): raise Invalid('invalid key resource identifier')
    if v['demo']['modelKeyResource']==v['demo']['dataKeyResource']: raise Invalid('model and data need distinct key resources')
    if v['chat']['serviceType'] not in ('ClusterIP','NodePort'): raise Invalid('unsupported exposure')
    if v['chat']['serviceType']=='NodePort' and (not isinstance(v['chat']['nodePort'],int) or not 30000 <= v['chat']['nodePort'] <= 32767): raise Invalid('explicit NodePort required')
    if v['gitops']['enabled'] and not re.fullmatch('[a-f0-9]{40}',v['gitops']['revision']): raise Invalid('GitOps revision must be a full commit ID')

def run(argv, data=None):
    p=subprocess.run(argv,input=data,text=True,capture_output=True,timeout=240)
    if p.returncode: raise Invalid(f'{argv[0]} command failed: {p.stderr.strip()[:1200]}')
    return p.stdout

class Cluster:
    def get(self,kind,name=None,namespace=None):
        kind={'Application':'applications.argoproj.io','AppProject':'appprojects.argoproj.io'}.get(kind,kind)
        args=['oc','get',kind,'-o','json','--request-timeout=20s']
        if name: args += [name,'--ignore-not-found=true']
        if namespace: args += ['-n',namespace]
        raw=run(args)
        return json.loads(raw) if raw.strip() else None
    def create(self,obj):
        return run(['oc','create','-f','-','--request-timeout=30s'],json.dumps(obj))
    def apply(self,obj,dry=False):
        args=['oc','apply','--server-side','--field-manager=confidential-inference-addon','-f','-','--request-timeout=30s']
        if dry:args += ['--dry-run=server']
        return run(args,json.dumps(obj))

def inventory(v,api):
    validate(v,complete=True)
    b=v['base']; ns=v['installation']['namespace']; report=[]
    def check(ok,resource,action,detail):
        report.append({'resource':resource,'action':action if ok else 'incompatible','detail':detail})
    runtime=api.get('runtimeclass',b['runtimeClassName'])
    check(runtime and runtime.get('handler')==b['runtimeHandler'],'runtime','reuse','RuntimeClass handler must match qualified stock profile; not proof of attestation')
    sc=api.get('storageclass',b['storageClassName'])
    check(sc and sc.get('volumeBindingMode','Immediate')=='Immediate','storage','reuse','Immediate binding required; WFFC placement is not qualified')
    serving=api.get('deploy',b['kserveDeployment'],b['kserveNamespace'])
    images=[c['image'] for c in (serving or {}).get('spec',{}).get('template',{}).get('spec',{}).get('containers',[])]
    check(serving and any(i.endswith(':'+b['kserveVersion']) for i in images) and serving.get('status',{}).get('availableReplicas',0)>0,'kserve','reuse','Require compatible available controller; never install or overwrite it implicitly')
    for crd in ('inferenceservices.serving.kserve.io',):
        check(api.get('crd',crd) is not None,crd,'reuse','Shared platform CRD must already be installed')
    registration=api.get('crd','volumepopulators.populator.storage.k8s.io')
    check(registration is None or any(x.get('name')=='v1beta1' and x.get('served') for x in registration.get('spec',{}).get('versions',[])),'volume-populator-registration','reuse' if registration is not None else 'create','Pinned upstream CRD; existing schema is never rewritten')
    trustee=api.get('kbsconfig',b['trusteeName'],b['trusteeNamespace'])
    check(trustee is not None,'trustee','configure-through-existing-owner','Key policies and enrollment remain in the trusted domain')
    existing=api.get('namespace',ns)
    check(not existing or existing.get('metadata',{}).get('labels',{}).get(OWNER)==v['installation']['name'],'namespace','reuse' if existing else 'create','Refuse taking over a namespace belonging to another installation')
    for x in ('cv-controller','model-populator','sidecar-admission'):
        report.append({'resource':x,'action':'create','detail':'Isolated namespace or namespace-specific cluster object'})
    return report

def preflight(v,api):
    report=inventory(v,api)
    print(json.dumps({'inventory':report,'hardwareE2EQualified':False},indent=2))
    if any(x['action']=='incompatible' for x in report): raise Invalid('preflight failed; no resources applied')

def helm(chart,values,namespace,release=None):
    with tempfile.TemporaryDirectory(prefix='inference-render-') as d:
        p=Path(d)/'values.json';p.write_text(json.dumps(values))
        text=run(['helm','template',release or chart.name,str(chart),'--namespace',namespace,'--include-crds','-f',str(p)])
    return [o for o in yaml.safe_load_all(text) if o]

def owned(obj,v):
    obj=copy.deepcopy(obj)
    obj.setdefault('metadata',{}).setdefault('labels',{})[OWNER]=v['installation']['name']
    cluster_kinds={'CustomResourceDefinition','ClusterRole','ClusterRoleBinding','SecurityContextConstraints','ValidatingAdmissionPolicy','ValidatingAdmissionPolicyBinding','VolumePopulator'}
    if obj['kind'] not in cluster_kinds and obj['kind']!='Namespace':obj['metadata'].setdefault('namespace',v['installation']['namespace'])
    if obj['kind'] in ('PersistentVolumeClaim','EncryptedModelSource'):
        obj['metadata'].setdefault('annotations',{})['argocd.argoproj.io/sync-options']='Prune=false,Delete=false'
    return obj

def resolved_values(v):
    ns=v['installation']['namespace'];d=v['demo'];im=v['images']
    return {
      'global':{'installationName':v['installation']['name']},
      'confidential-volumes':{'controller':{'enabled':True,'image':im['controller'],'clusterId':v['installation']['clusterIdentity'],'sidecarWorkloads':[d['name']],'approvalKeys':v['approvalKeys']}},
      'encrypted-model-populator':{'controller':{'enabled':True,'image':im['populator']},'storageClassName':v['base']['storageClassName'],'registry':{'origin':v['registry']['origin']},'openshift':{'createImporterSCC':True,'injectRegistryCA':v['registry']['injectServiceCA']}},
      'confidential-storage-sidecar':{'sccName':ns+'-storage-sidecar','identityEnabled':True,'allowedSidecarImages':[im['sidecar']],'applicationImage':im['application'],'allowedClaims':[d['name']+'-model',d['name']+'-data']}
    }

def gitops(v):
    validate(v,complete=True)
    if not v['gitops']['enabled']:raise Invalid('enable GitOps and pin a reviewed repository commit first')
    return [owned(o,v) for o in helm(ROOT/'charts/addon-bootstrap',v|{'resolved':resolved_values(v)},v['base']['gitopsNamespace'])]

def image_access(v):
    # Explicitly scope internal image pulls to named streams and this installation's SAs.
    from urllib.parse import urlsplit
    origin=urlsplit(v['registry']['origin']).netloc
    groups={}
    for image in v['images'].values():
        if image.startswith(origin+'/'):
            parts=image[len(origin)+1:].split('/')
            if len(parts)!=2:raise Invalid('unsupported internal image repository')
            namespace,stream=parts[0],parts[1].split('@')[0]
            groups.setdefault(namespace,set()).add(stream)
    repository=v['demo']['source'].get('repository')
    if repository:
        namespace,stream=repository.split('/')
        groups.setdefault(namespace,set()).add(stream)
    result=[]
    for namespace,streams in groups.items():
        role='inference-pull-'+v['installation']['namespace']
        result += [
            {'apiVersion':'rbac.authorization.k8s.io/v1','kind':'Role','metadata':{'name':role,'namespace':namespace},'rules':[{'apiGroups':['image.openshift.io'],'resources':['imagestreams/layers'],'resourceNames':sorted(streams),'verbs':['get']}]},
            {'apiVersion':'rbac.authorization.k8s.io/v1','kind':'RoleBinding','metadata':{'name':role,'namespace':namespace},'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':role},'subjects':[{'kind':'ServiceAccount','name':sa,'namespace':v['installation']['namespace']} for sa in ['confidential-volume-controller','encrypted-model-populator','encrypted-model-importer','storage-sidecar']]}
        ]
    return result

def foundation(v):
    validate(v,complete=True)
    ns=v['installation']['namespace'];d=v['demo']; im=v['images']
    objects=[{'apiVersion':'v1','kind':'Namespace','metadata':{'name':ns}},yaml.safe_load((ROOT/'prerequisites/volumepopulators.yaml').read_text())]+image_access(v)
    objects+=helm(ROOT/'charts/vendor/confidential-volumes',{'controller':{'enabled':True,'image':im['controller'],'clusterId':v['installation']['clusterIdentity'],'sidecarWorkloads':[d['name']],'approvalKeys':v['approvalKeys']}},ns)
    objects+=helm(ROOT/'charts/vendor/encrypted-model-populator',{'controller':{'enabled':True,'image':im['populator']},'storageClassName':v['base']['storageClassName'],'registry':{'origin':v['registry']['origin']},'openshift':{'createImporterSCC':True,'injectRegistryCA':v['registry']['injectServiceCA']}},ns)
    objects+=helm(ROOT/'charts/vendor/confidential-storage-sidecar',{'sccName':ns+'-storage-sidecar','identityEnabled':True,'allowedSidecarImages':[im['sidecar']],'applicationImage':im['application'],'allowedClaims':[d['name']+'-model',d['name']+'-data']},ns)
    return [owned(o,v) for o in objects]

def provision(v):
    validate(v,complete=True)
    source=v['demo']['source']
    if set(source)!= {'format','repository','manifestDigest','diskDigest','diskBytes'}: raise Invalid('complete publisher receipt/source required; no implicit reuse of lab artifacts')
    if source['repository'].split('/')[0]!=v['installation']['namespace']:raise Invalid('publish or promote ciphertext into the workload namespace registry; cross-namespace model sources are not supported')
    objects=[owned(o,v) for o in helm(ROOT/'charts/inference-release',v,v['installation']['namespace'])]
    claims={o['metadata']['name']:o for o in objects if o['kind']=='PersistentVolumeClaim'}
    binding={'values':{'installation':v['installation'],'demo':v['demo']},'claims':claims}
    objects += [owned(o,v) for o in helm(ROOT/'charts/volume-binding',v|{'bindingJson':json.dumps(binding),'bindingCode':(ROOT/'scripts/binding.py').read_text()},v['installation']['namespace'])]
    return objects

def compatible_crd(old,new):
    def signature(o):
        s=o['spec']
        return {'group':s['group'],'scope':s['scope'],'names':{k:s['names'][k] for k in ('kind','plural','singular')},'versions':[{k:v[k] for k in ('name','served','storage','schema') if k in v} for v in s['versions']]}
    return signature(old)==signature(new)

def check_ownership(obj,old,v):
    if old is None:return
    if obj['kind']=='CustomResourceDefinition':
        if not compatible_crd(old,obj):raise Invalid('existing shared CRD schema incompatible; upgrade through its owner')
        return
    if old.get('metadata',{}).get('labels',{}).get(OWNER)!=v['installation']['name']:raise Invalid('resource owned elsewhere: '+obj['kind']+'/'+obj['metadata']['name'])

def apply_objects(objects,v,api):
    # All ownership conflicts checked before the first mutation. Shared compatible CRDs are read-only.
    todo=[]
    for obj in objects:
        old=api.get(obj['kind'],obj['metadata']['name'],obj['metadata'].get('namespace'))
        check_ownership(obj,old,v)
        if obj['kind']=='CustomResourceDefinition' and old:continue
        todo.append(obj)
    phases=[('Namespace','CustomResourceDefinition'),('ValidatingAdmissionPolicy','ValidatingAdmissionPolicyBinding')]
    done=set()
    for kinds in phases:
        for i,obj in enumerate(todo):
            if obj['kind'] in kinds:
                api.apply(obj,dry=True);api.apply(obj);done.add(i)
                if obj['kind']=='CustomResourceDefinition':run(['oc','wait','--for=condition=Established','--timeout=60s','crd/'+obj['metadata']['name']])
        if 'ValidatingAdmissionPolicy' in kinds:
            for obj in todo:
                if obj['kind']=='ValidatingAdmissionPolicy':
                    for _ in range(30):
                        current=api.get(obj['kind'],obj['metadata']['name'])
                        status=current.get('status',{})
                        if status.get('observedGeneration')==current['metadata'].get('generation'):
                            if status.get('typeChecking',{}).get('expressionWarnings'):raise Invalid('admission type checking failed; no SCC permission granted')
                            break
                        time.sleep(1)
                    else:raise Invalid('admission not checked; no SCC permission granted')
    # A scoped executor cannot dry-run a binding whose new referenced Role does
    # not exist yet. Validate non-bindings, install Role definitions, then validate
    # bindings before creating claims/workloads. Never bypass RBAC escalation checks.
    bindings={'RoleBinding','ClusterRoleBinding'}
    for i,obj in enumerate(todo):
        if i not in done and obj['kind'] not in bindings:api.apply(obj,dry=True)
    for i,obj in enumerate(todo):
        if i not in done and obj['kind'] in ('Role','ClusterRole'):
            api.apply(obj);done.add(i)
    for i,obj in enumerate(todo):
        if i not in done and obj['kind'] in bindings:api.apply(obj,dry=True)
    for i,obj in enumerate(todo):
        if i not in done:api.apply(obj)

def bind(v,api):
    sys.path.insert(0,str(ROOT/'scripts'))
    from binding import declarations
    expected=provision(v)
    pvcs={x['metadata']['name']:x for x in expected if x['kind']=='PersistentVolumeClaim'}
    ns=v['installation']['namespace']; actual={name:api.get('pvc',name,ns) for name in pvcs}
    cvs=declarations(v,pvcs,actual)
    # Check every immutable CV before creating any; creates cannot overwrite a concurrent object.
    pending=[]
    for obj in cvs:
        old=api.get('confidentialvolume',obj['metadata']['name'],ns)
        if old:
            if old['spec']!=obj['spec']:raise Invalid('immutable ConfidentialVolume mismatch; refusing to rebind')
        else:pending.append(obj)
    for obj in pending:api.create(owned(obj,v))
    return cvs

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',choices=['validate','render','preflight','install-addon','demo-provision','bind-volumes','status','render-gitops','enable-gitops','demo-chat'])
    p.add_argument('--values',type=Path,default=ROOT/'values-global.yaml')
    p.add_argument('--output',type=Path,default=ROOT/'output/rendered.yaml')
    a=p.parse_args();v=load(a.values);api=Cluster()
    if a.command=='validate':print('Values schema and security constraints passed; empty site inputs are not deployment-ready.');return
    if a.command in ('render-gitops','enable-gitops'):
        objects=gitops(v)
        if a.command=='enable-gitops':
            preflight(v,api)
            # Installation performs admission type checking before granting privileges.
            for name in ['confidential-volume-controller','encrypted-model-populator']:
                current=api.get('deploy',name,v['installation']['namespace'])
                if not current or current.get('metadata',{}).get('labels',{}).get(OWNER)!=v['installation']['name']:raise Invalid('install-addon must complete before GitOps activation')
            apply_objects(objects,v,api)
        else:
            a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(yaml.safe_dump_all(objects,sort_keys=False))
        return
    if a.command=='render':
        objects=foundation(v)
        a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(yaml.safe_dump_all(objects,sort_keys=False));print(str(a.output));return
    if a.command=='preflight':preflight(v,api)
    elif a.command=='install-addon':
        preflight(v,api);apply_objects(foundation(v),v,api)
        for name in ['confidential-volume-controller','encrypted-model-populator']:run(['oc','rollout','status','deployment/'+name,'-n',v['installation']['namespace'],'--timeout=180s'])
        print('Add-on controllers ready. This does not authorize keys or establish hardware E2E qualification.')
    elif a.command=='demo-provision':
        objects=provision(v)
        preflight(v,api)
        apply_objects([owned(o,v) for o in image_access(v)]+objects,v,api)
    elif a.command=='bind-volumes':print(json.dumps(bind(v,api),indent=2))
    elif a.command=='demo-chat':
        if not v['chat']['enabled']:raise Invalid('chat.enabled must be explicitly set')
        apply_objects([owned(o,v) for o in helm(ROOT/'charts/inference-chat',v,v['installation']['namespace'])],v,api)
    elif a.command=='status':
        for kind in ['pvc','confidentialvolume','confidentialworkload','inferenceservice']:
            data=api.get(kind,namespace=v['installation']['namespace'])
            print(json.dumps({'kind':kind,'items':[{'name':o['metadata']['name'],'uid':o['metadata']['uid'],'status':o.get('status',{})} for o in data['items']]},indent=2))

if __name__=='__main__':
    try:main()
    except (Invalid,jsonschema.ValidationError) as e:print(str(e),file=sys.stderr);sys.exit(1)
