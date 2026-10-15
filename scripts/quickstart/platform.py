"""Platform inspection/bootstrap. Existing CoCo services remain externally owned."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys

import addon
from .core import ROOT, require, sha, write


def tools(r):
    require(sys.version_info >= (3,12),'Python 3.12+ required; see quickstart prerequisites')
    for tool in ('oc','helm','git'):
        require(shutil.which(tool),'missing client: '+tool)
    helm=r.command(['helm','version','--short']).strip()
    require(helm.startswith('v3.'),'Helm 3 required (put helm@3/bin first in PATH)')
    r.command([sys.executable,'-m','pip','install','-r',ROOT/'requirements-quickstart.txt'],timeout=300)
    r.command([sys.executable,'-m','pip','check'])
    return {'state':'ToolsReady','python':sys.version.split()[0],'helm':helm}


def dependencies(r):
    r.require_stage('tools')
    b=r.v['base']
    required=(('runtimeclass',b['runtimeClassName'],None),
              ('storageclass',b['storageClassName'],None),
              ('kbsconfig',b['trusteeName'],b['trusteeNamespace']))
    objects=[]
    for kind,name,namespace in required:
        obj=r.get(kind,name,namespace)
        require(obj is not None,'missing existing CoCo dependency: '+kind+'/'+name)
        objects.append({'kind':kind,'name':name,'uid':obj['metadata']['uid']})
    serving=r.get('deployment',b['kserveDeployment'],b['kserveNamespace'])
    if serving is None and r.q.get('dependencies',{}).get('installKServe') is True:
        require(r.get('crd','certificates.cert-manager.io') is not None,'cert-manager must be installed by its platform owner before KServe')
        require(b['kserveVersion']=='v0.20.0','only pinned KServe v0.20.0 installation is qualified')
        existing_namespace=r.get('namespace',b['kserveNamespace'])
        require(not existing_namespace or existing_namespace['metadata'].get('labels',{}).get(addon.OWNER)==r.installation,'refusing to install into a foreign KServe namespace')
        r.apply({'apiVersion':'v1','kind':'Namespace','metadata':{'name':b['kserveNamespace']}})
        for chart in ('kserve-crd','kserve-resources'):
            args=['helm','template',chart,'oci://ghcr.io/kserve/charts/'+chart,'--version','v0.20.0','--namespace',b['kserveNamespace'],'--include-crds']
            if chart=='kserve-resources':args+=['--set','kserve.controller.deploymentMode=Standard','--set','kserve.controller.gateway.disableIngressCreation=true']
            import yaml
            objects=[obj for obj in yaml.safe_load_all(r.command(args,timeout=300)) if obj]
            for obj in objects:
                if obj['kind'] not in ('CustomResourceDefinition','ClusterRole','ClusterRoleBinding','MutatingWebhookConfiguration','ValidatingWebhookConfiguration'):
                    obj.setdefault('metadata',{}).setdefault('namespace',b['kserveNamespace'])
            addon.apply_objects([addon.owned(obj,r.v) for obj in objects],r.v,r.api)
        r.oc('rollout','status','deployment/'+b['kserveDeployment'],'-n',b['kserveNamespace'],'--timeout=300s',timeout=330)
        serving=r.get('deployment',b['kserveDeployment'],b['kserveNamespace'])
    require(serving is not None,'KServe missing: set quickstart.dependencies.installKServe=true after platform cert-manager setup')
    require(any(c['image'].endswith(':'+b['kserveVersion']) for c in serving['spec']['template']['spec']['containers']), 'incompatible KServe version')
    require(serving.get('status',{}).get('availableReplicas',0)>0,'KServe controller unavailable')
    registry=r.get('configs.imageregistry.operator.openshift.io','cluster')
    require(registry and registry['spec'].get('managementState')=='Managed','enable the existing OpenShift internal registry through its platform owner')
    require(any(c['type']=='Available' and c['status']=='True' for c in registry.get('status',{}).get('conditions',[])),'internal registry unavailable')
    return {'state':'DependenciesReady','reused':objects,'kserveUID':serving['metadata']['uid']}


def preflight(r):
    r.require_stage('dependencies')
    v=r.v;b=v['base']
    require(v['installation']['clusterIdentity'] and b['storageClassName'],'cluster identity and block storage class required')
    require(r.get('runtimeclass',b['runtimeClassName'])['handler']==b['runtimeHandler'],'runtime handler mismatch')
    require(r.get('storageclass',b['storageClassName']).get('volumeBindingMode','Immediate')=='Immediate','Immediate raw Block CSI required')
    cv=r.get('clusterversion','version')
    for ns in (r.ns,r.trusted):
        obj=r.get('namespace',ns)
        require(not obj or obj['metadata'].get('labels',{}).get(addon.OWNER)==r.installation,'namespace belongs to another installation')
    nodes=r.get('nodes')['items']
    candidates=[n for n in nodes if int(n['status'].get('allocatable',{}).get(b['gpuResourceName'],'0'))>0]
    if r.q.get('runtimeNode'):candidates=[n for n in candidates if n['metadata']['name']==r.q['runtimeNode']]
    require(len(candidates)==1,'select one qualified GPU node in quickstart.runtimeNode')
    node=candidates[0]
    # Capacity is rechecked at deployment. CPU-only preparation may run while GPUs are busy.
    pods=json.loads(r.oc('get','pods','-A','-o','json',sensitive=True))['items']
    allocated=sum(int(c.get('resources',{}).get('requests',{}).get(b['gpuResourceName'],0))
                  for p in pods if p['spec'].get('nodeName')==node['metadata']['name'] and p['status'].get('phase') not in ('Failed','Succeeded')
                  for c in p['spec']['containers'])
    require(r.q.get('allowReadOnlyHostArtifacts') is True,'enable read-only access to verified installed stock artifacts in site values')
    return {'state':'PlatformReady','clusterUID':cv['metadata']['uid'],'openshift':cv['status']['desired']['version'],
            'node':node['metadata']['name'],'gpuCapacity':int(node['status']['allocatable'][b['gpuResourceName']]),'gpuAllocated':allocated,
            'inferenceRequiresFreeGPU':True,'podCapacity':int(node['status']['allocatable']['pods']),
            'activePods':sum(p['spec'].get('nodeName')==node['metadata']['name'] and p['status'].get('phase') not in ('Succeeded','Failed') for p in pods),
            'steadyAddonPodsRequired':5}


def bootstrap(r):
    pre=r.require_stage('preflight')
    vault=r.q['vault']
    require(r.get('serviceaccount',vault['serviceAccount'],vault['enrollmentNamespace']) is not None,'create the external scoped Vault enrollment identity described in quickstart.md before bootstrap')
    from types import SimpleNamespace
    from .release import module
    adapter=module('key_enrollment').Adapter(SimpleNamespace(vault_namespace=vault['namespace'],vault_pod=vault['pod'],
        enrollment_namespace=vault['enrollmentNamespace'],service_account=vault['serviceAccount'],auth_mount=vault['authMount'],role=vault['role']))
    adapter.login();adapter.token=None
    for ns in (r.ns,r.trusted):
        r.apply({'apiVersion':'v1','kind':'Namespace','metadata':{'name':ns}})
    p=r.state/'authority'
    if not p.exists():
        spec=importlib.util.spec_from_file_location('quickstart_trust',ROOT/'components/inference-release/trust.py')
        mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
        mod.create(p,r.out/'trust',r.name+'-authority.'+r.trusted+'.svc',r.name)
    require((p/'approval.key').is_file() and (r.out/'trust/authority.json').is_file(),'partial authority bootstrap; retain state and diagnose')
    values=r.resolved();values['approvalKeys']=json.loads((r.out/'trust/approval-keys.json').read_text());r.save_values(values)
    # Only private TLS/receipt keys, submitted via stdin; approval signer stays local/trusted.
    r.apply({'apiVersion':'v1','kind':'Secret','metadata':{'name':r.name+'-authority-credentials','namespace':r.trusted},
             'type':'Opaque','data':{n:base64.b64encode((p/n).read_bytes()).decode() for n in ('tls.key','receipt.key')}},sensitive=True)
    for ns in (r.ns,r.trusted):
        r.apply({'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':'registry-ca','namespace':ns,
                    'annotations':{'service.beta.openshift.io/inject-cabundle':'true'}}})
    r.wait('registry CA injection',lambda: (r.get('configmap','registry-ca',r.ns) or {}).get('data',{}).get('service-ca.crt'))
    # Preparation uses no cluster-admin token. Build service account is OpenShift's managed builder.
    for name in ('quickstart-preparation','quickstart-reader','quickstart-enroller'):
        r.apply({'apiVersion':'v1','kind':'ServiceAccount','metadata':{'name':name,'namespace':r.trusted},'automountServiceAccountToken':False})
    return {'state':'BootstrapReady','clusterUID':pre['clusterUID'],
            'namespaces':{ns:r.get('namespace',ns)['metadata']['uid'] for ns in (r.ns,r.trusted)},
            'approvalKeyId':r.name,'authorityHostname':r.name+'-authority.'+r.trusted+'.svc'}
