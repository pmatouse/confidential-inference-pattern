"""Explicit trusted preparation, enrollment and deployment stages."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import sys
import time
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization

import addon
from .core import ROOT, require, sha, write
from . import build as builders


def module(name):
    path=ROOT/'components/inference-release'
    if str(path) not in sys.path:sys.path.insert(0,str(path))
    spec=importlib.util.spec_from_file_location('qs_release_'+name,path/(name+'.py'))
    obj=importlib.util.module_from_spec(spec);spec.loader.exec_module(obj);return obj


def authority_values(r,serve=False):
    values={'installation':r.installation,'image':r.read('images.json')['authority']['image'],
            'state':{'storageClassName':r.v['base']['storageClassName'],'size':'1Gi'},'mode':'serve' if serve else 'bootstrap'}
    if serve:
        cm=r.get('configmap',r.name+'-authority-public',r.trusted)
        values.update(publicConfigMap=r.name+'-authority-public',credentialsSecret=r.name+'-authority-credentials',
                      publicConfigSha256=sha(json.dumps(cm['data'],sort_keys=True,separators=(',',':')).encode()))
    return values


def retry_failed_job(r,name):
    job=r.get('job',name,r.trusted)
    if job and any(c['type']=='Failed' and c['status']=='True' for c in job.get('status',{}).get('conditions',[])):
        require(job['metadata'].get('labels',{}).get(addon.OWNER)==r.installation,'refusing foreign failed Job')
        require(not job['status'].get('active',0),'failed Job still active')
        r.save('failed-job-'+name+'.json',{'uid':job['metadata']['uid'],'conditions':job['status']['conditions']})
        r.oc('delete','job',name,'-n',r.trusted,'--wait=true',timeout=120)


def install(r):
    r.require_stage('push');v=r.resolved()
    builders.cleanup_build_pods(r)
    addon.preflight(v,r.api);addon.apply_objects(addon.foundation(v),v,r.api)
    for name in ('confidential-volume-controller','encrypted-model-populator'):
        r.oc('rollout','status','deployment/'+name,'-n',r.ns,'--timeout=300s',timeout=330)
    # Only named streams, only trusted preparation/authority service accounts.
    role=r.name+'-trusted-pull'
    r.apply({'apiVersion':'rbac.authorization.k8s.io/v1','kind':'Role','metadata':{'name':role,'namespace':r.ns},
             'rules':[{'apiGroups':['image.openshift.io'],'resources':['imagestreams/layers'],
                       'resourceNames':['confidential-storage-authority','inference-preparation'],'verbs':['get']}]})
    r.apply({'apiVersion':'rbac.authorization.k8s.io/v1','kind':'RoleBinding','metadata':{'name':role,'namespace':r.ns},
             'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':role},
             'subjects':[{'kind':'ServiceAccount','name':name,'namespace':r.trusted} for name in (r.name+'-authority','quickstart-preparation','quickstart-enroller')]})
    retry_failed_job(r,r.name+'-authority-bootstrap')
    r.helm('charts/storage-authority',authority_values(r),r.trusted,r.name+'-authority')
    r.oc('wait','-n',r.trusted,'--for=condition=Complete','job/'+r.name+'-authority-bootstrap','--timeout=300s',timeout=330)
    claim=r.get('pvc',r.name+'-authority-state',r.trusted)
    return {'state':'FoundationReady','authorityClaimUID':claim['metadata']['uid'],
            'controllers':{n:r.get('deployment',n,r.ns)['metadata']['uid'] for n in ('confidential-volume-controller','encrypted-model-populator')}}


def publisher(r):
    values={'workloadNamespace':r.ns,'modelImageStream':r.name+'-model','helperImageStream':'confidential-storage-sidecar',
            'publisherServiceAccount':'quickstart-preparation','readerName':'quickstart-reader','registryCAConfigMap':'registry-ca',
            'image':r.read('images.json')['preparation']['image']}
    pod=r.name+'-publisher'
    r.helm('charts/model-publisher',values,r.trusted,pod)
    r.oc('wait','-n',r.trusted,'--for=condition=Ready','pod/'+pod,'--timeout=300s',timeout=330)
    return pod


def private_key(r,name):
    path=r.state/(name+'.key')
    if not path.exists():write(path,os.urandom(32))
    require(not path.is_symlink() and path.stat().st_mode&0o077==0 and len(path.read_bytes())==32,'invalid retained private key')
    return path


def remove_publisher(r):
    pod=r.get('pod',r.name+'-publisher',r.trusted)
    if pod:
        require(pod['metadata'].get('labels',{}).get(addon.OWNER)==r.installation,'foreign preparation Pod')
        r.oc('delete','pod',pod['metadata']['name'],'-n',r.trusted,'--wait=false')


def model(r):
    r.require_stage('install')
    saved=r.receipt('model')
    if not saved and (r.state/'model-committed.json').exists():saved={'result':r.read('model-committed.json',private=True)}
    if saved:
        source=r.read('model-source.json');require(source==r.resolved()['demo']['source'],'model source changed')
        # Immutable model identity remains; do not recreate keys or plaintext on a serving retry.
        for name in ('model','data'):require((r.state/(name+'.key')).is_file(),'missing retained key')
        remove_publisher(r)
        return saved['result']
    pod=publisher(r)
    model_key=private_key(r,'model');private_key(r,'data')
    script="import os,sys; p='/build/model.key'; data=sys.stdin.buffer.read(); assert len(data)==32; os.umask(0o077); exists=os.path.exists(p); assert not exists or open(p,'rb').read()==data; None if exists else open(p,'xb').write(data)"
    r.oc('exec','-i','-n',r.trusted,pod,'--','python3','-c',script,body=model_key.read_bytes(),binary=True,sensitive=True)
    prep='''exec 9>/build/model-preparation.lock
flock -n 9
cd /opt/preparation
if [ ! -d /build/tools-fetch ]; then
  rm -rf /build/tools-fetch.partial
  python3 components/model-publisher/fetch_tools.py --work /build/tools-fetch.partial
  mv /build/tools-fetch.partial /build/tools-fetch
fi
if [ ! -f /build/encrypted/guest-manifest.unsigned.json ]; then
  if [ ! -f /build/qwen/publisher-source.json ]; then
    rm -rf /build/qwen.partial
    python3 components/encrypted-model-populator/fetch_qwen.py --model /build/qwen.partial
    mv /build/qwen.partial /build/qwen
  fi
  rm -rf /build/encrypted.partial
  python3 components/encrypted-model-populator/prepare.py --tools /build/tools-fetch/tools --model /build/qwen --key /build/model.key --work /build/encrypted.partial
  mv /build/encrypted.partial /build/encrypted
fi
'''
    builders.execute(r,pod,prep,timeout=7200)
    descriptor=json.loads(r.oc('exec','-n',r.trusted,pod,'--','cat','/build/encrypted/guest-manifest.unsigned.json'))
    r.save('model-descriptor.json',descriptor)
    publish='''exec 9>/build/model-preparation.lock
flock -n 9
cd /opt/preparation
if [ ! -f /build/oci/source.json ]; then
  rm -rf /build/oci.partial
  python3 components/encrypted-model-populator/publish.py --disk /build/encrypted/volume.raw --work /build/oci.partial --registry %s --repository %s --ca /registry-ca/service-ca.crt --token /registry-auth/token
  mv /build/oci.partial /build/oci
fi
'''%(shlex.quote(r.v['registry']['origin']),shlex.quote(r.ns+'/'+r.name+'-model'))
    builders.execute(r,pod,publish,timeout=3600)
    source=json.loads(r.oc('exec','-n',r.trusted,pod,'--','cat','/build/oci/source.json'))
    require(set(source)=={'format','repository','manifestDigest','diskDigest','diskBytes'},'unexpected publisher receipt')
    r.save('model-source.json',source);v=r.resolved();v['demo']['source']=source;r.save_values(v)
    # Remove only producer plaintext/key-bearing scratch, retain ciphertext receipt for recovery.
    builders.execute(r,pod,'rm -rf /build/qwen /build/encrypted/root /build/encrypted/initrd.gz /build/encrypted/plaintext.ext4 /build/model.key')
    result={'state':'ModelPublished','source':source,'descriptorSha256':sha((r.out/'model-descriptor.json').read_bytes())}
    r.save('model-committed.json',result,private=True)
    remove_publisher(r)
    return result


def volumes(r):
    r.require_stage('model');v=r.resolved()
    old=r.receipt('volumes')
    if old:
        for n,uid in old['result']['claims'].items():require((r.get('pvc',n,r.ns) or {}).get('metadata',{}).get('uid')==uid,'retained claim replaced')
        return old['result']
    expected={r.name+'-model',r.name+'-data'}
    reservation=r.state/'claim-reservation.json'
    if not reservation.exists():
        require(all(r.get('pvc',n,r.ns) is None for n in expected),'fresh release requires absent model/data claims')
        write(reservation,{'names':sorted(expected),'run':r.name})
    addon.apply_objects([addon.owned(o,v) for o in addon.image_access(v)]+addon.provision(v),v,r.api)
    for name in sorted(expected):
        r.wait('Bound '+name,lambda n=name:(r.get('pvc',n,r.ns) or {}).get('status',{}).get('phase')=='Bound',timeout=1800,interval=10)
    # The provisioned binding Job is the single writer; do not race it with a second local binder.
    r.oc('wait','-n',r.ns,'--for=condition=Complete','job/'+r.name+'-binding','--timeout=300s',timeout=330)
    claims={n:r.get('pvc',n,r.ns)['metadata']['uid'] for n in expected}
    # Binder/workload controller owns public request generation.
    def request():
        cms=r.get('configmaps',ns=r.ns)['items']
        found=[]
        for cm in cms:
            raw=cm.get('data',{}).get('request.json')
            if raw:
                obj=json.loads(raw)
                if obj.get('contract',{}).get('namespace')==r.ns and {x['uid'] for x in obj.get('claims',[])}==set(claims.values()):found.append(obj)
        require(len(found)<=1,'ambiguous release requests')
        return found[0] if found else None
    req=r.wait('approval request',request,timeout=300)
    r.save('request.json',req);r.save('blank-uids.json',[claims[r.name+'-data']])
    return {'state':'VolumesBound','claims':claims,'requestSha256':sha(json.dumps(req,sort_keys=True,separators=(',',':')).encode())}


def measure(r):
    r.require_stage('volumes')
    # The measurement calculation is derived from approved bytes and fixed profile parameters.
    lock=json.loads((ROOT/'profiles/runtime/osc-snp-nvidia-artifacts.json').read_text())
    path=r.cache/'build'
    for key,item in lock['files'].items():require(sha((path/key).read_bytes())==item['sha256'],'stock artifact changed before measurement')
    from sevsnpmeasure.guest import snp_calc_launch_digest
    from sevsnpmeasure.vcpu_types import CPU_SIGS
    measured=snp_calc_launch_digest(vcpus=lock['vcpus'],vcpu_sig=CPU_SIGS[lock['vcpuSignature']],guest_features=lock['guestFeatures'],
        append=lock['append'],ovmf_hash_str='',ovmf_file=str(path/'ovmf'),kernel=str(path/'kernel'),initrd=str(path/'initrd')).hex()
    runtime={'runtimeClassName':r.v['base']['runtimeClassName'],'guestImageSha256':lock['files']['initrd']['sha256'],
             'launchMeasurement':measured,'initDataSha256':'0'*64}
    r.save('runtime.json',runtime)
    im=r.read('images.json')['sidecar'];v=r.resolved()
    profile=module('profile').instantiate(json.loads((ROOT/'profiles/osc-snp-nvidia-x86_64-v1.json').read_text()),
        im['image'],r.get('service','kubernetes','default')['spec']['clusterIP'],im['build'],im['namespace'],
        r.read('model-descriptor.json'),r.name,v['demo']['modelMount'],v['demo']['dataMount'])
    draft=module('render').draft(r.read('request.json'),profile)
    models={v['demo']['approvedManifestRef']:{'descriptor':r.read('model-descriptor.json'),'source':r.read('model-source.json')}}
    planned=module('enroll').plan(r.read('request.json'),draft,models,r.read('blank-uids.json'))
    for filename,data in [('profile.json',profile),('draft.json',draft),('models.json',models),('enrollment-plan.json',planned)]:r.save(filename,data)
    return {'state':'ReleaseMeasured','launchMeasurement':measured,'policySha256':draft['policySha256']}


def enrollment_metadata(r):
    deployment=r.get('deployment',r.name+'-authority',r.trusted)
    prior=r.out/'enrollment-result.json'
    if prior.exists():return r.read('enrollment-result.json')
    require(not deployment or deployment['spec'].get('replicas',1)==0,'metadata enrollment requires authority not serving; never write its database concurrently')
    values={'installation':r.installation,'image':r.read('images.json')['authority']['image'],
            'stateClaim':r.name+'-authority-state','serviceAccount':'quickstart-enroller','plan':r.read('enrollment-plan.json')}
    job=r.name+'-enrollment'
    retry_failed_job(r,job)
    r.helm('charts/storage-enrollment',values,r.trusted,job)
    r.oc('wait','-n',r.trusted,'--for=condition=Complete','job/'+job,'--timeout=300s',timeout=330)
    log=r.oc('logs','-n',r.trusted,'job/'+job)
    entries=[]
    for line in log.splitlines():
        if line.startswith('{'):
            obj=json.loads(line)
            if 'records' in obj and 'requestSha256' in obj:entries.append(obj)
    require(len(entries)==1,'one public enrollment result required')
    r.save('enrollment-result.json',entries[0]);return entries[0]


def public_certificate(r,secret,field):
    # Fetch the specified public field, never the full secret/private-key payload.
    encoded=r.oc('get','secret',secret,'-n',r.v['base']['trusteeNamespace'],
                 '-o','go-template={{index .data '+json.dumps(field)+'}}',sensitive=True).strip()
    value=base64.b64decode(encoded,validate=True).decode()
    require(value.startswith('-----BEGIN CERTIFICATE-----'),'public certificate required')
    return value


def package_release(r,enrolled):
    t=r.q['trustee'];origin=t['origin'];ca=public_certificate(r,t['caSecret'],'tls.crt')
    signer_certificate=public_certificate(r,t['signerSecret'],'tls.crt')
    as_signer=x509.load_pem_x509_certificate(signer_certificate.encode()).public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    registry_ca=r.get('configmap','registry-ca',r.ns)['data']['service-ca.crt']
    aa='[token_configs]\n[token_configs.coco_as]\nurl = '+json.dumps(origin)+'\n[token_configs.kbs]\nurl = '+json.dumps(origin)+'\ncert = '+json.dumps(ca)+'\n'
    cdh='socket = "unix:///run/confidential-containers/cdh.sock"\ncredentials = []\n[kbc]\nname = "cc_kbc"\nurl = '+json.dumps(origin)+'\nkbs_cert = '+json.dumps(ca)+'\n[image]\nextra_root_certificates = ['+json.dumps(registry_ca)+']\nauthenticated_registry_credentials_uri = '+json.dumps('kbs:///default/model-keys/'+r.name+'-registry')+'\n'
    encodings={r.v['demo'][k]:'lower-hex64' for k in ('modelKeyResource','dataKeyResource')}
    authority=json.loads((r.out/'trust/authority.json').read_text())
    guest=module('enroll').guest_configuration(r.read('request.json'),r.read('draft.json'),r.read('enrollment-plan.json'),enrolled,authority,encodings)
    packaged=module('render').package(r.read('request.json'),r.read('draft.json'),guest,aa,cdh,r.read('runtime.json'))
    for name,raw in packaged.items():write(r.out/'release'/name,raw)
    write(r.out/'trust/trustee-ca.pem',ca);write(r.out/'trust/as-signer.pem',as_signer)
    return json.loads(packaged['runtime.json'])


HANDLERS={'install':install,'model':model,'volumes':volumes,'measure':measure}


def owner_bindings(r,runtime,tags):
    owner=r.q['trustee']['owner'];application=r.get('applications.argoproj.io',owner['application'],owner['namespace'])
    require(application and application['spec']['source']['repoURL']==owner['repository'] and application['spec']['source']['targetRevision']==owner['branch'],'Trustee GitOps owner does not match declared source')
    path=Path(owner['valuesFile']);require(not path.is_absolute() and '..' not in path.parts,'unsafe owner values path')
    require('/'+str(path) in application['spec']['source']['helm'].get('valueFiles',[]),'owner does not consume the configured values file')
    checkout=r.state/'trustee-owner'
    if not checkout.exists():r.command(['git','clone','--single-branch','--branch',owner['branch'],owner['repository'],checkout],timeout=600)
    r.command(['git','-C',checkout,'fetch','origin',owner['branch']],timeout=180)
    local=r.command(['git','-C',checkout,'rev-parse','HEAD']).strip()
    remote=r.command(['git','-C',checkout,'rev-parse','origin/'+owner['branch']]).strip()
    dirty=r.command(['git','-C',checkout,'status','--porcelain']).strip()
    require(not dirty or all(line[3:]==str(path) for line in dirty.splitlines()),'unexpected dirty Trustee owner checkout')
    if not dirty and local!=remote:
        # Fast-forward only; a locally committed previous attempt may already contain this release.
        ancestor=r.command(['git','-C',checkout,'merge-base','HEAD','origin/'+owner['branch']]).strip()
        if ancestor==local:r.command(['git','-C',checkout,'merge','--ff-only','origin/'+owner['branch']])
        else:require(ancestor==remote,'Trustee owner history diverged; reconcile explicitly')
    target=checkout/path;text=target.read_text();values=yaml.load(text,Loader=addon.UniqueLoader)
    bindings=values['kbs']['resourcePolicy']['modelKeyBindings']
    wanted={'launchMeasurement':runtime['launchMeasurement'],'initData':runtime['initDataSha256']}
    missing=[]
    for tag in tags:
        require(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}',tag),'invalid resource tag')
        if tag in bindings:require(bindings[tag]==wanted,'existing resource tag has another binding')
        else:missing.append(tag)
    if missing:
        marker='    modelKeyBindings:\n';require(text.count(marker)==1,'owner chart needs an explicit modelKeyBindings map')
        addition=''.join('      '+tag+':\n        launchMeasurement: '+json.dumps(wanted['launchMeasurement'])+'\n        initData: '+json.dumps(wanted['initData'])+'\n' for tag in sorted(missing))
        text=text.replace(marker,marker+addition)
        parsed=yaml.load(text,Loader=addon.UniqueLoader)
        expected=copy.deepcopy(values);expected['kbs']['resourcePolicy']['modelKeyBindings'].update({t:wanted for t in missing})
        require(parsed==expected,'owner edit changed unrelated configuration')
        target.write_text(text)
    if r.command(['git','-C',checkout,'status','--porcelain']).strip():
        r.command(['git','-C',checkout,'add','--',str(path)])
        r.command(['git','-C',checkout,'commit','-m','Enroll exact quickstart attestation bindings for '+r.name],timeout=180)
    commit=r.command(['git','-C',checkout,'rev-parse','HEAD']).strip()
    r.command(['git','-C',checkout,'push','origin','HEAD:'+owner['branch']],timeout=180)
    r.oc('annotate','applications.argoproj.io',owner['application'],'-n',owner['namespace'],'argocd.argoproj.io/refresh=hard','--overwrite')
    from importlib import import_module
    adapter=module('key_enrollment')
    def loaded():
        cm=r.get('configmap','resource-policy',r.v['base']['trusteeNamespace']);policy=cm['data']['resource-policy.rego']
        try:adapter.validate_bindings(policy,sha(policy.encode()),runtime,tags)
        except ValueError:return None
        return policy
    policy=r.wait('owner-managed exact Trustee bindings',loaded,timeout=600,interval=5)
    r.save('trustee-owner.json',{'commit':commit,'application':owner['application'],'policySha256':sha(policy.encode()),'tags':tags})
    return sha(policy.encode())


def registry_credential(r):
    path=r.state/'registry-auth.json'
    if path.exists():
        require(r.read('registry-credential.json')['expiresAt']>time.time()+3600,'registry credential expires within an hour; renew it through the backend before continuing')
        return path
    raw=r.oc('create','token','quickstart-reader','-n',r.trusted,'--duration=24h',sensitive=True).strip()
    claims=json.loads(base64.urlsafe_b64decode(raw.split('.')[1]+'==='))
    require(claims['exp']>time.time()+3600,'registry token lifetime too short')
    host=r.v['registry']['origin'].removeprefix('https://')
    write(path,{'auths':{host:{'auth':base64.b64encode(('serviceaccount:'+raw).encode()).decode()}}})
    r.save('registry-credential.json',{'expiresAt':claims['exp'],'namespace':r.trusted,'serviceAccount':'quickstart-reader','scope':'GET helper ImageStream layers'})
    return path


def trustee_pod(r):
    deployment=r.get('deployment',r.q['trustee']['deployment'],r.v['base']['trusteeNamespace'])
    selector=deployment['spec']['selector']['matchLabels']
    pods=r.get('pods',ns=r.v['base']['trusteeNamespace'])['items']
    active=[p for p in pods if all(p['metadata'].get('labels',{}).get(k)==v for k,v in selector.items()) and not p['metadata'].get('deletionTimestamp') and p['status'].get('phase')=='Running' and p['status'].get('containerStatuses') and all(c['ready'] for c in p['status']['containerStatuses'])]
    return active[0] if len(active)==1 else None


def verify_loaded_keys(r,values,pod=None):
    pod=pod or trustee_pod(r)
    if not pod:return False
    # Trustee's Secret converter flattens resource paths using literal \x2F.
    base='/opt/confidential-containers/storage/repository/'
    paths=[base+('default/model-keys/'+t).replace('/',r'\x2F') for t in sorted(values)]
    # Hash via stdin to avoid sha256sum's filename escaping; never read key bytes back.
    args=['exec','-n',r.v['base']['trusteeNamespace'],pod['metadata']['name'],'-c','kbs','--',
          'sh','-c','for path do sha256sum < "$path" || exit; done','check-resources',*paths]
    try:result=r.oc(*args,sensitive=True)
    except RuntimeError:return False
    actual=[line.split()[0] for line in result.splitlines()]
    return actual==[sha(values[tag]) for tag in sorted(values)]


def ensure_loaded_keys(r,expected):
    # Updating owner-managed policy can roll Trustee while keys are projected.
    # Wait for that rollout before deciding whether a separate restart is needed.
    pod=r.wait('healthy Trustee after owner reconciliation',lambda:trustee_pod(r),timeout=600,interval=5)
    if verify_loaded_keys(r,expected,pod):return pod
    require(r.q.get('allowTrusteeRestart') is True,'keys projected but KBS not loaded; allow one controlled Trustee restart in site inputs')
    pending=r.state/'trustee-restart.json'
    if not pending.exists():write(pending,{'pod':pod['metadata']['name'],'uid':pod['metadata']['uid']})
    old=json.loads(pending.read_text());current=r.get('pod',old['pod'],r.v['base']['trusteeNamespace'])
    if current and not current['metadata'].get('deletionTimestamp'):
        require(current['metadata']['uid']==old['uid'],'restart Pod identity changed')
        r.oc('delete','pod',old['pod'],'-n',r.v['base']['trusteeNamespace'],'--wait=false','--ignore-not-found=true')
    def loaded():
        current=trustee_pod(r)
        if current and current['metadata']['uid']!=old['uid'] and verify_loaded_keys(r,expected,current):return current
        return None
    return r.wait('replacement Trustee with exact loaded resources',loaded,timeout=600,interval=5)


def enroll(r):
    r.require_stage('measure')
    enrolled=enrollment_metadata(r);runtime=package_release(r,enrolled)
    tags=[r.v['demo'][k].split('/')[-1] for k in ('modelKeyResource','dataKeyResource')]+[r.name+'-registry']
    require(all(r.v['demo'][k].startswith('kbs:///default/model-keys/') for k in ('modelKeyResource','dataKeyResource')),'qualified owner adapter requires default/model-keys resources')
    policy_sha=owner_bindings(r,runtime,tags)
    credential=registry_credential(r)
    mapping={tags[0]:str(private_key(r,'model')),tags[1]:str(private_key(r,'data')),tags[2]:{'path':str(credential),'encoding':'registry-json'}}
    write(r.state/'key-files.json',mapping)
    vault=r.q['vault'];require(vault['backendPath']=='secret/data/hub/modelKeys','this backend adapter requires the declared standard VP modelKeys mapping')
    expected={tags[0]:private_key(r,'model').read_bytes().hex().encode(),tags[1]:private_key(r,'data').read_bytes().hex().encode(),tags[2]:credential.read_bytes()}
    if not r.receipt('enroll'):
        command=[sys.executable,ROOT/'components/inference-release/key_enrollment.py','--key-files',r.state/'key-files.json','--runtime',r.out/'release/runtime.json','--journal',r.state/'key-enrollment.json','--policy-sha256',policy_sha]
        for cli,key in [('vault-namespace','namespace'),('vault-pod','pod'),('enrollment-namespace','enrollmentNamespace'),('service-account','serviceAccount'),('auth-mount','authMount'),('role','role'),('external-secret','externalSecret'),('secret','projectionSecret')]:command+=['--'+cli,vault[key]]
        command+=['--trustee-namespace',r.v['base']['trusteeNamespace']]
        r.command(command,timeout=600,sensitive=True)
    pod=ensure_loaded_keys(r,expected)
    return {'state':'TrustReady','policySha256':policy_sha,'runtime':runtime,'tags':tags,'trusteePodUID':pod['metadata']['uid']}


def deploy(r):
    trust=r.require_stage('enroll');v=r.resolved()
    node=r.require_stage('preflight')['node'];resource=v['base']['gpuResourceName']
    pods=json.loads(r.oc('get','pods','-A','-o','json',sensitive=True))['items']
    used=sum(int(c.get('resources',{}).get('requests',{}).get(resource,0)) for p in pods
             if p['spec'].get('nodeName')==node and p['status'].get('phase') not in ('Failed','Succeeded')
             and not (p['metadata']['namespace']==r.ns and p['metadata'].get('labels',{}).get('serving.kserve.io/inferenceservice')==r.name)
             for c in p['spec']['containers'])
    require(used<int(r.get('node',node)['status']['allocatable'][resource]),'no free GPU; operator must explicitly free capacity before qs-deploy')
    authority=json.loads((r.out/'trust/authority.json').read_text())
    runtime=json.loads((r.out/'release/runtime.json').read_text())
    config={'database':'/state/retained/authority.db','policy_sha256':r.read('draft.json')['policySha256'],'init_data':runtime['initDataSha256'],
      'audience':authority['audience'],'as_signer':'/config/as-signer.pem','as_issuer':'CoCo-Attestation-Service','as_issuer_claim':'absent-rcar',
      'as_gpu_binding':'nvidia-nonce-match','appraisals':[{'configuration':3,'policy_id':'default','submod':'cpu0','tee':'snp'},{'configuration':3,'policy_id':'default','submod':'gpu0','tee':'nvidia'}],
      'listen':{'host':'0.0.0.0','port':8443},'receipt_issuer':r.name,'receipt_key':'/private/receipt.key','receipt_key_id':'receipt-v1',
      'tls_certificate':'/config/tls.pem','tls_key':'/private/tls.key',
      'trustee_rcar':{'address':None,'ca_file':'/config/trustee-ca.pem','init_data_file':'/config/initdata.toml','origin':r.q['trustee']['origin'],'policy_selector':None}}
    data={'server.json':json.dumps(config),'initdata.toml':(r.out/'release/initdata.toml').read_text()}
    data.update({name:(r.out/'trust'/name).read_text() for name in ('tls.pem','as-signer.pem','trustee-ca.pem')})
    r.apply({'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':r.name+'-authority-public','namespace':r.trusted},'data':data})
    r.helm('charts/storage-authority',authority_values(r,True),r.trusted,r.name+'-authority')
    r.oc('rollout','status','deployment/'+r.name+'-authority','-n',r.trusted,'--timeout=300s',timeout=330)
    approval=r.state/'deployment-approval.json'
    if not approval.exists():r.command([sys.executable,ROOT/'components/confidential-volume-controller/approve.py','--request',r.out/'request.json','--artifacts',r.out/'release','--key',r.state/'authority/approval.key','--key-id',r.name,'--lifetime','604800','--output',approval])
    r.apply(json.loads(approval.read_text()))
    def ready():
        obj=r.get('inferenceservice',r.name,r.ns)
        return obj if obj and any(c['type']=='Ready' and c['status']=='True' for c in obj.get('status',{}).get('conditions',[])) else None
    service=r.wait('confidential KServe predictor Ready',ready,timeout=1800,interval=10)
    addon.apply_objects([addon.owned(o,v) for o in addon.helm(ROOT/'charts/inference-chat',v,r.ns)],v,r.api)
    r.oc('rollout','status','deployment/'+r.name+'-chat','-n',r.ns,'--timeout=300s',timeout=330)
    return {'state':'Serving','inferenceServiceUID':service['metadata']['uid'],'chatService':r.name+'-chat','runtime':runtime}


HANDLERS.update(enroll=enroll,deploy=deploy)
