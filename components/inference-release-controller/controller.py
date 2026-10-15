"""Trusted sequential release orchestration; no key bytes in API status or logs."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import time
import urllib.error
import urllib.request

GROUP='inference.confidentialcontainers.org'
VERSION='v1alpha1'
STAGES=('model','volumes','measure','enroll','deploy','test-first','test-reopen','report')
PHASES=('Preparing','Binding','Measuring','Enrolling','Approving','Verifying','Verifying','Ready')

def canonical(obj):return json.dumps(obj,sort_keys=True,separators=(',',':')).encode()
def digest(obj):return hashlib.sha256(canonical(obj)).hexdigest()
def require(ok,message):
    if not ok:raise ValueError(message)

class API:
    def __init__(self):
        sa=Path('/var/run/secrets/kubernetes.io/serviceaccount')
        self.sa=sa
        self.root='https://'+os.environ['KUBERNETES_SERVICE_HOST']+':'+os.environ.get('KUBERNETES_SERVICE_PORT_HTTPS','443')
        self.context=ssl.create_default_context(cafile=str(sa/'ca.crt'))
    def call(self,method,path,obj=None):
        req=urllib.request.Request(self.root+path,method=method,data=None if obj is None else canonical(obj),
            headers={'Authorization':'Bearer '+(self.sa/'token').read_text().strip(),'Content-Type':'application/json'})
        try:
            with urllib.request.urlopen(req,context=self.context,timeout=20) as response:return json.load(response)
        except urllib.error.HTTPError as e:
            if e.code==404:return None
            if e.code==409:raise Conflict() from None
            raise RuntimeError('API request failed: HTTP '+str(e.code)) from None
class Conflict(Exception):pass

def core(ns,kind,name=''):return '/api/v1/namespaces/'+ns+'/'+kind+('/'+name if name else '')
def releases(ns,name=''):return '/apis/'+GROUP+'/'+VERSION+'/namespaces/'+ns+'/inferencereleases'+('/'+name if name else '')
def jobs(ns,name=''):return '/apis/batch/v1/namespaces/'+ns+'/jobs'+('/'+name if name else '')

def validate(release,site,policy):
    meta=release['metadata'];spec=release['spec']
    require(meta['name']==policy['releaseName'] and meta['namespace']==policy['namespace'],'ReleaseOutsideGrant')
    require(set(spec)=={'siteConfigRef','acceptance'},'UnknownReleaseFields')
    ref=spec['siteConfigRef']
    require(ref=={'name':policy['siteConfigMap'],'key':'values.json','sha256':policy['siteSha256']},'SiteOutsideGrant')
    require(site.get('immutable') is True,'SiteMustBeImmutable')
    values=json.loads(site['data']['values.json'])
    require(digest(values)==ref['sha256'],'SiteDigestMismatch')
    require(spec['acceptance']=={'mode':'FreshDemo','allowTestVMReplacement':True},'ExplicitAcceptanceRequired')
    require(values['installation']['namespace']==policy['workloadNamespace'],'WrongWorkloadNamespace')
    require(values['quickstart']['trustedNamespace']==policy['namespace'],'WrongTrustedNamespace')
    require(values['demo']['name']==policy['releaseName'],'WrongRunIdentity')
    require(re.fullmatch(r'[^\s@]+@sha256:[a-f0-9]{64}',policy['image']),'UnpinnedExecutor')
    return values

def job_name(release,stage,retry):
    return 'ir-'+release['metadata']['uid'].replace('-','')[:16]+'-'+str(STAGES.index(stage))+'-'+hashlib.sha256(retry.encode()).hexdigest()[:8]

def job(release,policy,stage,retry):
    name=job_name(release,stage,retry);ns=policy['namespace']
    env=[{'name':k,'value':v} for k,v in {'RELEASE_NAME':release['metadata']['name'],
        'RELEASE_NAMESPACE':ns,'RELEASE_UID':release['metadata']['uid'],'RELEASE_SPEC_SHA256':digest(release['spec']),
        'STAGE':stage,'JOB_NAME':name,'QUICKSTART_STATE_ROOT':'/state/private',
        'QUICKSTART_OUTPUT_ROOT':'/state/output','QUICKSTART_CACHE':'/state/cache',
        'QUICKSTART_EXECUTOR':'controller','PYTHONDONTWRITEBYTECODE':'1','HOME':'/tmp',
        'GIT_ASKPASS':'/opt/pattern/components/inference-release-controller/git-askpass.py','GIT_TERMINAL_PROMPT':'0',
        'GIT_CONFIG_COUNT':'2','GIT_CONFIG_KEY_0':'url.https://github.com/.insteadOf',
        'GIT_CONFIG_VALUE_0':'git@github.com:','GIT_CONFIG_KEY_1':'credential.helper','GIT_CONFIG_VALUE_1':'',
        'GIT_AUTHOR_NAME':'Confidential inference release','GIT_AUTHOR_EMAIL':'inference-release@localhost',
        'GIT_COMMITTER_NAME':'Confidential inference release','GIT_COMMITTER_EMAIL':'inference-release@localhost'}.items()]
    return {'apiVersion':'batch/v1','kind':'Job','metadata':{'name':name,'namespace':ns,
        'labels':{'inference.confidentialcontainers.org/release-uid':release['metadata']['uid']}},
        'spec':{'backoffLimit':0,'activeDeadlineSeconds':14400,'template':{'metadata':{'annotations':{'openshift.io/required-scc':'restricted-v2'},'labels':{'coco.io/skip-initdata':'true'}},'spec':{
        'serviceAccountName':policy['stageServiceAccount'],'restartPolicy':'Never',
        'securityContext':{'runAsNonRoot':True,'fsGroupChangePolicy':'OnRootMismatch','seccompProfile':{'type':'RuntimeDefault'}},
        'containers':[{'name':'stage','image':policy['image'],'command':['python3','/opt/pattern/components/inference-release-controller/worker.py'],
        'env':env,'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},
        'resources':{'requests':{'cpu':'100m','memory':'256Mi'},'limits':{'cpu':'2','memory':'2Gi'}},
        'volumeMounts':[{'name':'state','mountPath':'/state'},{'name':'site','mountPath':'/site','readOnly':True},
            {'name':'git','mountPath':'/credentials','readOnly':True},{'name':'tmp','mountPath':'/tmp'}]}],
        'volumes':[{'name':'state','persistentVolumeClaim':{'claimName':policy['stateClaim']}},
            {'name':'site','configMap':{'name':policy['siteConfigMap']}},
            {'name':'git','secret':{'secretName':policy['gitCredentialsSecret'],'defaultMode':288}},
            {'name':'tmp','emptyDir':{}}]}}}}

def valid_receipt(cm,release,stage,site_sha,jobobj):
    require(cm and cm.get('immutable') is True,'MissingStageReceipt')
    receipt=json.loads(cm['data']['receipt.json'])
    require(receipt['releaseUID']==release['metadata']['uid'] and receipt['specSha256']==digest(release['spec']) and
        receipt['siteSha256']==site_sha and receipt['stage']==stage and receipt['jobUID']==jobobj['metadata']['uid'],'ReceiptIdentityMismatch')
    states={'model':'ModelPublished','volumes':'VolumesBound','measure':'ReleaseMeasured','enroll':'TrustReady','deploy':'Serving','test-first':'FirstBootPassed','test-reopen':'FreshVMPersistencePassed','report':'E2EPassed'}
    require(receipt['state']==states[stage],'WrongStageOutcome')
    return receipt

class Reconciler:
    def __init__(self,api,policy,identity):self.api,self.policy,self.identity=api,policy,identity
    def lease(self,release):
        ns=self.policy['namespace'];name='ir-'+release['metadata']['uid'].replace('-','')[:24]
        path='/apis/coordination.k8s.io/v1/namespaces/'+ns+'/leases'
        old=self.api.call('GET',path+'/'+name);now=time.time()
        if old:
            spec=old['spec'];stamp=spec.get('renewTime','1970-01-01T00:00:00Z')
            import datetime
            renewed=datetime.datetime.fromisoformat(stamp.replace('Z','+00:00')).timestamp()
            if spec['holderIdentity']!=self.identity and renewed+spec['leaseDurationSeconds']>now:return False
        obj={'apiVersion':'coordination.k8s.io/v1','kind':'Lease','metadata':{'name':name,'namespace':ns},
            'spec':{'holderIdentity':self.identity,'leaseDurationSeconds':30,'renewTime':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(now))}}
        if old:obj['metadata']['resourceVersion']=old['metadata']['resourceVersion']
        try:self.api.call('PUT' if old else 'POST',path+'/'+name if old else path,obj)
        except Conflict:return False
        return True
    def status(self,release,phase,reason,completed,stage=None):
        state={'observedGeneration':release['metadata']['generation'],'inputSha256':digest(release['spec']),
               'phase':phase,'reason':reason,'completed':completed,'currentStage':stage,
               'conditions':[{'type':'Ready','status':'True' if phase=='Ready' else 'False',
                   'reason':reason,'observedGeneration':release['metadata']['generation']}]}
        if release.get('status')==state:return
        updated=copy.deepcopy(release);updated['status']=state
        self.api.call('PUT',releases(self.policy['namespace'],release['metadata']['name'])+'/status',updated)
    def reconcile(self,release):
        if release['metadata'].get('deletionTimestamp'):return
        if not self.lease(release):return
        completed=[]
        try:
            site=self.api.call('GET',core(self.policy['namespace'],'configmaps',self.policy['siteConfigMap']))
            validate(release,site,self.policy)
            prior=release.get('status',{})
            require(not prior.get('inputSha256') or prior['inputSha256']==digest(release['spec']),'ImmutableReleaseChanged')
            for stage in STAGES:
                # Completed jobs/receipts are stable history even after an operator changes retry nonce.
                old=next((x for x in prior.get('completed',[]) if x['stage']==stage),None)
                retry=release['metadata'].get('annotations',{}).get(GROUP+'/retry','initial')
                require(len(retry)<=64,'RetryTokenTooLong')
                name=old['job'] if old else job_name(release,stage,retry)
                obj=self.api.call('GET',jobs(self.policy['namespace'],name))
                if not obj:
                    require(old is None,'CompletedJobMissing')
                    # A different failed attempt is allowed only after its Pod is gone.
                    alljobs=self.api.call('GET',jobs(self.policy['namespace']))['items']
                    for j in alljobs:
                        if j['metadata'].get('labels',{}).get(GROUP+'/release-uid')==release['metadata']['uid']:
                            require(not j.get('status',{}).get('active',0),'PriorJobStillActive')
                    pods=self.api.call('GET',core(self.policy['namespace'],'pods'))['items']
                    related={j['metadata']['uid'] for j in alljobs if j['metadata'].get('labels',{}).get(GROUP+'/release-uid')==release['metadata']['uid']}
                    require(not any(p.get('status',{}).get('phase') not in ('Succeeded','Failed') and any(o['uid'] in related for o in p['metadata'].get('ownerReferences',[])) for p in pods),'PriorJobPodStillActive')
                    try:self.api.call('POST',jobs(self.policy['namespace']),job(release,self.policy,stage,retry))
                    except Conflict:pass
                    self.status(release,PHASES[STAGES.index(stage)] if stage!='report' else 'Verifying','StageScheduled',completed,stage);return
                require(obj['metadata'].get('labels',{}).get(GROUP+'/release-uid')==release['metadata']['uid'],'ForeignJob')
                conditions=obj.get('status',{}).get('conditions',[])
                if any(c['type']=='Failed' and c['status']=='True' for c in conditions):
                    self.status(release,'Blocked','StageFailedExplicitRetryRequired',completed,stage);return
                if not any(c['type']=='Complete' and c['status']=='True' for c in conditions):
                    self.status(release,'Progressing','StageRunning',completed,stage);return
                cm=self.api.call('GET',core(self.policy['namespace'],'configmaps',name+'-receipt'))
                receipt=valid_receipt(cm,release,stage,self.policy['siteSha256'],obj)
                for pod in self.api.call('GET',core(self.policy['namespace'],'pods'))['items']:
                    if pod.get('status',{}).get('phase')=='Succeeded' and any(o['uid']==obj['metadata']['uid'] for o in pod['metadata'].get('ownerReferences',[])):
                        self.api.call('DELETE',core(self.policy['namespace'],'pods',pod['metadata']['name']),{'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':pod['metadata']['uid']}})
                completed.append({'stage':stage,'job':name,'receipt':name+'-receipt','receiptSha256':digest(receipt)})
            evidence=json.loads(cm['data']['e2e-report.json'])['reopen']
            pod=self.api.call('GET',core(self.policy['workloadNamespace'],'pods',evidence['pod']))
            require(pod and pod['metadata']['uid']==evidence['podUid'],'VerifiedPredictorReplaced')
            ready=pod.get('status',{}).get('containerStatuses',[])
            require(not pod['metadata'].get('deletionTimestamp') and ready and all(c['ready'] for c in ready),'PredictorNotReady')
            for name,uid in evidence['pvcUids'].items():
                claim=self.api.call('GET',core(self.policy['workloadNamespace'],'persistentvolumeclaims',name))
                require(claim and claim['metadata']['uid']==uid,'VerifiedClaimReplaced')
            self.status(release,'Ready','E2EPassed',completed)
        except (ValueError,KeyError,TypeError,AttributeError) as e:
            self.status(release,'Blocked',str(e) if isinstance(e,ValueError) and re.fullmatch('[A-Za-z]+',str(e)) else 'InvalidReleaseArtifact',completed)

def main():
    policy=json.loads(Path('/configuration/policy.json').read_text());api=API()
    reconciler=Reconciler(api,policy,os.environ['POD_UID'])
    while True:
        try:
            release=api.call('GET',releases(policy['namespace'],policy['releaseName']))
            if release:reconciler.reconcile(release)
        except Conflict:pass
        except Exception:print('RELEASE_RECONCILE_RETRY',flush=True)
        time.sleep(5)
if __name__=='__main__':main()
