"""Release orchestration failure/restart/ownership tests with a fake Kubernetes API."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('release_reconciler',ROOT/'components/inference-release-controller/controller.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Fake:
    def __init__(self):self.items={};self.created=[];self.version=0
    def call(self,method,path,obj=None):
        if method=='GET':
            if path in self.items:return copy.deepcopy(self.items[path])
            if path.endswith(('/jobs','/pods')):return {'items':[copy.deepcopy(x) for k,x in self.items.items() if k.rsplit('/',1)[0]==path]}
            return None
        if method=='DELETE':
            old=self.items[path]
            if old['metadata']['uid']!=obj['preconditions']['uid']:raise m.Conflict()
            del self.items[path];return {}
        obj=copy.deepcopy(obj)
        if path.endswith('/status'):
            parent=path[:-7];self.items[parent]['status']=obj['status'];return obj
        if '/leases' in path:
            import datetime
            datetime.datetime.strptime(obj['spec']['renewTime'],'%Y-%m-%dT%H:%M:%S.%fZ')
        if method=='POST':
            path+='/'+obj['metadata']['name']
            if path in self.items:raise m.Conflict()
            obj['metadata']['uid']='uid-'+str(len(self.items));self.created.append(path)
        elif method=='PUT' and obj['metadata']['resourceVersion']!=self.items[path]['metadata']['resourceVersion']:raise m.Conflict()
        self.version+=1;obj['metadata']['resourceVersion']=str(self.version);self.items[path]=obj;return copy.deepcopy(obj)

class ReleaseControllerTests(unittest.TestCase):
    def setUp(self):
        self.api=Fake();self.values={'installation':{'namespace':'work'},'quickstart':{'trustedNamespace':'trusted'},'demo':{'name':'qwen'}}
        self.policy={'releaseName':'qwen','namespace':'trusted','workloadNamespace':'work','siteConfigMap':'site','siteSha256':m.digest(self.values),
            'image':'registry/executor@sha256:'+'a'*64,'stageServiceAccount':'stage','stateClaim':'state','gitCredentialsSecret':'git'}
        self.release={'metadata':{'name':'qwen','namespace':'trusted','uid':'11111111-1111-4111-8111-111111111111','generation':1},
            'spec':{'siteConfigRef':{'name':'site','key':'values.json','sha256':m.digest(self.values)},'acceptance':{'mode':'FreshDemo','allowTestVMReplacement':True}}}
        self.rpath=m.releases('trusted','qwen');self.api.items[self.rpath]=copy.deepcopy(self.release)
        self.api.items[m.core('trusted','configmaps','site')]={'immutable':True,'data':{'values.json':json.dumps(self.values)}}
        self.c=m.Reconciler(self.api,self.policy,'controller-one')
    def reconcile(self):self.c.reconcile(self.api.call('GET',self.rpath));return self.api.items[self.rpath].get('status',{})
    def finish(self,stage,state=None):
        release=self.api.items[self.rpath];retry=release['metadata'].get('annotations',{}).get(m.GROUP+'/retry','initial')
        name=m.job_name(release,stage,retry);j=self.api.items[m.jobs('trusted',name)]
        j['status']={'conditions':[{'type':'Complete','status':'True'}]}
        states=['ModelPublished','VolumesBound','ReleaseMeasured','TrustReady','Serving','FirstBootPassed','FreshVMPersistencePassed','E2EPassed']
        receipt={'releaseUID':release['metadata']['uid'],'specSha256':m.digest(release['spec']),'siteSha256':self.policy['siteSha256'],
            'stage':stage,'jobUID':j['metadata']['uid'],'state':state or states[m.STAGES.index(stage)]}
        cm={'immutable':True,'data':{'receipt.json':json.dumps(receipt)}}
        if stage=='report':
            cm['data']['e2e-report.json']=json.dumps({'reopen':{'pod':'predictor','podUid':'pod-uid','pvcUids':{'model':'m','data':'d'}}})
            self.api.items[m.core('work','pods','predictor')]={'metadata':{'uid':'pod-uid'},'spec':{'volumes':[{'name':alias,'persistentVolumeClaim':{'claimName':alias+'-pvc'}} for alias in ('model','data')]},'status':{'containerStatuses':[{'ready':True}]}}
            for name,uid in [('model','m'),('data','d')]:self.api.items[m.core('work','persistentvolumeclaims',name+'-pvc')]={'metadata':{'uid':uid}}
        self.api.items[m.core('trusted','configmaps',m.job_name(release,stage,retry)+'-receipt')]=cm
    def test_worker_can_load_shared_renderers_without_controller_name_collision(self):
        code="""import sys
from pathlib import Path
root=Path.cwd()
sys.path.insert(0,str(root/'components/inference-release-controller'))
import worker
from quickstart.release import module
for name in ('profile','render','enroll'):
    module(name)
"""
        result=subprocess.run([sys.executable,'-c',code],cwd=ROOT,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_worker_republishes_committed_receipt_without_replaying_effects(self):
        import tempfile
        import os
        from types import SimpleNamespace
        from unittest.mock import patch
        spec=importlib.util.spec_from_file_location('test_release_worker',ROOT/'components/inference-release-controller/worker.py')
        worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)
        self.reconcile()
        name=m.job_name(self.release,'model','initial')
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory)
            (state/'executor-owner.json').write_text('{"executor":"controller"}')
            saved={'siteSha256':self.policy['siteSha256'],'result':{'state':'ModelPublished'}}
            run=SimpleNamespace(state=state,identity={'siteSha256':self.policy['siteSha256']},
                require_stage=lambda stage:None,receipt=lambda stage:saved)
            env={'RELEASE_NAMESPACE':'trusted','RELEASE_NAME':'qwen','STAGE':'model',
                'RELEASE_UID':self.release['metadata']['uid'],'RELEASE_SPEC_SHA256':m.digest(self.release['spec']),'JOB_NAME':name}
            with patch.dict(os.environ,env),patch.object(worker,'API',return_value=self.api),patch.object(worker,'Run',return_value=run),patch.dict(worker.release.HANDLERS,{'model':lambda run:self.fail('committed side effects replayed')}):
                worker.main()
                count=len(self.api.created)
                worker.main()
                self.assertEqual(len(self.api.created),count)
            receipt=self.api.items[m.core('trusted','configmaps',name+'-receipt')]
            self.assertTrue(receipt['immutable'])
            self.assertEqual(json.loads(receipt['data']['receipt.json'])['state'],'ModelPublished')

    def test_exact_retry_and_new_controller_do_not_duplicate_jobs(self):
        self.reconcile();count=len(self.api.created)
        self.reconcile();self.assertEqual(count,len(self.api.created))
        other=m.Reconciler(self.api,self.policy,'controller-two');other.reconcile(self.api.call('GET',self.rpath))
        self.assertEqual(count,len(self.api.created))
    def test_all_stages_once_and_ready_resync_is_read_only(self):
        self.reconcile()
        for stage in m.STAGES:self.finish(stage);status=self.reconcile()
        self.assertEqual(status['phase'],'Ready');count=len(self.api.created)
        for _ in range(5):self.reconcile()
        self.assertEqual(count,len(self.api.created));self.assertEqual(len(status['completed']),8)
        self.api.items[m.core('work','pods','predictor')]['metadata']['uid']='replacement'
        self.assertEqual(self.reconcile()['reason'],'VerifiedPredictorReplaced')
        self.assertEqual(count,len(self.api.created))
    def test_readiness_resolves_volume_aliases_and_rejects_replaced_claim(self):
        self.reconcile()
        for stage in m.STAGES:self.finish(stage);status=self.reconcile()
        self.assertEqual(status['phase'],'Ready')
        self.api.items[m.core('work','persistentvolumeclaims','model-pvc')]['metadata']['uid']='new-claim'
        self.assertEqual(self.reconcile()['reason'],'VerifiedClaimReplaced')

    def test_success_without_bound_receipt_never_advances(self):
        self.reconcile();self.finish('model');name=m.job_name(self.release,'model','initial')
        self.api.items[m.core('trusted','configmaps',name+'-receipt')]['data']['receipt.json']='{}'
        self.assertEqual(self.reconcile()['reason'],'InvalidReleaseArtifact')
        self.assertEqual(len([k for k in self.api.created if '/jobs/' in k]),1)
    def test_wrong_job_receipt_is_rejected(self):
        self.reconcile();self.finish('model');name=m.job_name(self.release,'model','initial');cm=self.api.items[m.core('trusted','configmaps',name+'-receipt')]
        receipt=json.loads(cm['data']['receipt.json']);receipt['jobUID']='other';cm['data']['receipt.json']=json.dumps(receipt)
        self.assertEqual(self.reconcile()['reason'],'ReceiptIdentityMismatch')
    def test_stage_failure_requires_explicit_retry(self):
        self.reconcile();name=m.job_name(self.release,'model','initial');j=self.api.items[m.jobs('trusted',name)]
        j['status']={'conditions':[{'type':'Failed','status':'True'}]}
        self.assertEqual(self.reconcile()['phase'],'Blocked');count=len(self.api.created)
        self.reconcile();self.assertEqual(count,len(self.api.created))
        self.api.items[self.rpath]['metadata']['annotations']={m.GROUP+'/retry':'operator-1'}
        self.assertEqual(self.reconcile()['reason'],'StageScheduled')
        self.assertEqual(len(self.api.created),count+1)
    def test_retry_waits_for_failed_jobs_live_pod(self):
        self.reconcile();name=m.job_name(self.release,'model','initial');j=self.api.items[m.jobs('trusted',name)]
        j['status']={'conditions':[{'type':'Failed','status':'True'}]}
        self.api.items[m.core('trusted','pods','old')]={'metadata':{'ownerReferences':[{'uid':j['metadata']['uid']}]},'status':{'phase':'Running'}}
        self.api.items[self.rpath]['metadata']['annotations']={m.GROUP+'/retry':'new'}
        self.assertEqual(self.reconcile()['reason'],'PriorJobPodStillActive')
    def test_modified_site_is_blocked_before_job(self):
        self.api.items[m.core('trusted','configmaps','site')]['data']['values.json']='{}'
        self.assertEqual(self.reconcile()['reason'],'SiteDigestMismatch')
        self.assertFalse(any('/jobs/' in p for p in self.api.created))
    def test_missing_acceptance_and_unpinned_executor_are_rejected(self):
        site=self.api.items[m.core('trusted','configmaps','site')]
        r=copy.deepcopy(self.release);r['spec']['acceptance']['allowTestVMReplacement']=False
        with self.assertRaises(ValueError):m.validate(r,site,self.policy)
        with self.assertRaises(ValueError):m.validate(self.release,site,dict(self.policy,image='mutable:latest'))
    def test_job_has_no_inline_credentials_or_host_privileges(self):
        j=m.job(self.release,self.policy,'enroll','initial');p=j['spec']['template']['spec'];c=p['containers'][0]
        self.assertEqual(j['spec']['template']['metadata']['annotations']['openshift.io/required-scc'],'restricted-v2')
        self.assertEqual(j['spec']['backoffLimit'],0)
        self.assertFalse(c['securityContext']['allowPrivilegeEscalation'])
        self.assertTrue(c['securityContext']['readOnlyRootFilesystem'])
        self.assertFalse(any('hostPath' in v for v in p['volumes']))
        self.assertEqual([v['secret']['secretName'] for v in p['volumes'] if 'secret' in v],['git'])
        self.assertNotIn('GITHUB_TOKEN',json.dumps(j))
        for stage in set(m.STAGES)-{'enroll'}:
            pod=m.job(self.release,self.policy,stage,'initial')['spec']['template']['spec']
            self.assertFalse(any('secret' in v for v in pod['volumes']))
    def test_job_completed_but_controller_status_lost_recovers(self):
        self.reconcile();self.finish('model');self.api.items[self.rpath].pop('status',None)
        self.assertEqual(self.reconcile()['currentStage'],'volumes')
        self.assertEqual(len([p for p in self.api.created if '/jobs/' in p]),2)

if __name__=='__main__':unittest.main()
