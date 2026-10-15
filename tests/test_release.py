"""Synthetic contract tests only; not confidential execution qualification."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'components/confidential-volume-controller'),str(ROOT/'components/confidential-volume-contract')]
from test_sidecar import fixture
from test_controller import request,artifacts
spec=importlib.util.spec_from_file_location('release_render',ROOT/'components/inference-release/render.py')
release=importlib.util.module_from_spec(spec);spec.loader.exec_module(release)

class ReleaseTests(unittest.TestCase):
    def setUp(self):
        api,c,_=fixture();c.reconcile(1000);self.req=request(api)
        def settings(image,uid):
            return {'image':image,'args':[],'uid':uid,'gid':uid,'noNewPrivileges':uid!=0,'readonlyRoot':uid!=0,'capabilities':[],'rawDevices':[],'environment':['PATH=/usr/bin','KUBERNETES_SERVICE_PORT=443','KUBERNETES_SERVICE_PORT_HTTPS=443','KUBERNETES_PORT_443_TCP_PORT=443','KUBERNETES_PORT_443_TCP_PROTO=tcp'],'mounts':[],'ephemeralStorages':[],'additionalGroups':[[1001]]}
        image=self.req['contract']['workload']['image']
        self.profile={'runtimeClassName':'kata-cc-nvidia-gpu','applicationPython':'/usr/bin/python3','kubernetesServiceHost':'172.30.0.1','application':settings(image,1001),'helper':settings('example.invalid/helper@sha256:'+'a'*64,0),'pause':settings('pause',0)}
        a=self.profile['application']
        for name,path in [('model-target','/models/qwen'),('rendezvous','/rendezvous'),('shm','/dev/shm')]:
            source='/run/kata-containers/sandbox/ephemeral/'+name
            a['mounts'].append({'destination':path,'source':source,'options':['rbind'],'type_':'bind'})
            a['ephemeralStorages'].append({'driver':'ephemeral','driver_options':[],'fs_group':None,'fstype':'tmpfs','mount_point':source,'options':['fsgid=1001'],'shared':False,'source':'tmpfs'})
    def test_draft_is_deterministic_and_uses_all_declared_bindings(self):
        d=release.draft(self.req,self.profile)
        self.assertEqual(d,release.draft(self.req,self.profile))
        app,helper=d['predictor']['containers']
        self.assertNotIn('volumeDevices',app)
        self.assertEqual(len(helper['volumeDevices']),len(self.req['contract']['volumes']))
        self.assertFalse(app['securityContext']['privileged'])
        self.assertEqual(app['workingDir'],'/')
        self.assertEqual(helper['workingDir'],'/')
        self.assertEqual(d['predictor']['labels']['coco.io/skip-initdata'],'true')
        self.assertIn('ExecProcessRequest := false',d['policy'])
        self.assertFalse(d['predictor']['automountServiceAccountToken'])
    def test_wrong_image_refused(self):
        self.profile['application']['image']='another@sha256:'+'b'*64
        with self.assertRaises(ValueError):release.draft(self.req,self.profile)
    def test_relaxed_profile_refused(self):
        self.profile['application']['uid']=0
        with self.assertRaises(ValueError):release.draft(self.req,self.profile)
    def test_package_validated_by_controller(self):
        d=release.draft(self.req,self.profile);old=artifacts(self.req)
        guest=json.loads(old['guest-config.json']);guest['authority']['policy_sha256']=d['policySha256']
        runtime=json.loads(old['runtime.json']);runtime['runtimeClassName']='kata-cc-nvidia-gpu'
        result=release.package(self.req,d,guest,'[token_configs]\n','socket="unix:///run/private.sock"\n',runtime)
        parsed=json.loads(result['sidecar-deployment.json'])
        self.assertEqual(parsed['predictor']['containers'][0]['image'],self.req['contract']['workload']['image'])
        self.assertEqual(len(result),4)
        self.assertIn('cv-sidecar-',result['sidecar-deployment.json'])
    def test_enrollment_for_other_policy_rejected(self):
        d=release.draft(self.req,self.profile);old=artifacts(self.req)
        with self.assertRaises(ValueError):release.package(self.req,d,json.loads(old['guest-config.json']),'','',json.loads(old['runtime.json']))
    def test_draft_cannot_be_reused_for_replacement_claim(self):
        d=release.draft(self.req,self.profile);self.req['claims'][0]['uid']='replacement'
        with self.assertRaises(ValueError):release.package(self.req,d,{},'','',{})
    def test_authority_model_root_is_bounded(self):
        sys.path.insert(0,str(ROOT/'components/confidential-storage-authority'))
        from storage_profiles import destination
        self.assertTrue(destination('/model'))
        for bad in ['/model/..','/model//a','/etc','/models-other']:self.assertFalse(destination(bad))
