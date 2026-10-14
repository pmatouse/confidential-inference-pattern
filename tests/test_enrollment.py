import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'components/confidential-volume-controller'))
sys.path.insert(0,str(ROOT/'components/confidential-storage-authority'))
from test_sidecar import fixture
from test_controller import request
from authority import Authority,AttestedPeer
from bootstrap import bootstrap
from publication_fixture import fixture as publisher_fixture
spec=importlib.util.spec_from_file_location('release_enrollment',ROOT/'components/inference-release/enroll.py')
enrollment=importlib.util.module_from_spec(spec);spec.loader.exec_module(enrollment)

class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        api,c,_=fixture();c.reconcile(1000);self.request=request(api)
        self.models={};self.blank=[]
        for v in self.request['contract']['volumes']:
            if v['access']=='ReadWrite':self.blank.append(v['claimRef']['uid']);continue
            d,s=publisher_fixture();d['diskBytes']=s['diskBytes']=v['requestedBytes']
            d['dataBytes']=d['hashOffsetBytes']=v['requestedBytes']-max(16*1024*1024,v['requestedBytes']//64)
            name=v['bindingId']+'-source';s['repository']='synthetic-test/'+v['bindingId']
            for claim in self.request['claims']:
                if claim['uid']==v['claimRef']['uid']:claim['dataSourceRef']={'kind':'EncryptedModelSource','name':name}
            self.request['sources'].append({'name':name,'spec':s})
            self.models[v['content']['approvedManifestRef']]={'source':s,'descriptor':d}
        self.draft={'requestSha256':enrollment.sha(self.request),'policy':'synthetic-rego','policySha256':hashlib.sha256(b'synthetic-rego').hexdigest()}
    def plan(self):return enrollment.plan(self.request,self.draft,self.models,self.blank)
    def test_multiple_models_and_data_retry_preserves_records(self):
        p=self.plan();self.assertEqual(len(p['records']),4)
        with tempfile.TemporaryDirectory() as d:
            state=Path(d)/'retained';bootstrap(state,'demo')
            result=enrollment.apply(state,'demo',p)
            self.assertEqual(result,enrollment.apply(state,'demo',p))
            self.assertEqual(sorted(r['state'] for r in result['records']),['Ready','Ready','Uninitialized','Uninitialized'])
            a=Authority(state/'authority.db');r=next(r for r in result['records'] if r['state']=='Uninitialized')
            peer=AttestedPeer(r['policy_sha256'],'b'*64)
            a.begin(r['volume_id'],peer,'init-1','initialize',1)
            before=a.inspect(r['volume_id'])
            enrollment.apply(state,'demo',p)
            self.assertEqual(a.inspect(r['volume_id']),before)
    def test_explicit_blank_uid_approval_required(self):
        self.blank.pop()
        with self.assertRaises(ValueError):self.plan()
    def test_changed_source_never_approved(self):
        self.models=copy.deepcopy(self.models)
        next(iter(self.models.values()))['source']['diskDigest']='sha256:'+'9'*64
        with self.assertRaises(ValueError):self.plan()
    def test_rw_source_rejected(self):
        next(c for c in self.request['claims'] if c['uid'] in self.blank)['dataSourceRef']={'kind':'VolumeSnapshot','name':'old-data'}
        self.draft['requestSha256']=enrollment.sha(self.request)
        with self.assertRaises(ValueError):self.plan()
    def test_changed_policy_cannot_reset_registered_volume(self):
        p=self.plan()
        with tempfile.TemporaryDirectory() as d:
            state=Path(d)/'retained';bootstrap(state,'demo')
            before=enrollment.apply(state,'demo',p)
            modified=copy.deepcopy(p);modified['records'][-1]['registration']['policy_sha256']='e'*64
            with self.assertRaises(ValueError):enrollment.apply(state,'demo',modified)
            self.assertEqual(enrollment.apply(state,'demo',p),before)
    def test_draft_of_replaced_request_rejected(self):
        self.request['workloadUID']='replaced'
        with self.assertRaises(ValueError):self.plan()
    def test_partial_registration_is_resumed_without_new_identity(self):
        p=self.plan()
        with tempfile.TemporaryDirectory() as d:
            state=Path(d)/'retained';bootstrap(state,'demo');a=Authority(state/'authority.db')
            r=p['records'][0]['registration']
            a.register(r['volume_id'],r['policy_sha256'],r['profile_sha256'],r['credential_uri'],mount_binding=r['mount_binding'])
            self.assertEqual(len(enrollment.apply(state,'demo',p)['records']),4)
    def test_public_guest_package_matches_controller_contract(self):
        from test_release import ReleaseTests,release
        profile=ReleaseTests();profile.setUp()
        self.draft=release.draft(self.request,profile.profile)
        p=self.plan()
        with tempfile.TemporaryDirectory() as d:
            state=Path(d)/'retained';bootstrap(state,'demo')
            result=enrollment.apply(state,'demo',p)
            authority={'trustee_rcar':True,'audience':'https://authority.example/v1','certificate_der':[1],
                'address':None,'receipt_public_key':[1]*32,'receipt_issuer':'demo','receipt_key_id':'key-1'}
            encodings={v['keyResource']:'raw32' for v in self.request['contract']['volumes']}
            guest=enrollment.guest_configuration(self.request,self.draft,p,result,authority,encodings)
            runtime={'runtimeClassName':'kata-cc-nvidia-gpu','guestImageSha256':'a'*64,'launchMeasurement':'b'*96,'initDataSha256':'c'*64}
            package=release.package(self.request,self.draft,guest,'[token_configs]\n','credentials=[]\n[kbc]\nname="cc_kbc"\n',runtime)
            self.assertEqual(len(package),4)
            altered=copy.deepcopy(result);altered['records'][0]['credential_uri']='kbs:///wrong/key/value'
            with self.assertRaises(ValueError):enrollment.guest_configuration(self.request,self.draft,p,altered,authority,encodings)
