"""Operator image maintenance must not overwrite active stage or retained state."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
spec=importlib.util.spec_from_file_location('release_bootstrap',ROOT/'scripts/release-controller.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.out=Path(self.temp.name);(self.out/'controller-bootstrap.json').write_text('{}')
        self.policy={'image':'registry/runner@sha256:'+'b'*64,'siteSha256':'c'*64,'stateClaim':'retained'}
        self.old=dict(self.policy,image='registry/runner@sha256:'+'a'*64)
        self.calls=[];self.applied=[];self.active=False
        def get(kind,name=None,ns=None):
            if kind=='deployment':return {'metadata':{'labels':{m.addon.OWNER:'demo'}},'spec':{'template':{'spec':{'volumes':[{'name':'configuration','configMap':{'name':'old-grant'}}]}}}}
            if kind=='configmap':return {'data':{'policy.json':json.dumps(self.old)}}
            if kind=='pods':return {'items':[]}
            if kind=='jobs':return {'items':[{'metadata':{'uid':'job','labels':{'inference.confidentialcontainers.org/release-uid':'release'}},'status':{'active':1 if self.active else 0}}]}
            self.fail(kind)
        self.r=SimpleNamespace(out=self.out,trusted='trusted',installation='demo',get=get,
            oc=lambda *a,**k:self.calls.append(a),wait=lambda text,check,**kw:self.assertTrue(check()),
            apply=lambda obj:self.applied.append(copy.deepcopy(obj)),save=lambda *a:None)
        self.cfg=patch.object(m,'configuration',return_value={'policy':self.policy})
        self.cfg.start();self.addCleanup(self.cfg.stop)
        self.helm=patch.object(m.addon,'helm',return_value=[{'kind':'ConfigMap','metadata':{'name':'new-grant'},'data':{'policy.json':'{}'}},
            {'kind':'Deployment','metadata':{'name':'inference-release-controller'},'spec':{'replicas':1}},
            {'kind':'PersistentVolumeClaim','metadata':{'name':'retained'}}])
        self.helm.start();self.addCleanup(self.helm.stop)
    def test_active_stage_pauses_controller_but_never_changes_image_or_state(self):
        self.active=True
        with self.assertRaisesRegex(ValueError,'stage still active'):m.upgrade(self.r)
        self.assertEqual(len(self.calls),1);self.assertEqual(json.loads(self.calls[0][-1])['spec']['replicas'],0)
        self.assertEqual(self.applied,[])
    def test_changed_site_or_grant_rejected_before_stopping_controller(self):
        self.old['siteSha256']='d'*64
        with self.assertRaisesRegex(ValueError,'cannot change site'):m.upgrade(self.r)
        self.assertEqual(self.calls,[]);self.assertEqual(self.applied,[])
    def test_only_controller_and_grant_updated_while_paused_then_resumed(self):
        m.upgrade(self.r)
        self.assertEqual([x['kind'] for x in self.applied],['ConfigMap','Deployment'])
        self.assertEqual(self.applied[1]['spec']['replicas'],0)
        patches=[a for a in self.calls if a[0]=='patch']
        self.assertEqual([json.loads(a[-1])['spec']['replicas'] for a in patches],[0,1])

class BootstrapRBACChartTests(unittest.TestCase):
    def test_bootstrap_reuses_shared_crd_and_creates_missing_crd_only_once(self):
        import yaml
        crd=yaml.safe_load((ROOT/'charts/inference-release-controller/crds/inferencereleases.yaml').read_text())
        class BeforeSeed(Exception):pass
        for existing in (False,True):
            applied=[];old=copy.deepcopy(crd) if existing else None
            if old:old['metadata']['labels']={m.addon.OWNER:'other-installation'}
            r=SimpleNamespace(name='fresh',trusted='trusted',ns='work',require_stage=lambda stage:None,
                receipt=lambda stage:None,get=lambda kind,*args:old if kind=='crd' else None,
                apply=lambda obj:applied.append(copy.deepcopy(obj)),oc=lambda *args:None,
                save=lambda *args:(_ for _ in ()).throw(BeforeSeed()))
            docs=[copy.deepcopy(crd),{'kind':'Deployment','metadata':{'name':'controller'},'spec':{}}]
            with patch.object(m,'configuration',return_value={'policy':{}}),patch.object(m.addon,'helm',return_value=docs):
                with self.assertRaises(BeforeSeed):m.install(r)
            crds=[o for o in applied if o['kind']=='CustomResourceDefinition']
            self.assertEqual(len(crds),0 if existing else 1)
            self.assertTrue(all('namespace' not in o['metadata'] for o in crds))
            self.assertEqual(next(o for o in applied if o['kind']=='Deployment')['metadata']['namespace'],'trusted')

    def test_shared_trustee_deployment_read_is_named_and_read_only(self):
        site=m.addon.load(ROOT/'overrides/sites/edge-controller.yaml')
        policy={'namespace':site['quickstart']['trustedNamespace'],'workloadNamespace':site['installation']['namespace'],
            'releaseName':site['demo']['name'],'siteConfigMap':'site','siteSha256':'a'*64,
            'image':'registry/runner@sha256:'+'b'*64,'stateClaim':'state','stageServiceAccount':'executor','gitCredentialsSecret':'git'}
        docs=m.addon.helm(ROOT/'charts/inference-release-controller',{'site':site,'policy':policy,'storageClassName':'test','stateSize':'1Gi'},policy['namespace'],'inference-release-controller')
        role=next(o for o in docs if o['kind']=='Role' and o['metadata']['name']==policy['releaseName']+'-trustee-enrollment')
        rules=[r for r in role['rules'] if 'deployments' in r['resources']]
        self.assertEqual(rules,[{'apiGroups':['apps'],'resources':['deployments'],'resourceNames':[site['quickstart']['trustee']['deployment']],'verbs':['get']}])
        self.assertFalse(any(o['kind']=='ClusterRoleBinding' and o['roleRef']['name']=='cluster-admin' for o in docs))


class GitCredentialTests(unittest.TestCase):
    def test_ssh_key_is_private_host_pinned_and_ambient_token_is_not_selected(self):
        import os
        spec=importlib.util.spec_from_file_location('credential_worker',ROOT/'components/inference-release-controller/worker.py')
        worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)
        with tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,{},clear=True):
            root=Path(directory);(root/'ssh-privatekey').write_text('test-key');(root/'known_hosts').write_text('test-host')
            private=root/'private';private.mkdir(mode=0o700)
            with patch.object(worker.tempfile,'mkdtemp',return_value=str(private)):worker.configure_git(root)
            self.assertEqual((private/'key').stat().st_mode&0o777,0o600)
            self.assertNotIn('GIT_ASKPASS',os.environ)
            self.assertIn('StrictHostKeyChecking=yes',os.environ['GIT_SSH_COMMAND'])
            self.assertIn('IdentitiesOnly=yes',os.environ['GIT_SSH_COMMAND'])
            self.assertEqual(os.environ['GIT_CONFIG_VALUE_1'],'https://github.com/')
            (root/'token').write_text('test-token')
            with self.assertRaisesRegex(ValueError,'exactly one'):worker.configure_git(root)
            (root/'token').unlink();(root/'known_hosts').unlink()
            with self.assertRaisesRegex(ValueError,'pinned known_hosts'):worker.configure_git(root)


if __name__=='__main__':unittest.main()
