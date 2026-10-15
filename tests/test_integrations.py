"""Stock chart adaptation and administrator-bootstrap boundaries."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
import yaml

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import addon
from quickstart import integrations as m

ARCHIVE=ROOT/'prerequisites/trustee/trustee-0.10.2.tgz'
OWNER={'repository':'git@github.com:example/coco.git','branch':'main','application':'trustee','namespace':'gitops','valuesFile':'overrides/inference.yaml'}
VAULT={'namespace':'vault','pod':'vault-0','role':'demo-enroller','authMount':'hub','serviceAccount':'enroller','enrollmentNamespace':'demo-enrollment','backendPath':'secret/data/hub/modelKeys','externalSecret':'model-keys-eso','projectionSecret':'model-keys'}

def fixture(root,multi=False):
    (root/'overrides').mkdir()
    (root/'values-global.yaml').write_text(yaml.safe_dump({'global':{'hubClusterDomain':'apps.example.com','secretStore':{'backend':'vault'},'coco':{'secured':True}}}))
    (root/'overrides/trustee.yaml').write_text(yaml.safe_dump({'kbs':{'secretResources':[{'name':'existing','key':'secret/data/hub/existing'}]}}))
    topology={'clusterGroup':{'applications':{'other':{'path':'untouched'},'trustee':{'name':'trustee','chart':'trustee','chartVersion':'0.10.*','overrides':[{'name':'kbs.gpu.enabled','value':'true'}],'extraValueFiles':['/overrides/trustee.yaml']}}}}
    (root/'values-baremetal.yaml').write_text(yaml.safe_dump(topology))
    source={'repoURL':OWNER['repository'],'targetRevision':'main','helm':{'valueFiles':['/values-global.yaml','/overrides/trustee.yaml'],'parameters':[]}}
    app={'spec':{'source':source}}
    if multi:
        app={'spec':{'sources':[{'repoURL':'quay.io/validatedpatterns','chart':'trustee','targetRevision':'0.10.2','helm':{'valueFiles':['$values/values-global.yaml','$values/overrides/trustee.yaml']}},{'repoURL':OWNER['repository'],'targetRevision':'main','ref':'values'}]}}
    r=SimpleNamespace(q={'trustee':{'owner':copy.deepcopy(OWNER)},'vault':copy.deepcopy(VAULT),'integrations':{'topologyFile':'values-baremetal.yaml'}})
    return r,app,topology


class IntegrationTests(unittest.TestCase):
    def test_stock_files_unchanged_except_policy(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);result=m.stock_adapter(ARCHIVE,root)
            with tarfile.open(ARCHIVE) as tar:
                for f in tar:
                    if not f.isfile() or f.name=='trustee/templates/resource-policy.yaml':continue
                    name=f.name.removeprefix('trustee/')
                    if name not in ('Chart.yaml','values.yaml','LICENSE') and not name.startswith('templates/'):continue
                    self.assertEqual((root/f.name.removeprefix('trustee/')).read_bytes(),tar.extractfile(f).read(),f.name)
            self.assertFalse((root/'.git').exists())
            self.assertEqual(result['changedStockFiles'],['templates/resource-policy.yaml'])
            m.stock_adapter(ARCHIVE,root)
            (root/'templates/kbs.yaml').write_text('tampered')
            with self.assertRaisesRegex(ValueError,'adapter differs'):m.stock_adapter(ARCHIVE,root)

    def test_wrong_archive_pin_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'bad.tgz';p.write_bytes(b'not approved')
            with self.assertRaisesRegex(ValueError,'reviewed pin'):m.stock_adapter(p,Path(d)/'chart')

    def test_stock_single_and_multi_source_preserve_resources_and_other_apps(self):
        for multi in (False,True):
            with self.subTest(multi=multi),tempfile.TemporaryDirectory() as d:
                root=Path(d);r,app,before=fixture(root,multi)
                result,resources=m.configure_owner(root,app,r,ARCHIVE)
                self.assertEqual(resources,[{'name':'existing','key':'secret/data/hub/existing'},{'name':'model-keys','key':'secret/data/hub/modelKeys'}])
                after=yaml.safe_load((root/'values-baremetal.yaml').read_text())
                self.assertEqual(after['clusterGroup']['applications']['other'],before['clusterGroup']['applications']['other'])
                changed=after['clusterGroup']['applications']['trustee']
                self.assertNotIn('chart',changed);self.assertNotIn('chartVersion',changed)
                self.assertEqual(changed['overrides'],before['clusterGroup']['applications']['trustee']['overrides'])
                self.assertEqual(result['mode'],'StockChartAdapter')
                # Reconciliation is idempotent even with the original Application snapshot.
                old=(root/'values-baremetal.yaml').read_bytes()
                m.configure_owner(root,app,r,ARCHIVE)
                self.assertEqual((root/'values-baremetal.yaml').read_bytes(),old)

    def test_active_chart_selected_by_later_override_is_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);r,app,_=fixture(root)
            chart=root/'charts/compatible';chart.mkdir(parents=True)
            (chart/'policy.yaml').write_text('modelKeyBindings model_key_bindings')
            app['spec']['source']['path']='charts/compatible'
            result,_=m.configure_owner(root,app,r,ARCHIVE)
            self.assertEqual(result['mode'],'ExistingCompatibleOwner')
            self.assertEqual(result['path'],'charts/compatible')
            self.assertFalse((root/'charts/addons').exists())

    def test_foreign_model_mapping_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);r,app,_=fixture(root)
            (root/'overrides/trustee.yaml').write_text('kbs:\n  secretResources:\n  - name: model-keys\n    key: foreign\n')
            with self.assertRaisesRegex(ValueError,'points elsewhere'):m.configure_owner(root,app,r,ARCHIVE)

    def test_unknown_local_chart_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);r,app,top=fixture(root)
            top['clusterGroup']['applications']['trustee']={'path':'charts/unknown'}
            (root/'values-baremetal.yaml').write_text(yaml.safe_dump(top))
            with self.assertRaisesRegex(ValueError,'unrecognized local'):m.configure_owner(root,app,r,ARCHIVE)

    def test_owner_identity_and_traversal_refused(self):
        with self.assertRaises(ValueError):m.owner_source({'spec':{'source':{'repoURL':'foreign'}}},OWNER)
        with tempfile.TemporaryDirectory() as d,tempfile.TemporaryDirectory() as other:
            root=Path(d);(root/'link').symlink_to(other)
            for name in ('../escape','/absolute','link/escape'):
                with self.assertRaises(ValueError):m.safe_path(root,name)

    def test_parent_must_consume_exact_owner_and_topology(self):
        parent={'spec':{'syncPolicy':{'automated':{}},'sources':[
            {'repoURL':OWNER['repository'],'targetRevision':'main','ref':'patternref'},
            {'repoURL':'quay.io/validatedpatterns','helm':{'valueFiles':['$patternref/values-baremetal.yaml']}}]}}
        m.validate_parent(parent,OWNER,'values-baremetal.yaml')
        with self.assertRaisesRegex(ValueError,'topology'):m.validate_parent(parent,OWNER,'unconsumed.yaml')
        parent['spec']['sources'][0]['targetRevision']='other'
        with self.assertRaisesRegex(ValueError,'repository/branch'):m.validate_parent(parent,OWNER,'values-baremetal.yaml')

    def test_checkout_resume_accepts_only_journaled_edits_or_commit(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);r=SimpleNamespace(out=root)
            state={'baseCommit':'base','plannedFiles':{'values.yaml':'digest'}}
            (root/'integration-owner-state.json').write_text(json.dumps(state))
            with patch.object(m,'changed_files',return_value=state['plannedFiles']):
                m.verify_checkout_resume(r,root,'base','base')
            with patch.object(m,'changed_files',return_value={'values.yaml':'modified'}):
                with self.assertRaisesRegex(ValueError,'outside'):m.verify_checkout_resume(r,root,'base','base')
            state['commit']='new';(root/'integration-owner-state.json').write_text(json.dumps(state))
            with patch.object(m,'changed_files',return_value={}):
                m.verify_checkout_resume(r,root,'new','base')
                with self.assertRaisesRegex(ValueError,'history changed'):m.verify_checkout_resume(r,root,'unexpected','base')

    def test_inline_secret_overrides_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);r,app,_=fixture(root)
            app['spec']['source']['helm']['valuesObject']={'kbs':{'secretResources':[{'name':'hidden'}]}}
            with self.assertRaisesRegex(ValueError,'inline secretResources'):m.configure_owner(root,app,r,ARCHIVE)

    def test_bootstrap_never_overwrites_existing_role_or_backend(self):
        admin=Mock();admin.call.side_effect=[json.dumps({'hub/':{'type':'kubernetes'}}),m.vault_policy(VAULT),json.dumps({'data':{'token_policies':['root']}})]
        r=SimpleNamespace(q={'vault':VAULT})
        with patch.object(m,'VaultAdmin',return_value=admin),self.assertRaisesRegex(ValueError,'role differs'):m.setup_vault(r)
        self.assertTrue(all(c.args[0][0] in ('auth','policy','read') for c in admin.call.call_args_list))

    def test_fresh_backend_uses_cas_zero_and_admin_not_retained(self):
        calls=[]
        def call(args,body=None,missing=False):
            calls.append((args,body))
            if args[0]=='auth':return json.dumps({'hub/':{'type':'kubernetes'}})
            if args[0] in ('read','policy'):return None
            return ''
        admin=SimpleNamespace(call=call,token='sensitive')
        with patch.object(m,'VaultAdmin',return_value=admin):result=m.setup_vault(SimpleNamespace(q={'vault':VAULT}))
        self.assertTrue(result['backendCreated']);self.assertIsNone(admin.token)
        backend=next(body for args,body in calls if args[:2]==['write','secret/data/hub/modelKeys'])
        self.assertEqual(backend,{'options':{'cas':0},'data':{'bootstrap-marker':'reserved-no-secret'}})

    def test_existing_backend_and_scoped_role_are_read_only(self):
        role={'bound_service_account_names':['enroller'],'bound_service_account_namespaces':['demo-enrollment'],'audience':'vault','token_policies':['demo-enroller'],'token_no_default_policy':True,'token_ttl':900,'token_max_ttl':3600}
        admin=Mock();admin.call.side_effect=[json.dumps({'hub/':{'type':'kubernetes'}}),m.vault_policy(VAULT),json.dumps({'data':role}),json.dumps({'data':{'current_version':4}})]
        with patch.object(m,'VaultAdmin',return_value=admin):result=m.setup_vault(SimpleNamespace(q={'vault':VAULT}))
        self.assertFalse(result['backendCreated']);self.assertFalse(any(c.args[0][0]=='write' for c in admin.call.call_args_list))

    def test_vault_credential_only_on_stdin_and_errors_redacted(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'token';path.write_text('private-value');path.chmod(0o600)
            with patch.dict(os.environ,{'CI_VAULT_ADMIN_TOKEN_FILE':str(path)}):
                admin=m.VaultAdmin(SimpleNamespace(q={'vault':VAULT}))
                with patch.object(m.subprocess,'run',return_value=SimpleNamespace(returncode=1,stdout='private-value',stderr='forbidden')) as command:
                    with self.assertRaisesRegex(ValueError,'sensitive output withheld'):admin.call(['read','secret/metadata/hub/modelKeys'])
                    self.assertNotIn('private-value',str(command.call_args.args))
                    self.assertTrue(command.call_args.kwargs['input'].startswith('private-value\n'))

    def test_helm_rejects_malformed_binding(self):
        with tempfile.TemporaryDirectory() as d:
            chart=Path(d);m.stock_adapter(ARCHIVE,chart)
            values={'global':{'hubClusterDomain':'apps.example.com'},'kbs':{'resourcePolicy':{'modelKeyBindings':{'bad':{'launchMeasurement':'wrong','initData':'wrong'}}}}}
            with self.assertRaises(addon.Invalid):addon.helm(chart,values,'trustee-operator-system')


if __name__=='__main__':unittest.main()
