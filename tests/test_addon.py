
import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import addon
from binding import declarations

class FakeCluster:
    def __init__(self,v):
        b=v['base']
        self.objects={
          ('runtimeclass',b['runtimeClassName']):{'handler':b['runtimeHandler']},
          ('storageclass',b['storageClassName']):{'volumeBindingMode':'Immediate'},
          ('deploy',b['kserveDeployment']):{'status':{'availableReplicas':1},'spec':{'template':{'spec':{'containers':[{'image':'kserve/kserve-controller:'+b['kserveVersion']}]}}}},
          ('crd','inferenceservices.serving.kserve.io'):{},
          ('crd','volumepopulators.populator.storage.k8s.io'):{'spec':{'versions':[{'name':'v1beta1','served':True}]}},
          ('kbsconfig',b['trusteeName']):{},
        }
        self.mutations=[]
    def get(self,kind,name=None,namespace=None):return self.objects.get((kind,name))
    def apply(self,obj,dry=False):self.mutations.append(obj)
    def create(self,obj):self.mutations.append(obj)

class AddonTests(unittest.TestCase):
    def setUp(self):
        self.v=addon.load(addon.ROOT/'overrides/sites/edge-rtx6k.yaml')
        self.v['demo']['source']={'format':'luks-verity-v1','repository':self.v['installation']['namespace']+'/models','manifestDigest':'sha256:'+'a'*64,'diskDigest':'sha256:'+'b'*64,'diskBytes':2**31}
    def test_generic_missing_inputs_cannot_install(self):
        v=addon.load(addon.ROOT/'values-global.yaml')
        with self.assertRaises(addon.Invalid):addon.validate(v,complete=True)
    def test_no_unknown_fields(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'site.yaml';f.write_text('disableAttestation: true\n')
            with self.assertRaises(Exception):addon.load(f)
    def test_duplicate_yaml_fields(self):
        with self.assertRaises(addon.Invalid):addon.yaml.load('a: 1\na: 2\n',Loader=addon.UniqueLoader)
    def test_no_floating_images(self):
        self.v['images']['sidecar']='example.invalid/helper:latest'
        with self.assertRaises(addon.Invalid):addon.validate(self.v)
    def test_no_unqualified_runtime(self):
        self.v['base']['runtimeClassName']='runc'
        with self.assertRaises(addon.Invalid):addon.validate(self.v)
    def test_wffc_rejected(self):
        api=FakeCluster(self.v);api.objects[('storageclass','lvms-vg1')]['volumeBindingMode']='WaitForFirstConsumer'
        self.assertTrue(any(r['action']=='incompatible' for r in addon.inventory(self.v,api)))
        self.assertEqual(api.mutations,[])
    def test_missing_registration_installed_once(self):
        api=FakeCluster(self.v);del api.objects[('crd','volumepopulators.populator.storage.k8s.io')]
        row=next(r for r in addon.inventory(self.v,api) if r['resource']=='volume-populator-registration')
        self.assertEqual(row['action'],'create')
        self.assertEqual(api.mutations,[])
    def test_missing_trustee_rejected(self):
        api=FakeCluster(self.v);del api.objects[('kbsconfig','kbsconfig')]
        self.assertTrue(any(r['resource']=='trustee' and r['action']=='incompatible' for r in addon.inventory(self.v,api)))
    def test_existing_namespace_is_not_adopted(self):
        api=FakeCluster(self.v);api.objects[('namespace',self.v['installation']['namespace'])]={'metadata':{'labels':{}}}
        self.assertTrue(any(r['resource']=='namespace' and r['action']=='incompatible' for r in addon.inventory(self.v,api)))
    def test_cross_owner_apply_prechecked_before_mutation(self):
        api=FakeCluster(self.v);api.objects[('ConfigMap','other')]={'metadata':{}}
        objs=[{'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':n,'namespace':'test'}} for n in ['new','other']]
        with self.assertRaises(addon.Invalid):addon.apply_objects(objs,self.v,api)
        self.assertEqual(api.mutations,[])
    def test_foundation_does_not_render_platform_owners(self):
        docs=addon.foundation(self.v)
        forbidden={'KataConfig','KbsConfig','ClusterPolicy','InferenceService','Secret','Subscription'}
        self.assertFalse(forbidden & {o['kind'] for o in docs})
        self.assertTrue(any(o['kind']=='ValidatingAdmissionPolicy' for o in docs))
        self.assertTrue(all(o['metadata']['labels'][addon.OWNER]=='confidential-inference' for o in docs))
    def test_claims_ciphertext_and_blank(self):
        docs=addon.provision(self.v)
        claims=[o for o in docs if o['kind']=='PersistentVolumeClaim']
        self.assertEqual(len(claims),2)
        ro,rw=claims
        self.assertEqual(ro['spec']['dataSourceRef']['kind'],'EncryptedModelSource')
        self.assertNotIn('dataSourceRef',rw['spec'])
        self.assertTrue(all(c['spec']['volumeMode']=='Block' for c in claims))
        self.assertTrue(all(c['metadata']['annotations']['argocd.argoproj.io/sync-options']=='Prune=false,Delete=false' for c in claims))
        self.assertFalse(any(o['kind']=='InferenceService' for o in docs))
    def test_bindings_and_unprivileged_intent(self):
        obj=next(o for o in addon.provision(self.v) if o['kind']=='ConfidentialWorkload')
        p=obj['spec']['template']['spec']['predictor']
        bindings=json.loads(p['annotations'][addon.GROUP+'/bindings'])
        self.assertEqual([b['mountPath'] for b in bindings],['/model','/data'])
        app=p['containers'][0]
        self.assertFalse(app['securityContext']['privileged']);self.assertNotIn('volumeDevices',app)
    def claims(self):
        expected={o['metadata']['name']:o for o in addon.provision(self.v) if o['kind']=='PersistentVolumeClaim'}
        actual=copy.deepcopy(expected)
        for n,c in enumerate(actual.values()):
            c['metadata']['uid']=f'00000000-0000-4000-8000-{n:012d}'
            c['status']={'phase':'Bound'}
        return expected,actual
    def test_actual_uids_are_bound(self):
        e,a=self.claims();result=declarations(self.v,e,a)
        for cv in result:self.assertEqual(cv['spec']['claimRef']['uid'],a[cv['metadata']['name']]['metadata']['uid'])
        self.assertEqual(result[0]['spec']['initialization']['policy'],'Never')
        self.assertEqual(result[1]['spec']['initialization']['policy'],'OnceIfApproved')
    def test_pending_claim_refused(self):
        e,a=self.claims();next(iter(a.values()))['status']['phase']='Pending'
        with self.assertRaises(addon.Invalid):declarations(self.v,e,a)
    def test_changed_source_refused(self):
        e,a=self.claims();next(iter(a.values()))['spec']['dataSourceRef']['name']='different'
        with self.assertRaises(addon.Invalid):declarations(self.v,e,a)
    def test_deleting_claim_refused(self):
        e,a=self.claims();next(iter(a.values()))['metadata']['deletionTimestamp']='now'
        with self.assertRaises(addon.Invalid):declarations(self.v,e,a)
    def test_cross_namespace_registry_source_rejected(self):
        self.v['demo']['source']['repository']='another-namespace/models'
        with self.assertRaises(addon.Invalid):addon.provision(self.v)
    def test_no_source_no_provision(self):
        self.v['demo']['source']={}
        with self.assertRaises(addon.Invalid):addon.provision(self.v)
    def test_second_site_no_lab_namespace(self):
        self.v['installation']['namespace']='another-inference';self.v['installation']['clusterIdentity']='another-site'
        self.v['demo']['name']='another-qwen'
        self.v['demo']['source']['repository']='another-inference/models'
        for name in ('controller','populator','sidecar'):
            self.v['images'][name]='registry.example.invalid/addon/'+name+'@sha256:'+'a'*64
        docs=addon.foundation(self.v)+addon.provision(self.v)
        serialized=json.dumps(docs)
        self.assertNotIn('confidential-inference-demo',serialized)
        self.assertNotIn('qwen-demo-001-model',serialized)
    def test_root_chart_matches_bootstrap_resources(self):
        docs=addon.helm(addon.ROOT/'charts/confidential-inference',addon.resolved_values(self.v),self.v['installation']['namespace'])
        for obj in docs:
            if obj['kind']!='CustomResourceDefinition':
                self.assertEqual(obj['metadata']['labels'][addon.OWNER],self.v['installation']['name'])
        self.assertEqual(sum(o['kind']=='Deployment' for o in docs),2)
    def test_gitops_excludes_shared_service_ownership(self):
        self.v['gitops'].update(enabled=True,revision='a'*40)
        objects=addon.gitops(self.v)
        app=next(o for o in objects if o['kind']=='Application')
        self.assertTrue(app['spec']['source']['helm']['skipCrds'])
        self.assertFalse(app['spec']['syncPolicy']['automated']['prune'])
        project=next(o for o in objects if o['kind']=='AppProject')
        kinds={r['kind'] for r in project['spec']['namespaceResourceWhitelist']}
        self.assertFalse(kinds & {'Secret','InferenceService','KbsConfig','KataConfig','Subscription'})
    def test_binding_job_has_no_secret_or_pod_privileges(self):
        docs=addon.provision(self.v)
        job=next(o for o in docs if o['kind']=='Job')
        self.assertFalse(job['spec']['template']['spec']['containers'][0]['securityContext']['allowPrivilegeEscalation'])
        role=next(o for o in docs if o['kind']=='Role')
        resources={r for rule in role['rules'] for r in rule['resources']}
        self.assertEqual(resources,{'persistentvolumeclaims','confidentialvolumes'})
    def test_chat_has_no_api_credential(self):
        self.v['chat']['enabled']=True
        docs=addon.helm(addon.ROOT/'charts/inference-chat',self.v,self.v['installation']['namespace'])
        deploy=next(o for o in docs if o['kind']=='Deployment')
        self.assertFalse(deploy['spec']['template']['spec']['automountServiceAccountToken'])
        self.assertFalse(any(o['kind'] in ('Role','RoleBinding','Secret') for o in docs))
    def test_model_root_is_bounded(self):
        sys.path.insert(0,str(addon.ROOT/'components/confidential-volume-contract'))
        from compiler import destination,Invalid
        self.assertEqual(destination('/model'),'/model')
        self.assertEqual(destination('/model/qwen'),'/model/qwen')
        for bad in ['/','/etc','/models2','/model/../etc','/model//qwen']:
            with self.assertRaises(Invalid):destination(bad)

if __name__=='__main__':unittest.main()
