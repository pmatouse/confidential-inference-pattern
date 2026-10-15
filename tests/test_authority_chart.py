import json
from pathlib import Path
import subprocess
import unittest
import yaml
ROOT=Path(__file__).resolve().parents[1]

class AuthorityChartTests(unittest.TestCase):
    def render(self,mode='bootstrap',extra=()):
        args=['helm','template','demo-authority',str(ROOT/'charts/storage-authority'),
            '--namespace','trusted-demo','--set','installation=demo-1','--set',f'mode={mode}',
            '--set','image=example.invalid/authority@sha256:'+'a'*64,
            '--set','state.storageClassName=trusted-storage']
        args+=list(extra)
        return list(yaml.safe_load_all(subprocess.check_output(args,text=True,stderr=subprocess.PIPE)))
    def test_bootstrap_has_no_credentials_or_network_identity(self):
        docs=self.render();job=next(x for x in docs if x['kind']=='Job')
        spec=job['spec']['template']['spec']
        self.assertFalse(spec['automountServiceAccountToken'])
        self.assertEqual(spec['securityContext']['fsGroupChangePolicy'],'OnRootMismatch')
        self.assertEqual(len(spec['containers']),1)
        self.assertEqual(spec['containers'][0]['command'],['python3','bootstrap.py'])
        self.assertNotIn('secret',json.dumps(spec).lower())
        self.assertFalse(any(x['kind'] in ['Role','RoleBinding','Secret'] for x in docs))
        pvc=next(x for x in docs if x['kind']=='PersistentVolumeClaim')
        self.assertEqual(pvc['metadata']['annotations']['helm.sh/resource-policy'],'keep')
    def test_normal_restart_only_verifies_existing_state(self):
        docs=self.render('serve',['--set','publicConfigMap=release-1','--set','credentialsSecret=authority-keys'])
        self.assertFalse(any(x['kind']=='Job' for x in docs))
        spec=next(x for x in docs if x['kind']=='Deployment')['spec']
        self.assertEqual(spec['strategy']['type'],'Recreate')
        pod=spec['template']['spec'];c=pod['containers'][0]
        self.assertEqual(c['command'],['python3','serve.py'])
        self.assertIn('--state',c['args'])
        self.assertFalse(pod['automountServiceAccountToken'])
        self.assertEqual(pod['securityContext']['fsGroupChangePolicy'],'OnRootMismatch')
        self.assertNotIn('bootstrap.py',json.dumps(pod))
        self.assertTrue(c['securityContext']['readOnlyRootFilesystem'])
        self.assertEqual(c['securityContext']['capabilities']['drop'],['ALL'])
        mounts={m['name'] for m in c['volumeMounts']}
        self.assertNotIn('credentials',mounts)
        self.assertEqual(next(v for v in pod['volumes'] if v['name']=='private')['emptyDir']['medium'],'Memory')
    def test_missing_credentials_refuses_serve(self):
        with self.assertRaises(subprocess.CalledProcessError):self.render('serve')
    def test_unknown_mode_refused(self):
        with self.assertRaises(subprocess.CalledProcessError):self.render('initialize-every-start')
    def test_existing_claim_is_reused(self):
        docs=self.render(extra=['--set','state.existingClaim=retained-authority'])
        self.assertFalse(any(x['kind']=='PersistentVolumeClaim' for x in docs))

    def test_public_config_changes_rollout_but_preserve_retained_volume(self):
        first=self.render('serve',['--set','publicConfigMap=release-1','--set','credentialsSecret=authority-keys','--set','publicConfigSha256='+'a'*64])
        second=self.render('serve',['--set','publicConfigMap=release-1','--set','credentialsSecret=authority-keys','--set','publicConfigSha256='+'b'*64])
        a=next(x for x in first if x['kind']=='Deployment')['spec']['template']
        b=next(x for x in second if x['kind']=='Deployment')['spec']['template']
        self.assertNotEqual(a['metadata']['annotations'],b['metadata']['annotations'])
        self.assertEqual(a['spec'],b['spec'])
