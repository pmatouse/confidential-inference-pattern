"""Trusted preparation privilege and namespace boundaries."""
from pathlib import Path
import json
import subprocess
import tempfile
import unittest
import yaml
ROOT=Path(__file__).resolve().parents[1]

class PreparationCharts(unittest.TestCase):
    def render(self,chart,values,namespace='trusted-enrollment'):
        with tempfile.TemporaryDirectory() as work:
            path=Path(work)/'values.json';path.write_text(json.dumps(values))
            raw=subprocess.check_output(['helm','template','demo',str(ROOT/'charts'/chart),'-n',namespace,'-f',str(path)],stderr=subprocess.PIPE,text=True)
        return list(yaml.safe_load_all(raw))
    def publisher(self):
        return {'workloadNamespace':'inference','modelImageStream':'model-v1','readerName':'guest-reader'}
    def test_publisher_unprivileged_and_scoped_across_namespaces(self):
        docs=self.render('model-publisher',self.publisher())
        pod=next(x for x in docs if x['kind']=='Pod')['spec']
        self.assertFalse(pod['automountServiceAccountToken'])
        c=pod['containers'][0]
        self.assertEqual(c['securityContext']['capabilities']['drop'],['ALL'])
        self.assertFalse(c['securityContext']['allowPrivilegeEscalation'])
        self.assertTrue(c['securityContext']['readOnlyRootFilesystem'])
        self.assertFalse(any('hostPath' in v for v in pod['volumes']))
        roles={x['metadata']['name']:x for x in docs if x['kind']=='Role'}
        self.assertEqual(roles['guest-reader']['rules'],[{'apiGroups':['image.openshift.io'],'resources':['imagestreams/layers'],'resourceNames':['confidential-storage-sidecar'],'verbs':['get']}])
        for b in (x for x in docs if x['kind']=='RoleBinding'):
            self.assertEqual(b['metadata']['namespace'],'inference')
            self.assertEqual(b['subjects'][0]['namespace'],'trusted-enrollment')
    def test_reader_cannot_be_in_workload_project(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.render('model-publisher',self.publisher(),namespace='inference')
    def test_enrollment_has_no_keys_tokens_or_formatters(self):
        docs=self.render('storage-enrollment',{'installation':'demo','image':'example.invalid/authority@sha256:'+'a'*64,'stateClaim':'retained','serviceAccount':'authority','plan':{'purpose':'trusted-storage-enrollment/v1','schemaVersion':1,'records':[]}})
        job=next(x for x in docs if x['kind']=='Job')['spec']['template']['spec']
        self.assertEqual(job['securityContext']['fsGroupChangePolicy'],'OnRootMismatch')
        self.assertFalse(job['automountServiceAccountToken'])
        self.assertFalse(any('secret' in v or 'hostPath' in v for v in job['volumes']))
        self.assertIn('enroll.py apply',job['containers'][0]['args'][0])
        self.assertNotIn('cryptsetup',json.dumps(job))
