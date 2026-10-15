"""The reusable profile must not carry deployment state or relax vLLM."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'components/inference-release'))
s=importlib.util.spec_from_file_location('runtime_profile',ROOT/'components/inference-release/profile.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)

class ProfileTests(unittest.TestCase):
    def test_template_requires_site_inputs_and_preserves_application_isolation(self):
        t=json.loads((ROOT/'profiles/osc-snp-nvidia-x86_64-v1.json').read_text())
        self.assertEqual(t['helper']['image'],'')
        self.assertEqual(t['kubernetesServiceHost'],'')
        self.assertNotIn('startupChecks',t)
        d={'format':'luks-verity-v1','files':[{'path':'weights.bin','bytes':1,'sha256':'a'*64}]}
        args=(t,'registry.example/helper@sha256:'+'b'*64,'172.30.0.1','build-1','enrollment',d,'run-1')
        r=m.instantiate(*args)
        self.assertEqual(r['application'],t['application'])
        self.assertEqual(r['application']['capabilities'],[])
        self.assertEqual(r['application']['rawDevices'],[])
        self.assertEqual(r['startupChecks']['inventory'],d['files'])
        for index,bad in ((1,'registry.example/helper:latest'),(2,'hostname.invalid'),(3,'x\nBYPASS=1')):
            changed=list(args);changed[index]=bad
            with self.assertRaises(ValueError):m.instantiate(*changed)
