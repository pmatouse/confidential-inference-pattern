import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('demo_startup',Path(__file__).resolve().parents[1]/'components/inference-release/startup.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class StartupTests(unittest.TestCase):
    def settings(self):
        return {'modelMount':'/model','dataMount':'/data','identity':'qwen-demo-003','inventory':[{'path':'model.safetensors','bytes':1024,'sha256':'a'*64}]}
    def test_valid_measured_program(self):
        code=m.render(self.settings())
        compile(code,'measured-startup','exec')
        self.assertIn("saved['firstBoot'] != boot",code)
        self.assertIn('STORAGE_MODEL_RO_HASHES_PASS',code)
    def test_rejects_escaping_inventory(self):
        s=self.settings();s['inventory'][0]['path']='../host-key'
        with self.assertRaises(ValueError):m.render(s)
    def test_requires_separate_mounts(self):
        s=self.settings();s['dataMount']='/model'
        with self.assertRaises(ValueError):m.render(s)
