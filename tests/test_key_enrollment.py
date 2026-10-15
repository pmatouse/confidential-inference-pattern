import hashlib,importlib.util,json
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('key_enrollment',Path(__file__).resolve().parents[1]/'components/inference-release/key_enrollment.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class KeyEnrollmentTests(unittest.TestCase):
    def test_existing_tag_is_not_rotated(self):
        with self.assertRaises(ValueError):m.new_tags(['new-model','existing-data'],['existing-data'])
    def test_only_exact_reviewed_bindings(self):
        rt={'initDataSha256':'a'*64,'launchMeasurement':'b'*96}
        bindings={tag:{'initData':rt['initDataSha256'],'launchMeasurement':rt['launchMeasurement']} for tag in ['model','data']}
        policy='model_key_bindings := '+json.dumps(bindings)+'\n'
        sha=hashlib.sha256(policy.encode()).hexdigest()
        m.validate_bindings(policy,sha,rt,['model','data'])
        with self.assertRaises(ValueError):m.validate_bindings(policy,sha,rt|{'initDataSha256':'c'*64},['model','data'])
        with self.assertRaises(ValueError):m.validate_bindings(policy+'allow := true\n',sha,rt,['model','data'])

    def test_multiline_binding_map(self):
        rt={'initDataSha256':'a'*64,'launchMeasurement':'b'*96}
        bindings={tag:{'initData':rt['initDataSha256'],'launchMeasurement':rt['launchMeasurement']} for tag in ['model','data','registry']}
        policy='package policy\nmodel_key_bindings := '+json.dumps(bindings,indent=2)+'\ndefault allow := false\n'
        m.validate_bindings(policy,hashlib.sha256(policy.encode()).hexdigest(),rt,list(bindings))
        duplicate=policy+'model_key_bindings := {}\n'
        with self.assertRaises(ValueError):m.validate_bindings(duplicate,hashlib.sha256(duplicate.encode()).hexdigest(),rt,list(bindings))
