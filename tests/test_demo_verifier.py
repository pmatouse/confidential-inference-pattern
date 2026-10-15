import importlib.util
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('demo_verifier',ROOT/'scripts/verify-demo.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)

class VerificationTests(unittest.TestCase):
    def test_fresh_vm_requires_first_canary_and_different_pod_and_boot(self):
        old={'podUid':'old-pod','boot':'first-boot'}
        e={'STORAGE_DATA_FRESH_VM_REOPEN_PASS':{'firstBoot':'first-boot','boot':'new-boot'}}
        self.assertEqual(m.persistence(e,'reopen','new-pod',old),'new-boot')
        for uid,first,boot in [('old-pod','first-boot','new-boot'),('new-pod','wrong','new-boot'),('new-pod','first-boot','first-boot')]:
            with self.assertRaises(ValueError):
                m.persistence({'STORAGE_DATA_FRESH_VM_REOPEN_PASS':{'firstBoot':first,'boot':boot}},'reopen',uid,old)

    def test_gpu_and_readonly_hash_markers_are_both_required(self):
        for log in ('STORAGE_MODEL_RO_HASHES_PASS','{"event":"CUDA_GPU_PROBE_PASS"}'):
            with self.assertRaises(ValueError):m.events(log)
