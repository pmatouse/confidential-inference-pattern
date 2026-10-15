"""Both entry points must preserve stage order, inputs and fail-stop boundaries."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from quickstart.core import STAGES


class InstallationParityTests(unittest.TestCase):
    def invoke(self, target, fail=''):
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            runner = scratch / 'make-stub'
            runner.write_text('#!' + sys.executable + '\n' + '''import json, os, sys
with open(os.environ['CALL_LOG'], 'a') as stream:
    stream.write(json.dumps(sys.argv[1:]) + '\\n')
sys.exit(1 if sys.argv[1] == os.environ['FAIL_STAGE'] else 0)
''')
            runner.chmod(0o700)
            log = scratch / 'calls.jsonl'
            env = {**os.environ, 'CALL_LOG': str(log), 'FAIL_STAGE': fail,
                   'QUICKSTART_CACHE': str(scratch / 'cache with spaces')}
            result = subprocess.run(['make', '-j8', target, 'MAKE=' + str(runner),
                                     'VALUES=site with spaces.yaml', 'RUN=demo',
                                     'PYTHON=' + sys.executable], cwd=ROOT, env=env,
                                    capture_output=True, text=True)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            for call in calls:
                self.assertIn('VALUES=site with spaces.yaml', call)
                self.assertIn('RUN=demo', call)
                expected = sys.executable if call[0] == 'qs-tools' else str(scratch / 'cache with spaces/venv/bin/python')
                self.assertIn('PYTHON=' + expected, call)
            return result, [call[0] for call in calls]

    def test_manual_and_controller_share_the_complete_foundation(self):
        boundary = STAGES.index('model')
        foundation = ['qs-' + stage for stage in STAGES[:boundary]]
        for target, suffix in [('quickstart-foundation', []), ('controller-demo', [
                'release-controller-image', 'release-controller-install', 'release-controller-start'])]:
            with self.subTest(target=target):
                result, calls = self.invoke(target)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, foundation + suffix)

    def test_failed_gate_never_reaches_handover_or_submission(self):
        for failure in ('qs-tools', 'qs-integrations', 'qs-install', 'release-controller-install'):
            with self.subTest(failure=failure):
                result, calls = self.invoke('controller-demo', fail=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls[-1], failure)
                self.assertNotIn('release-controller-start', calls)

    def test_manual_and_controller_execute_the_same_release_stages(self):
        spec = importlib.util.spec_from_file_location('parity_controller', ROOT / 'components/inference-release-controller/controller.py')
        controller = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(controller)
        self.assertEqual(controller.STAGES, STAGES[STAGES.index('model'):])
        # The manual guide must enumerate every operation, including the foundation.
        guide = (ROOT / 'docs/demo/quickstart.md').read_text()
        for stage in STAGES:
            self.assertIn('`make qs-' + stage + '`', guide)
