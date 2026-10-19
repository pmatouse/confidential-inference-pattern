"""Security and ordering checks for automatic RHOAI dependency installation."""
import copy
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('rhoai_bootstrap', ROOT / 'charts/rhoai-platform/files/bootstrap.py')
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)
EXPECTED = 'rhods-operator.3.6.0-ea.2'
NS = 'redhat-ods-operator'


class FakeAPI:
    def __init__(self):
        self.objects = {}
        self.patches = []

    def request(self, path, patch=None):
        if patch is not None:
            self.patches.append((path, patch))
            return {}
        return copy.deepcopy(self.objects.get(path))

    def operator_object(self, resource, name, value):
        self.objects[bootstrap.named_path('operators.coreos.com/v1alpha1', NS, resource, name)] = value


class Dependencies(unittest.TestCase):
    def setUp(self):
        self.api = FakeAPI()
        self.sub = {
            'spec': {'startingCSV': EXPECTED, 'installPlanApproval': 'Manual'},
            'status': {'currentCSV': EXPECTED, 'installPlanRef': {'name': 'install-test', 'namespace': NS}},
        }
        self.plan = {'metadata': {'resourceVersion': '123'}, 'spec': {'clusterServiceVersionNames': [EXPECTED], 'approved': False}}
        self.put()

    def put(self):
        self.api.operator_object('subscriptions', 'rhods-operator', self.sub)
        self.api.operator_object('installplans', 'install-test', self.plan)

    def ready_crds(self):
        for name, version in bootstrap.CRDS.items():
            self.api.objects['/apis/apiextensions.k8s.io/v1/customresourcedefinitions/' + name] = {
                'spec': {'versions': [{'name': version, 'served': True}]},
                'status': {'conditions': [{'type': 'Established', 'status': 'True'}]},
            }

    def test_exact_release_approval_is_atomic(self):
        self.assertFalse(bootstrap.operator_step(self.api, NS, EXPECTED))
        self.assertEqual(len(self.api.patches), 1)
        _, patch = self.api.patches[0]
        self.assertIn({'op': 'test', 'path': '/metadata/resourceVersion', 'value': '123'}, patch)
        self.assertIn({'op': 'test', 'path': '/spec/clusterServiceVersionNames', 'value': [EXPECTED]}, patch)
        self.assertIn({'op': 'test', 'path': '/spec/approved', 'value': False}, patch)
        self.assertEqual(patch[-1], {'op': 'replace', 'path': '/spec/approved', 'value': True})

    def test_wrong_or_additional_bundle_never_approved(self):
        for bundles in [[], ['rhods-operator.9.9.9'], [EXPECTED, 'unreviewed-operator.1.0']]:
            with self.subTest(bundles=bundles):
                self.plan['spec']['clusterServiceVersionNames'] = bundles
                self.put()
                with self.assertRaises(RuntimeError):
                    bootstrap.operator_step(self.api, NS, EXPECTED)
                self.assertEqual(self.api.patches, [])

    def test_foreign_namespace_never_approved(self):
        self.sub['status']['installPlanRef']['namespace'] = 'another-operator'
        self.put()
        with self.assertRaises(RuntimeError):
            bootstrap.operator_step(self.api, NS, EXPECTED)
        self.assertEqual(self.api.patches, [])

    def test_automatic_upgrades_or_changed_pin_rejected(self):
        for field, value in [('installPlanApproval', 'Automatic'), ('startingCSV', 'other')]:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.sub)
                changed['spec'][field] = value
                self.api.operator_object('subscriptions', 'rhods-operator', changed)
                with self.assertRaises(RuntimeError):
                    bootstrap.operator_step(self.api, NS, EXPECTED)
                self.assertEqual(self.api.patches, [])

    def test_existing_different_version_rejected(self):
        self.sub['status']['installedCSV'] = 'rhods-operator.3.5.0'
        self.put()
        with self.assertRaises(RuntimeError):
            bootstrap.operator_step(self.api, NS, EXPECTED)
        self.assertEqual(self.api.patches, [])

    def test_approved_plan_is_not_patched_twice(self):
        self.plan['spec']['approved'] = True
        self.put()
        self.assertFalse(bootstrap.operator_step(self.api, NS, EXPECTED))
        self.assertEqual(self.api.patches, [])

    def test_installed_csv_waits_for_served_dsc_api(self):
        self.api.operator_object('clusterserviceversions', EXPECTED, {'status': {'phase': 'Succeeded'}})
        self.assertFalse(bootstrap.operator_step(self.api, NS, EXPECTED))
        self.ready_crds()
        self.assertTrue(bootstrap.operator_step(self.api, NS, EXPECTED))
        self.assertEqual(self.api.patches, [])

    def test_serving_waits_for_ready_current_generation_and_apis(self):
        path = '/apis/datasciencecluster.opendatahub.io/v2/datascienceclusters/default-dsc'
        self.assertFalse(bootstrap.serving_step(self.api))
        self.api.objects[path] = {'metadata': {'generation': 2}, 'status': {'observedGeneration': 1, 'conditions': [{'type': 'Ready', 'status': 'True'}]}}
        self.ready_crds()
        self.assertFalse(bootstrap.serving_step(self.api))
        self.api.objects[path]['status']['observedGeneration'] = 2
        self.assertTrue(bootstrap.serving_step(self.api))
        crd = self.api.objects['/apis/apiextensions.k8s.io/v1/customresourcedefinitions/llminferenceservices.serving.kserve.io']
        crd['spec']['versions'][0]['served'] = False
        self.assertFalse(bootstrap.serving_step(self.api))


if __name__ == '__main__':
    unittest.main()
