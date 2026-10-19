"""Bounded Argo hook for the pinned RHOAI operator and serving APIs."""
import json
import os
from pathlib import Path
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request


CRDS = {
    'datascienceclusters.datasciencecluster.opendatahub.io': 'v2',
    'llminferenceservices.serving.kserve.io': 'v1alpha2',
    'llminferenceserviceconfigs.serving.kserve.io': 'v1alpha2',
}


class Kubernetes:
    def __init__(self):
        account = Path('/var/run/secrets/kubernetes.io/serviceaccount')
        self.token = (account / 'token').read_text().strip()
        self.context = ssl.create_default_context(cafile=str(account / 'ca.crt'))
        self.url = 'https://kubernetes.default.svc'

    def request(self, path, patch=None):
        headers = {'Authorization': 'Bearer ' + self.token}
        if patch is not None:
            headers['Content-Type'] = 'application/json-patch+json'
        request = urllib.request.Request(
            self.url + path, headers=headers,
            data=None if patch is None else json.dumps(patch).encode(),
            method='GET' if patch is None else 'PATCH')
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if error.code == 404 and patch is None:
                return None
            raise


def named_path(group, namespace, resource, name):
    return f'/apis/{group}/namespaces/{urllib.parse.quote(namespace, safe="")}/{resource}/{urllib.parse.quote(name, safe="")}'


def true_condition(obj, kind):
    return any(c.get('type') == kind and c.get('status') == 'True'
               for c in obj.get('status', {}).get('conditions', []))


def crd_ready(api, name):
    crd = api.request('/apis/apiextensions.k8s.io/v1/customresourcedefinitions/' + name)
    return bool(crd and true_condition(crd, 'Established') and any(
        v['name'] == CRDS[name] and v.get('served') for v in crd['spec']['versions']))


def operator_step(api, namespace, expected):
    sub = api.request(named_path('operators.coreos.com/v1alpha1', namespace, 'subscriptions', 'rhods-operator'))
    if not sub:
        return False
    spec, status = sub['spec'], sub.get('status', {})
    if spec.get('installPlanApproval') != 'Manual' or spec.get('startingCSV') != expected:
        raise RuntimeError('RHOAI Subscription differs from the pinned manual-approval configuration')
    for field in ('currentCSV', 'installedCSV'):
        if status.get(field) and status[field] != expected:
            raise RuntimeError(f'Unexpected RHOAI {field}: {status[field]}; expected {expected}')
    csv = api.request(named_path('operators.coreos.com/v1alpha1', namespace, 'clusterserviceversions', expected))
    if csv and csv.get('status', {}).get('phase') == 'Succeeded':
        return crd_ready(api, 'datascienceclusters.datasciencecluster.opendatahub.io')
    ref = status.get('installPlanRef')
    if not ref:
        return False
    if ref.get('namespace', namespace) != namespace:
        raise RuntimeError('InstallPlan reference points outside the RHOAI operator namespace')
    path = named_path('operators.coreos.com/v1alpha1', namespace, 'installplans', ref['name'])
    plan = api.request(path)
    if not plan:
        return False
    if plan['spec'].get('clusterServiceVersionNames') != [expected]:
        raise RuntimeError('Refusing InstallPlan: its CSV list differs from the single approved RHOAI release')
    if not plan['spec'].get('approved'):
        # Atomic tests prevent approving a plan whose resolution changed after GET.
        api.request(path, patch=[
            {'op': 'test', 'path': '/metadata/resourceVersion', 'value': plan['metadata']['resourceVersion']},
            {'op': 'test', 'path': '/spec/clusterServiceVersionNames', 'value': [expected]},
            {'op': 'test', 'path': '/spec/approved', 'value': False},
            {'op': 'replace', 'path': '/spec/approved', 'value': True},
        ])
        print('Approved the pinned RHOAI InstallPlan:', expected, flush=True)
    return False


def serving_step(api):
    dsc = api.request('/apis/datasciencecluster.opendatahub.io/v2/datascienceclusters/default-dsc')
    if not dsc or not true_condition(dsc, 'Ready'):
        return False
    observed = dsc.get('status', {}).get('observedGeneration')
    if observed is not None and observed < dsc['metadata']['generation']:
        return False
    return all(crd_ready(api, name) for name in CRDS)


def main():
    api = Kubernetes()
    phase = os.environ['PHASE']
    if phase not in ('operator', 'serving'):
        raise RuntimeError('Unknown dependency phase')
    deadline = time.monotonic() + int(os.environ['TIMEOUT_SECONDS'])
    while time.monotonic() < deadline:
        ready = (operator_step(api, os.environ['OPERATOR_NAMESPACE'], os.environ['EXPECTED_CSV'])
                 if phase == 'operator' else serving_step(api))
        if ready:
            print('RHOAI_DEPENDENCY_READY:', phase, flush=True)
            return
        time.sleep(5)
    raise TimeoutError('RHOAI dependency did not become ready: ' + phase)


if __name__ == '__main__':
    main()
