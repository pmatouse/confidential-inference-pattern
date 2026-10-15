"""Instantiate a public stock-runtime compatibility template; does not approve it."""
import argparse
import copy
import ipaddress
import json
from pathlib import Path
import re
from startup import render


def instantiate(template, helper, host, build_name, build_namespace, descriptor,
                identity, model_mount='/model', data_mount='/data'):
    if not re.fullmatch(r'[^\s@]+@sha256:[a-f0-9]{64}', helper):
        raise ValueError('digest-pinned helper required')
    ipaddress.IPv4Address(host)
    for name in (build_name, build_namespace):
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', name):
            raise ValueError('explicit build identity required')
    if descriptor.get('format') != 'luks-verity-v1':
        raise ValueError('verified publisher descriptor required')
    p = copy.deepcopy(template)
    p['helper']['image'] = helper
    p['kubernetesServiceHost'] = host
    for field in ('environment', 'requiredEnvironment'):
        p['helper'][field] += ['OPENSHIFT_BUILD_NAME='+build_name,
                              'OPENSHIFT_BUILD_NAMESPACE='+build_namespace]
    p['startupChecks'] = dict(modelMount=model_mount, dataMount=data_mount,
                              inventory=descriptor['files'], identity=identity)
    render(p['startupChecks'])
    return p


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('template', 'descriptor', 'output'):
        p.add_argument('--'+name, type=Path, required=True)
    for name in ('helper-image', 'service-host', 'helper-build-name',
                 'helper-build-namespace', 'identity'):
        p.add_argument('--'+name, required=True)
    p.add_argument('--model-mount', default='/model')
    p.add_argument('--data-mount', default='/data')
    a = p.parse_args()
    result = instantiate(json.loads(a.template.read_text()), a.helper_image,
                         a.service_host, a.helper_build_name, a.helper_build_namespace,
                         json.loads(a.descriptor.read_text()), a.identity,
                         a.model_mount, a.data_mount)
    with a.output.open('x') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
    print('Public profile candidate prepared; review image metadata before approval.')


if __name__ == '__main__':
    main()
