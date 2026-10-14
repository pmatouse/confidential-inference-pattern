#!/usr/bin/env python3
"""Package public enrollment results; never signs or changes Trustee policy."""
import argparse
import json
from pathlib import Path
from enroll import guest_configuration
from render import package

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for f in ('request','draft','plan','enrollment','authority','encodings','runtime','aa','cdh','output'):
        p.add_argument('--'+f,type=Path,required=True)
    a=p.parse_args()
    inputs={k:json.loads(getattr(a,k).read_text()) for k in ('request','draft','plan','enrollment','authority','encodings','runtime')}
    guest=guest_configuration(inputs['request'],inputs['draft'],inputs['plan'],inputs['enrollment'],inputs['authority'],inputs['encodings'])
    result=package(inputs['request'],inputs['draft'],guest,a.aa.read_text(),a.cdh.read_text(),inputs['runtime'])
    a.output.mkdir(mode=0o700)
    for name,raw in result.items():
        with (a.output/name).open('x') as f:f.write(raw)
    print('Public package validated by the controller contract; Trustee policy and signing remain explicit trusted steps.')

if __name__=='__main__':main()
