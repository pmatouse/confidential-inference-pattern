#!/usr/bin/env python3
"""Evaluate the rendered stock-chart adapter with a caller-supplied OPA binary."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import addon
from quickstart.integrations import stock_adapter

ROOT=Path(__file__).resolve().parents[1]
opa=os.environ.get('OPA','opa')
binding={'launchMeasurement':'a'*96,'initData':'b'*64}
cpu={'ear.status':'affirming','ear.trustworthiness-vector':{'hardware':2,'configuration':3,'executables':3},
     'ear.veraison.annotated-evidence':{'snp':{'measurement':binding['launchMeasurement'],'policy_debug_allowed':False,'policy_migrate_ma':False},'init_data':binding['initData']}}
gpu={'ear.status':'affirming','ear.trustworthiness-vector':{'hardware':2,'configuration':3,'executables':3},
     'ear.veraison.annotated-evidence':{'nvidia':{'x-nvidia-overall-att-result':True,'secboot':True,'dbgstat':'disabled','measres':'success'}}}
valid={'submods':{'cpu0':cpu,'gpu0':gpu}}
cases=[('bound-cpu-and-gpu',valid,'model-keys','model',True),('unknown-tag',valid,'model-keys','unknown',False),
       ('no-gpu',{'submods':{'cpu0':cpu}},'model-keys','model',False),('no-cpu',{'submods':{'gpu0':gpu}},'model-keys','model',False),
       ('legacy-cpu-resource',{'submods':{'cpu0':cpu}},'passphrase','key',True),('empty-evidence',{'submods':{}},'model-keys','model',False)]
for name,path,value in [
    ('wrong-launch',['cpu0','ear.veraison.annotated-evidence','snp','measurement'],'c'*96),
    ('wrong-initdata',['cpu0','ear.veraison.annotated-evidence','init_data'],'c'*64),
    ('debug-cpu',['cpu0','ear.veraison.annotated-evidence','snp','policy_debug_allowed'],True),
    ('migration-cpu',['cpu0','ear.veraison.annotated-evidence','snp','policy_migrate_ma'],True),
    ('gpu-report-failed',['gpu0','ear.veraison.annotated-evidence','nvidia','x-nvidia-overall-att-result'],False),
    ('gpu-debug',['gpu0','ear.veraison.annotated-evidence','nvidia','dbgstat'],'enabled'),
    ('gpu-secboot',['gpu0','ear.veraison.annotated-evidence','nvidia','secboot'],False),
    ('gpu-measurement',['gpu0','ear.veraison.annotated-evidence','nvidia','measres'],'failure'),
    ('gpu-hardware',['gpu0','ear.trustworthiness-vector','hardware'],97),
    ('cpu-configuration',['cpu0','ear.trustworthiness-vector','configuration'],36),
    ('cpu-executables',['cpu0','ear.trustworthiness-vector','executables'],33)]:
    evidence=copy.deepcopy(valid);target=evidence['submods']
    for key in path[:-1]:target=target[key]
    target[path[-1]]=value;cases.append((name,evidence,'model-keys','model',False))
with tempfile.TemporaryDirectory() as directory:
    root=Path(directory);chart=root/'chart'
    stock_adapter(ROOT/'prerequisites/trustee/trustee-0.10.2.tgz',chart)
    values={'global':{'hubClusterDomain':'apps.example.com'},'kbs':{'resourcePolicy':{'modelKeyBindings':{'model':binding}}}}
    objects=addon.helm(chart,values,'trustee-operator-system')
    policy=next(o['data']['resource-policy.rego'] for o in objects if o['kind']=='ConfigMap' and o['metadata']['name']=='resource-policy')
    (root/'policy.rego').write_text(policy)
    for name,evidence,kind,tag,expected in cases:
        (root/'input.json').write_text(json.dumps(evidence));(root/'data.json').write_text(json.dumps({'plugin':'resource','resource-path':['default',kind,tag]}))
        result=subprocess.check_output([opa,'eval','--format','raw','--data',str(root/'policy.rego'),'--data',str(root/'data.json'),'--input',str(root/'input.json'),'data.policy.allow'],text=True).strip()
        assert result==str(expected).lower(),(name,result)
        print(name+': PASS')
print(json.dumps({'casesPassed':len(cases),'stockChart':'0.10.2','policy':'bound SNP + NVIDIA; unbound model tags denied'}))
