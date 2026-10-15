#!/usr/bin/env python3
"""Trusted edge Vault/ESO enrollment adapter; never installed in a workload controller.

Uses only the dedicated short-lived Vault role. Existing ESO projection is used
for tag-existence and write verification; its trusted operator needs Secret read
access. No Vault administrator token is discovered. All secret subprocess output
is captured and never included in errors. One CAS merge patch preserves other tags.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time


def require(ok, message):
    if not ok: raise ValueError(message)


def validate_bindings(policy, policy_sha, runtime, tags):
    require(hashlib.sha256(policy.encode()).hexdigest()==policy_sha,'resource policy differs from reviewed owner output')
    matches=list(re.finditer(r'^model_key_bindings := ',policy,re.M))
    require(len(matches)==1,'expected owner binding map')
    bindings,_=json.JSONDecoder().raw_decode(policy[matches[0].end():])
    require(isinstance(bindings,dict),'expected binding object')
    expected={'initData':runtime['initDataSha256'],'launchMeasurement':runtime['launchMeasurement']}
    require(all(bindings.get(tag)==expected for tag in tags),'exact measured key bindings not installed')


def new_tags(tags, existing):
    require(2<=len(tags)<=3 and len(set(tags))==len(tags),'distinct model/data and optional registry resources required')
    require(all(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}',t) for t in tags),'invalid key tag')
    require(not set(tags)&set(existing),'refusing existing key tags')


def stamp(value):
    return dt.datetime.fromisoformat(value.replace('Z','+00:00'))


class Adapter:
    def __init__(self, args):self.args=args;self.token=None
    def oc(self,args,body=None):
        r=subprocess.run(['oc','--request-timeout=30s']+args,input=body,text=True,capture_output=True)
        if r.returncode:raise RuntimeError('Kubernetes operation failed; output withheld')
        return r.stdout
    def vault(self,args,body='',authenticated=True):
        if authenticated:
            require(self.token is not None,'scoped login required')
            script='set -eu\nread -r VAULT_TOKEN; export VAULT_TOKEN\nexec '+shlex.join(['vault']+args)
            body=self.token+'\n'+body
        else:script='unset VAULT_TOKEN\nexec '+shlex.join(['vault']+args)
        r=subprocess.run(['oc','--request-timeout=30s','exec','-i','-n',self.args.vault_namespace,self.args.vault_pod,'--','sh','-c',script],input=body,text=True,capture_output=True)
        if r.returncode:raise RuntimeError('Scoped Vault operation failed; output withheld')
        return r.stdout
    def login(self):
        jwt=self.oc(['create','token',self.args.service_account,'-n',self.args.enrollment_namespace,'--audience=vault','--duration=10m']).strip()
        auth=json.loads(self.vault(['write','-format=json','auth/'+self.args.auth_mount+'/login','-'],json.dumps({'role':self.args.role,'jwt':jwt}),False))['auth']
        require(auth['policies']==[self.args.role] and 0<auth['lease_duration']<=900,'unexpected scoped token')
        self.token=auth['client_token']
    def metadata(self):return json.loads(self.vault(['read','-format=json','secret/metadata/hub/modelKeys']))['data']
    def projection(self):
        a=self.args
        es=json.loads(self.oc(['get','externalsecret',a.external_secret,'-n',a.trustee_namespace,'-o','json']))
        require(es['spec']['dataFrom']==[{'extract':es['spec']['dataFrom'][0]['extract']}],'unexpected ESO sources')
        require(es['spec']['dataFrom'][0]['extract']['key']=='secret/data/hub/modelKeys','wrong ESO backend record')
        require(es['spec']['target']['name']==a.secret,'wrong ESO target')
        require(any(c['type']=='Ready' and c['status']=='True' for c in es['status'].get('conditions',[])),'ESO not ready')
        tags=self.oc(['get','secret',a.secret,'-n',a.trustee_namespace,'-o','go-template={{range $k,$v := .data}}{{$k}}{{"\\n"}}{{end}}']).splitlines()
        return es['status']['refreshTime'],tags
    def verify_written(self, values, version):
        for _ in range(90):
            meta=self.metadata();require(meta['current_version']==version,'backend changed during verification; manual review required')
            refreshed,tags=self.projection()
            if stamp(refreshed)>=stamp(meta['updated_time']) and set(values)<=set(tags):
                for tag,wanted in values.items():
                    encoded=self.oc(['get','secret',self.args.secret,'-n',self.args.trustee_namespace,'-o','go-template={{index .data '+json.dumps(tag)+'}}']).strip()
                    require(base64.b64decode(encoded,validate=True).decode()==wanted,'published key differs; refusing rotation')
                return
            time.sleep(2)
        raise RuntimeError('ESO verification timed out; retain journal and keys, retry recovery')


def execute(args):
    os.umask(0o077)
    mapping=json.loads(args.key_files.read_text()); values={}
    for tag,filename in mapping.items():
        encoding='lower-hex64'
        if isinstance(filename,dict):
            require(set(filename)=={'path','encoding'},'explicit credential file encoding required')
            encoding=filename['encoding'];filename=filename['path']
        p=Path(filename)
        require(p.is_file() and not p.is_symlink() and p.stat().st_mode&0o077==0,'private key file required')
        raw=p.read_bytes()
        if encoding=='lower-hex64':
            require(len(raw)==32,'32-byte key required');values[tag]=raw.hex()
        else:
            require(encoding=='registry-json' and 0<len(raw)<=16384,'unsupported credential encoding')
            config=json.loads(raw);require(set(config)=={'auths'} and len(config['auths'])==1,'one explicit registry credential required')
            require(all(set(v)=={'auth'} for v in config['auths'].values()),'unsupported registry credential')
            values[tag]=raw.decode()
    runtime=json.loads(args.runtime.read_text());adapter=Adapter(args)
    policy=json.loads(adapter.oc(['get','cm','resource-policy','-n',args.trustee_namespace,'-o','json']))['data']['resource-policy.rego']
    validate_bindings(policy,args.policy_sha256,runtime,values)
    adapter.login()
    identity={'tags':sorted(values),'keySha256':{t:hashlib.sha256(v.encode()).hexdigest() for t,v in values.items()},'policySha256':args.policy_sha256,'runtime':runtime}
    if args.journal.exists():
        previous=json.loads(args.journal.read_text());require(previous['identity']==identity,'journal identity differs')
        adapter.verify_written(values,previous['beforeVersion']+1)
        receipt=previous|{'state':'verified','afterVersion':previous['beforeVersion']+1}
    else:
        meta=adapter.metadata();refreshed,tags=adapter.projection()
        require(stamp(refreshed)>=stamp(meta['updated_time']),'ESO projection is stale; retry after refresh')
        require(adapter.metadata()['current_version']==meta['current_version'],'backend changed before reservation')
        new_tags(list(values),tags)
        pending={'state':'submitted-or-uncertain','beforeVersion':meta['current_version'],'identity':identity}
        with args.journal.open('x') as f:json.dump(pending,f,sort_keys=True);f.flush();os.fsync(f.fileno())
        # Exact HTTP PATCH only: never fall back to reading/replacing the record.
        result=json.loads(adapter.vault(['kv','patch','-format=json','-mount=secret','-method=patch','-cas='+str(meta['current_version']),'hub/modelKeys','-'],json.dumps(values)))
        version=result['data']['version'];require(version==meta['current_version']+1,'unexpected backend version')
        adapter.verify_written(values,version)
        receipt=pending|{'state':'verified','afterVersion':version}
    temporary=args.journal.with_suffix('.verified.tmp')
    with temporary.open('x') as f:json.dump(receipt,f,sort_keys=True);f.flush();os.fsync(f.fileno())
    temporary.replace(args.journal)
    adapter.token=None
    print(json.dumps({'state':receipt['state'],'beforeVersion':receipt['beforeVersion'],'afterVersion':receipt['afterVersion'],'keys':len(values),'administratorCredentialUsed':False}))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ('key-files','runtime','journal'):p.add_argument('--'+arg,type=Path,required=True)
    p.add_argument('--policy-sha256',required=True)
    for name,default in [('vault-namespace','vault'),('vault-pod','vault-0'),('enrollment-namespace','confidential-inference-enrollment'),('service-account','confidential-inference-enroller'),('auth-mount','hub'),('role','confidential-inference-enroller'),('trustee-namespace','trustee-operator-system'),('external-secret','model-keys-eso'),('secret','model-keys')]:p.add_argument('--'+name,default=default)
    execute(p.parse_args())
