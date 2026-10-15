"""Private run state, bounded subprocesses and ownership-checked cluster operations."""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

import yaml
import addon

ROOT = Path(__file__).resolve().parents[2]
STAGES = ('tools','dependencies','preflight','integrations','bootstrap','build','push','install','model',
          'volumes','measure','enroll','deploy','test-first','test-reopen','report')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()


def write(path, data, private=True):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not path.is_symlink(), 'refusing symlink output')
    raw = data if isinstance(data, bytes) else data.encode() if isinstance(data,str) else canonical(data)+b'\n'
    temp = path.with_name(path.name+'.tmp-'+str(os.getpid()))
    fd = os.open(temp, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600 if private else 0o644)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.replace(temp,path)
    finally:
        if temp.exists():temp.unlink()


class Run:
    def __init__(self, values, name, exclusive=True):
        os.umask(0o077)
        self.source = Path(values).resolve()
        self.v = addon.load(self.source)
        require(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,39}',name), 'invalid run name')
        require(name == self.v['demo']['name'], 'RUN must match demo.name')
        self.name = name
        self.ns = self.v['installation']['namespace']
        self.installation = self.v['installation']['name']
        self.q = self.v.get('quickstart',{})
        self.trusted = self.q.get('trustedNamespace', self.ns+'-trusted')
        require(self.trusted != self.ns and re.fullmatch(addon.NAME,self.trusted),'separate trusted namespace required')
        self.cache = Path(os.environ.get('QUICKSTART_CACHE',str(ROOT/'.cache/quickstart'))).resolve()/name
        self.cache.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.state = Path(os.environ.get('QUICKSTART_STATE_ROOT',str(ROOT/'.private/quickstart')))/name
        self.out = Path(os.environ.get('QUICKSTART_OUTPUT_ROOT',str(ROOT/'output/quickstart')))/name
        self.state.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.out.mkdir(mode=0o700,parents=True,exist_ok=True)
        require(not self.state.is_symlink() and self.state.stat().st_mode&0o077==0,'private run directory required')
        self.lock = (self.state/'lock').open('a')
        try:
            if exclusive:fcntl.flock(self.lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise ValueError('another executor owns this run') from None
        owner=self.state/'executor-owner.json'
        if exclusive and owner.exists():
            require(json.loads(owner.read_text())['executor']==os.environ.get('QUICKSTART_EXECUTOR','manual'),
                    'orchestration ownership differs; explicit handover required')
        self.identity = {'run':name,'siteSha256':sha(canonical(self.v)), 'namespace':self.ns,
                         'installation':self.installation,'schemaVersion':1}
        p=self.state/'identity.json'
        if p.exists():require(json.loads(p.read_text())==self.identity,'run configuration changed; use a new run or explicit migration')
        else:write(p,self.identity)
        self.api = addon.Cluster()
        self.stage = 'status'
        self.log = None

    def command(self, args, body=None, timeout=180, binary=False, sensitive=False, cwd=None):
        args=[str(x) for x in args]
        if args and args[0]=='git' and os.environ.get('GITHUB_TOKEN') and shutil.which('gh'):
            args=['git','-c','url.https://github.com/.insteadOf=git@github.com:','-c','credential.helper=','-c','credential.helper=!gh auth git-credential',*args[1:]]
        result=subprocess.run(args,input=body,capture_output=True,
                              text=not binary,timeout=timeout,cwd=cwd,env=os.environ.copy())
        if self.log and not sensitive and not binary:
            with self.log.open('ab') as f:
                for raw in (result.stdout,result.stderr):
                    f.write(raw if isinstance(raw,bytes) else raw.encode())
        if result.returncode:
            raise RuntimeError('Command failed: '+str(args[0])+' '+str(args[1] if len(args)>1 else '')+
                               '; see private stage log (sensitive output withheld)')
        return result.stdout

    def oc(self,*args,body=None,binary=False,sensitive=False,timeout=180):
        return self.command(['oc','--request-timeout='+('0' if 'exec' in args or 'logs' in args else '120s'),*args],body=body,binary=binary,
                            sensitive=sensitive,timeout=timeout)

    def get(self, kind, name=None, ns=None):
        args=['get',kind]
        if name:args.append(name)
        if ns:args+=['-n',ns]
        args+=['-o','json']
        if name:args+=['--ignore-not-found']
        raw=self.oc(*args,sensitive=True)
        return json.loads(raw) if raw.strip() else None

    def apply(self,obj, sensitive=False):
        obj=copy.deepcopy(obj)
        obj.setdefault('metadata',{}).setdefault('labels',{})[addon.OWNER]=self.installation
        old=self.get(obj['kind'],obj['metadata']['name'],obj['metadata'].get('namespace'))
        require(not old or old['metadata'].get('labels',{}).get(addon.OWNER)==self.installation,
                'refusing foreign resource '+obj['kind']+'/'+obj['metadata']['name'])
        return self.oc('apply','--server-side','--field-manager=confidential-inference-quickstart','-f','-',
                       body=json.dumps(obj),sensitive=sensitive)

    def helm(self, chart, values, namespace, release):
        objects=addon.helm(ROOT/chart,values,namespace,release)
        for obj in objects:
            if obj['kind'] not in ('Namespace','CustomResourceDefinition','ClusterRole','ClusterRoleBinding'):
                obj.setdefault('metadata',{}).setdefault('namespace',namespace)
            self.apply(obj)
        return objects

    def wait(self, description, check, timeout=300, interval=3):
        until=time.monotonic()+timeout
        while time.monotonic()<until:
            value=check()
            if value:return value
            time.sleep(interval)
        raise RuntimeError('Timed out: '+description)

    def save(self,name,obj,private=False):
        write((self.state if private else self.out)/name,obj)
        return obj

    def read(self,name,private=False):
        return json.loads(((self.state if private else self.out)/name).read_text())

    def resolved(self):
        p=self.out/'resolved-values.json'
        return json.loads(p.read_text()) if p.exists() else copy.deepcopy(self.v)

    def save_values(self,v):
        self.save('resolved-values.json',v)

    def receipt(self,stage):
        p=self.out/'receipts'/f'{stage}.json'
        return json.loads(p.read_text()) if p.exists() else None

    def finish(self,stage,result):
        require(isinstance(result,dict),'stage must return a receipt')
        receipt={'schemaVersion':1,'stage':stage,'run':self.name,'siteSha256':self.identity['siteSha256'],
                 'result':result,'completedAt':int(time.time())}
        if not (self.out/'first-receipts'/f'{stage}.json').exists():
            self.save('first-receipts/'+stage+'.json',receipt)
        self.save('receipts/'+stage+'.json',receipt)
        print(json.dumps({'stage':stage,'result':result.get('state','Complete'),
                          'receipt':str(self.out/'receipts'/f'{stage}.json')},sort_keys=True),flush=True)

    def require_stage(self,stage):
        receipt=self.receipt(stage)
        require(receipt and receipt['siteSha256']==self.identity['siteSha256'], 'run make qs-'+stage+' first')
        if stage != 'tools':
            current=self.get('clusterversion','version')
            original=self.receipt('preflight')
            if original:require(current['metadata']['uid']==original['result']['clusterUID'],'kubecontext cluster changed')
        if stage not in ('tools','dependencies','preflight'):
            bootstrap=self.receipt('bootstrap')
            if bootstrap:
                for ns,uid in bootstrap['result']['namespaces'].items():
                    current=self.get('namespace',ns)
                    require(current and current['metadata']['uid']==uid,'installation namespace replaced')
        return receipt['result']
