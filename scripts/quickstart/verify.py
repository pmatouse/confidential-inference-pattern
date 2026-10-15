"""Executable first-boot and fresh-VM proof; never reset authority history."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request

from .core import ROOT, require, write


def predictor(r):
    items=r.get('pods',ns=r.ns)['items']
    found=[p for p in items if p['metadata'].get('labels',{}).get('serving.kserve.io/inferenceservice')==r.name
           and not p['metadata'].get('deletionTimestamp') and p['status'].get('phase')=='Running'
           and p['status'].get('containerStatuses') and all(c['ready'] for c in p['status']['containerStatuses'])]
    require(len(found)<=1,'multiple Ready predictors')
    return found[0] if found else None


@contextmanager
def tunnel(r):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    with (r.state/'port-forward.log').open('ab') as log:
        proc=subprocess.Popen(['oc','-n',r.ns,'port-forward','service/'+r.name+'-chat',str(port)+':'+str(r.resolved()['chat']['port']),'--address=127.0.0.1'],stdout=log,stderr=log)
        try:
            def available():
                require(proc.poll() is None,'chat port-forward exited')
                try:
                    with urllib.request.urlopen(f'http://127.0.0.1:{port}/',timeout=2) as reply:return reply.status==200
                except OSError:return False
            r.wait('chat HTTP endpoint',available,timeout=60)
            yield f'http://127.0.0.1:{port}'
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:proc.wait(timeout=10)
                except subprocess.TimeoutExpired:proc.kill();proc.wait()


def authority_snapshot(r):
    plan=r.read('enrollment-plan.json')
    ids=[entry['registration']['volume_id'] for entry in plan['records']]
    script='''import sqlite3,json,sys
ids=json.loads(sys.argv[1])
db=sqlite3.connect('file:/state/retained/authority.db?mode=ro',uri=True)
db.execute('BEGIN')
records=[json.loads(db.execute('SELECT record FROM volumes WHERE id=?',(v,)).fetchone()[0]) for v in ids]
counts={v:db.execute('SELECT count(*) FROM operations WHERE volume_id=?',(v,)).fetchone()[0] for v in ids}
print(json.dumps({'records':records,'operationCounts':counts}))
'''
    raw=r.oc('exec','-n',r.trusted,'deployment/'+r.name+'-authority','--','python3','-c',script,json.dumps(ids),sensitive=True)
    result=json.loads(raw)
    validate_authority(result,r.read('draft.json')['policySha256'])
    log=r.oc('logs','-n',r.trusted,'deployment/'+r.name+'-authority',sensitive=True)
    markers=['STORAGE_EAR submod='+part+' status=affirming hardware=2 configuration=3 executables=3' for part in ('cpu0','gpu0')]
    require(all(m in log for m in markers),'CPU and GPU appraisal markers missing')
    result['attestationMarkers']=markers
    return result


def validate_authority(snapshot,policy):
    records=snapshot['records']
    require(len(records)==2 and len({v['volume_id'] for v in records})==2,'two unique enrolled volumes required')
    rw=[]
    for record in records:
        require(record['state']=='Ready' and not record['revoked'] and record['policy_sha256']==policy,'volume not Ready under expected policy')
        require(record.get('owner') and record.get('header_sha256') and record.get('manifest_sha256'),'active owner and committed hashes required')
        if record.get('initialization_approval'):rw.append(record)
    require(len(rw)==1,'one initialized RW volume required')
    steps=rw[0]['initialization_steps']
    require([s['step'] for s in steps]==['luks-format','integrity-initialize','filesystem-create','durability-barrier'] and all(s['status']=='Complete' for s in steps),'all four initialization steps must be committed')


def compare_authority(first,second):
    before={r['volume_id']:r for r in first['records']};after={r['volume_id']:r for r in second['records']}
    require(before.keys()==after.keys(),'authority volume identities changed')
    for name,old in before.items():
        new=after[name]
        for key in ('generation','policy_sha256','profile_sha256','header_sha256','manifest_sha256','initialization_approval','initialization_steps'):
            require(old.get(key)==new.get(key),'reopen changed retained '+key)
        require(new['owner']['session_sha256']!=old['owner']['session_sha256'],'new attested owner session required')
        require(new.get('last_closed') and new['last_closed']['session_sha256']==old['owner']['session_sha256'],'previous owner did not close')
        require(second['operationCounts'][name]>first['operationCounts'][name],'reopen operation was not recorded')


def application_test(r,phase):
    runtime=r.read('release/runtime.json');v=r.resolved()
    target=r.out/('application-'+phase+'.json')
    temporary=r.out/('application-'+phase+'.pending.json')
    if temporary.exists():temporary.unlink() # public, uncommitted verification output only
    with tunnel(r) as url:
        args=[sys.executable,ROOT/'scripts/verify-demo.py','--namespace',r.ns,'--workload',r.name,
              '--chat-url',url,'--model',v['demo']['modelName'],'--expected-initdata',runtime['initDataSha256'],
              '--expected-application-image',v['images']['application'],'--phase',phase,'--output',temporary]
        if phase=='reopen':args+=['--previous',r.out/'application-first.json']
        r.command(args,timeout=240)
    result=json.loads(temporary.read_text());write(target,result);temporary.unlink()
    return result


def test_first(r):
    r.require_stage('deploy')
    previous=r.out/'application-first.json'
    if previous.exists():
        baseline=r.read('application-first.json');pod=predictor(r)
        require(pod and pod['metadata']['uid']==baseline['podUid'],'first-boot evidence retained; current VM differs, run qs-test-reopen')
    result=application_test(r,'first');snapshot=authority_snapshot(r)
    r.save('authority-first.json',snapshot)
    return {'state':'FirstBootPassed','podUID':result['podUid'],'pvcUIDs':result['pvcUids'],'cpuGpuAttestation':True,'chatStatus':result['chatStatus']}


def test_reopen(r):
    r.require_stage('test-first');baseline=r.read('application-first.json')
    old=r.get('pod',baseline['pod'],r.ns)
    if old:
        require(old['metadata']['uid']==baseline['podUid'],'refusing replacement Pod with reused name')
        # Persist the intent before deleting. A retry waits for the replacement; it never
        # deletes another VM or clears a stuck authority owner.
        write(r.state/'reopen-intent.json',{'pod':baseline['pod'],'uid':baseline['podUid']})
        logpath=r.state/'reopen-shutdown.log'
        with logpath.open('ab') as log:
            stream=subprocess.Popen(['oc','-n',r.ns,'logs','-f',baseline['pod'],'-c','storage-sidecar'],stdout=log,stderr=log)
            try:
                time.sleep(2)
                r.oc('delete','pod',baseline['pod'],'-n',r.ns,'--wait=false')
                r.wait('old predictor terminated',lambda:r.get('pod',baseline['pod'],r.ns) is None,timeout=600,interval=5)
            finally:
                if stream.poll() is None:stream.terminate()
                try:stream.wait(timeout=10)
                except subprocess.TimeoutExpired:stream.kill();stream.wait()
    require((r.state/'reopen-intent.json').exists(),'no recorded controlled replacement; preserve state and investigate')
    pod=r.wait('fresh confidential predictor',lambda:predictor(r),timeout=1800,interval=10)
    require(pod['metadata']['uid']!=baseline['podUid'],'replacement UID must differ')
    result=application_test(r,'reopen');snapshot=authority_snapshot(r)
    compare_authority(r.read('authority-first.json'),snapshot)
    r.save('authority-reopen.json',snapshot)
    return {'state':'FreshVMPersistencePassed','podUID':result['podUid'],'previousPodUID':baseline['podUid'],
            'samePVCs':True,'initializationUnchanged':True,'oldOwnerClosed':True,'cpuGpuAttestation':True,'chatStatus':result['chatStatus']}


def report(r):
    r.require_stage('test-reopen')
    pod=predictor(r);latest=r.read('application-reopen.json')
    require(pod and pod['metadata']['uid']==latest['podUid'],'current predictor differs from tested replacement')
    for name,uid in r.require_stage('volumes')['claims'].items():
        require(r.get('pvc',name,r.ns)['metadata']['uid']==uid,'tested claim replaced')
    compare_authority(r.read('authority-first.json'),authority_snapshot(r))
    summary={'state':'E2EPassed','run':r.name,'namespace':r.ns,'first':r.read('application-first.json'),
             'reopen':latest,'images':r.read('images.json'),'source':r.read('model-source.json'),
             'limitations':['Qualified OSC SNP/NVIDIA profile only','Chat proxy HTTP outside TEE; localhost port-forward',
                            'Retained authority is trusted; full RW snapshot rollback resistance is not claimed']}
    r.save('e2e-report.json',summary)
    return {'state':'E2EPassed','report':str(r.out/'e2e-report.json')}


def chat(r):
    r.require_stage('deploy')
    with tunnel(r) as url:
        print('Chat: '+url+' (localhost; Ctrl-C stops the tunnel)',flush=True)
        try:
            while True:time.sleep(1)
        except KeyboardInterrupt:pass
    return {'state':'Closed'}


HANDLERS={'test-first':test_first,'test-reopen':test_reopen,'report':report,'chat':chat}
