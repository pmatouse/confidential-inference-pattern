"""Execute one shared stage under retained ownership; publish only a bounded public receipt."""
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
from quickstart.core import Run, write, require
from quickstart import release, verify
# The shared release renderer imports the existing CV controller as "controller".
# Load this reconciler under a distinct name to keep both modules independent.
import importlib.util
_spec=importlib.util.spec_from_file_location('inference_release_reconciler',Path(__file__).with_name('controller.py'))
_reconciler=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_reconciler)
API,releases,jobs,core,digest,STAGES=(_reconciler.API,_reconciler.releases,_reconciler.jobs,_reconciler.core,_reconciler.digest,_reconciler.STAGES)


def main():
    api=API();ns=os.environ['RELEASE_NAMESPACE'];name=os.environ['RELEASE_NAME'];stage=os.environ['STAGE']
    intent=api.call('GET',releases(ns,name))
    require(intent and intent['metadata']['uid']==os.environ['RELEASE_UID'] and digest(intent['spec'])==os.environ['RELEASE_SPEC_SHA256'],'release identity changed')
    require(not intent['metadata'].get('deletionTimestamp') and stage in STAGES,'release retired or invalid stage')
    values=Path('/site/values.json')
    r=Run(values,name)
    require(r.identity['siteSha256']==intent['spec']['siteConfigRef']['sha256'],'site identity changed')
    require(json.loads((r.state/'executor-owner.json').read_text())['executor']=='controller','explicit controller handover required')
    ownership=r.state/'controller-binding.json'
    binding={'releaseUID':intent['metadata']['uid'],'specSha256':digest(intent['spec'])}
    if ownership.exists():require(json.loads(ownership.read_text())==binding,'retained controller identity changed')
    else:write(ownership,binding)
    r.require_stage('install')
    index=STAGES.index(stage)
    if index:r.require_stage(STAGES[index-1])
    r.stage=stage;r.log=r.state/(stage+'.log')
    saved=r.receipt(stage)
    if saved:
        # Never replay a committed destructive acceptance step after a lost Job acknowledgement.
        require(saved['siteSha256']==r.identity['siteSha256'],'stale receipt')
        result=saved['result']
    else:
        handler={**release.HANDLERS,**verify.HANDLERS}[stage]
        result=handler(r);r.finish(stage,result)
    jobobj=api.call('GET',jobs(ns,os.environ['JOB_NAME']))
    public={'schemaVersion':1,**binding,'siteSha256':r.identity['siteSha256'],'stage':stage,
            'jobUID':jobobj['metadata']['uid'],'state':result['state'],
            'stageReceiptSha256':digest(r.receipt(stage))}
    data={'receipt.json':json.dumps(public,sort_keys=True)}
    if stage=='report':data['e2e-report.json']=json.dumps(r.read('e2e-report.json'),sort_keys=True)
    cm={'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':os.environ['JOB_NAME']+'-receipt','namespace':ns},'immutable':True,'data':data}
    old=api.call('GET',core(ns,'configmaps',cm['metadata']['name']))
    if old:require(old['data']==data and old.get('immutable') is True,'receipt collision')
    else:api.call('POST',core(ns,'configmaps'),cm)
    print(json.dumps({'stage':stage,'state':result['state']}),flush=True)
if __name__=='__main__':
    try:main()
    except Exception:
        print('RELEASE_STAGE_FAILED: inspect retained private stage log; explicit retry required',flush=True)
        sys.exit(1)
