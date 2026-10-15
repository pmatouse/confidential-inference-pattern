#!/usr/bin/env python3
"""Execute one explicit, resumable quickstart stage; private output never enters Git."""
import argparse
import json
import sys
import os
import subprocess
from pathlib import Path

# Bootstrap before importing PyYAML/cryptography; never modify the user's Python.
root = Path(__file__).resolve().parents[1]
cache = Path(os.environ.get('QUICKSTART_CACHE',str(root/'.cache/quickstart'))).resolve()
venv = cache/'venv'
if len(sys.argv)>1 and sys.argv[1] in ('tools','all') and not (venv/'ready').exists():
    if not (venv/'bin/python').exists():subprocess.run([sys.executable,'-m','venv',str(venv)],check=True)
    subprocess.run([str(venv/'bin/python'),'-m','pip','install','-r',str(root/'requirements-quickstart.txt')],check=True)
    (venv/'ready').touch()
if (venv/'bin/python').exists() and Path(sys.prefix).resolve()!=venv.resolve():
    os.execv(str(venv/'bin/python'),[str(venv/'bin/python'),__file__,*sys.argv[1:]])

from quickstart.core import Run, STAGES, require
from quickstart import platform


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('stage',choices=[*STAGES,'all','status','chat'])
    p.add_argument('--values',type=Path,required=True)
    p.add_argument('--run',default='')
    a=p.parse_args()
    if not a.run:
        import addon
        a.run=addon.load(a.values)['demo']['name']
    r=Run(a.values,a.run,exclusive=a.stage not in ('status','chat'))
    handlers={name:getattr(platform,name) for name in ('tools','dependencies','preflight','bootstrap')}
    # All handlers use the same receipt and execution ownership contract.
    for module_name in ('build','release','verify'):
        try:module=__import__('quickstart.'+module_name,fromlist=['HANDLERS'])
        except ModuleNotFoundError as error:
            if error.name!='quickstart.'+module_name:raise
            continue
        handlers.update(module.HANDLERS)
    if a.stage=='status':
        completed=[s for s in STAGES if r.receipt(s)]
        print(json.dumps({'run':r.name,'completed':completed,'next':next((s for s in STAGES if s not in completed),None)},indent=2));return
    if a.stage=='all':
        first_missing=next((i for i,s in enumerate(STAGES) if not r.receipt(s)),len(STAGES))
        for stage in STAGES[:first_missing]:r.require_stage(stage)
        sequence=STAGES[first_missing:] or ('report',)
    else:sequence=(a.stage,)
    for stage in sequence:
        r.stage=stage;r.log=r.state/(stage+'.log')
        require(stage in handlers,'stage not implemented: '+stage)
        print('Quickstart stage: '+stage,flush=True)
        result=handlers[stage](r)
        if stage!='chat':r.finish(stage,result)
        if stage in STAGES and STAGES.index(stage)+1<len(STAGES):
            print('Next: make qs-'+STAGES[STAGES.index(stage)+1]+' VALUES='+str(a.values)+' RUN='+r.name,flush=True)


if __name__=='__main__':
    try:main()
    except KeyboardInterrupt:
        print('Quickstart interrupted. Retain state and resume the same run.',file=sys.stderr)
        sys.exit(130)
    except (ValueError,RuntimeError,OSError,subprocess.TimeoutExpired) as error:
        print('Quickstart stopped: '+str(error),file=sys.stderr)
        print('Retain run state. Fix this gate and rerun the same target; use qs-status for progress.',file=sys.stderr)
        sys.exit(1)
