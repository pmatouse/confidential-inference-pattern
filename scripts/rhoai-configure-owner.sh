#!/usr/bin/env bash
# Generate public configuration in the existing CoCo owner; never create a
# second Trustee installation. Run bootstrap before keys, then ready after render.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
: "${COCO_CHECKOUT:?Set the checkout of your CoCo pattern fork}"
STATE_DIR=${STATE_DIR:-$ROOT/.private/rhoai}
HARDWARE_PROFILE=${HARDWARE_PROFILE:-amd-snp-gpu}
ADDON_REPO=${ADDON_REPO:-$(git -C "$ROOT" remote get-url origin)}
ADDON_REVISION=${ADDON_REVISION:-rhoai-confidential-qwen}
TRUSTEE_CHART_PATH=${TRUSTEE_CHART_PATH:-charts/hub/rhoai-trustee}
MODE=${1:-bootstrap}
export ROOT COCO_CHECKOUT STATE_DIR HARDWARE_PROFILE ADDON_REPO ADDON_REVISION TRUSTEE_CHART_PATH MODE
python3 - <<'PY'
import os,pathlib,subprocess,shutil,yaml
r=pathlib.Path(os.environ['ROOT']);owner=pathlib.Path(os.environ['COCO_CHECKOUT']).resolve();state=pathlib.Path(os.environ['STATE_DIR'])
mode=os.environ['MODE'];assert mode in ['bootstrap','ready']
profile=os.environ['HARDWARE_PROFILE'];assert profile=='amd-snp-gpu','This release qualifies only the SNP GPU profile'
p=owner/'overrides'/f'values-hw-{profile}.yaml';v=yaml.safe_load(p.read_text());apps=v.setdefault('clusterGroup',{}).setdefault('applications',{})
t=apps.setdefault('trustee',{})
# Preserve resource lists from the site's existing public Trustee values.
resources={}
for filename in t.get('extraValueFiles',[]):
 f=owner/filename.lstrip('/')
 assert '{{' not in filename,'Resolve templated Trustee value filenames explicitly'
 if f.is_file():
  for doc in yaml.safe_load_all(f.read_text()):
   for item in (doc or {}).get('kbs',{}).get('secretResources',[]):resources[item['name']]=item
if not resources:
 for item in yaml.safe_load((r/'integration/trustee/values.yaml').read_text())['kbs']['secretResources']:resources[item['name']]=item
resources['rhoai-qwen-secrets']={'name':'rhoai-qwen-secrets','key':'secret/data/hub/rhoaiQwen','decodingStrategy':'Base64'}
chart=pathlib.PurePosixPath(os.environ['TRUSTEE_CHART_PATH']);assert str(chart).startswith('charts/hub/') and '..' not in chart.parts
shutil.copytree(r/'integration/trustee',owner/str(chart),dirs_exist_ok=True)
t.update({'chart':None,'path':str(chart),'repoURL':subprocess.check_output(['git','-C',str(owner),'remote','get-url','origin'],text=True).strip(),'chartVersion':None})
extra=t.setdefault('extraValueFiles',[])
if '/overrides/values-rhoai-qwen-trustee.yaml' not in extra:extra.append('/overrides/values-rhoai-qwen-trustee.yaml')
trustee_file=owner/'overrides/values-rhoai-qwen-trustee.yaml'
trustee=yaml.safe_load(trustee_file.read_text()) if trustee_file.exists() else {}
trustee.setdefault('kbs',{})['secretResources']=list(resources.values())
# Preserve an existing approved binding during a bootstrap rerun.
if mode=='ready':
 trustee['kbs']['resourcePolicy']=yaml.safe_load((state/'trustee-binding.yaml').read_text())['kbs']['resourcePolicy']
 shutil.copyfile(state/'site.yaml',owner/'overrides/values-rhoai-qwen.yaml')
trustee_file.write_text(yaml.safe_dump(trustee,sort_keys=False))
for name in ['kserve','kserve-crd','confidential-inference','qwen-chat','encrypted-inference','hello-openshift','kbs-access-curl','kbs-access-sealed']:
 apps.setdefault(name,{})['disabled']=True
for name,namespace,values,wave in [('rhoai-platform','redhat-ods-operator','platform','30'),('rhoai-model-publisher',os.environ.get('PUBLISHER_NAMESPACE','rhoai-model-publisher'),'publisher','32'),('rhoai-confidential-qwen',os.environ.get('DEMO_NAMESPACE','rhoai-confidential-qwen'),'qwen','40')]:
 app={'name':name,'namespace':namespace,'project':'hub','repoURL':os.environ['ADDON_REPO'],'path':'charts/'+name,'chartVersion':os.environ['ADDON_REVISION'],'extraValueFiles':['/overrides/values-rhoai-'+values+'.yaml'],'annotations':{'argocd.argoproj.io/sync-wave':wave},'disabled':mode!='ready'}
 # Bootstrap must not stop an already configured, ready installation.
 if mode=='bootstrap' and name in apps:continue
 apps[name]=app
(owner/'overrides/values-rhoai-platform.yaml').write_text('components:\n  enabled: true\n')
(owner/'overrides/values-rhoai-publisher.yaml').write_text(yaml.safe_dump({'publish':False,'storageClass':os.environ.get('STORAGE_CLASS','lvms-vg1')}))
p.write_text(yaml.safe_dump(v,sort_keys=False))
print('Generated public CoCo owner configuration:',mode)
print('Commit and push this fork before installation or reconciliation. No private state was copied.')
PY
