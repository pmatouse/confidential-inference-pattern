#!/usr/bin/env bash
# Render the attested application identity from pinned images and Helm inputs.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
STATE_DIR=${STATE_DIR:-$ROOT/.private/rhoai}
DEMO_NAMESPACE=${DEMO_NAMESPACE:-rhoai-confidential-qwen}
PUBLISHER_NAMESPACE=${PUBLISHER_NAMESPACE:-rhoai-model-publisher}
HELM=${HELM:-helm}
: "${SNP_LAUNCH_MEASUREMENT:?Supply the independently calculated 8-vCPU stock GPU launch measurement}"
export ROOT STATE_DIR DEMO_NAMESPACE PUBLISHER_NAMESPACE HELM SNP_LAUNCH_MEASUREMENT
umask 077
mkdir -p "$STATE_DIR"
test -s "$STATE_DIR/initializer-image"
oc get image "$(cat "$STATE_DIR/initializer-image" | cut -d@ -f2)" -o json > "$STATE_DIR/initializer-metadata.json"
oc get configmap initdata -n imperative -o json > "$STATE_DIR/base-initdata.json"
oc get service kubernetes -n default -o json > "$STATE_DIR/kubernetes-service.json"
oc get secret firmware-reference-values -n trustee-operator-system -o json > "$STATE_DIR/firmware-reference.json"
oc get configmap signing-cabundle -n openshift-service-ca -o json > "$STATE_DIR/service-ca.json"
export CHAT_HOST=${CHAT_HOST:-qwen-chat-$DEMO_NAMESPACE.$(oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}')}
python3 - <<'PY'
import os,pathlib,json,hashlib,base64,gzip,re,subprocess,tomllib,yaml
r=pathlib.Path(os.environ['ROOT']);p=pathlib.Path(os.environ['STATE_DIR']);ns=os.environ['DEMO_NAMESPACE']
launch=os.environ['SNP_LAUNCH_MEASUREMENT'];assert re.fullmatch('[0-9a-f]{96}',launch)
firmware=json.loads(base64.b64decode(json.loads((p/'firmware-reference.json').read_text())['data']['json']))
assert launch in firmware['snp_launch_measurement'],'Launch identity is not in the independently provisioned CoCo reference store'
image=(p/'initializer-image').read_text().strip();assert '@sha256:' in image
values={'guest':{'initdata':'pending'},'images':{'initializer':image},'chat':{'hostname':os.environ['CHAT_HOST']},'model':{'uri':f"http://encrypted-model.{os.environ['PUBLISHER_NAMESPACE']}.svc:8080/qwen.tar"}}
if (p/'site-overrides.yaml').exists():
 def merge(a,b):
  for k,v in b.items():
   if isinstance(v,dict) and isinstance(a.get(k),dict):merge(a[k],v)
   else:a[k]=v
 merge(values,yaml.safe_load((p/'site-overrides.yaml').read_text()))
(p/'site.yaml').write_text(yaml.safe_dump(values))
rendered=subprocess.check_output([os.environ['HELM'],'template','qwen',str(r/'charts/rhoai-confidential-qwen'),'-n',ns,'-f',str(p/'site.yaml')],text=True)
objects=list(yaml.safe_load_all(rendered));template=next(o for o in objects if o['kind']=='LLMInferenceServiceConfig')['spec']['template']
ip=json.loads((p/'kubernetes-service.json').read_text())['spec']['clusterIP']
baseenv=['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','TERM=xterm','container=oci','NSS_SDB_USE_CACHE=no']
kubeenv=[f'KUBERNETES_SERVICE_HOST={ip}','KUBERNETES_SERVICE_PORT=443','KUBERNETES_SERVICE_PORT_HTTPS=443',f'KUBERNETES_PORT=tcp://{ip}:443',f'KUBERNETES_PORT_443_TCP=tcp://{ip}:443','KUBERNETES_PORT_443_TCP_PROTO=tcp','KUBERNETES_PORT_443_TCP_PORT=443',f'KUBERNETES_PORT_443_TCP_ADDR={ip}']
defaultbinds=['/etc/resolv.conf','/etc/hostname','/run/.containerenv','/etc/hosts','/dev/termination-log','/run/secrets','/dev/shm']
profile={'namespace':ns,'containers':{'POD':{'image':'pause','args':['/usr/bin/pod'],'environment':baseenv+kubeenv,'requiredEnvironment':[],'bindDestinations':defaultbinds}}}
images={'format-disk':'helper','check-ready':'helper','storage-initializer':'initializer','main':'vllm','chat':'chat'}
for c in template['initContainers']+template['containers']:
 env=json.loads((r/'policies/image-environments'/f"{images[c['name']]}.json").read_text())['environment']
 if c['name']=='storage-initializer':
  built=json.loads((p/'initializer-metadata.json').read_text())
  assert built['metadata']['name']==image.split('@')[1]
  actual=built['dockerImageMetadata']['Config']['Env']
  extra=[x for x in actual if x not in env]
  assert len(extra)==2 and f'OPENSHIFT_BUILD_NAMESPACE={ns}' in extra
  assert any(re.fullmatch(r'OPENSHIFT_BUILD_NAME=storage-initializer-streaming-[0-9]+',x) for x in extra)
  assert set(env)<=set(actual),'Built initializer differs from the pinned base environment'
  env=actual
 required=[x['name']+'='+x['value'] for x in c.get('env',[])]
 keys={x.split('=',1)[0] for x in required}
 env=[x for x in env if x.split('=',1)[0] not in keys]+required+baseenv+kubeenv
 if c['name']=='main':env+=['HOME=/home','VLLM_LOGGING_LEVEL=INFO','HF_HUB_CACHE=/models']
 binds=defaultbinds+[x['mountPath'] for x in c.get('volumeMounts',[])]
 if c['name']=='main':binds+=['/home','/tmp','/models','/var/run/kserve/tls']
 profile['containers'][c['name']]={'image':c['image'],'args':c['command'],'environment':sorted(set(env)),'requiredEnvironment':required,'bindDestinations':sorted(set(binds))}
raw=json.dumps(profile,sort_keys=True,separators=(',',':'))
# Keep lines short for the stock agent's policy parser.
chunks=[raw[n:n+256] for n in range(0,len(raw),256)]
expression='json.unmarshal(concat("", [\n'+',\n'.join(json.dumps(c) for c in chunks)+'\n]))'
policy=(r/'policies/rhoai-guest.rego.in').read_text().replace('__PROFILE__',expression)
(p/'guest-policy.rego').write_text(policy);(p/'policy-profile.json').write_text(json.dumps(profile,indent=2)+'\n')
base=json.loads((p/'base-initdata.json').read_text())['data'];aa=base['aa.toml'];cdh=tomllib.loads(base['cdh.toml'])
cert=cdh['kbc']['kbs_cert'];url=cdh['kbc']['url']
ca=json.loads((p/'service-ca.json').read_text())['data']['ca-bundle.crt']
cdh_text='socket = "unix:///run/confidential-containers/cdh.sock"\ncredentials = []\n[kbc]\nname = "cc_kbc"\nurl = '+json.dumps(url)+'\nkbs_cert = '+json.dumps(cert)+'\n[image]\nextra_root_certificates = '+json.dumps([ca])+'\nauthenticated_registry_credentials_uri = "kbs:///default/rhoai-qwen-secrets/registry"\n'
raw='algorithm = "sha256"\nversion = "0.1.0"\n[data]\n'+''.join(json.dumps(k)+' = '+json.dumps(v)+'\n' for k,v in {'aa.toml':aa,'cdh.toml':cdh_text,'policy.rego':policy}.items())
digest=hashlib.sha256(raw.encode()).hexdigest();(p/'initdata.toml').write_text(raw);(p/'initdata.sha256').write_text(digest+'\n')
values['guest']['initdata']=base64.b64encode(gzip.compress(raw.encode(),mtime=0)).decode();(p/'site.yaml').write_text(yaml.safe_dump(values))
binding={'kbs':{'resourcePolicy':{'confidentialGuestBindings':{'rhoai-qwen-secrets':{'launchMeasurement':launch,'initData':digest}}}}}
(p/'trustee-binding.yaml').write_text(yaml.safe_dump(binding))
print('Measured guest policy:',digest)
print('Publish trustee-binding.yaml through the CoCo owner before deploying site.yaml.')
PY
