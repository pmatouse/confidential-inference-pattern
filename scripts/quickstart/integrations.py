"""Administrator-only stock-pattern integration; credentials never enter retained state.

Git owns chart/ESO/policy configuration. Vault admin is used only here, via stdin;
release workers retain their existing scoped Kubernetes-auth identity.
"""
import base64
import copy
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import tempfile

import yaml
import addon
from .core import ROOT, require, sha, write


def private_file(variable):
    value=os.environ.get(variable)
    require(value,'provide external credential file: '+variable)
    path=Path(value).expanduser().resolve()
    require(path.is_file() and path.stat().st_mode & 0o077 == 0,'credential file must be private: '+variable)
    return path


def git_credentials():
    key=private_file('CI_GIT_SSH_KEY_FILE');hosts=private_file('CI_GIT_KNOWN_HOSTS_FILE')
    require('PRIVATE KEY' in key.read_text(),'SSH private key required')
    require(hosts.read_text().strip(),'pinned SSH hosts required')
    # Do not let an ambient broad GitHub token override the explicit deploy key.
    os.environ.pop('GITHUB_TOKEN',None)
    os.environ['GIT_TERMINAL_PROMPT']='0'
    os.environ['GIT_SSH_COMMAND']='ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile='+shlex.quote(str(hosts))+' -i '+shlex.quote(str(key))
    os.environ['GIT_CONFIG_COUNT']='1';os.environ['GIT_CONFIG_KEY_0']='credential.helper';os.environ['GIT_CONFIG_VALUE_0']=''
    return key,hosts


def install_git_secret(r):
    if not r.q.get('integrations',{}).get('enabled'):return
    key,hosts=git_credentials()
    data={'ssh-privatekey':base64.b64encode(key.read_bytes()).decode(),'known_hosts':base64.b64encode(hosts.read_bytes()).decode()}
    old=r.get('secret','inference-release-git',r.trusted)
    if old:
        require(old.get('data')==data,'existing Git credential differs; rotate explicitly')
        return
    r.apply({'apiVersion':'v1','kind':'Secret','metadata':{'name':'inference-release-git','namespace':r.trusted},'type':'Opaque','data':data},sensitive=True)


def owner_source(application,owner):
    sources=application['spec'].get('sources') or [application['spec'].get('source',{})]
    matches=[s for s in sources if s.get('repoURL')==owner['repository'] and s.get('targetRevision')==owner['branch']]
    require(len(matches)==1,'Trustee GitOps owner does not match declared source')
    return matches[0]


def safe_path(checkout,name):
    relative=Path(name)
    require(not relative.is_absolute() and '..' not in relative.parts and relative.parts,'unsafe owner path')
    path=checkout/relative
    require(path.resolve().is_relative_to(checkout.resolve()),'owner path escapes checkout')
    return path


def changed_files(r,checkout):
    tracked=r.command(['git','-C',checkout,'diff','HEAD','--name-only']).splitlines()
    untracked=r.command(['git','-C',checkout,'ls-files','--others','--exclude-standard']).splitlines()
    return {name:sha(safe_path(checkout,name).read_bytes()) for name in sorted(set(tracked+untracked))}


def verify_checkout_resume(r,checkout,head,remote):
    journal=r.out/'integration-owner-state.json'
    state=json.loads(journal.read_text()) if journal.exists() else {}
    if head!=remote:
        require(state.get('commit')==head and state.get('baseCommit')==remote,'owner history changed; reconcile before bootstrap')
    changed=changed_files(r,checkout)
    require(not changed or (state.get('baseCommit')==head and changed==state.get('plannedFiles')),'owner checkout has edits outside the recorded bootstrap plan')
    return state


def stock_adapter(archive,destination):
    lock=json.loads((ROOT/'prerequisites/trustee/chart-lock.json').read_text())
    require(sha(archive.read_bytes())==lock['archiveSha256'],'stock Trustee archive differs from reviewed pin')
    files={}
    with tarfile.open(archive) as tar:
        for member in tar:
            require(not member.issym() and not member.islnk(),'stock chart symlink refused')
            if member.isfile():
                name=member.name.removeprefix('trustee/')
                require(name in lock['files'],'unexpected stock chart file')
                raw=tar.extractfile(member).read()
                require(sha(raw)==lock['files'][name],'stock chart file changed')
                files[name]=raw
    require(set(files)==set(lock['files']),'incomplete stock chart')
    policy=files['templates/resource-policy.yaml'].decode()
    marker='    allow if {\n'
    require(policy.count(marker)==1,'unrecognized stock policy')
    policy=policy.replace(marker,marker+'        data["resource-path"][1] != "model-keys"\n')
    extra=(ROOT/'prerequisites/trustee/model-policy.rego').read_text()
    policy+='\n'+''.join('    '+line+'\n' for line in extra.splitlines())
    validation='''{{- range $tag, $binding := (.Values.kbs.resourcePolicy.modelKeyBindings | default dict) -}}
{{- if or (not (regexMatch "^[a-z0-9][a-z0-9-]{0,62}$" $tag)) (ne (len $binding) 2) (not (regexMatch "^[0-9a-f]{96}$" ($binding.launchMeasurement | default ""))) (not (regexMatch "^[0-9a-f]{64}$" ($binding.initData | default ""))) -}}
{{- fail "invalid exact model key binding" -}}
{{- end -}}
{{- end -}}
'''
    # The upstream archive includes development metadata, including a nested Git repo.
    # Verify the entire archive above, but materialize only chart runtime inputs and license.
    files={k:v for k,v in files.items() if k in ('Chart.yaml','values.yaml','LICENSE') or k.startswith('templates/')}
    files['templates/resource-policy.yaml']=(validation+policy).encode()
    receipt={'stockChart':lock['chart'],'version':lock['version'],'archiveSha256':lock['archiveSha256'],
             'changedStockFiles':['templates/resource-policy.yaml'],'generatedFiles':{k:sha(v) for k,v in files.items()}}
    files['confidential-inference-provenance.json']=(json.dumps(receipt,indent=2)+'\n').encode()
    for name,raw in files.items():
        path=safe_path(destination,name)
        if path.exists():require(path.read_bytes()==raw,'existing adapter differs; explicit upgrade required')
        else:write(path,raw,private=False)
    return receipt


def merged_owner_values(checkout,application,owner):
    """Reconstruct Helm inputs to preserve existing secret lists; reject hidden overrides."""
    sources=application['spec'].get('sources') or [application['spec'].get('source',{})]
    helm_sources=[s for s in sources if 'helm' in s]
    require(len(helm_sources)==1,'one Trustee Helm source required')
    helm=helm_sources[0]['helm'];values={}
    ref=owner_source(application,owner).get('ref')
    for name in helm.get('valueFiles',[]):
        if name.startswith('$'):
            require(ref and name.startswith('$'+ref+'/'),'foreign values repository unsupported')
            name=name[len(ref)+2:]
        path=safe_path(checkout,name.lstrip('/'))
        if path.exists():values=addon.merge(values,yaml.load(path.read_text(),Loader=addon.UniqueLoader) or {})
        else:require(helm.get('ignoreMissingValueFiles',False),'owner values file missing')
    inline=helm.get('valuesObject') or yaml.safe_load(helm.get('values','')) or {}
    require(not inline.get('kbs',{}).get('secretResources'),'move inline secretResources into an owner values file')
    for p in helm.get('parameters',[]):
        require(not p['name'].startswith(('kbs.secretResources','kbs.resourcePolicy.modelKeyBindings')),'conflicting owner Helm parameter')
    return addon.merge(values,inline)


def configure_owner(checkout,application,r,archive):
    owner=r.q['trustee']['owner'];cfg=r.q['integrations'];v=r.q['vault']
    topology=safe_path(checkout,cfg['topologyFile']);top=yaml.load(topology.read_text(),Loader=addon.UniqueLoader)
    app=top['clusterGroup']['applications'][cfg.get('applicationKey','trustee')]
    require(app.get('name',cfg.get('applicationKey','trustee'))==owner['application'],'topology does not own this Trustee application')
    values=merged_owner_values(checkout,application,owner)
    resources=copy.deepcopy(values.get('kbs',{}).get('secretResources',[{'name':'kbsres1','key':'secret/data/hub/kbsres1'},{'name':'passphrase','key':'secret/data/hub/passphrase'}]))
    require(isinstance(resources,list) and len({s['name'] for s in resources})==len(resources),'ambiguous secret resource list')
    matches=[x for x in resources if x['name']==v['projectionSecret']]
    wanted={'name':v['projectionSecret'],'key':v['backendPath']}
    require(not matches or matches==[wanted],'existing model-key resource points elsewhere')
    if not matches:resources.append(wanted)
    target=safe_path(checkout,owner['valuesFile'])
    override=yaml.load(target.read_text(),Loader=addon.UniqueLoader) if target.exists() else {}
    override=override or {};kbs=override.setdefault('kbs',{})
    kbs['secretResources']=resources;kbs.setdefault('resourcePolicy',{}).setdefault('modelKeyBindings',{})
    # Binding writer accepts the ordinary YAML empty-map representation as well.
    require(isinstance(kbs['resourcePolicy']['modelKeyBindings'],dict),'binding map required')
    # A later parent values file may select a local chart. Respect the actual
    # reconciled source rather than replacing it from an earlier topology default.
    active_path=owner_source(application,owner).get('path')
    existing_path=active_path or app.get('path')
    if existing_path:
        chart=safe_path(checkout,existing_path)
        templates='\n'.join(p.read_text() for p in chart.rglob('*.yaml'))+'\n'+'\n'.join(p.read_text() for p in chart.rglob('*.rego'))
        require('modelKeyBindings' in templates and 'model_key_bindings' in templates,'unrecognized local Trustee chart; refuse automatic replacement')
        if (chart/'confidential-inference-provenance.json').exists():
            adapter=stock_adapter(archive,chart)|{'mode':'StockChartAdapter','path':existing_path}
        else:adapter={'mode':'ExistingCompatibleOwner','path':existing_path}
    else:
        require(app.get('chart')=='trustee' and app.get('chartVersion') in ('0.10.*','0.10.2'),'unqualified stock Trustee chart')
        chart_path='charts/addons/confidential-inference-trustee'
        adapter=stock_adapter(archive,safe_path(checkout,chart_path))|{'mode':'StockChartAdapter','path':chart_path}
        app.pop('chart');app.pop('chartVersion');app['path']=chart_path
    extra=app.setdefault('extraValueFiles',[])
    value_file='/'+owner['valuesFile']
    if value_file in extra:extra.remove(value_file)
    extra.append(value_file)
    text=yaml.safe_dump(override,sort_keys=False)
    write(target,text,private=False);write(topology,yaml.safe_dump(top,sort_keys=False),private=False)
    return adapter,resources


class VaultAdmin:
    def __init__(self,r):self.r=r;self.token=private_file('CI_VAULT_ADMIN_TOKEN_FILE').read_text().strip();require(self.token and '\n' not in self.token,'invalid Vault credential')
    def call(self,args,body=None,missing=False):
        script='set -eu\nread -r VAULT_TOKEN; export VAULT_TOKEN\nexec '+shlex.join(['vault',*args])
        v=self.r.q['vault']
        result=subprocess.run(['oc','--request-timeout=30s','exec','-i','-n',v['namespace'],v['pod'],'--','sh','-c',script],
                              input=self.token+'\n'+(json.dumps(body) if body is not None else ''),text=True,capture_output=True,timeout=60)
        if missing and result.returncode and ('No value found at' in result.stderr or 'No policy named' in result.stderr):return None
        require(result.returncode==0,'Vault bootstrap operation failed; sensitive output withheld')
        return result.stdout


def vault_policy(v):
    require(v['backendPath']=='secret/data/hub/modelKeys','current adapter requires the stock hub/modelKeys mapping')
    return 'path "secret/data/hub/modelKeys" { capabilities = ["patch"] }\npath "secret/metadata/hub/modelKeys" { capabilities = ["read"] }\n'


def validate_parent(parent,owner,topology_file):
    require(parent is not None and parent['spec'].get('syncPolicy',{}).get('automated') is not None,'automated parent Argo application required')
    sources=parent['spec'].get('sources') or [parent['spec'].get('source',{})]
    matching=[s for s in sources if s.get('repoURL')==owner['repository'] and s.get('targetRevision')==owner['branch']]
    require(len(matching)==1,'parent does not consume the declared owner repository/branch')
    files=[f for s in sources for f in s.get('helm',{}).get('valueFiles',[])]
    require(any(f.lstrip('/')==topology_file or (f.startswith('$') and f.split('/',1)[-1]==topology_file) for f in files),'parent does not consume the declared topology file')


def setup_vault(r):
    v=r.q['vault'];admin=VaultAdmin(r)
    for name in ('role','authMount','serviceAccount','enrollmentNamespace'):
        require(re.fullmatch('[a-z0-9][a-z0-9-]*',v[name]),'invalid Vault integration identifier')
    # Existing mounts/configuration belong to the base pattern; never reset them.
    mounts=json.loads(admin.call(['auth','list','-format=json']))
    require(mounts.get(v['authMount']+'/',{}).get('type')=='kubernetes','existing Vault Kubernetes auth mount required')
    policy=vault_policy(v)
    old=admin.call(['policy','read',v['role']],missing=True)
    if old is not None:
        require(''.join(old.split())==''.join(policy.split()),'existing Vault policy differs; refuse privilege replacement')
    else:admin_policy_write(admin,v['role'],policy)
    desired={'bound_service_account_names':[v['serviceAccount']],'bound_service_account_namespaces':[v['enrollmentNamespace']],
             'audience':'vault','token_policies':[v['role']],'token_no_default_policy':True,'token_ttl':900,'token_max_ttl':3600}
    role_path='auth/'+v['authMount']+'/role/'+v['role']
    old=admin.call(['read','-format=json',role_path],missing=True)
    if old:
        data=json.loads(old)['data'];require(all(data.get(k)==value for k,value in desired.items()),'existing Vault role differs; refuse privilege replacement')
        require(not data.get('bound_service_account_namespace_selector') and not data.get('token_period'),
                'existing Vault role expands namespace access or token lifetime; refuse reuse')
    else:admin.call(['write',role_path,'-'],desired)
    metadata=admin.call(['read','-format=json','secret/metadata/hub/modelKeys'],missing=True)
    created=metadata is None
    if created:admin.call(['write','secret/data/hub/modelKeys','-'],{'options':{'cas':0},'data':{'bootstrap-marker':'reserved-no-secret'}})
    admin.token=None
    return {'backendCreated':created,'adminCredentialRetained':False,'role':v['role'],'backendPath':v['backendPath']}


def admin_policy_write(admin,name,policy):
    # CLI policy write accepts HCL on stdin; JSON API wrapper preserves stdin framing.
    admin.call(['write','sys/policies/acl/'+name,'-'],{'policy':policy})


def integrations(r):
    r.require_stage('preflight');cfg=r.q.get('integrations',{})
    if not cfg.get('enabled'):return {'state':'ExternalIntegrationsReused'}
    require(r.v['base']['trusteeNamespace']=='trustee-operator-system','stock chart uses the standard Trustee namespace')
    require(r.q['vault']['projectionSecret']=='model-keys' and r.q['vault']['externalSecret']=='model-keys-eso','qualified model-key resource names required')
    git_credentials();private_file('CI_VAULT_ADMIN_TOKEN_FILE')
    owner=r.q['trustee']['owner'];require(owner['repository'].startswith('git@'),'bootstrap requires repository-scoped SSH credentials')
    app=r.get('applications.argoproj.io',owner['application'],owner['namespace']);owner_source(app,owner)
    parent=r.get('applications.argoproj.io',cfg['parentApplication'],owner['namespace'])
    validate_parent(parent,owner,cfg['topologyFile'])
    lock=json.loads((ROOT/'prerequisites/trustee/chart-lock.json').read_text())
    archive=ROOT/'prerequisites/trustee'/('trustee-'+lock['version']+'.tgz')
    require(sha(archive.read_bytes())==lock['archiveSha256'],'stock chart archive pin mismatch')
    # Checkout stays in disposable cache, never copied into the retained controller PVC.
    checkout=r.cache/'integration-owner'
    if not checkout.exists():r.command(['git','clone','--depth','1','--single-branch','--branch',owner['branch'],owner['repository'],checkout],timeout=300)
    r.command(['git','-C',checkout,'fetch','origin',owner['branch']])
    head=r.command(['git','-C',checkout,'rev-parse','HEAD']).strip()
    remote=r.command(['git','-C',checkout,'rev-parse','origin/'+owner['branch']]).strip()
    state=verify_checkout_resume(r,checkout,head,remote)
    adapter,resources=configure_owner(checkout,app,r,archive)
    r.save('integration-plan.json',{'adapter':adapter,'secretResources':resources,'topologyFile':cfg['topologyFile'],'valuesFile':owner['valuesFile']})
    planned=changed_files(r,checkout)
    if planned:r.save('integration-owner-state.json',{'baseCommit':head,'plannedFiles':planned})
    # Validate generated Helm output before any live policy/backend changes.
    source=app['spec'].get('source') or next(s for s in app['spec']['sources'] if 'helm' in s)
    values=merged_owner_values(checkout,app,owner)
    values=addon.merge(values,yaml.safe_load(safe_path(checkout,owner['valuesFile']).read_text()))
    for p in source.get('helm',{}).get('parameters',[]):
        if p.get('value') is not None:
            parts=p['name'].split('.');target=values
            for key in parts[:-1]:target=target.setdefault(key,{})
            target[parts[-1]]=yaml.safe_load(p['value'])
    rendered=addon.helm(safe_path(checkout,adapter['path']),values,r.v['base']['trusteeNamespace'],'trustee')
    policies=[o for o in rendered if o['kind']=='ConfigMap' and o['metadata']['name']=='resource-policy']
    require(len(policies)==1 and 'model_key_bindings :=' in policies[0]['data']['resource-policy.rego'],'owner policy rendering failed')
    es=[o for o in rendered if o['kind']=='ExternalSecret' and o['metadata']['name']==r.q['vault']['externalSecret']]
    require(len(es)==1 and es[0]['spec']['dataFrom'][0]['extract']['key']==r.q['vault']['backendPath'],'owner ESO rendering failed')
    ns=r.q['vault']['enrollmentNamespace'];sa=r.q['vault']['serviceAccount']
    for obj in ({'apiVersion':'v1','kind':'Namespace','metadata':{'name':ns}},
                {'apiVersion':'v1','kind':'ServiceAccount','metadata':{'name':sa,'namespace':ns},'automountServiceAccountToken':False}):r.apply(obj)
    backend=setup_vault(r)
    r.command(['git','-C',checkout,'add','--',cfg['topologyFile'],owner['valuesFile'],adapter['path']])
    if r.command(['git','-C',checkout,'diff','--cached','--name-only']).strip():
        r.command(['git','-C',checkout,'-c','user.name=Confidential inference bootstrap','-c','user.email=confidential-inference@localhost','commit','-m','Configure confidential inference Trustee and ESO integration'])
    commit=r.command(['git','-C',checkout,'rev-parse','HEAD']).strip()
    r.save('integration-owner-state.json',{'baseCommit':remote,'commit':commit,'plannedFiles':planned})
    r.command(['git','-C',checkout,'push','origin','HEAD:'+owner['branch']],timeout=180)
    for name in (cfg['parentApplication'],owner['application']):r.oc('annotate','applications.argoproj.io',name,'-n',owner['namespace'],'argocd.argoproj.io/refresh=hard','--overwrite')
    def ready():
        current=r.get('applications.argoproj.io',owner['application'],owner['namespace'])
        src=current['spec'].get('source',{})
        if src.get('path')!=adapter['path'] or '/'+owner['valuesFile'] not in src.get('helm',{}).get('valueFiles',[]):return False
        obj=r.get('externalsecret',r.q['vault']['externalSecret'],r.v['base']['trusteeNamespace'])
        if not obj or not any(c['type']=='Ready' and c['status']=='True' for c in obj.get('status',{}).get('conditions',[])):return False
        kbs=r.get('kbsconfig','kbsconfig',r.v['base']['trusteeNamespace'])
        if not kbs or r.q['vault']['projectionSecret'] not in kbs.get('spec',{}).get('kbsSecretResources',[]):return False
        policy=r.get('configmap','resource-policy',r.v['base']['trusteeNamespace'])
        return policy and policy.get('data',{}).get('resource-policy.rego')==policies[0]['data']['resource-policy.rego']
    r.wait('owner-managed Trustee policy and ESO integration',ready,timeout=600,interval=5)
    return {'state':'IntegrationsReady','ownerCommit':commit,'adapter':adapter['mode'],**backend}


HANDLERS={'integrations':integrations}
