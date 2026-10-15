"""Public-only builds, verified artifact acquisition and immutable image publication."""
import copy
import hashlib
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import sys
import subprocess
import tarfile
import time

from .core import ROOT, require, sha, write

RUST='docker.io/library/rust@sha256:4ec71e955e6c08aeb238885083222ddff79d82eb87654a96c76e38e94da1a53b'
GO_SHA='9e9b755d63b36acf30c12a9a3fc379243714c1c6d3dd72861da637f336ebb35b'


def fetch(r,url,path,digest=None):
    if path.exists() and (digest is None or sha(path.read_bytes())==digest):return
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_suffix(path.suffix+'.download')
    r.command(['curl','--fail','--silent','--show-error','--location','--retry','3','--output',temp,url],timeout=1200)
    require(not digest or sha(temp.read_bytes())==digest,'download digest mismatch: '+path.name)
    os.replace(temp,path)


def archive(path, entries):
    # Atomic publication: an interrupted read must never become a reusable build context.
    temporary=path.with_suffix(path.suffix+'.partial')
    with temporary.open('wb') as output, gzip.GzipFile(filename='',mode='wb',fileobj=output,mtime=0) as compressed, tarfile.open(fileobj=compressed,mode='w') as tar:
        for name,source in sorted(entries.items()):
            for attempt in range(4):
                try:
                    raw=source if isinstance(source,bytes) else source.read_bytes()
                    break
                except OSError:
                    if attempt==3:raise
                    time.sleep(2*(attempt+1))
            info=tarfile.TarInfo(name);info.size=len(raw);info.mode=0o755 if name.endswith('.sh') or name=='encrypted-model-populator' else 0o644
            tar.addfile(info,io.BytesIO(raw))
    os.replace(temporary,path)


def source_entries(roots):
    # Git's public source inventory excludes private/untracked scratch in component directories.
    listed=subprocess.check_output(['git','-C',str(ROOT),'ls-files','-z','--',*roots],text=True).split('\0')
    # These newly imported public inputs are also usable while developing this quickstart.
    additions=['components/model-publisher/'+name for name in ('bundle-tools.py','tools-inventory.json','extract-kernel-modules.py')]
    listed += [name for name in additions if any(name.startswith(root+'/') for root in roots)]
    entries={}
    for name in sorted(set(listed)-{''}):
        p=ROOT/name
        require(p.is_file() and not p.is_symlink(),'public build input missing or symlinked: '+name)
        entries[name]=p
    return entries


def builder(r):
    name=r.name+'-compiler'
    old=r.get('pod',name,r.trusted)
    if not old:
        r.apply({'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':r.trusted},'spec':{
          'automountServiceAccountToken':False,'restartPolicy':'Never','securityContext':{'runAsNonRoot':True,'seccompProfile':{'type':'RuntimeDefault'}},
          'containers':[{'name':'compiler','image':RUST,'command':['sleep','86400'],
            'env':[{'name':'CARGO_HOME','value':'/work/cargo'},{'name':'HOME','value':'/work'},{'name':'TMPDIR','value':'/work'}],
            'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},
            'resources':{'requests':{'cpu':'1','memory':'2Gi'},'limits':{'cpu':'4','memory':'12Gi'}},
            'volumeMounts':[{'name':'work','mountPath':'/work'}]}], 'volumes':[{'name':'work','emptyDir':{}}]}})
    else:require(old['spec']['containers'][0]['image']==RUST,'compiler identity changed')
    r.oc('wait','-n',r.trusted,'--for=condition=Ready','pod/'+name,'--timeout=300s',timeout=330)
    return name


def execute(r,pod,script,timeout=180):
    return r.oc('exec','-i','-n',r.trusted,pod,'--','sh','-eu','-s',body=script,timeout=timeout)


def send(r,pod,path,destination):
    execute(r,pod,'mkdir -p '+shlex.quote(destination))
    r.oc('exec','-i','-n',r.trusted,pod,'--','tar','xzf','-','-C',destination,body=path.read_bytes(),binary=True,timeout=300)


def receive(r,pod,source,destination,expected=None):
    # Verify length/hash against the compiler before accepting potentially truncated exec streams.
    digest=expected or r.oc('exec','-n',r.trusted,pod,'--','sha256sum',source).split()[0]
    for _ in range(3):
        raw=r.oc('exec','-n',r.trusted,pod,'--','cat',source,binary=True,timeout=300)
        if sha(raw)==digest:
            write(destination,raw);return
    raise RuntimeError('binary transport digest mismatch: '+source)


def artifacts(r,work):
    lock=json.loads((ROOT/'profiles/runtime/osc-snp-nvidia-artifacts.json').read_text())
    node=r.require_stage('preflight')['node']
    pods=r.get('pods',ns='openshift-machine-config-operator')['items']
    selected=[p for p in pods if p['spec'].get('nodeName')==node and p['metadata'].get('labels',{}).get('k8s-app')=='machine-config-daemon']
    require(len(selected)==1,'one existing machine-config-daemon required for read-only stock artifact acquisition')
    pod=selected[0]['metadata']['name'];paths={}
    for key,item in lock['files'].items():
        path=work/key
        if not path.exists() or sha(path.read_bytes())!=item['sha256']:
            raw=r.oc('exec','-n','openshift-machine-config-operator',pod,'-c','machine-config-daemon','--','cat','/rootfs'+item['path'],binary=True,timeout=600)
            require(sha(raw)==item['sha256'],'installed '+key+' differs from approved stock profile')
            write(path,raw)
        paths[key]=str(path)
    fetch(r,lock['kernelModulesRPM']['url'],work/'kernel-modules.rpm',lock['kernelModulesRPM']['sha256'])
    r.save('stock-artifacts.json',{'profile':lock['profile'],'node':node,'files':lock['files'],'kernelModulesRPM':lock['kernelModulesRPM']})
    return lock


def image_build(r,name,context,build_file='Containerfile'):
    digest=sha(context.read_bytes());receipt=r.out/('build-'+name+'.json')
    if receipt.exists():
        saved=json.loads(receipt.read_text())
        if saved['contextSha256']==digest:
            obj=r.get('build',saved['build'],r.ns)
            require(obj and obj['status']['phase']=='Complete','completed image build disappeared/changed')
            return saved
    r.apply({'apiVersion':'image.openshift.io/v1','kind':'ImageStream','metadata':{'name':name,'namespace':r.ns}})
    r.apply({'apiVersion':'build.openshift.io/v1','kind':'BuildConfig','metadata':{'name':name,'namespace':r.ns},'spec':{
      'runPolicy':'Serial','source':{'type':'Binary','binary':{}},'strategy':{'type':'Docker','dockerStrategy':{'dockerfilePath':build_file,'noCache':True}},
      'output':{'to':{'kind':'ImageStreamTag','name':name+':build'}},
      'resources':{'requests':{'cpu':'100m','memory':'512Mi'},'limits':{'cpu':'2','memory':'2Gi'}}}})
    pending=r.state/('pending-build-'+name+'.json')
    if pending.exists():
        prior=json.loads(pending.read_text())
        obj=r.get('build',prior['build'],r.ns)
        if prior['contextSha256']==digest and obj and obj['status']['phase'] not in ('Failed','Error','Cancelled'):
            build=prior['build']
        else:build=None
    else:build=None
    if build is None:
        build=r.oc('start-build',name,'-n',r.ns,'--from-archive='+str(context),'-o','name',timeout=600).strip().split('/')[-1]
        write(pending,{'build':build,'contextSha256':digest})
    def completed():
        obj=r.get('build',build,r.ns);phase=obj['status']['phase']
        require(phase not in ('Failed','Error','Cancelled'),'image build failed: '+build+'; inspect oc logs build/'+build)
        return obj if phase=='Complete' else None
    obj=r.wait('image '+name,completed,timeout=1800,interval=10)
    ref=obj['status'].get('output',{}).get('to',{}).get('imageDigest')
    require(ref and ref.startswith('sha256:'),'completed build has no digest')
    image=r.v['registry']['origin'].removeprefix('https://')+'/'+r.ns+'/'+name+'@'+ref
    saved={'image':image,'build':build,'namespace':r.ns,'contextSha256':digest}
    r.save('build-'+name+'.json',saved)
    print('Image built: '+name+' '+ref,flush=True)
    return saved


def cleanup_build_pods(r):
    """Drop completed build compute only; keep Build/ImageStream and image receipts."""
    allowed={'confidential-volume-controller','confidential-storage-authority','confidential-storage-sidecar','encrypted-model-populator','inference-preparation'}
    for pod in r.get('pods',ns=r.ns)['items']:
        if pod['status'].get('phase')!='Succeeded':continue
        name=pod['metadata'].get('annotations',{}).get('openshift.io/build.name')
        if not name:continue
        build=r.get('build',name,r.ns)
        config=(build or {}).get('metadata',{}).get('labels',{}).get('openshift.io/build-config.name')
        if config not in allowed:continue
        owner=r.get('buildconfig',config,r.ns)
        require(owner['metadata'].get('labels',{}).get('inference.confidentialcontainers.org/installation')==r.installation,'build owner changed')
        r.oc('logs',pod['metadata']['name'],'-n',r.ns)
        r.oc('delete','pod',pod['metadata']['name'],'-n',r.ns,'--wait=false')


def build(r):
    r.require_stage('bootstrap')
    if r.receipt('build'):
        result=r.require_stage('build')
        for item in result['images'].values():
            obj=r.get('build',item['build'],r.ns)
            require(obj and obj['status']['phase']=='Complete' and obj['status']['output']['to']['imageDigest']==item['image'].split('@')[1],'recorded build changed')
        cleanup_build_pods(r)
        return result
    work=r.cache/'build';work.mkdir(exist_ok=True)
    lock=artifacts(r,work)
    pod=builder(r)
    # Wheel hashes are frozen in the repository; package metadata only locates exact pinned bytes.
    wheels=work/'wheels';wheels.mkdir(exist_ok=True)
    for filename,digest in json.loads((ROOT/'components/confidential-storage-authority/runtime-wheels.json').read_text()).items():
        package,version=filename.split('-')[:2]
        index=json.loads(r.command(['curl','--fail','--silent','--show-error','--location',f'https://pypi.org/pypi/{package}/{version}/json'],sensitive=True))
        urls=[u for u in index['urls'] if u['filename']==filename and u['digests']['sha256']==digest]
        require(len(urls)==1,'pinned wheel unavailable');fetch(r,urls[0]['url'],wheels/filename,digest)
    entries=source_entries(['components/confidential-volume-controller','components/confidential-volume-contract','components/confidential-storage-authority','components/confidential-storage-guest/profiles','components/inference-release'])
    entries.update({'wheels/'+p.name:p for p in wheels.iterdir() if p.is_file()})
    entries['Containerfile']=ROOT/'components/confidential-volume-controller/Containerfile'
    controller=work/'controller.tar.gz'
    if not controller.exists():archive(controller,entries)
    controller_image=image_build(r,'confidential-volume-controller',controller)
    authority=work/'authority.tar.gz'
    if not authority.exists():r.command([sys.executable,ROOT/'scripts/prepare-authority-build.py','--wheels',wheels,'--output',authority])
    authority_image=image_build(r,'confidential-storage-authority',authority)
    # Compiler inputs never include private run state, model files or credentials.
    fetch(r,'https://go.dev/dl/go1.25.5.linux-amd64.tar.gz',work/'go.tar.gz',GO_SHA)
    upstream=work/'guest-components'
    if not upstream.exists():
        r.command(['git','clone','--no-checkout','https://github.com/manuelh-dev/guest-components.git',upstream],timeout=600)
        r.command(['git','-C',upstream,'checkout','--detach','0ab1fb1be6e46293f29600085f929ae035ca3739'])
    staged=work/'service-source'
    if not staged.exists():r.command([sys.executable,ROOT/'components/confidential-storage-sidecar/stage-service.py','--upstream',upstream,'--output',staged],timeout=300)
    source=work/'compiler-source.tar.gz'
    if not source.exists():
        entries={str(p.relative_to(staged)):p for p in staged.rglob('*') if p.is_file()}
        entries.update(source_entries(['components/encrypted-model-populator','components/model-publisher']))
        entries['runtime-lock.json']=ROOT/'profiles/runtime/osc-snp-nvidia-artifacts.json'
        entries['kernel-modules.rpm']=work/'kernel-modules.rpm';entries['go.tar.gz']=work/'go.tar.gz'
        archive(source,entries)
    send(r,pod,source,'/work/source')
    script='''cd /work/source
export CARGO_HOME=/work/cargo
export CARGO_BUILD_JOBS=4
export GOMAXPROCS=4
if [ ! -f /work/service-built ]; then
  cargo test --locked --manifest-path components/confidential-storage-service/Cargo.toml --features trustee-rcar
  cargo build --release --locked --manifest-path components/confidential-storage-service/Cargo.toml --features trustee-rcar
  touch /work/service-built
fi
if [ ! -x /work/go/bin/go ]; then tar xzf go.tar.gz -C /work; fi
export PATH=/work/go/bin:$PATH
export GOCACHE=/work/go-cache GOPATH=/work/go-path
cd components/encrypted-model-populator
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /work/encrypted-model-populator .
cd /work/source
if [ ! -d /work/tools-fetch ]; then python3 components/model-publisher/fetch_tools.py --work /work/tools-fetch; fi
if [ ! -f /work/storage-tools.tar ]; then python3 components/model-publisher/bundle-tools.py --tools /work/tools-fetch/tools --output /work/storage-tools.tar; fi
python3 components/model-publisher/extract-kernel-modules.py kernel-modules.rpm runtime-lock.json /work/modules
'''
    execute(r,pod,script,timeout=7200)
    receive(r,pod,'/work/source/components/confidential-storage-service/target/release/confidential-storage-service',work/'confidential-storage-service')
    receive(r,pod,'/work/encrypted-model-populator',work/'encrypted-model-populator')
    receive(r,pod,'/work/storage-tools.tar',work/'storage-tools.tar')
    for name,digest in lock['modules'].items():receive(r,pod,'/work/modules/'+name+'.ko.xz',work/(name+'.ko.xz'),digest)
    tools=work/'tools.tar'
    if not tools.exists():
        files={};inventory=json.loads((ROOT/'components/model-publisher/tools-inventory.json').read_text())['files']
        with tarfile.open(work/'storage-tools.tar') as tar:
            for member in tar:
                require(member.isfile() and member.name in inventory and member.name not in files,'unexpected tool member')
                raw=tar.extractfile(member).read();require(sha(raw)==inventory[member.name],'tool library identity changed: '+member.name)
                files[member.name]=raw
        require(set(files)==set(inventory),'incomplete tools inventory')
        files.update({'modules/'+n+'.ko.xz':(work/(n+'.ko.xz')).read_bytes() for n in lock['modules']})
        with tarfile.open(tools,'w') as tar:
            for name,raw in sorted(files.items()):
                info=tarfile.TarInfo(name);info.size=len(raw);info.mode=0o700;tar.addfile(info,io.BytesIO(raw))
    payload=work/'payload.tar.gz'
    if not payload.exists():r.command([sys.executable,ROOT/'components/confidential-storage-sidecar/prepare-payload.py','--base',work/'initrd','--tools',tools,'--output',payload],timeout=300)
    sidecar=work/'sidecar.tar.gz'
    if not sidecar.exists():r.command([sys.executable,ROOT/'components/confidential-storage-sidecar/prepare-build.py','--service',work/'confidential-storage-service','--service-sha256',sha((work/'confidential-storage-service').read_bytes()),'--payload',payload,'--inventory',payload.with_suffix('.inventory.json'),'--output',sidecar])
    helper_image=image_build(r,'confidential-storage-sidecar',sidecar)
    populator=work/'populator.tar.gz'
    if not populator.exists():archive(populator,{'encrypted-model-populator':work/'encrypted-model-populator','Containerfile':('FROM '+r.v['images']['python']+'\nCOPY encrypted-model-populator /usr/local/bin/encrypted-model-populator\nUSER 1001\nENTRYPOINT ["/usr/local/bin/encrypted-model-populator"]\n').encode()})
    populator_image=image_build(r,'encrypted-model-populator',populator)
    preparation=work/'preparation.tar.gz'
    if not preparation.exists():
        entries=source_entries(['components/model-publisher','components/encrypted-model-populator','components/inference-release','models'])
        entries['Containerfile']=('FROM '+RUST+'\nCOPY components /opt/preparation/components\nCOPY models /opt/preparation/models\nWORKDIR /opt/preparation\nUSER 1001\nENTRYPOINT ["sleep"]\nCMD ["21600"]\n').encode()
        archive(preparation,entries)
    preparation_image=image_build(r,'inference-preparation',preparation)
    images={'controller':controller_image,'populator':populator_image,'sidecar':helper_image,'authority':authority_image,'preparation':preparation_image}
    r.save('images.json',images)
    cleanup_build_pods(r)
    r.oc('delete','pod',pod,'-n',r.trusted,'--wait=false')
    return {'state':'BuildsComplete','images':images}


def push(r):
    images=r.require_stage('build')['images']
    for name,receipt in images.items():
        stream=receipt['image'].split('/')[-1].split('@')[0]
        actual=r.get('imagestreamtag',stream+':build',r.ns)
        require(actual and actual['image']['metadata']['name']==receipt['image'].split('@')[1],'registry image differs from completed build')
    v=r.resolved()
    for name in ('controller','populator','sidecar'):v['images'][name]=images[name]['image']
    r.save_values(v)
    return {'state':'ImagesPinned','images':{k:v['image'] for k,v in images.items()},'pushPerformedBy':'OpenShift Build output'}


HANDLERS={'build':build,'push':push}
