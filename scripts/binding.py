"""Resolve immutable claims; no keys, signing, device access or formatting."""
import re

class Invalid(ValueError):pass

def declarations(values,expected,actual):
    d=values['demo'];ns=values['installation']['namespace'];result=[]
    for role in ('model','data'):
        name=d['name']+'-'+role;claim=actual[name]
        if not claim or claim.get('status',{}).get('phase')!='Bound':raise Invalid('all claims must be Bound before approval')
        if claim['metadata'].get('deletionTimestamp'):raise Invalid('claim is terminating')
        if claim['metadata']['namespace']!=ns:raise Invalid('cross-namespace claim')
        for k in ('storageClassName','volumeMode','accessModes','dataSourceRef'):
            if claim['spec'].get(k)!=expected[name]['spec'].get(k):raise Invalid('claim intent changed')
        # API may canonicalize quantities; compare integer bytes.
        def size(s):
            m=re.fullmatch(r'([1-9][0-9]*)(Mi|Gi)',s)
            if not m:raise Invalid('unsupported claim capacity')
            return int(m[1])*(2**20 if m[2]=='Mi' else 2**30)
        if size(claim['spec']['resources']['requests']['storage'])!=size(expected[name]['spec']['resources']['requests']['storage']):raise Invalid('claim capacity mismatch')
        uid=claim['metadata']['uid']
        if not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',uid):raise Invalid('invalid claim UID')
        spec={'claimRef':{'name':name,'uid':uid},'access':'ReadOnly' if role=='model' else 'ReadWrite','profile':'luks-verity-v1' if role=='model' else 'luks-integrity-v1','initialization':{'policy':'Never'} if role=='model' else {'policy':'OnceIfApproved','filesystem':'ext4','owner':{'uid':1001,'gid':1001}},'keyResource':d[role+'KeyResource']}
        if role=='model':spec['content']={'approvedManifestRef':d['approvedManifestRef']}
        result.append({'apiVersion':'storage.confidentialcontainers.org/v1alpha1','kind':'ConfidentialVolume','metadata':{'name':name,'namespace':ns},'spec':spec})
    if result[0]['spec']['claimRef']['uid']==result[1]['spec']['claimRef']['uid']:raise Invalid('volumes must be different claims')
    return result


def in_cluster_main():
    import json,os,ssl,time,urllib.request,urllib.error
    from pathlib import Path
    config=json.loads(Path('/configuration/binding.json').read_text())
    values=config['values'];expected=config['claims'];ns=values['installation']['namespace']
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):return None
    root='https://'+os.environ['KUBERNETES_SERVICE_HOST']+':'+os.environ.get('KUBERNETES_SERVICE_PORT_HTTPS','443')
    base=Path('/var/run/secrets/kubernetes.io/serviceaccount')
    client=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(base/'ca.crt'))),NoRedirect())
    def call(path,method='GET',body=None):
        headers={'Authorization':'Bearer '+(base/'token').read_text().strip(),'Content-Type':'application/json'}
        req=urllib.request.Request(root+path,data=None if body is None else json.dumps(body).encode(),headers=headers,method=method)
        try:
            with client.open(req,timeout=20) as r:return json.loads(r.read(1024*1024))
        except urllib.error.HTTPError as e:
            if e.code==404:return None
            if e.code==409:return {'conflict':True}
            raise RuntimeError('binding API request failed, HTTP '+str(e.code)) from None
    for _ in range(120):
        actual={name:call('/api/v1/namespaces/'+ns+'/persistentvolumeclaims/'+name) for name in expected}
        if all(x and x.get('status',{}).get('phase')=='Bound' for x in actual.values()):break
        time.sleep(5)
    else:raise RuntimeError('claim binding timeout')
    cvs=declarations(values,expected,actual)
    path='/apis/storage.confidentialcontainers.org/v1alpha1/namespaces/'+ns+'/confidentialvolumes'
    pending=[]
    for obj in cvs:
        old=call(path+'/'+obj['metadata']['name'])
        if old and old['spec']!=obj['spec']:raise Invalid('existing volume declaration does not match actual claim')
        if not old:pending.append(obj)
    for obj in pending:
        obj['metadata']['labels']={'inference.confidentialcontainers.org/installation':values['installation']['name']}
        result=call(path,'POST',obj)
        if result.get('conflict'):
            old=call(path+'/'+obj['metadata']['name'])
            if not old or old['spec']!=obj['spec']:raise Invalid('concurrent declaration mismatch')
    print(json.dumps({'result':'bound','volumes':[{'name':c['metadata']['name'],'claimUID':c['spec']['claimRef']['uid']} for c in cvs]},sort_keys=True))

if __name__=='__main__':in_cluster_main()
