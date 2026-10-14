#!/usr/bin/env python3
"""Trusted offline metadata enrollment; never fetches keys or touches a device."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys
import uuid
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'components/confidential-storage-authority'))
from authority import Authority, Denied
from bootstrap import verify
from publication import from_publisher
from storage_profiles import profile_digest
from initialization import validate_plan

def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'))
def sha(v):return hashlib.sha256(canonical(v).encode()).hexdigest()
def require(ok,message):
    if not ok:raise ValueError(message)

def plan(request,draft,models,approved_blank_uids):
    require(request['purpose']=='confidential-volume-reconcile-request/v1','unexpected request')
    require(draft['requestSha256']==sha(request),'draft/request mismatch')
    require(draft['policySha256']==hashlib.sha256(draft['policy'].encode()).hexdigest(),'policy hash mismatch')
    entries=request['contract']['volumes'];uids=set(approved_blank_uids)
    rw={v['claimRef']['uid'] for v in entries if v['access']=='ReadWrite'}
    require(uids==rw and len(uids)==len(approved_blank_uids),'explicit approval of every and only new RW claim UID required')
    claims={v['uid']:v for v in request['claims']}
    sources={v['name']:v['spec'] for v in request['sources']}
    records=[]
    for v in entries:
        claim=claims[v['claimRef']['uid']]
        require(claim['name']==v['claimRef']['name'],'claim identity mismatch')
        identity={'cluster':request['clusterId'],'namespace':request['contract']['namespace'],'claimUID':claim['uid']}
        volume='v-'+base64.b32encode(bytes.fromhex(sha(identity))).decode().rstrip('=').lower()
        ro=v['access']=='ReadOnly'
        record={'volume_id':volume,'generation':1,'policy_sha256':draft['policySha256'],
            'profile_sha256':profile_digest('ro-luks2-verity-v2' if ro else 'rw-luks2-v2'),
            'credential_uri':v['keyResource'],
            'mount_binding':{'manifest_uri':'kbs:///storage/volume-manifests/'+volume,
                'container_name':v['container'],'destination':v['mountPath'],'access':'ro' if ro else 'rw'}}
        entry={'registration':record,'bindingId':v['bindingId'],'claimUID':claim['uid'],'devicePath':v['devicePath']}
        if ro:
            require(v['initialization']=={'policy':'Never'},'RO initialization forbidden')
            published=models[v['content']['approvedManifestRef']]
            ref=claim['dataSourceRef']
            require(ref and ref['kind']=='EncryptedModelSource','RO populated source required')
            require(published['source']==sources[ref['name']],'reviewed publisher source differs from populated source')
            require(published['source']['diskBytes']==v['requestedBytes'],'model geometry mismatch')
            entry['manifest']=from_publisher(record,published['descriptor'],published['source']).decode()
        else:
            require(claim['dataSourceRef'] is None,'RW first-use cannot come from a data source')
            require(v['initialization']=={'policy':'OnceIfApproved','filesystem':'ext4','owner':{'uid':1001,'gid':1001}},'unqualified RW initialization')
            # Public identifiers, not encryption secrets. Stable retry identity is
            # derived from the actual claim UID, never a reusable PVC name.
            entry['initialization']={'schema_version':1,'new_volume':True,
                'provisioning_id':str(uuid.uuid5(uuid.NAMESPACE_URL,'coco-provision:'+canonical(identity))),
                'luks_uuid':str(uuid.uuid5(uuid.NAMESPACE_URL,'coco-luks:'+canonical(identity))),
                'device_bytes':v['requestedBytes'],'filesystem':'ext4',
                'header_bytes':16*1024*1024,'data_offset_bytes':16*1024*1024}
            validate_plan(entry['initialization'])
        records.append(entry)
    require(len({r['registration']['volume_id'] for r in records})==len(records),'duplicate claim binding')
    return {'schemaVersion':1,'purpose':'trusted-storage-enrollment/v1','requestSha256':sha(request),'records':records}

def matches(existing,wanted):
    return all(existing.get(k)==v for k,v in wanted.items()) and not existing['revoked']

def apply(state,installation,plan):
    """Retry-safe partial progress. No reset, takeover, policy update or reformat."""
    require(plan['purpose']=='trusted-storage-enrollment/v1' and plan['schemaVersion']==1,'unexpected enrollment')
    verify(Path(state).absolute(),installation)
    a=Authority(Path(state)/'authority.db')
    # Precheck every existing identity before changing any record.
    for item in plan['records']:
        wanted=item['registration']
        with a._transaction() as db:
            row=db.execute('SELECT record FROM volumes WHERE id=?',(wanted['volume_id'],)).fetchone()
        if row:
            current=json.loads(row[0]);require(matches(current,wanted),'retained registration differs; explicit migration required')
            if 'initialization' in item and current.get('initialization_approval'):
                require(current['initialization_approval']['plan']==item['initialization'],'retained initialization differs')
            if 'manifest' in item and current.get('manifest_sha256'):
                require(current['manifest_sha256']==hashlib.sha256(item['manifest'].encode()).hexdigest(),'retained model differs')
    result=[]
    for item in plan['records']:
        wanted=item['registration'];volume=wanted['volume_id']
        try:a.inspect(volume)
        except Denied:
            a.register(volume,wanted['policy_sha256'],wanted['profile_sha256'],wanted['credential_uri'],mount_binding=wanted['mount_binding'])
        current=a.inspect(volume)
        require(matches(current,wanted),'registration changed during enrollment')
        if 'manifest' in item:
            a.approve_published_model(volume,item['manifest'].encode())
        elif not current.get('initialization_approval'):
            a.approve_initialization(volume,item['initialization'])
        result.append(a.inspect(volume))
    return {'requestSha256':plan['requestSha256'],'records':result}

def guest_configuration(request,draft,planned,enrolled,authority,encodings):
    """Resolve the public guest configuration only from matching retained records."""
    require(planned['requestSha256']==enrolled['requestSha256']==draft['requestSha256']==sha(request),'enrollment/request mismatch')
    require(set(authority)=={'trustee_rcar','audience','certificate_der','address','receipt_public_key','receipt_issuer','receipt_key_id'},'unexpected authority public fields')
    require(authority['trustee_rcar'] is True,'standard Trustee RCAR required')
    require(len(authority['receipt_public_key'])==32 and authority['certificate_der'],'authority public trust pins required')
    require(set(encodings)=={v['keyResource'] for v in request['contract']['volumes']} and all(v in ('raw32','lower-hex64') for v in encodings.values()),'explicit resource encodings required')
    records={r['volume_id']:r for r in enrolled['records']}
    require(len(records)==len(enrolled['records'])==len(planned['records']),'enrolled volume count differs')
    entries={v['bindingId']:v for v in request['contract']['volumes']}
    require({p['bindingId'] for p in planned['records']}==set(entries),'plan bindings differ')
    volumes=[]
    for item in planned['records']:
        wanted=item['registration'];record=records[wanted['volume_id']]
        require(matches(record,wanted),'retained record differs from planned registration')
        v=entries[item['bindingId']]
        require(item['claimUID']==v['claimRef']['uid'] and item['devicePath']==v['devicePath'],'plan claim or device differs')
        binding=wanted['mount_binding']
        access='ro' if v['access']=='ReadOnly' else 'rw'
        require(binding['access']==access and wanted['policy_sha256']==draft['policySha256'],'plan access or policy differs')
        require(wanted['profile_sha256']==profile_digest('ro-luks2-verity-v2' if access=='ro' else 'rw-luks2-v2'),'plan storage profile differs')
        require(wanted['credential_uri']==v['keyResource'] and binding['destination']==v['mountPath'] and binding['container_name']==v['container'],'plan guest binding differs')
        expected={k:record[k] for k in ('volume_id','generation','policy_sha256','profile_sha256')}
        expected.update(binding,session_sha256='',operation_id='',nonce='')
        volume={'binding_id':item['bindingId'],'transport_path':item['devicePath'],'expected':expected,'manifest':[]}
        if 'manifest' in item:
            require(record['state']=='Ready' and record['manifest_sha256']==hashlib.sha256(item['manifest'].encode()).hexdigest(),'approved manifest differs')
            volume['manifest']=list(item['manifest'].encode())
        else:
            from initialization import approved_policy
            require(record['initialization_approval']['plan']==item['initialization'],'approved initialization differs')
            require(approved_policy(record)==draft['policySha256'],'initialization policy differs')
            volume['initialization_plan_sha256']=record['initialization_approval']['plan_sha256']
        volumes.append(volume)
    return {'schema_version':2,'purpose':'confidential-storage-guest/v2',
            'authority':dict(authority,policy_sha256=draft['policySha256'],init_data=''),
            'kbs':{'provider':'private-cdh','resources':encodings},'volumes':volumes}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='operation',required=True)
    draft=sub.add_parser('plan')
    for f in ('request','draft','models','blank-claim-uids','output'):draft.add_argument('--'+f,type=Path,required=True)
    enroll=sub.add_parser('apply')
    for f in ('plan','state','output'):enroll.add_argument('--'+f,type=Path,required=True)
    enroll.add_argument('--installation',required=True)
    a=p.parse_args()
    if a.operation=='plan':
        result=plan(json.loads(a.request.read_text()),json.loads(a.draft.read_text()),json.loads(a.models.read_text()),json.loads(a.blank_claim_uids.read_text()))
    else:result=apply(a.state,a.installation,json.loads(a.plan.read_text()))
    with a.output.open('x') as f:f.write(canonical(result)+'\n')
    print('Public enrollment result written; no key access, disk operation or deployment performed.')
