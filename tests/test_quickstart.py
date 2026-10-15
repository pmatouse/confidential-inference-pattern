"""Quickstart safety boundaries that do not require cluster access."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from quickstart.core import write, sha
from quickstart.build import archive
from quickstart.verify import validate_authority, compare_authority, gracefully_terminated


class QuickstartTests(unittest.TestCase):
    def test_stopped_vm_does_not_depend_on_api_garbage_collection(self):
        pod={'metadata':{'uid':'old','deletionTimestamp':'time'},'spec':{'containers':[{'name':'app'},{'name':'sidecar'}]},
             'status':{'phase':'Succeeded','containerStatuses':[{'name':name,'state':{'terminated':{'exitCode':0}}} for name in ('app','sidecar')]}}
        self.assertTrue(gracefully_terminated(None,'old'))
        self.assertTrue(gracefully_terminated(pod,'old'))
        self.assertFalse(gracefully_terminated(pod,'different'))
        for mutation in ('live','failed','missing','not-deleting'):
            changed=copy.deepcopy(pod)
            if mutation=='live':changed['status']['containerStatuses'][1]['state']={'running':{}}
            if mutation=='failed':changed['status']['containerStatuses'][1]['state']['terminated']['exitCode']=1
            if mutation=='missing':changed['status']['containerStatuses'].pop()
            if mutation=='not-deleting':changed['metadata'].pop('deletionTimestamp')
            self.assertFalse(gracefully_terminated(changed,'old'),mutation)

    def test_controller_owned_state_blocks_manual_mutations(self):
        from unittest.mock import patch
        from quickstart.core import Run
        values={'demo':{'name':'demo'},'installation':{'name':'demo','namespace':'work'},'quickstart':{'trustedNamespace':'trusted'}}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            env={'QUICKSTART_STATE_ROOT':str(root/'private'),'QUICKSTART_OUTPUT_ROOT':str(root/'public'),'QUICKSTART_CACHE':str(root/'cache'),'QUICKSTART_EXECUTOR':'manual'}
            with patch.dict(os.environ,env),patch('addon.load',return_value=values),patch('addon.Cluster'):
                run=Run(root/'site.yaml','demo')
                write(run.state/'executor-owner.json',{'executor':'controller'})
                run.lock.close()
                with self.assertRaisesRegex(ValueError,'ownership differs'):
                    Run(root/'site.yaml','demo')
                with patch.dict(os.environ,{'QUICKSTART_EXECUTOR':'controller'}):
                    worker=Run(root/'site.yaml','demo')
                    self.assertEqual(worker.state,root/'private/demo')
                    worker.lock.close()

    def test_public_build_archive_is_reproducible_and_binary_executable(self):
        with tempfile.TemporaryDirectory() as d:
            a,b=Path(d)/'a.gz',Path(d)/'b.gz'
            entries={'encrypted-model-populator':b'binary','Containerfile':b'FROM scratch'}
            archive(a,entries);archive(b,entries)
            self.assertEqual(a.read_bytes(),b.read_bytes())
            with tarfile.open(a) as t:self.assertEqual(t.getmember('encrypted-model-populator').mode,0o755)

    def test_stock_artifact_read_retries_transport_but_never_digest_mismatch(self):
        from types import SimpleNamespace
        from unittest.mock import Mock,patch
        from quickstart.build import read_stock_artifact
        item={'path':'/approved/initrd','sha256':sha(b'approved')}
        r=SimpleNamespace(oc=Mock(side_effect=[RuntimeError('transport'),b'approved']))
        with patch('quickstart.build.time.sleep'):
            self.assertEqual(read_stock_artifact(r,'daemon',item),b'approved')
        self.assertEqual(r.oc.call_count,2)
        r.oc=Mock(side_effect=[b'different',b'approved'])
        with self.assertRaisesRegex(ValueError,'differs from approved'):read_stock_artifact(r,'daemon',item)
        self.assertEqual(r.oc.call_count,1)
        r.oc=Mock(side_effect=RuntimeError('transport'))
        with patch('quickstart.build.time.sleep'),self.assertRaises(RuntimeError):read_stock_artifact(r,'daemon',item)
        self.assertEqual(r.oc.call_count,3)

    def test_compiler_receive_recovers_transport_without_publishing_unverified_bytes(self):
        from types import SimpleNamespace
        from unittest.mock import Mock,patch
        from quickstart.build import receive
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'binary';target.write_bytes(b'previous')
            r=SimpleNamespace(trusted='trusted',oc=Mock(side_effect=[RuntimeError('transport'),b'truncated',b'complete']))
            with patch('quickstart.build.time.sleep'):receive(r,'compiler','/work/binary',target,sha(b'complete'))
            self.assertEqual(r.oc.call_count,3);self.assertEqual(target.read_bytes(),b'complete')
            r.oc=Mock(return_value=b'corrupt')
            with self.assertRaisesRegex(RuntimeError,'digest mismatch'):receive(r,'compiler','/work/binary',target,sha(b'complete'))
            self.assertEqual(r.oc.call_count,3);self.assertEqual(target.read_bytes(),b'complete')
            r.oc=Mock(side_effect=RuntimeError('transport'))
            with patch('quickstart.build.time.sleep'),self.assertRaises(RuntimeError):receive(r,'compiler','/work/binary',target,sha(b'complete'))
            self.assertEqual(r.oc.call_count,3);self.assertEqual(target.read_bytes(),b'complete')

    def test_failed_archive_read_never_publishes_partial_context(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d, patch('quickstart.build.time.sleep'):
            output=Path(d)/'context.gz'
            with self.assertRaises(OSError):archive(output,{'absent':Path(d)/'absent'})
            self.assertFalse(output.exists())

    def test_private_write_rejects_symlink_and_uses_private_mode(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'key';write(p,b'private')
            self.assertEqual(p.stat().st_mode&0o777,0o600)
            link=Path(d)/'link';link.symlink_to(p)
            with self.assertRaises(ValueError):write(link,b'changed')
            self.assertEqual(p.read_bytes(),b'private')

    def test_loaded_keys_hash_flattened_paths_without_returning_key_bytes(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from quickstart.release import verify_loaded_keys
        values={'model':b'example-model-key','data':b'example-data-key'}
        calls=[]
        def oc(*args,**kwargs):
            calls.append((args,kwargs))
            return ''.join(sha(values[k])+'  -\n' for k in sorted(values))
        r=SimpleNamespace(v={'base':{'trusteeNamespace':'trustee'}},oc=oc)
        with patch('quickstart.release.trustee_pod',return_value={'metadata':{'name':'kbs'}}):
            self.assertTrue(verify_loaded_keys(r,values))
        self.assertTrue(calls[0][1]['sensitive'])
        self.assertIn(r'/opt/confidential-containers/storage/repository/default\x2Fmodel-keys\x2Fdata',calls[0][0])
        self.assertNotIn(b'example-data-key',calls[0][0])

    def test_enrollment_waits_for_owner_rollout_and_does_not_restart_loaded_trustee(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from quickstart.release import ensure_loaded_keys
        pod={'metadata':{'name':'replacement','uid':'new'}}
        def wait(description,check,**kwargs):
            self.assertIsNone(check())
            return check()
        with tempfile.TemporaryDirectory() as directory:
            r=SimpleNamespace(state=Path(directory),q={'allowTrusteeRestart':False},wait=wait,
                oc=lambda *args,**kwargs:self.fail('owner rollout must not cause a second restart'))
            with patch('quickstart.release.trustee_pod',side_effect=[None,pod]),patch('quickstart.release.verify_loaded_keys',return_value=True) as verify:
                self.assertEqual(ensure_loaded_keys(r,{'key':b'expected'}),pod)
                verify.assert_called_once_with(r,{'key':b'expected'},pod)
            self.assertFalse((r.state/'trustee-restart.json').exists())

    def test_enrollment_restarts_stale_trustee_once_and_requires_new_uid_and_exact_keys(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from quickstart.release import ensure_loaded_keys
        old={'metadata':{'name':'old','uid':'old'}};new={'metadata':{'name':'new','uid':'new'}}
        def wait(description,check,**kwargs):
            for _ in range(5):
                result=check()
                if result:return result
            self.fail('readiness never passed')
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory);calls=[]
            def oc(*args):
                self.assertEqual(json.loads((state/'trustee-restart.json').read_text())['uid'],'old')
                calls.append(args)
            r=SimpleNamespace(state=state,q={'allowTrusteeRestart':True},v={'base':{'trusteeNamespace':'trustee'}},
                wait=wait,get=lambda *args:old,oc=oc)
            with patch('quickstart.release.trustee_pod',side_effect=[old,None,old,new,new]),patch('quickstart.release.verify_loaded_keys',side_effect=[False,False,True]):
                self.assertEqual(ensure_loaded_keys(r,{'key':b'expected'}),new)
            self.assertEqual(len(calls),1)
            self.assertIn('--ignore-not-found=true',calls[0])

    def test_completed_pending_build_is_recovered_without_second_submission(self):
        from types import SimpleNamespace
        from quickstart.build import image_build
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);out=root/'out';out.mkdir();state=root/'state';state.mkdir()
            context=root/'context';context.write_bytes(b'public-source')
            write(state/'pending-build-example.json',{'build':'example-1','contextSha256':sha(context.read_bytes())})
            obj={'status':{'phase':'Complete','output':{'to':{'imageDigest':'sha256:'+'a'*64}}}}
            def unexpected(*args,**kwargs):self.fail('must not submit a second build')
            r=SimpleNamespace(out=out,state=state,ns='test',v={'registry':{'origin':'https://registry'}},
                get=lambda *args:obj,apply=lambda obj:None,oc=unexpected,
                wait=lambda description,check,**kwargs:check(),save=lambda name,data:write(out/name,data))
            result=image_build(r,'example',context)
            self.assertEqual(result['build'],'example-1')
            obj['status']['phase']='Failed'
            with self.assertRaises(ValueError):image_build(r,'example',context)

    def test_first_stage_receipt_is_preserved_on_retry(self):
        from quickstart.core import Run
        with tempfile.TemporaryDirectory() as directory:
            r=Run.__new__(Run);r.out=Path(directory);r.name='demo';r.identity={'siteSha256':'a'*64}
            r.save=lambda name,obj:write(r.out/name,obj)
            r.finish('example',{'state':'first'})
            r.finish('example',{'state':'retry'})
            self.assertEqual(json.loads((r.out/'first-receipts/example.json').read_text())['result']['state'],'first')
            self.assertEqual(json.loads((r.out/'receipts/example.json').read_text())['result']['state'],'retry')

    def snapshot(self):
        base={'state':'Ready','revoked':False,'policy_sha256':'a'*64,'header_sha256':'b'*64,
              'manifest_sha256':'c'*64,'owner':{'session_sha256':'old'},'generation':1,'profile_sha256':'d'*64}
        ro=dict(base,volume_id='model')
        rw=dict(base,volume_id='data',initialization_approval={'plan':{}},initialization_steps=[
            {'step':s,'step_id':str(i),'status':'Complete'} for i,s in enumerate(
            ('luks-format','integrity-initialize','filesystem-create','durability-barrier'))])
        return {'records':[ro,rw],'operationCounts':{'model':1,'data':1}}

    def test_reopen_requires_new_session_and_closed_old_owner(self):
        first=self.snapshot();validate_authority(first,'a'*64)
        with self.assertRaises(ValueError):compare_authority(first,first)
        later=copy.deepcopy(first)
        for record in later['records']:
            record['last_closed']=record['owner'];record['owner']={'session_sha256':'new'}
            later['operationCounts'][record['volume_id']]+=1
        compare_authority(first,later)
        later['records'][1]['initialization_steps'][0]['step_id']='reformatted'
        with self.assertRaises(ValueError):compare_authority(first,later)

    def test_first_run_rejects_incomplete_initialization_and_wrong_policy(self):
        snapshot=self.snapshot()
        with self.assertRaises(ValueError):validate_authority(snapshot,'e'*64)
        snapshot['records'][1]['initialization_steps'][-1]['status']='Started'
        with self.assertRaises(ValueError):validate_authority(snapshot,'a'*64)


if __name__=='__main__':unittest.main()
