import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock
import controller as C
import live_adapter as A
import lifecycle as L
from test_controller import ENV, ABSENT
from test_protocol import complete

class AdapterControls(unittest.TestCase):
    def test_admin_intent_precedes_write_and_single_attempt(self):
        calls=[]
        def fake(argv,env,deadline):
            self.assertEqual(env['AWS_MAX_ATTEMPTS'],'1')
            self.assertEqual(L.REPORT['operation_intents'][-1]['operation'],'put-role-policy')
            self.assertIn('--profile',argv);calls.append(argv);return complete(0,b'{}')
        with mock.patch.object(L,'CAPTURE',fake),mock.patch.object(L,'DEADLINE',time.monotonic()+10), \
             mock.patch.object(L,'persist',lambda:None),mock.patch.object(L,'REPORT',{'operations':[]}):
            L.call('iam','put-role-policy','--role-name','synthetic')
        self.assertEqual(len(calls),1)
    def test_unknown_admin_error_redacted(self):
        with mock.patch.object(L,'CAPTURE',lambda *a:complete(err=b'An error occurred (SECRET) raw-secret')), \
             mock.patch.object(L,'DEADLINE',time.monotonic()+10),mock.patch.object(L,'persist',lambda:None), \
             mock.patch.object(L,'REPORT',{'operations':[]}):
            with self.assertRaisesRegex(RuntimeError,'^ADMIN_OPERATION_FAILED$'):
                L.call('iam','get-role')
            self.assertNotIn('SECRET',json.dumps(L.REPORT));self.assertNotIn('raw-secret',json.dumps(L.REPORT))
    def test_exact_cleanup_refuses_foreign(self):
        def foreign(*args,**kwargs):
            return {'Role':{'Arn':L.RES['role_arn'],'RoleName':L.RES['role_name'],
                'Tags':[{'Key':L.TAG_KEY,'Value':'foreign'}],'RoleId':'other','AssumeRolePolicyDocument':L.TRUST}}
        with mock.patch.object(L,'call',side_effect=foreign) as call:
            with self.assertRaisesRegex(RuntimeError,'ROLE_OWNERSHIP_NOT_VERIFIED'):L.cleanup()
            self.assertEqual(call.call_count,1)
    def test_owned_cleanup_exact_policy_and_both_absences(self):
        role={'Role':{'Arn':L.RES['role_arn'],'RoleName':L.RES['role_name'],
            'Tags':[{'Key':L.TAG_KEY,'Value':L.TAG_VALUE}],'RoleId':'synthetic','AssumeRolePolicyDocument':L.TRUST}}
        replies=[role,{'PolicyDocument':L.POLICY},{},None,role,{},None]
        operations=[]
        def call(service,op,*args,**kw):operations.append(op);return replies.pop(0)
        with mock.patch.object(L,'call',side_effect=call),mock.patch.object(L,'ROLE_ID','synthetic'):
            result=L.cleanup()
        self.assertTrue(result['inline_policy_absent'] and result['role_absent'])
        self.assertEqual(operations,['get-role','get-role-policy','delete-role-policy','get-role-policy','get-role','delete-role','get-role'])
    def test_real_runner_prepared_state_readiness_then_maintained_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);directory.chmod(0o700)
            with mock.patch.object(L,'OUT',directory):
                backend=A.Backend();backend.fresh_state();runner=backend.runner
                initial=(backend.args.state_dir/'state.json').read_bytes()
                native_calls=[]
                def native(args,state,action,env,deadline):
                    native_calls.append(action)
                    if action=='read':return dict(ABSENT,schema=1,reason='None',credential_kind='None',s3_kind='None',ses_kind='None',mutation_status=0)
                    result=dict(ABSENT,schema=1,reason='None',credential_kind='None',s3_kind='None',ses_kind='None',mutation_status=200)
                    result['object']='Owned' if action=='put' else 'Absent'
                    return result
                att=dict(principal_type='AssumedRole',role_match=True,session_present=True,expiry_guard=True,
                    expected_role_arn_sha256=hashlib.sha256(L.RES['role_arn'].encode()).hexdigest())
                backend.env=runner.VerifiedEnvironment(ENV,att)
                with mock.patch.object(runner,'native',side_effect=native):
                    result=backend.native_read(ENV,time.monotonic()+5)
                self.assertEqual((backend.args.state_dir/'state.json').read_bytes(),initial)
                # Real maintained state machine, fake native transport only; no state reset.
                result=runner.run(backend.args,launcher=native,
                    credential_loader=lambda *args:backend.env)
                self.assertTrue(result['qualified']);self.assertEqual(native_calls,['read','read','put','delete'])
                frozen=(backend.args.state_dir/'state.json').read_bytes()
                with self.assertRaisesRegex(runner.Failure,'RUN_REQUIRES_REVIEW'):
                    runner.run(backend.args,launcher=native,credential_loader=lambda *args:backend.env)
                self.assertEqual((backend.args.state_dir/'state.json').read_bytes(),frozen)
    def test_cli_adapter_actual_key_and_triple(self):
        backend=A.Backend();runner=mock.Mock();backend.runner=runner
        backend.args=types.SimpleNamespace(state_dir=Path('/synthetic'))
        runner.read.return_value={'run_id':'a'*32}
        def fake(argv,env,deadline):
            self.assertIn(L.RES['prefix']+'a'*32+'.txt',argv)
            self.assertEqual({k:env[k] for k in C.TRIPLE},ENV)
            self.assertNotIn('--profile',argv)
            return complete(err=b'An error occurred (NoSuchKey) when calling the GetObject operation: hidden')
        with mock.patch.object(A,'capture',side_effect=fake),mock.patch.object(L,'persist'), \
             mock.patch.object(L,'REPORT',{'operations':[]}):
            self.assertEqual(backend.cli_read(ENV,time.monotonic()+5)['code'],'NoSuchKey')

if __name__=='__main__':unittest.main()
