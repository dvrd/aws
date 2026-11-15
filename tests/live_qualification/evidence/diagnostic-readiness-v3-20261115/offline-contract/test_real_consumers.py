"""Real maintained consumers; transport is synthetic and no process may spawn."""
import datetime,json,os,tempfile,time,types,unittest
from pathlib import Path
from unittest import mock
import live_adapter as A
import lifecycle as L
from held_capture import Captured

class RealConsumers(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='aws416-consumer-offline-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700);self.calls=[];self.behavior={};self.identity_bad=False
        self.stack=__import__('contextlib').ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(A,'capture',side_effect=self.transport))
        self.stack.enter_context(mock.patch.object(L,'persist'))
        self.stack.enter_context(mock.patch.object(L,'REPORT',{'operations':[]}))
        self.stack.enter_context(mock.patch.object(A.subprocess,'Popen',side_effect=AssertionError('ACTUAL_PROCESS_FORBIDDEN')))
        self.backend=A.Backend();self.runner=self.backend.runner
        binary=self.root/'never-execute';binary.write_bytes(b'owned fixture never executed\n');binary.chmod(0o700)
        resource=self.root/'resource.json';resource.write_text(json.dumps(dict(schema=1,phase='READY',bucket='webtools-qualification-offline',prefix='qualification/'+'f'*32+'/',region='us-east-1',expected_account='000000000000',credential_source='environment',expected_role_arn='arn:aws:iam::000000000000:role/offline-owned',public_access_block_verified=True,encryption='AES256')));resource.chmod(0o600)
        self.backend.args=types.SimpleNamespace(resource_plan=resource,binary=binary,state_dir=self.root/'state',command='run',live=True,allow_write=True,aws_cli=Path(L.CLI),ses_sender='',ses_identity_verified=False)
        self.runner.plan(self.backend.args)
        self.env=dict(PATH='/usr/bin:/bin',AWS_ACCESS_KEY_ID='synthetic-key',AWS_SECRET_ACCESS_KEY='synthetic-secret',AWS_SESSION_TOKEN='synthetic-token',AWS_CREDENTIAL_EXPIRATION=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=900)).isoformat())

    def transport(self,argv,env,deadline,limit=16384):
        self.assertEqual({k:env[k] for k in A.C.TRIPLE},{k:self.env[k] for k in A.C.TRIPLE});self.assertEqual(env['AWS_MAX_ATTEMPTS'],'1')
        if 'get-caller-identity' in argv:
            name='identity';payload=dict(Account='000000000000',Arn='arn:aws:sts::000000000000:assumed-role/'+('wrong' if self.identity_bad else 'offline-owned')+'/session')
        else:
            self.assertEqual(str(argv[0]),str(self.backend.args.binary));name=argv[argv.index('--action')+1]
            payload=dict(schema=1,ok=True,reason='None',object='Owned' if name=='put' else 'Absent',credential_kind='None',s3_kind='None',ses_kind='None',put_effect='Response_Received' if name=='put' else 'Not_Sent',delete_effect='Response_Received' if name=='delete' else 'Not_Sent',ses_effect='Not_Sent',mutation_status=200 if name in ('put','delete') else 0,read_status=404,read_error_code='NoSuchKey')
        self.calls.append(name);mode=self.behavior.get(name)
        if mode=='unknown':return Captured(phase='Read',failure_type='Deadline',pid=123,wait_state='VerifiedReaped',reservation_state='Reaped')
        if mode=='denied':payload.update(ok=False,reason='Read_Failed',object='Unverified',s3_kind='Rejected',read_status=403,read_error_code='AccessDenied')
        data=b'{' if mode=='malformed' else json.dumps(payload).encode()
        return Captured(phase='Completed',returncode=2 if mode=='denied' else 0,pid=123,wait_state='VerifiedReaped',reservation_state='Reaped',stdout=data,stderr=b'private-stderr-marker')

    def state(self):return self.runner.read(self.backend.args.state_dir/'state.json')
    def guard(self):self.backend.guard_role(self.env,225)
    def assert_private(self):
        text=json.dumps(L.REPORT)+''.join(p.read_text() for p in self.backend.args.state_dir.iterdir() if p.is_file())
        for value in ['private-stderr-marker',*(self.env[k] for k in A.C.TRIPLE)]:self.assertNotIn(value,text)

    def test_actual_guard_same_triple_and_wrong_role(self):
        self.guard();self.assertTrue(self.backend.env.attestation['role_match']);self.identity_bad=True
        with self.assertRaisesRegex(self.runner.Failure,'EXPECTED_ROLE_NOT_VERIFIED'):self.guard()
        self.assertEqual(self.calls,['identity','identity']);self.assertEqual(self.state()['phase'],'PREPARED');self.assert_private()

    def test_actual_native_read_keeps_prepared(self):
        self.guard();before=(self.backend.args.state_dir/'state.json').read_bytes();result=self.backend.native_read(self.env,time.monotonic()+30)
        self.assertEqual((result['object'],result['read_status'],result['read_error_code']),('Absent',404,'NoSuchKey'))
        self.assertEqual((self.backend.args.state_dir/'state.json').read_bytes(),before);self.assertEqual(self.calls,['identity','read']);self.assert_private()

    def test_actual_campaign_complete_once_no_replay(self):
        self.guard();self.backend.native_read(self.env,time.monotonic()+30);result=self.backend.maintained_campaign(self.env,180)
        self.assertEqual(result,dict(qualified=True,phase='COMPLETE',s3_qualified=True));self.assertEqual(self.calls,['identity','read','identity','read','put','delete'])
        before=(self.backend.args.state_dir/'state.json').read_bytes();count=len(self.calls)
        with self.assertRaisesRegex(self.runner.Failure,'RUN_REQUIRES_REVIEW'):self.backend.maintained_campaign(self.env,180)
        self.assertEqual(len(self.calls),count);self.assertEqual((self.backend.args.state_dir/'state.json').read_bytes(),before);self.assert_private()

    def test_actual_campaign_unknown_put_retains_intent_no_replay(self):
        self.guard();self.behavior['put']='unknown'
        with self.assertRaisesRegex(RuntimeError,'MAINTAINED_CAPTURE_UNKNOWN'):self.backend.maintained_campaign(self.env,180)
        self.assertEqual(self.state()['phase'],'PUT_INTENT');self.assertEqual(self.calls,['identity','identity','read','put']);count=len(self.calls)
        with self.assertRaisesRegex(self.runner.Failure,'RUN_REQUIRES_REVIEW'):self.backend.maintained_campaign(self.env,180)
        self.assertEqual(len(self.calls),count);self.assert_private()

    def test_actual_campaign_read_denial_never_puts(self):
        self.guard();self.behavior['read']='denied';result=self.backend.maintained_campaign(self.env,180)
        self.assertEqual(result,dict(qualified=False,phase='READ_INTENT',s3_qualified=False));self.assertEqual(self.calls,['identity','identity','read']);self.assertEqual(self.state()['read_result']['read_status'],403);self.assert_private()

    def test_actual_campaign_malformed_native_retains_intent(self):
        self.guard();self.behavior['read']='malformed';result=self.backend.maintained_campaign(self.env,180)
        self.assertFalse(result['qualified']);self.assertEqual(self.state()['phase'],'READ_INTENT');self.assertEqual(self.calls,['identity','identity','read']);self.assert_private()

if __name__=='__main__':unittest.main()
