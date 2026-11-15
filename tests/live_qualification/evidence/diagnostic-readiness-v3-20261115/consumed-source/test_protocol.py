import json,time,unittest
from unittest import mock
import controller as C
import live_adapter as A
import lifecycle as L
from held_capture import Captured


def complete(code=254,out=b'',err=b''):
    return Captured(phase='Completed',returncode=code,pid=123,wait_state='VerifiedReaped',reservation_state='Reaped',stdout=out,stderr=err)


def envelope(operation='AssumeRole',code='AccessDenied',retry=None):
    clause='' if retry is None else ' (reached max retries: '+retry+')'
    return ('\naws: [ERROR]: An error occurred ('+code+') when calling the '+operation+
            ' operation'+clause+': synthetic-secret\n').encode()


class ProtocolControls(unittest.TestCase):
    def assume(self,result):
        with mock.patch.object(A,'capture',return_value=result) as capture, \
             mock.patch.object(L,'REPORT',{'operations':[]}),mock.patch.object(L,'persist'), \
             mock.patch.object(L,'DEADLINE',time.monotonic()+60):
            status,env=A.Backend.__new__(A.Backend).assume_attempt(900,time.monotonic()+45)
            row=L.REPORT['operations'][-1]
            text=json.dumps(row)
            self.assertNotIn('synthetic-secret',text);self.assertNotIn('Expiration',text)
            self.assertNotIn('held_child_reaped',row)
            self.assertEqual(capture.call_count,1)
            return status,env,row

    def test_exact_absent_and_zero_retry_sts_denial(self):
        for retry in [None,'0']:
            status,env,row=self.assume(complete(err=envelope(retry=retry)))
            self.assertEqual((status,env),('Denied',None))
            self.assertEqual(row['diagnostic']['error_code'],'AccessDenied')
            self.assertEqual(row['diagnostic']['wait_state'],'VerifiedReaped')
            self.assertEqual(row['diagnostic']['retry_info'],'Absent' if retry is None else 'Zero')

    def test_case_one_or_malformed_retry_never_allows_retry(self):
        for retry in ['1','2','-1','01','0x','0.0','', '9999999']:
            status,env,row=self.assume(complete(err=envelope(retry=retry)))
            self.assertEqual((status,env),('Unknown',None))
        self.assertEqual(C.service_error(254,envelope(retry='1'),'AssumeRole')['failure_type'],
                         'UnexpectedRetries')

    def test_count_all_envelopes_reject_mixed_errors_operations_and_malformed(self):
        cases=[envelope('GetObject'),envelope()+envelope(),
            envelope()+envelope('GetRole','NoSuchEntity'),
            b'prefix '+envelope().lstrip(),b'An error occurred (AccessDenied) malformed',
            b'An error occurred (AccessDenied) when calling the AssumeRole operation (reached max retries: 0): x\nAn error occurred (Other) broken']
        for stderr in cases:
            self.assertEqual(self.assume(complete(err=stderr))[0],'Unknown')

    def test_s3_uses_same_decoder_for_absence_and_denial(self):
        for code in ['NoSuchKey','AccessDenied']:
            for retry in [None,'0']:
                self.assertEqual(C.cli_observation(254,envelope('GetObject',code,retry))['code'],code)
            for retry in ['1','-1','01','0x']:
                self.assertEqual(C.cli_observation(254,envelope('GetObject',code,retry))['code'],'Unknown')
        for data in [envelope(),envelope('GetObject','NoSuchKey')+envelope('GetObject'),
                     envelope('GetObject','NoSuchKey')+envelope('GetRole','NoSuchEntity')]:
            self.assertEqual(C.cli_observation(254,data)['code'],'Unknown')

    def test_non_denial_errors_and_mixed_stdout_remain_unknown(self):
        for code in ['ValidationError','ExpiredToken','InvalidClientTokenId','FakeSecretCode']:
            status,env,row=self.assume(complete(err=envelope(code=code,retry='0')))
            self.assertEqual(status,'Unknown')
            self.assertEqual(row['diagnostic']['error_code'],'Other' if code=='FakeSecretCode' else code)
        status,env,row=self.assume(complete(out=b'conflicting',err=envelope(retry='0')))
        self.assertEqual(status,'Unknown');self.assertEqual(row['diagnostic']['failure_type'],'ConflictingResult')
        self.assertEqual(C.cli_observation(254,envelope('GetObject','NoSuchKey','0'),b'conflicting')['code'],'Unknown')

    def test_response_phase_and_private_issued_triple(self):
        arn='arn:aws:sts::'+L.OLD['expected_account']+':assumed-role/'+L.RES['role_name']+'/'+L.RES['session_name']
        reply=dict(AssumedRoleUser=dict(Arn=arn),Credentials=dict(AccessKeyId='synthetic-key',
         SecretAccessKey='synthetic-secret',SessionToken='synthetic-token',Expiration='2099-01-01T00:00:00Z'))
        status,env,row=self.assume(complete(0,json.dumps(reply).encode()))
        self.assertEqual(status,'Issued');self.assertEqual(env['AWS_SECRET_ACCESS_KEY'],'synthetic-secret')
        self.assertNotIn('synthetic-key',json.dumps(row));self.assertNotIn('synthetic-token',json.dumps(row))
        for body,phase in [(b'bad','JSONDecode'),(b'[]','ResponseShape'),(b'{}','SessionIdentity'),
            (json.dumps(dict(AssumedRoleUser=dict(Arn=arn))).encode(),'CredentialSchema')]:
            status,env,row=self.assume(complete(0,body))
            self.assertEqual(status,'Unknown');self.assertEqual(row['diagnostic']['phase'],phase)

    def test_capture_unverified_wait_never_becomes_reaped_attestation(self):
        status,env,row=self.assume(Captured(phase='Read',failure_type='OutputLimit',pid=456,
         cleanup_failure_type='PermissionDenied',wait_state='Unverified'))
        self.assertEqual(status,'Unknown');self.assertEqual(row['diagnostic']['wait_state'],'Unverified')
        self.assertEqual(row['diagnostic']['pid'],456)
        self.assertEqual(row['diagnostic']['cleanup_failure_type'],'PermissionDenied')

    def test_cli_flags_and_environment_are_explicit_no_profile_for_s3(self):
        env={key:'synthetic-'+key for key in C.TRIPLE}
        argv,safe=C.cli_request('/synthetic/aws',L.RES,L.RES['prefix']+'a'*32+'.txt',env)
        for flag,value in [('--cli-error-format','legacy'),('--color','off')]:
            self.assertEqual(argv[argv.index(flag)+1],value)
        self.assertIn('--no-cli-auto-prompt',argv);self.assertNotIn('--profile',argv)
        self.assertEqual(safe['AWS_CLI_AUTO_PROMPT'],'off');self.assertEqual(safe['AWS_MAX_ATTEMPTS'],'1')
        self.assertEqual(safe['AWS_CONFIG_FILE'],'/dev/null')
        with mock.patch.object(A,'capture',return_value=complete(err=envelope())) as capture, \
             mock.patch.object(L,'REPORT',{'operations':[]}),mock.patch.object(L,'persist'), \
             mock.patch.object(L,'DEADLINE',time.monotonic()+60):
            A.Backend.__new__(A.Backend).assume_attempt(900,time.monotonic()+45)
        args=capture.call_args.args[0]
        self.assertEqual(args[args.index('--duration-seconds')+1],'900')
        self.assertEqual(args[args.index('--profile')+1],'default')
        self.assertEqual(args[args.index('--cli-error-format')+1],'legacy')

class ReturnCodeControls(unittest.TestCase):
    def test_only_pinned_clienterror_254_can_authorize_sts_retry_or_s3_absence(self):
        helper=ProtocolControls()
        for code in [-9,1,252,253,255]:
            for retry in [None,'0']:
                self.assertEqual(helper.assume(complete(code,err=envelope(retry=retry)))[0],'Unknown')
                self.assertEqual(C.cli_observation(code,envelope('GetObject','NoSuchKey',retry))['code'],'Unknown')
                self.assertEqual(C.cli_observation(code,envelope('GetObject','AccessDenied',retry))['code'],'Unknown')
        self.assertEqual(helper.assume(complete(254,err=envelope(retry='0')))[0],'Denied')
        self.assertEqual(C.cli_observation(254,envelope('GetObject','NoSuchKey','0'))['code'],'NoSuchKey')

class AdditionalControls(unittest.TestCase):
    def test_atomic_private_report_and_bound(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory(prefix='owned-aws416-report-') as directory:
            path=Path(directory)
            with mock.patch.object(L,'OUT',path),mock.patch.object(L,'REPORT',{'phase':'synthetic'}):
                L.persist();self.assertEqual(json.loads((path/'result.json').read_text()),{'phase':'synthetic'})
                self.assertEqual((path/'result.json').stat().st_mode&0o777,0o600)
                self.assertEqual([x.name for x in path.iterdir()],['result.json'])
            previous=(path/'result.json').read_bytes()
            with mock.patch.object(L,'OUT',path),mock.patch.object(L,'REPORT',{'synthetic':'x'*65536}):
                with self.assertRaisesRegex(RuntimeError,'SAFE_REPORT_BOUND'):L.persist()
            self.assertEqual((path/'result.json').read_bytes(),previous)

    def test_plan_local_maintained_transport_pins_cli_only_not_native_args(self):
        import types
        runner=types.SimpleNamespace(MAX_BYTES=16384,capture=mock.Mock(return_value=(0,b'',b'')))
        original=runner.capture
        loader=mock.Mock();loader.exec_module.return_value=None
        with mock.patch.object(A.importlib.util,'spec_from_file_location',return_value=types.SimpleNamespace(loader=loader)), \
             mock.patch.object(A.importlib.util,'module_from_spec',return_value=runner):
            backend=A.Backend()
        with mock.patch.object(A,'capture',return_value=complete(0)) as captured, \
             mock.patch.object(L,'persist'),mock.patch.object(L,'REPORT',{'operations':[]}):
            backend.runner.capture([L.CLI,'sts','get-caller-identity'],{},time.monotonic()+1)
            argv,env=captured.call_args.args[:2]
            self.assertIn('--no-cli-auto-prompt',argv);self.assertEqual(env['AWS_MAX_ATTEMPTS'],'1')
            backend.runner.capture(['/synthetic/native','read'],{},time.monotonic()+1)
            self.assertEqual(captured.call_args.args[0],['/synthetic/native','read'])
        original.assert_not_called()

if __name__=='__main__':unittest.main()
