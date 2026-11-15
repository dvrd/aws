"""Synthetic bounded readiness controls; no AWS processes or network calls."""
import copy,json,types,unittest
from pathlib import Path
from unittest import mock
import controller as C
import live_adapter as A
import lifecycle as L

ENV={k:'synthetic-'+k for k in C.TRIPLE}
ABSENT=dict(ok=True,object='Absent',read_status=404,read_error_code='NoSuchKey',
    put_effect='Not_Sent',delete_effect='Not_Sent',ses_effect='Not_Sent')

class Backend:
    def __init__(self):
        self.now=0;self.sts=[('Issued',ENV)];self.cli=['NoSuchKey'];self.calls=[];self.envs=[]
        self.native=ABSENT.copy();self.unknown_cleanup=False;self.elapsed=0
    def preflight(self):self.calls.append('preflight')
    def fresh_state(self):self.calls.append('fresh')
    def create_and_verify_owned_role(self):self.calls.append('create')
    def assume_attempt(self,seconds,deadline):
        self.calls.append('sts');self.now+=self.elapsed
        result=self.sts.pop(0)
        if isinstance(result,BaseException):raise result
        return result
    def pause(self,seconds):self.calls.append('pause');self.now+=seconds
    def guard_role(self,env,seconds):self.calls.append('guard');assert env==ENV and seconds==225
    def cli_read(self,env,deadline):
        self.calls.append('cli');self.envs.append(env);self.now+=self.elapsed
        code=self.cli.pop(0)
        if isinstance(code,BaseException):raise code
        return dict(code=code,status=None,deny_layer='Unknown' if code=='AccessDenied' else 'NotApplicable')
    def native_read(self,env,deadline):self.calls.append('native');self.envs.append(env);return self.native
    def maintained_campaign(self,env,seconds):
        self.calls.append('campaign');self.envs.append(env)
        return dict(qualified=True,phase='COMPLETE',s3_qualified=True)
    def verify_owned_cleanup(self):
        self.calls.append('cleanup')
        if self.unknown_cleanup:raise RuntimeError('secret')
        return dict(inline_policy_absent=True,role_absent=True)

class ReadinessControls(unittest.TestCase):
    def run_case(self,b):
        events=[];result=C.campaign(b,lambda:b.now,lambda e:events.append(copy.deepcopy(e)))
        self.assertNotIn('synthetic-AWS',json.dumps(events));return result,events
    def test_confirmed_denials_then_one_session_same_triple_ready(self):
        b=Backend();b.sts=[('Denied',None)]*5+[('Issued',ENV)];b.cli=['AccessDenied']*5+['NoSuchKey']
        r,e=self.run_case(b);self.assertTrue(r['passed']);self.assertEqual(r['session_count'],1)
        self.assertEqual(b.calls.count('sts'),6);self.assertEqual(b.calls.count('cli'),6)
        self.assertEqual(b.calls.count('native'),1);self.assertEqual(b.calls.count('campaign'),1)
        self.assertTrue(all(env is b.envs[0] for env in b.envs))
        self.assertEqual(len([x for x in e if x['phase']=='ASSUME_ROLE_INTENT']),6)
        self.assertEqual(len([x for x in e if x['phase']=='CLI_READ_INTENT']),6)
    def test_six_denials_no_seventh_or_s3(self):
        b=Backend();b.sts=[('Denied',None)]*6;r,e=self.run_case(b)
        self.assertEqual(r['issuance'],'NotIssued');self.assertEqual(b.calls.count('sts'),6)
        self.assertNotIn('cli',b.calls);self.assertEqual(b.calls[-1],'cleanup')
    def test_ambiguous_timeout_or_response_stops_without_retry(self):
        for failure in [TimeoutError('secret'),('Unknown',None),RuntimeError('secret')]:
            b=Backend();b.sts=[failure,('Issued',ENV)];r,e=self.run_case(b)
            self.assertEqual(r['issuance'],'Unknown');self.assertEqual(b.calls.count('sts'),1)
            self.assertEqual(r['error'],'STS_ISSUANCE_UNKNOWN');self.assertNotIn('cli',b.calls)
    def test_issued_session_never_renewed_after_cli_failure(self):
        for code in ['ExpiredToken','InvalidToken','Unknown','SlowDown','NoSuchBucket','ObjectPresent',TimeoutError('secret')]:
            b=Backend();b.cli=[code,'NoSuchKey'];r,e=self.run_case(b)
            self.assertFalse(r['passed']);self.assertEqual(b.calls.count('sts'),1)
            self.assertEqual(b.calls.count('cli'),1);self.assertNotIn('native',b.calls)
    def test_cli_six_denials_no_native_or_write(self):
        b=Backend();b.cli=['AccessDenied']*6;r,e=self.run_case(b)
        self.assertEqual(b.calls.count('cli'),6);self.assertEqual(r['session_count'],1)
        self.assertNotIn('native',b.calls);self.assertNotIn('campaign',b.calls)
    def test_sts_absolute_deadline_no_extra_attempt(self):
        b=Backend();b.sts=[('Denied',None)]*6;b.elapsed=20;r,e=self.run_case(b)
        self.assertLessEqual(b.calls.count('sts'),2);self.assertFalse(r['passed'])
    def test_late_issued_reply_records_issued_without_new_attempt(self):
        b=Backend();b.elapsed=45;r,e=self.run_case(b)
        self.assertEqual(r['session_count'],1);self.assertEqual(b.calls.count('sts'),1)
        self.assertNotIn('cli',b.calls);self.assertEqual(r['error'],'STS_READINESS_DEADLINE')
    def test_late_cli_absence_cannot_reach_native(self):
        b=Backend();b.cli_read=lambda env,deadline: (setattr(b,'now',100) or dict(code='NoSuchKey',status=None,deny_layer='NotApplicable'))
        r,e=self.run_case(b);self.assertFalse(r['passed']);self.assertNotIn('native',b.calls)
    def test_native_denial_once_never_retried_or_written(self):
        b=Backend();b.native.update(ok=False,object='Unverified',read_status=403,read_error_code='AccessDenied')
        r,e=self.run_case(b);self.assertEqual(b.calls.count('native'),1);self.assertNotIn('campaign',b.calls)
    def test_unknown_cleanup_cannot_pass(self):
        b=Backend();b.unknown_cleanup=True;r,e=self.run_case(b)
        self.assertFalse(r['passed']);self.assertTrue(r['cleanup_unknown'])
    def test_no_permission_expansion_and_new_exact_scope(self):
        r=json.loads(Path('resources.json').read_text());p=json.loads(Path('permissions.json').read_text())
        self.assertRegex(r['prefix'],r'^qualification/[0-9a-f]{32}/$')
        self.assertEqual(p['Statement'][0]['Action'],['s3:GetObject','s3:PutObject','s3:DeleteObject'])
        self.assertEqual(p['Statement'][0]['Resource'],'arn:aws:s3:::'+r['bucket']+'/'+r['prefix']+'*')
        self.assertEqual(p['Statement'][1]['Action'],'s3:ListBucket')
        self.assertEqual(r['approval_status'],'NOT_AUTHORIZED')

if __name__=='__main__':unittest.main()
