"""Offline controls of frozen methods. All subprocess creation is mocked/refused."""
import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

FROZEN=Path('/tmp/aws416-readiness-plan-20261115-held-child')
OUT=Path('/tmp/aws416-readiness-offline-diagnosis-20261115')
sys.path.insert(0,str(FROZEN))
with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('REAL_SUBPROCESS_REFUSED')):
 A=importlib.import_module('live_adapter')
L=A.L;C=A.C
SECRET='SYNTHETIC_SECRET_ONLY_NOT_REAL'
TRIPLE=dict(AccessKeyId='SYNTHETIC_ACCESS_ONLY',SecretAccessKey=SECRET,
 SessionToken='SYNTHETIC_SESSION_ONLY',Expiration='2099-01-01T00:00:00Z')
EXPECTED=('arn:aws:sts::'+L.OLD['expected_account']+':assumed-role/'+
 L.RES['role_name']+'/'+L.RES['session_name'])
RESULTS=[]


def response(**changes):
 value=dict(AssumedRoleUser=dict(Arn=EXPECTED),Credentials=dict(TRIPLE))
 value.update(changes)
 return json.dumps(value).encode()


class ActualClassifier(unittest.TestCase):
 def run_case(self,name,reply,expected):
  backend=A.Backend.__new__(A.Backend)
  capture=mock.Mock(side_effect=reply) if isinstance(reply,BaseException) else mock.Mock(return_value=reply)
  with mock.patch.object(A,'capture',capture),mock.patch.object(L,'REPORT',{'operations':[]}), \
       mock.patch.object(L,'persist'),mock.patch.object(subprocess,'Popen',side_effect=AssertionError('REAL_SUBPROCESS_REFUSED')):
   outcome,env=backend.assume_attempt(900,A.time.monotonic()+45)
   self.assertEqual(outcome,expected)
   self.assertEqual(capture.call_count,1)
   safe=json.dumps(L.REPORT,sort_keys=True)
   self.assertNotIn(SECRET,safe)
   self.assertNotIn(TRIPLE['SessionToken'],safe)
   self.assertNotIn(TRIPLE['AccessKeyId'],safe)
   self.assertEqual(env is not None,expected=='Issued')
   row=L.REPORT['operations'][0]
   self.assertNotIn('returncode',row)
   RESULTS.append(dict(case=name,outcome=outcome,operation=row))
   return row

 def test_normal_success_is_issued(self):
  self.run_case('normal_success',(0,response(),b''),'Issued')
  self.run_case('whitespace_success',(0,b' \n'+response()+b'\n',b''),'Issued')

 def test_exact_denial_is_denied(self):
  self.run_case('exact_access_denied',(254,b'',
   b'An error occurred (AccessDenied) when calling the AssumeRole operation: synthetic'),'Denied')

 def test_distinct_cli_failures_collapse_to_identical_unknown(self):
  rows=[]
  for code in ['ExpiredToken','ValidationError','AccessDeniedException','InvalidClientTokenId']:
   rows.append(self.run_case('nonzero_'+code,(254,b'',(
    'An error occurred ('+code+') when calling the AssumeRole operation: synthetic').encode()),'Unknown'))
  rows.append(self.run_case('nonzero_empty',(255,b'',b''),'Unknown'))
  self.assertTrue(all(row==rows[0] for row in rows))

 def test_zero_exit_decode_or_validation_failures_are_same_unknown(self):
  cases=[('empty_stdout',b''),('invalid_json',b'not-json'),('wrong_top_level',b'[]'),
   ('missing_arn',response(AssumedRoleUser={})),
   ('mismatched_arn',response(AssumedRoleUser=dict(Arn=EXPECTED+'-different'))),
   ('missing_credentials',json.dumps(dict(AssumedRoleUser=dict(Arn=EXPECTED))).encode()),
   ('missing_token',response(Credentials={k:v for k,v in TRIPLE.items() if k!='SessionToken'})),
   ('wrong_secret_type',response(Credentials={**TRIPLE,'SecretAccessKey':42}))]
  rows=[self.run_case(name,(0,data,b''),'Unknown') for name,data in cases]
  self.assertTrue(all(row==rows[0] for row in rows))

 def test_capture_errors_are_same_unknown_and_claim_reap(self):
  for name,error in [('capture_timeout',TimeoutError(SECRET)),
   ('capture_permission',PermissionError(SECRET)),('capture_output_bound',C.Stop('CHILD_OUTPUT_LIMIT')),
   ('capture_deadline',C.Stop('CHILD_DEADLINE'))]:
   row=self.run_case(name,error,'Unknown')
   self.assertTrue(row['held_child_reaped'])

 def test_actual_capture_cleanup_permission_error_skips_wait_but_adapter_claims_reap(self):
  child=mock.Mock(pid=123456789,returncode=None)
  selector=mock.Mock()
  selector.get_map.return_value={'synthetic':True}
  selector.select.side_effect=C.Stop('CHILD_OUTPUT_LIMIT')
  backend=A.Backend.__new__(A.Backend)
  with mock.patch.object(A.subprocess,'Popen',return_value=child), \
       mock.patch.object(A.selectors,'DefaultSelector',return_value=selector), \
       mock.patch.object(A.os,'killpg',side_effect=PermissionError('synthetic')) as kill, \
       mock.patch.object(L,'REPORT',{'operations':[]}),mock.patch.object(L,'persist'):
   outcome,env=backend.assume_attempt(900,A.time.monotonic()+45)
   self.assertEqual((outcome,env),('Unknown',None))
   self.assertEqual(kill.call_count,1)
   child.wait.assert_not_called()
   self.assertTrue(L.REPORT['operations'][0]['held_child_reaped'])
   RESULTS.append(dict(case='actual_capture_cleanup_permission',outcome=outcome,
    operation=L.REPORT['operations'][0],actual_mock_wait_calls=child.wait.call_count,
    real_subprocess_or_signal=False))

 def test_controller_zero_count_is_not_evidence_of_no_issuance(self):
  backend=mock.Mock()
  backend.assume_attempt.return_value=('Unknown',None)
  report={'session_count':0}
  events=[]
  with self.assertRaises(C.Stop) as caught:
   C.assume_ready(backend,lambda:100.0,events.append,report)
  self.assertEqual(str(caught.exception),'STS_ISSUANCE_UNKNOWN')
  self.assertEqual(report,{'session_count':0,'issuance':'Unknown'})
  self.assertEqual(backend.assume_attempt.call_count,1)
  self.assertFalse(backend.pause.called)


if __name__=='__main__':
 before={name:hashlib.sha256((FROZEN/name).read_bytes()).hexdigest() for name in
  ['live_adapter.py','controller.py','lifecycle.py','SHA256SUMS.json']}
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(ActualClassifier)
 with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('REAL_SUBPROCESS_REFUSED')):
  result=unittest.TextTestRunner(verbosity=2).run(suite)
 after={name:hashlib.sha256((FROZEN/name).read_bytes()).hexdigest() for name in before}
 assert before==after
 receipt=dict(passed=result.wasSuccessful(),tests=result.testsRun,cases=RESULTS,
  frozen_before=before,frozen_after=after,real_subprocesses=False,real_signals=False,
  provider_or_native_execution=False,actual_live_issuance_remains='Unknown')
 (OUT/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
 raise SystemExit(0 if result.wasSuccessful() else 1)
