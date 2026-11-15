"""Actual installed retry metadata error format against the frozen adapter, offline."""
import argparse,io,json,re,subprocess,sys
from pathlib import Path
from unittest import mock
sys.path.insert(0,'/tmp/aws416-readiness-plan-20261115-held-child')
with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('REAL_SUBPROCESS_REFUSED')):
 import awscli
 from awscli.errorhandler import ClientErrorHandler
 from botocore.exceptions import ClientError
 import live_adapter as A
rows=[]
for fmt in [None,'enhanced','legacy']:
 for retries in [0,1]:
  for operation,code in [('AssumeRole','AccessDenied'),('GetRole','NoSuchEntity')]:
   error=ClientError({'Error':{'Code':code,'Message':'SYNTHETIC_OFFLINE_ERROR'},
    'ResponseMetadata':{'MaxAttemptsReached':True,'RetryAttempts':retries}},operation)
   stream=io.StringIO()
   rc=ClientErrorHandler(session=None).handle_exception(error,io.StringIO(),stream,
    parsed_globals=argparse.Namespace(cli_error_format=fmt,color='off'))
   data=stream.getvalue().encode()
   with mock.patch.object(A,'capture',return_value=(rc,b'',data)), \
        mock.patch.object(A.L,'REPORT',{'operations':[]}),mock.patch.object(A.L,'persist'), \
        mock.patch.object(subprocess,'Popen',side_effect=AssertionError('REAL_SUBPROCESS_REFUSED')):
    outcome,env=A.Backend.__new__(A.Backend).assume_attempt(900,A.time.monotonic()+45)
   assert outcome=='Unknown' and env is None
   match=re.search(rb'An error occurred \(([A-Za-z0-9]+)\)',data)
   assert match and match.group(1).decode()==code
   rows.append(dict(format='default_no_config' if fmt is None else fmt,
    synthetic_operation=operation,retry_metadata=retries,actual_frozen_adapter_outcome=outcome,
    lifecycle_general_code=match.group(1).decode(),synthetic_formatted_error=stream.getvalue()))
p=Path('/tmp/aws416-readiness-offline-diagnosis-20261115/retry-formatter-receipt.json')
p.write_text(json.dumps(dict(passed=True,installed_version=awscli.__version__,
 fixtures=rows,no_provider_cli_session_native_or_subprocess=True,
 live_cause_not_established=True,conclusion='Retry clause reproduces false Unknown for complete synthetic STS AccessDenied while IAM general code regex still matches; forcing legacy alone does not fix it.'),indent=2)+'\n')
print(json.dumps(dict(passed=True,fixtures=len(rows),complete_denial_false_unknown_reproduced=True,
                     forcing_legacy_alone_insufficient=True,live_cause_not_established=True)))
