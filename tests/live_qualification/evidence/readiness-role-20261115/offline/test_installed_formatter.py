"""Actual installed CLI formatter with synthetic ClientError; no client/session/API."""
import argparse,hashlib,io,json,os,re,subprocess,sys
from pathlib import Path
from unittest import mock

OUT=Path('/tmp/aws416-readiness-offline-diagnosis-20261115')
FROZEN=Path('/tmp/aws416-readiness-plan-20261115-held-child')
sys.path.insert(0,str(FROZEN))
with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('REAL_SUBPROCESS_REFUSED')):
 import awscli
 from awscli.errorhandler import ClientErrorHandler
 from botocore.exceptions import ClientError
 import live_adapter as A

records=[]
for fmt in [None,'enhanced','legacy','json']:
 for operation,code in [('AssumeRole','AccessDenied'),('GetRole','NoSuchEntity')]:
  error=ClientError({'Error':{'Code':code,'Message':'SYNTHETIC_OFFLINE_ERROR'}},operation)
  stream=io.StringIO()
  h=ClientErrorHandler(session=None)
  with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('REAL_SUBPROCESS_REFUSED')):
   rc=h.handle_exception(error,io.StringIO(),stream,
    parsed_globals=argparse.Namespace(cli_error_format=fmt,color='off'))
  data=stream.getvalue().encode()
  backend=A.Backend.__new__(A.Backend)
  with mock.patch.object(A,'capture',return_value=(rc,b'',data)), \
       mock.patch.object(A.L,'REPORT',{'operations':[]}),mock.patch.object(A.L,'persist'), \
       mock.patch.object(subprocess,'Popen',side_effect=AssertionError('REAL_SUBPROCESS_REFUSED')):
   result,env=backend.assume_attempt(900,A.time.monotonic()+45)
   assert env is None
  if operation=='AssumeRole':assert result==('Unknown' if fmt=='json' else 'Denied')
  iam_pattern=re.search(rb'An error occurred \(([A-Za-z0-9]+)\)',data)
  records.append(dict(error_format='default_no_session' if fmt is None else fmt,
   synthetic_operation=operation,synthetic_code=code,formatter_returncode=rc,
   synthetic_formatted_error=stream.getvalue(),actual_assume_adapter_outcome=result,
   lifecycle_legacy_code=iam_pattern.group(1).decode() if iam_pattern else None))
paths=[Path(awscli.__file__),Path(__import__('awscli.errorhandler',fromlist=['']).__file__),
 Path(__import__('awscli.clidriver',fromlist=['']).__file__),
 Path(__import__('botocore.exceptions',fromlist=['']).__file__)]
receipt=dict(passed=True,installed_version=awscli.__version__,
 no_cli_execution=True,no_session_created=True,no_network=True,
 no_user_aws_config_read=True,fixtures=records,
 source_sha256={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
 conclusion='Default/enhanced actual ClientError format retains legacy envelope and is accepted for synthetic AccessDenied; explicit JSON is rejected. Live format/cause remains unknown.')
(OUT/'formatter-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(dict(passed=True,installed_version=awscli.__version__,fixtures=len(records),
 default_enhanced_assume_denial_accepted=True,explicit_json_unknown=True)))
