"""Pure installed CLI model/parser/formatter controls; no CLI/client/provider execution."""
import argparse,datetime,hashlib,io,json,subprocess,time,unittest
from pathlib import Path
from unittest import mock
import awscli
from awscli.argparser import MainArgParser
from awscli.clidriver import CLIDriver
from awscli.errorhandler import ClientErrorHandler
from awscli.formatter import get_formatter
from botocore.exceptions import ClientError
import controller as C
import live_adapter as A
import lifecycle as L
from test_protocol import complete

SITE=Path(awscli.__file__).parent
RECORDS=[]

class InstalledCLIControls(unittest.TestCase):
    def test_actual_retry_formatter_all_target_operations(self):
        for fmt in [None,'legacy','enhanced']:
            for retries in [None,0,1]:
                for op,code in [('AssumeRole','AccessDenied'),('GetObject','AccessDenied'),
                                ('GetObject','NoSuchKey'),('GetRole','NoSuchEntity')]:
                    payload={'Error':{'Code':code,'Message':'SYNTHETIC_OFFLINE_ONLY'}}
                    if retries is not None:
                        payload['ResponseMetadata']={'MaxAttemptsReached':True,'RetryAttempts':retries}
                    stream=io.StringIO()
                    rc=ClientErrorHandler(session=None).handle_exception(ClientError(payload,op),
                        io.StringIO(),stream,parsed_globals=argparse.Namespace(cli_error_format=fmt,color='off'))
                    stderr=stream.getvalue().encode()
                    if op=='AssumeRole':
                        with mock.patch.object(A,'capture',return_value=complete(rc,err=stderr)), \
                             mock.patch.object(L,'REPORT',{'operations':[]}),mock.patch.object(L,'persist'), \
                             mock.patch.object(L,'DEADLINE',time.monotonic()+60):
                            status,env=A.Backend.__new__(A.Backend).assume_attempt(900,time.monotonic()+45)
                        self.assertEqual(status,'Unknown' if retries==1 else 'Denied')
                    elif op=='GetObject':
                        status=C.cli_observation(rc,stderr)['code']
                        self.assertEqual(status,'Unknown' if retries==1 else code)
                    else:
                        with mock.patch.object(L,'CAPTURE',return_value=complete(rc,err=stderr)), \
                             mock.patch.object(L,'REPORT',{'operations':[]}),mock.patch.object(L,'persist'), \
                             mock.patch.object(L,'DEADLINE',time.monotonic()+60):
                            self.assertIsNone(L.call('iam','get-role',absent=True))
                        status='Absent'
                    RECORDS.append(dict(format='default' if fmt is None else fmt,operation=op,
                     code=code,retry_info='Absent' if retries is None else 'Zero' if retries==0 else 'Unexpected',
                     result=status))

    def test_actual_global_argument_parser_accepts_all_prepared_requests(self):
        options=json.loads((SITE/'data/cli.json').read_text())['options']
        table={name:CLIDriver._create_cli_argument(None,name,value) for name,value in options.items()}
        parser=MainArgParser({'sts':None,'iam':None,'s3api':None},'offline','offline',table)
        args=[]
        def capture(argv,*rest):args.append(argv);return complete(0,b'{}')
        with mock.patch.object(A,'capture',side_effect=capture),mock.patch.object(L,'persist'), \
             mock.patch.object(L,'REPORT',{'operations':[]}),mock.patch.object(L,'DEADLINE',time.monotonic()+60):
            A.Backend.__new__(A.Backend).assume_attempt(900,time.monotonic()+45)
        with mock.patch.object(L,'CAPTURE',side_effect=capture),mock.patch.object(L,'persist'), \
             mock.patch.object(L,'REPORT',{'operations':[]}),mock.patch.object(L,'DEADLINE',time.monotonic()+60):
            L.call('iam','get-role','--role-name','synthetic')
        argv,env=C.cli_request(L.CLI,L.RES,L.RES['prefix']+'a'*32+'.txt',
                              {key:'synthetic' for key in C.TRIPLE})
        args.append(argv)
        for argv in args:
            parsed,rest=parser.parse_known_args(argv[1:])
            self.assertEqual(parsed.cli_error_format,'legacy');self.assertEqual(parsed.color,'off')
            self.assertTrue(parsed.no_cli_auto_prompt)
            self.assertFalse(parsed.cli_auto_prompt)
        self.assertEqual(len(args),3)

    def test_actual_sts_output_shape_and_json_datetime_schema(self):
        model=SITE/'botocore/data/sts/2011-06-15/service-2.json'
        model=json.loads(model.read_text());shape=model['shapes'][model['operations']['AssumeRole']['output']['shape']]
        credentials=model['shapes'][shape['members']['Credentials']['shape']]
        for name in ['AccessKeyId','SecretAccessKey','SessionToken','Expiration']:
            self.assertIn(name,credentials['members'])
        arn='arn:aws:sts::'+L.OLD['expected_account']+':assumed-role/'+L.RES['role_name']+'/'+L.RES['session_name']
        payload=dict(AssumedRoleUser=dict(Arn=arn,AssumedRoleId='SYNTHETIC'),
            Credentials=dict(AccessKeyId='synthetic-key',SecretAccessKey='synthetic-secret',
                SessionToken='synthetic-token',Expiration=datetime.datetime(2099,1,1,tzinfo=datetime.timezone.utc)))
        stream=io.StringIO();get_formatter('json',argparse.Namespace(query=None,color='off'))('AssumeRole',payload,stream)
        with mock.patch.object(A,'capture',return_value=complete(0,stream.getvalue().encode())), \
             mock.patch.object(L,'REPORT',{'operations':[]}),mock.patch.object(L,'persist'), \
             mock.patch.object(L,'DEADLINE',time.monotonic()+60):
            outcome,env=A.Backend.__new__(A.Backend).assume_attempt(900,time.monotonic()+45)
            self.assertEqual(outcome,'Issued');self.assertIsInstance(env['AWS_CREDENTIAL_EXPIRATION'],str)
            self.assertNotIn('synthetic-',json.dumps(L.REPORT))

if __name__=='__main__':
    with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('CLI_OR_NATIVE_EXECUTION_REFUSED')):
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(InstalledCLIControls))
    paths=[SITE/'__init__.py',SITE/'argparser.py',SITE/'clidriver.py',SITE/'errorhandler.py',
     SITE/'data/cli.json',SITE/'botocore/exceptions.py',SITE/'botocore/data/sts/2011-06-15/service-2.json']
    Path('installed-cli-receipt.json').write_text(json.dumps(dict(passed=result.wasSuccessful(),
     version=awscli.__version__,tests=result.testsRun,formatted_fixtures=RECORDS,
     source_sha256={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
     no_cli_client_provider_session_native_calls=True),indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
