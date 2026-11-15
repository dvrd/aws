"""Execute only the approved isolated role plan; credentials stay in memory."""
import datetime,hashlib,importlib.util,json,os,re,secrets,shutil,signal,subprocess,sys,time
from pathlib import Path
from unittest import mock
ROOT=Path('/Users/kakurega/dev/oss/Odin/shared')
PLAN=Path(__file__).resolve().parent
OUT=Path('/tmp/aws416-readiness-campaign-20261115')
RES=json.loads((PLAN/'resources.json').read_text())
TRUST=json.loads((PLAN/'trust.json').read_text())
POLICY=json.loads((PLAN/'permissions.json').read_text())
OLD=json.loads((PLAN/'operator-metadata.json').read_text())
CLI=shutil.which('aws')
BASE={k:os.environ[k] for k in ['PATH','HOME','USER','LOGNAME','LANG','LC_ALL','TMPDIR'] if k in os.environ}
BASE.update(AWS_MAX_ATTEMPTS='1',AWS_EC2_METADATA_DISABLED='true',AWS_PAGER='')
TAG_KEY='WebtoolsQualification'
TAG_VALUE=RES['ownership_tag']
POLICY_NAME='webtools-qualification-s3'
REPORT=dict(passed=False,operations=[],provider_scope='approved isolated S3 temporary role only',
            ses_sends=False,expiry_experiment=False,keys_persisted=False)
ROLE_ID=None

def require(value,reason):
    if not value:raise RuntimeError(reason)

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def persist():
    p=OUT/'result.json';p.write_text(json.dumps(REPORT,indent=2)+'\n');p.chmod(0o600)

def call(service,operation,*arguments,absent=False):
    argv=[CLI,service,operation,*map(str,arguments),'--profile',OLD['profile'],
          '--region',RES['region'],'--output','json','--no-cli-pager',
          '--cli-connect-timeout','5','--cli-read-timeout','10']
    if operation in {'create-role','put-role-policy','assume-role','delete-role-policy','delete-role'}:
        REPORT.setdefault('operation_intents',[]).append(dict(service=service,operation=operation))
        persist()
    code,stdout,stderr=CAPTURE(argv,BASE,min(DEADLINE,time.monotonic()+30))
    error=None
    if code:
        match=re.search(rb'An error occurred \(([A-Za-z0-9]+)\)',stderr)
        error=match.group(1).decode() if match else 'CLI_FAILURE'
        if error not in {'NoSuchEntity','AccessDenied','EntityAlreadyExists','LimitExceeded',
                         'MalformedPolicyDocument','InvalidInput','DeleteConflict'}:error='CLI_FAILURE'
    REPORT['operations'].append(dict(service=service,operation=operation,
        returncode=code,error_code=error,held_child_reaped=True));persist()
    if code:
        if absent and error=='NoSuchEntity':return None
        raise RuntimeError('ADMIN_OPERATION_FAILED')
    return json.loads(stdout) if stdout.strip() else {}

CAPTURE=None
DEADLINE=0

def verify_sources():
    require(CLI is not None,'CLI_REQUIRED')
    require(RES['prefix']=='qualification/2b363ab30ac7ad929bd6f8af342c20d8/','APPROVED_PREFIX_CHANGED')
    require(RES['duration_seconds']==900,'APPROVED_DURATION_CHANGED')
    require((RES['assume_attempt_limit'],RES['assume_readiness_seconds'],
        RES['cli_get_attempt_limit'],RES['readiness_seconds'],RES['retry_delay_seconds'])==
        (6,45,6,45,5),'APPROVED_READINESS_BOUNDS_CHANGED')
    account=OLD['expected_account'];principal=TRUST['Statement'][0]['Principal']['AWS']
    require(RES['role_arn']=='arn:aws:iam::'+account+':role/'+RES['role_name'],'ROLE_SCOPE_CHANGED')
    require(RES['bucket']==OLD['bucket'] and RES['region']==OLD['region'],'RESOURCE_CHANGED')
    require(POLICY['Statement'][0]['Resource']=='arn:aws:s3:::'+RES['bucket']+'/'+RES['prefix']+'*','POLICY_PREFIX')
    require(TRUST['Statement'][0]['Condition']['StringEquals']['sts:RoleSessionName']==RES['session_name'],'TRUST_SESSION')
    approved=json.loads((PLAN/'SHA256SUMS.json').read_text())
    require(all(sha(PLAN/n)==h for n,h in approved.items()),'APPROVED_INPUT_CHANGED')
    prior=json.loads((PLAN/'source-pins.json').read_text())
    binary=Path(RES['binary']);require(sha(binary)==RES['binary_sha256'],'BINARY_CHANGED')
    diagnostic=json.loads((PLAN/'diagnostic-source-pins.json').read_text())
    require(all(sha(ROOT/'aws'/n)==h for n,h in diagnostic['source_sha256'].items()),
            'DIAGNOSTIC_SOURCE_CHANGED')
    for name,h in prior['owner_source_before'].items():
        if name.endswith('.odin') and not name.startswith('aws/tests/live_qualification/'):
            require(sha(ROOT/name)==h,'NATIVE_SOURCE_CHANGED:'+name)
    for name,row in prior['standard_source_before'].items():
        path=ROOT.parent/name
        require(sha(path)==row['sha256'] and path.stat().st_size==row['bytes'],'SDK_SOURCE_CHANGED')
    require(sha(ROOT.parent/'odin')==prior['compiler_before'],'COMPILER_CHANGED')
    require(subprocess.check_output(['git','-C',str(ROOT/'aws'),'rev-parse','HEAD'],text=True).strip()==
            RES['owner_commit'],'RUNNER_SOURCE_CHANGED')
    require(not subprocess.check_output(['git','-C',str(ROOT/'aws'),'status','--porcelain'],text=True),'OWNER_DIRTY')
    REPORT['provenance']=dict(binary_sha256=sha(binary),compiler_sha256=prior['compiler_before'],
        native_owner_odin_files=sum(n.endswith('.odin') and not n.startswith(
            'aws/tests/live_qualification/') for n in prior['owner_source_before']),
        diagnostic_source_files=len(diagnostic['source_sha256']),owner_commit=RES['owner_commit'],
        standard_source_files=len(prior['standard_source_before']),runner_sha256=sha(ROOT/'aws/tests/live_qualification/run.py'),
        approved_files_sha256={n:sha(PLAN/n) for n in ['PLAN.md','trust.json','permissions.json','resources.json']})
    return account,principal

def preflight():
    account,principal=verify_sources()
    identity=call('sts','get-caller-identity')
    require(identity.get('Account')==account and identity.get('Arn')==principal,'ADMIN_IDENTITY_MISMATCH')
    require(call('iam','get-role','--role-name',RES['role_name'],absent=True) is None,'PREEXISTING_ROLE_REFUSED')
    REPORT['preflight']=dict(account_match=True,principal_exact_match=True,role_confirmed_absent=True,
        principal_sha256=hashlib.sha256(principal.encode()).hexdigest())
    persist()

def owned_role():
    reply=call('iam','get-role','--role-name',RES['role_name'],absent=True)
    if reply is None:return None
    role=reply['Role'];tags={t['Key']:t['Value'] for t in role.get('Tags',[])}
    require(role['Arn']==RES['role_arn'] and role['RoleName']==RES['role_name'],'ROLE_IDENTITY_CHANGED')
    require(tags.get(TAG_KEY)==TAG_VALUE,'ROLE_OWNERSHIP_NOT_VERIFIED')
    if ROLE_ID is not None:require(role['RoleId']==ROLE_ID,'ROLE_ID_CHANGED')
    require(role['AssumeRolePolicyDocument']==TRUST,'TRUST_DOCUMENT_CHANGED')
    return role

def cleanup():
    role=owned_role()
    if role is None:return dict(role_absent=True,role_deleted=False)
    policy=call('iam','get-role-policy','--role-name',RES['role_name'],
                '--policy-name',POLICY_NAME,absent=True)
    if policy is not None:
        require(policy['PolicyDocument']==POLICY,'INLINE_POLICY_CHANGED')
        call('iam','delete-role-policy','--role-name',RES['role_name'],'--policy-name',POLICY_NAME)
        require(call('iam','get-role-policy','--role-name',RES['role_name'],
            '--policy-name',POLICY_NAME,absent=True) is None,'POLICY_DELETE_UNCONFIRMED')
    require(owned_role() is not None,'ROLE_ABSENT_BEFORE_DELETE')
    call('iam','delete-role','--role-name',RES['role_name'])
    require(call('iam','get-role','--role-name',RES['role_name'],absent=True) is None,'ROLE_DELETE_UNCONFIRMED')
    return dict(ownership_verified=True,inline_policy_absent=True,role_absent=True,role_deleted=True)

