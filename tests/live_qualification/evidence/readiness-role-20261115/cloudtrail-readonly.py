import json,os,subprocess,pathlib,datetime,time,hashlib
p=pathlib.Path('/tmp/aws416-readiness-plan-20261115-held-child');r=json.loads((p/'resources.json').read_text());o=pathlib.Path('/tmp/aws416-readiness-campaign-20261115/result.json');stamp=o.stat().st_mtime
start=datetime.datetime.fromtimestamp(stamp-180,datetime.timezone.utc).isoformat();end=datetime.datetime.now(datetime.timezone.utc).isoformat()
argv=['aws','--profile','default','--region',r['region'],'--no-cli-pager','--cli-connect-timeout','3','--cli-read-timeout','10','cloudtrail','lookup-events','--lookup-attributes','AttributeKey=EventName,AttributeValue=AssumeRole','--start-time',start,'--end-time',end,'--max-results','50','--no-paginate','--output','json']
x=subprocess.run(argv,env={**os.environ,'AWS_MAX_ATTEMPTS':'1','AWS_PAGER':'','AWS_EC2_METADATA_DISABLED':'true'},capture_output=True,text=True,timeout=20)
assert x.returncode==0,'READONLY_AUDIT_UNAVAILABLE';d=json.loads(x.stdout);safe=[];expected='arn:aws:sts::683569193847:assumed-role/'+r['role_name']+'/'+r['session_name']
for row in d.get('Events',[]):
 e=json.loads(row['CloudTrailEvent']);q=e.get('requestParameters') or {}
 if q.get('roleArn')!=r['role_arn'] or q.get('roleSessionName')!=r['session_name']:continue
 code=e.get('errorCode');allowed={'AccessDenied','AccessDeniedException','ValidationError','ExpiredToken','ExpiredTokenException','RegionDisabledException','InvalidClientTokenId','MalformedPolicyDocument','PackedPolicyTooLarge','IDPCommunicationError','IDPRejectedClaim','InternalFailure','ServiceFailure'};resp=e.get('responseElements') or {};u=e.get('userIdentity') or {}
 safe.append({'event_time':e.get('eventTime'),'event_name':e.get('eventName'),'region_match':e.get('awsRegion')==r['region'],'error_code':code if code in allowed else 'None' if code is None else 'Other','exact_principal_match':u.get('arn')=='arn:aws:iam::683569193847:user/dvrd','account_match':u.get('accountId')=='683569193847','expected_assumed_role_arn':(resp.get('assumedRoleUser') or {}).get('arn')==expected,'issued_credentials_field_present':'credentials' in resp})
result={'read_only':True,'lookup_calls':1,'max_results':50,'paginated':False,'has_next_token':bool(d.get('NextToken')),'start_utc':start,'end_utc':end,'matching_events':safe,'no_role_or_session_creation':True,'raw_events_or_credentials_persisted':False}
pathlib.Path('/tmp/aws416-readiness-cloudtrail-readonly-20261115.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
