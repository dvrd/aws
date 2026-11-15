"""Prepared live adapter. Never run without a separately approved exact plan."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import selectors
import signal
import subprocess
import time
import types
from unittest import mock
import controller as C
import lifecycle as L


def capture(argv, env, deadline, limit=16384):
    child = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    selector=selectors.DefaultSelector(); buffers=[bytearray(),bytearray()]
    try:
        for index,stream in enumerate((child.stdout,child.stderr)):
            selector.register(stream,selectors.EVENT_READ,index)
        while selector.get_map():
            if time.monotonic() >= deadline: raise C.Stop('CHILD_DEADLINE')
            for key,_ in selector.select(min(0.2,max(0,deadline-time.monotonic()))):
                data=os.read(key.fd,4096)
                if not data: selector.unregister(key.fileobj);continue
                buffers[key.data].extend(data)
                if sum(map(len,buffers))>limit:raise C.Stop('CHILD_OUTPUT_LIMIT')
        code=child.wait(timeout=max(.01,deadline-time.monotonic()))
        if time.monotonic()>=deadline:raise C.Stop('CHILD_DEADLINE')
        return code,bytes(buffers[0]),bytes(buffers[1])
    finally:
        selector.close()
        try:
            # This capture alone owns wait/reap. A known returncode means the PID
            # was released already; never signal a potentially reused group.
            if child.returncode is None:
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                child.wait(timeout=5)
        finally:
            child.stdout.close();child.stderr.close()


class Backend:
    def __init__(self):
        self.start=time.monotonic();L.DEADLINE=self.start+360;L.CAPTURE=capture
        spec=importlib.util.spec_from_file_location('qualification_runner',L.ROOT/'aws/tests/live_qualification/run.py')
        self.runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.runner)
        original_capture=self.runner.capture
        def single_attempt(argv,env,deadline,limit=self.runner.MAX_BYTES):
            return original_capture(argv,{**env,'AWS_MAX_ATTEMPTS':'1'},min(deadline,L.DEADLINE),limit)
        self.runner.capture=single_attempt
        self.env=None
    def preflight(self):L.preflight()
    def fresh_state(self):
        if any((L.OUT/name).exists() for name in ['ownership.json','state','readiness.jsonl']):
            raise C.Stop('EXISTING_CAMPAIGN_REFUSED')
        resource=dict(schema=1,phase='READY',bucket=L.RES['bucket'],prefix=L.RES['prefix'],
            region=L.RES['region'],expected_account=L.OLD['expected_account'],
            credential_source='environment',expected_role_arn=L.RES['role_arn'],
            public_access_block_verified=True,encryption='AES256')
        path=L.OUT/'resource-plan.json';path.write_text(json.dumps(resource));path.chmod(0o600)
        self.args=types.SimpleNamespace(resource_plan=path,binary=Path(L.RES['binary']),
            state_dir=L.OUT/'state',command='run',live=True,allow_write=True,aws_cli=Path(L.CLI),
            ses_sender='',ses_identity_verified=False)
        self.runner.plan(self.args)
    def create_and_verify_owned_role(self):
        owner=dict(role_name=L.RES['role_name'],role_arn=L.RES['role_arn'],tag_key=L.TAG_KEY,
            tag_value=L.TAG_VALUE,inline_policy_name=L.POLICY_NAME)
        p=L.OUT/'ownership.json';p.write_text(json.dumps(owner));p.chmod(0o600)
        created=L.call('iam','create-role','--role-name',L.RES['role_name'],
            '--assume-role-policy-document','file://'+str(L.PLAN/'trust.json'),
            '--tags','Key='+L.TAG_KEY+',Value='+L.TAG_VALUE)
        L.ROLE_ID=created['Role']['RoleId'];owner['role_id']=L.ROLE_ID
        p.write_text(json.dumps(owner));p.chmod(0o600)
        L.require(L.owned_role() is not None,'OWNERSHIP_REQUIRED')
        L.call('iam','put-role-policy','--role-name',L.RES['role_name'],
            '--policy-name',L.POLICY_NAME,'--policy-document','file://'+str(L.PLAN/'permissions.json'))
        policy=L.call('iam','get-role-policy','--role-name',L.RES['role_name'],'--policy-name',L.POLICY_NAME)
        L.require(policy['PolicyDocument']==L.POLICY,'POLICY_MISMATCH')
    def pause(self, seconds):
        time.sleep(seconds)
    def assume_attempt(self, seconds, deadline):
        argv=[L.CLI,'sts','assume-role','--role-arn',L.RES['role_arn'],
            '--role-session-name',L.RES['session_name'],'--duration-seconds',str(seconds),
            '--profile',L.OLD['profile'],'--region',L.RES['region'],'--output','json',
            '--no-cli-pager','--cli-connect-timeout','5','--cli-read-timeout','10']
        L.REPORT.setdefault('operation_intents',[]).append(dict(service='sts',operation='assume-role'))
        L.persist()
        try:
            code,data,error=capture(argv,L.BASE,min(deadline,L.DEADLINE,time.monotonic()+20))
        except BaseException:
            L.REPORT['operations'].append(dict(service='sts',operation='assume-role',
                outcome='Unknown',held_child_reaped=True));L.persist()
            return 'Unknown',None
        outcome='Unknown';env=None
        # Only a complete official error envelope confirms a denied issuance attempt.
        denied=re.findall(rb'An error occurred \((AccessDenied)\) when calling the AssumeRole operation:',error)
        if code != 0 and len(denied)==1:
            outcome='Denied'
        elif code==0:
            try:
                response=json.loads(data)
                expected='arn:aws:sts::'+L.OLD['expected_account']+':assumed-role/'+L.RES['role_name']+'/'+L.RES['session_name']
                L.require(response['AssumedRoleUser']['Arn']==expected,'SESSION_MISMATCH')
                creds=response['Credentials']
                L.require(all(isinstance(creds.get(k),str) and creds[k] for k in
                    ['AccessKeyId','SecretAccessKey','SessionToken','Expiration']),'INCOMPLETE_SESSION')
                env={k:L.BASE[k] for k in ['PATH','LANG','LC_ALL','TMPDIR'] if k in L.BASE}
                env.update(AWS_ACCESS_KEY_ID=creds['AccessKeyId'],AWS_SECRET_ACCESS_KEY=creds['SecretAccessKey'],
                    AWS_SESSION_TOKEN=creds['SessionToken'],AWS_CREDENTIAL_EXPIRATION=creds['Expiration'])
                response.clear();outcome='Issued'
            except Exception:
                outcome,env='Unknown',None
        L.REPORT['operations'].append(dict(service='sts',operation='assume-role',
            outcome=outcome,held_child_reaped=True));L.persist()
        return outcome,env
    def guard_role(self,env,seconds):
        L.require(L.DEADLINE-time.monotonic()>seconds,'CONTROLLER_BUDGET')
        expiry=datetime.datetime.fromisoformat(env['AWS_CREDENTIAL_EXPIRATION'].replace('Z','+00:00'))
        L.require(expiry.tzinfo is not None and expiry.timestamp()>time.time()+seconds,'EXPIRY_GUARD')
        with mock.patch.dict(os.environ,env,clear=True):
            scope=self.runner.read(self.args.state_dir/'scope.json')
            state=self.runner.read(self.args.state_dir/'state.json')
            scope=self.runner.bound_credential_scope(self.args,state,scope)
            self.env=self.runner.credentials(self.args,scope,time.monotonic()+30)
        L.require(all(self.env[k]==env[k] for k in C.TRIPLE),'TRIPLE_MISMATCH')
        L.REPORT['credential_attestation']=self.env.attestation;L.persist()
    def cli_read(self,env,deadline):
        state=self.runner.read(self.args.state_dir/'state.json')
        self.key=L.RES['prefix']+state['run_id']+'.txt'
        argv,cli_env=C.cli_request(L.CLI,L.RES,self.key,env)
        code,_,stderr=capture(argv,cli_env,min(deadline,L.DEADLINE,time.monotonic()+20))
        return C.cli_observation(code,stderr)
    def native_read(self,env,deadline):
        L.require(all(self.env[k]==env[k] for k in C.TRIPLE),'TRIPLE_MISMATCH')
        state=self.runner.read(self.args.state_dir/'state.json')
        L.require(state['phase']=='PREPARED','READINESS_STATE_CHANGED')
        # Read-only native invocation; separate durable readiness intent is already saved.
        return self.runner.native(self.args,state,'read',self.env,deadline)
    def maintained_campaign(self,env,seconds):
        L.require(all(self.env[k]==env[k] for k in C.TRIPLE),'TRIPLE_MISMATCH')
        # Re-run maintained identity/expiry guard on same literal triple, no new session.
        with mock.patch.dict(os.environ,env,clear=True):result=self.runner.run(self.args)
        L.REPORT['campaign']=result;L.persist()
        return {k:result[k] for k in ['qualified','phase','s3_qualified']}
    def verify_owned_cleanup(self):
        L.DEADLINE=time.monotonic()+120
        result=L.cleanup();L.REPORT['cleanup']=result;L.persist()
        return {k:result.get(k,False) for k in ['inline_policy_absent','role_absent']}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--execute-approved-plan-sha256',required=True)
    args=parser.parse_args()
    digest=hashlib.sha256((L.PLAN/'SHA256SUMS.json').read_bytes()).hexdigest()
    L.require(args.execute_approved_plan_sha256==digest,'REVIEW_DIGEST_MISMATCH')
    # This guard is deliberately NOT an approval. Only an explicit new user approval
    # relayed by root authorizes invoking this command.
    L.OUT.mkdir(mode=0o700,exist_ok=False)
    def save(event):
        with open(L.OUT/'readiness.jsonl','a',encoding='utf8') as stream:
            os.chmod(stream.name,0o600);stream.write(json.dumps(event)+'\n')
            stream.flush();os.fsync(stream.fileno())
    result=C.campaign(Backend(),time.monotonic,save)
    L.REPORT['controller']=result;L.REPORT['passed']=result['passed'];L.persist()
    print(json.dumps(result))
    raise SystemExit(0 if result['passed'] else 1)

if __name__=='__main__':main()
