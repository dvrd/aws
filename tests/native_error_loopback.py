#!/usr/bin/env python3
"""Public S3 default native TLS error boundary; owned loopback and public fixtures only."""
import argparse,hashlib,json,os,selectors,shutil,signal,socket,ssl,subprocess,tempfile,threading,time
from pathlib import Path

OWNER=Path(__file__).resolve().parents[1]
PACKAGES=('aws','surf','http','websocket','async')
MARKER=b'private-native-loopback-marker'
KEY='public-fixture-key'
TOKEN='public-fixture-session'
ERROR_CODES={400:'ExpiredToken',403:'AccessDenied',503:'SlowDown',429:'SyntheticHTTP429'}
ERROR_SOURCE='https://docs.aws.amazon.com/AmazonS3/latest/API/API_Error.html'

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def snapshot(roots):
    result={}
    for root in roots:
        for path in sorted(root.rglob('*')):
            if path.is_file() and '.git' not in path.parts and '__pycache__' not in path.parts:
                result[str(path)]=digest(path)
    return result

def capture(argv,environment,deadline,limit):
    # Fixture-only bounded owner. Retain compiler/sanitizer stderr as well as stdout.
    child=None;selector=None;data=bytearray();failure=None;cleanup=[];code=None
    try:
        selector=selectors.DefaultSelector()
        child=subprocess.Popen(argv,env=environment,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
        selector.register(child.stdout,selectors.EVENT_READ)
        while selector.get_map():
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('owned child deadline')
            for key,_ in selector.select(min(remaining,.1)):
                chunk=os.read(key.fd,4096)
                if not chunk:selector.unregister(key.fileobj);continue
                if len(data)+len(chunk)>limit:raise AssertionError('owned output bound')
                data.extend(chunk)
        code=child.wait(timeout=max(.01,deadline-time.monotonic()))
    except BaseException as error:failure=error
    finally:
        if child is not None and child.returncode is None:
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            except BaseException as error:cleanup.append(type(error).__name__)
            try:child.wait(timeout=5)
            except BaseException as error:cleanup.append(type(error).__name__)
        for resource in (selector,child.stdout if child is not None else None):
            if resource is None:continue
            try:resource.close()
            except BaseException as error:cleanup.append(type(error).__name__)
    if failure is not None:raise failure
    assert not cleanup,'owned cleanup failed: '+','.join(cleanup)
    return code,bytes(data)

def peer(listener,context,method,status,observed):
    try:
        raw,_=listener.accept();observed['connections']+=1
        with raw:
            raw.settimeout(3)
            try:
                with context.wrap_socket(raw,server_side=True) as stream:
                    data=bytearray()
                    while b'\r\n\r\n' not in data:
                        part=stream.recv(4096)
                        if not part:raise AssertionError('incomplete request')
                        data.extend(part);assert len(data)<=16384
                    head,body=bytes(data).split(b'\r\n\r\n',1)
                    lines=head.split(b'\r\n');assert lines[0]==(method+' /fixturebucket/qualification/owned.txt HTTP/1.1').encode()
                    headers={}
                    for line in lines[1:]:
                        name,value=line.split(b':',1);name=name.lower();assert name not in headers;headers[name]=value.strip()
                    length=int(headers.get(b'content-length',b'0'));assert 0<=length<=1024
                    while len(body)<length:
                        part=stream.recv(length-len(body))
                        if not part:raise AssertionError('incomplete body')
                        body+=part
                    assert body==(b'public-fixture-body' if method=='PUT' else b'')
                    assert headers[b'x-amz-security-token']==TOKEN.encode()
                    authorization=headers[b'authorization']
                    assert authorization.startswith(('AWS4-HMAC-SHA256 Credential='+KEY+'/').encode())
                    assert b'x-amz-security-token' in authorization
                    observed['requests']+=1;observed['signed_session_request']=True
                    code=ERROR_CODES.get(status,'None')
                    observed['response_error_code']=code
                    response=b'' if status in (200,204) else b'<Error><Code>'+code.encode()+b'</Code><Message>'+MARKER+b'</Message></Error>'
                    stream.sendall(('HTTP/1.1 '+str(status)+' Owned\r\nContent-Length: '+str(len(response))+'\r\nConnection: close\r\n\r\n').encode()+response)
            except ssl.SSLError:
                observed['tls_rejected']=True
    except BaseException as error:observed['failure']=type(error).__name__

def run_case(binary,ca,context,method,status,capture,environment,trust=False,wrong_status=False):
    observed=dict(connections=0,requests=0,signed_session_request=False,tls_rejected=False,
                  response_error_code='NotSent')
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));listener.listen(4);listener.settimeout(3)
        thread=threading.Thread(target=peer,args=(listener,context,method,status,observed));thread.start()
        expected=403 if wrong_status else 0 if trust else status
        argv=[str(binary),'https://127.0.0.1:'+str(listener.getsockname()[1]),str(ca),method,str(expected),'trust-failure' if trust else 'response']
        try:code,data=capture(argv,environment,time.monotonic()+22,65536)
        finally:thread.join(timeout=4)
        assert not thread.is_alive(),'owned peer did not retire'
        listener.settimeout(.15)
        try:
            extra,_=listener.accept();extra.close();raise AssertionError('native request retried')
        except socket.timeout:pass
    assert not observed.get('failure'),observed
    assert MARKER not in data and KEY.encode() not in data and TOKEN.encode() not in data
    # The native child emits a fixed numeric/bool observation only; no response body.
    result=json.loads(data);assert set(result)=={'passed','ok','transport_ok','status'}
    assert code==(1 if wrong_status else 0),result
    assert result['passed'] is (not wrong_status)
    assert observed['connections']==1
    assert observed['requests']==(0 if trust else 1)
    assert observed['tls_rejected'] is trust
    assert observed['response_error_code']==('NotSent' if trust else ERROR_CODES.get(status,'None'))
    return dict(method=method,response_status=status,trust_negative=trust,wrong_status_negative=wrong_status,native_exit=code,observation=result,**observed)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--odin',type=Path,required=True);parser.add_argument('--shared-root',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True);args=parser.parse_args()
    shared=args.shared_root.resolve();sources=[OWNER,*[shared/n for n in PACKAGES if n!='aws']]
    before=snapshot(sources)
    environment={k:os.environ[k] for k in ('PATH','TMPDIR','LANG','LC_ALL')if k in os.environ}
    environment.update(AWS_EC2_METADATA_DISABLED='true',AWS_CONFIG_FILE='/dev/null',AWS_SHARED_CREDENTIALS_FILE='/dev/null')
    with tempfile.TemporaryDirectory(prefix='aws-native-error-loopback-') as temporary:
        directory=Path(temporary);collection=directory/'shared';collection.mkdir()
        for name,source in zip(PACKAGES,sources):
            shutil.copytree(source,collection/name,ignore=shutil.ignore_patterns('.git','__pycache__','evidence'))
        binary=directory/'native-errors';command=[str(args.odin),'build',str(OWNER/'tests/testdata/native_error_loopback'),'-collection:shared='+str(collection),'-thread-count:1','-vet','-warnings-as-errors','-sanitize:address','-out:'+str(binary)]
        code,output=capture(command,environment,time.monotonic()+180,1<<20)
        assert code==0,output.decode(errors='replace')[:4000]
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(OWNER/'tests/testdata/tls/localhost.pem',OWNER/'tests/testdata/tls/rsa2048.pem')
        ca=OWNER/'tests/testdata/tls/localhost.pem';wrong=OWNER/'tests/testdata/tls/root.pem'
        cases=[]
        for method in ('PUT','DELETE'):
            for status in (400,403,503,429,200 if method=='PUT' else 204):
                cases.append(run_case(binary,ca,context,method,status,capture,environment))
            cases.append(run_case(binary,wrong,context,method,403,capture,environment,trust=True))
        cases.append(run_case(binary,ca,context,'PUT',200,capture,environment,wrong_status=True))
        binary_sha=digest(binary)
    assert before==snapshot(sources),'source changed'
    report=dict(passed=True,owned_loopback_only=True,provider_calls=False,credentials='public synthetic strings only',source_unchanged=True,compiler_sha256=digest(args.odin),binary_sha256=binary_sha,build_command=command,cases=cases,source_before=before,error_mapping_source=ERROR_SOURCE,error_mapping={str(k):v for k,v in ERROR_CODES.items()},error_code_labels_are_peer_responses_not_sdk_xml_classification=True,limits=['Simulated400ExpiredToken/403AccessDenied/503SlowDown;429SyntheticHTTP429 is generic robustness only, not an AWS S3 error mapping.','No production SDK/Surf/API/trust/deadline change.'])
    args.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(dict(passed=True,cases=len(cases),report=str(args.report))))
if __name__=='__main__':main()
