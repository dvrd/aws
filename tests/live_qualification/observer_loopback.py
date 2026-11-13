#!/usr/bin/env python3
"""One owned TCP peer observes default native TLS; no provider or credentials."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--odin', required=True, type=Path)
parser.add_argument('--shared', required=True, type=Path)
parser.add_argument('--report', required=True, type=Path)
args = parser.parse_args()
source = Path(__file__).with_name('get_observation.odin')
digest = hashlib.sha256(source.read_bytes()).hexdigest()
with tempfile.TemporaryDirectory(prefix='aws-observer-native-') as work:
    directory = Path(work)
    (directory/'get_observation.odin').write_bytes(source.read_bytes())
    (directory/'main.odin').write_text('''package main
import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:strings"
main :: proc() {
 assert(len(os.args)==2&&strings.has_prefix(os.args[1],"https://127.0.0.1:"))
 capture:S3_Read_Observation
 context.user_ptr=&capture
 body,status,error:=observed_get(os.args[1],nil,1000,1024,context.allocator)
 defer delete(body)
 assert(error==.Unavailable&&status==0&&capture.calls==1&&capture.code==.None)
 data,encoded:=json.marshal(capture.calls);assert(encoded==nil);defer delete(data)
 fmt.println(string(data))
}
''')
    binary = directory/'probe'
    build = [str(args.odin), 'build', str(directory), '-thread-count:1', '-vet',
             '-warnings-as-errors', '-sanitize:address', '-collection:shared='+str(args.shared),
             '-out:'+str(binary)]
    compiled = subprocess.run(build, capture_output=True, text=True, timeout=90)
    assert compiled.returncode == 0, compiled.stderr
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0)); listener.listen(); listener.settimeout(10)
        port = listener.getsockname()[1]
        child = subprocess.Popen([str(binary), 'https://127.0.0.1:'+str(port)+'/'],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True)
        try:
            peer, _ = listener.accept()
            with peer:
                peer.settimeout(5); hello = peer.recv(65536)
            stdout, stderr = child.communicate(timeout=10)
            assert len(hello) >= 6 and hello[0] == 22 and hello[5] == 1
            assert child.returncode == 0 and stdout.strip() == b'1' and not stderr
            listener.settimeout(.2)
            try:
                extra, _ = listener.accept(); extra.close()
                raise AssertionError('extra native connection')
            except socket.timeout:
                pass
        finally:
            try: os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            child.wait(timeout=5); child.stdout.close(); child.stderr.close()
    assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
    report = dict(passed=True,source_sha256=digest,source_unchanged=True,provider_calls=False,
        credentials_used=False,native_executor_calls=1,owned_connections=1,tls_client_hello=True,
        stderr_empty=True,child_reaped=True,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        build_command=build,limits='ClientHello and input/trust path only; no successful TLS handshake.')
    args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))
