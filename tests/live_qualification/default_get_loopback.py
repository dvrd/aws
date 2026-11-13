#!/usr/bin/env python3
"""Owned loopback only: signed default GET must reach strict native TLS setup."""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--odin', type=Path, required=True)
    parser.add_argument('--shared-root', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parent/'production_get_probe'
    with tempfile.TemporaryDirectory(prefix='aws-native-get-loopback-') as tmp:
        binary = Path(tmp)/'probe'
        command = [str(args.odin), 'build', str(source),
                   '-collection:shared='+str(args.shared_root), '-thread-count:1',
                   '-vet', '-warnings-as-errors', '-sanitize:address', '-out:'+str(binary)]
        built = subprocess.run(command, capture_output=True, text=True, timeout=120)
        if built.returncode: raise SystemExit('Native loopback probe build failed')
        observed = {'accepted': 0, 'tls_record': False}
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0)); server.listen(1); server.settimeout(2)
            def accept():
                try:
                    peer, _ = server.accept()
                    with peer:
                        observed['accepted'] += 1; peer.settimeout(2)
                        data = peer.recv(5)
                        observed['tls_record'] = len(data) >= 3 and data[:2] == b'\x16\x03'
                except (OSError, TimeoutError): pass
            thread = threading.Thread(target=accept); thread.start()
            try:
                native = subprocess.run([str(binary), 'https://127.0.0.1:'+str(server.getsockname()[1])],
                                        capture_output=True, text=True, timeout=8)
            finally: thread.join(timeout=3)
        result = {'owned_loopback_only': True, 'provider_calls': False,
                  'credentials': 'public synthetic strings only', 'native_exit': native.returncode,
                  'accepted_connections': observed['accepted'], 'tls_client_hello_seen': observed['tls_record'],
                  'compiler_sha256': hashlib.sha256(args.odin.read_bytes()).hexdigest(),
                  'probe_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                  'passed': native.returncode == 0 and observed['accepted'] == 1 and observed['tls_record']}
        args.report.write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps(result))
        return 0 if result['passed'] else 1


if __name__ == '__main__': raise SystemExit(main())
