#!/usr/bin/env python3
"""Finite native AWS qualification with explicit scratch resources and durable intent.

Credential export and STS verification use the selected AWS CLI profile in memory;
S3/SES operations use the Odin bindings. No keys, provider bodies or URLs are logged.
"""
import argparse
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

MAX_BYTES = 16384
TOTAL_SECONDS = 180
SCOPE_KEYS = {'schema', 'bucket', 'region', 'prefix', 'profile', 'expected_account',
              'allow_write', 'allow_ses', 'ses_sender'}
RESULT_KEYS = {'schema', 'ok', 'reason', 'object', 'credential_kind', 's3_kind',
               'ses_kind', 'put_effect', 'delete_effect', 'ses_effect', 'mutation_status'}
REASONS = {'None', 'Invalid_Arguments', 'Invalid_Scope', 'Credential_Error', 'Read_Failed',
           'Foreign_Object', 'Put_Disabled', 'Put_Failed', 'Delete_Failed', 'Response_Mismatch',
           'SES_Disabled', 'SES_Failed'}
CREDENTIAL_KINDS = {'None', 'Invalid_Argument', 'Unsupported', 'Incomplete', 'Unavailable',
                    'Expired', 'Cancelled', 'Waiter_Limit', 'Busy', 'Allocation_Failed', 'Closed'}
S3_KINDS = {'None', 'Invalid_Input', 'Not_Found', 'Too_Large', 'Rejected', 'Unavailable'}
SES_KINDS = {'None', 'Invalid_Config', 'Invalid_Message', 'Allocation_Failed',
            'Unavailable', 'Rejected', 'Invalid_Response'}
EFFECTS = {'Unknown', 'Not_Sent', 'Response_Received'}


class Failure(Exception): pass


def decode(data):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value: raise Failure('DUPLICATE_JSON')
            value[key] = item
        return value
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Failure('INVALID_JSON')))


def private_file(fd):
    value = os.fstat(fd)
    if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.geteuid() or
            stat.S_IMODE(value.st_mode) != 0o600 or value.st_nlink != 1):
        raise Failure('PRIVATE_FILE_REQUIRED')


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        private_file(fd)
        if os.fstat(fd).st_size > MAX_BYTES: raise Failure('METADATA_TOO_LARGE')
        data = os.read(fd, MAX_BYTES+1)
        if len(data) > MAX_BYTES: raise Failure('METADATA_TOO_LARGE')
        return decode(data)
    finally: os.close(fd)


def atomic(directory, name, value):
    data = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    if len(data) > MAX_BYTES: raise Failure('METADATA_TOO_LARGE')
    fd, temporary = tempfile.mkstemp(prefix='.qualification-', dir=directory)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, directory/name)
        owner = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(owner)
        finally: os.close(owner)
    finally: Path(temporary).unlink(missing_ok=True)


@contextlib.contextmanager
def locked(path):
    if not path.is_absolute(): raise Failure('ABSOLUTE_STATE_REQUIRED')
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Failure('PRIVATE_DIRECTORY_REQUIRED')
    fd = os.open(path/'owner.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        private_file(fd); fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally: os.close(fd)


def binary_hash(path):
    if not path.is_absolute(): raise Failure('ABSOLUTE_BINARY_REQUIRED')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 128 << 20 or info.st_mode & 0o022 or not os.access(path, os.X_OK):
            raise Failure('EXECUTABLE_REQUIRED')
        with os.fdopen(os.dup(fd), 'rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()
    finally: os.close(fd)


def scope_valid(scope):
    if not isinstance(scope, dict) or set(scope) != SCOPE_KEYS or type(scope['schema']) is not int or scope['schema'] != 1:
        raise Failure('SCOPE_SCHEMA_INVALID')
    patterns = {'bucket': r'webtools-qualification-[a-z0-9-]{3,40}',
                'region': r'[a-z]{2}-[a-z]+-[0-9]', 'prefix': r'qualification/[0-9a-f]{32}/',
                'profile': r'[A-Za-z0-9_-]{1,64}', 'expected_account': r'[0-9]{12}'}
    for name, pattern in patterns.items():
        if not isinstance(scope[name], str) or not re.fullmatch(pattern, scope[name]):
            raise Failure('SCOPE_RESOURCE_INVALID')
    if any(type(scope[name]) is not bool for name in ('allow_write', 'allow_ses')):
        raise Failure('SCOPE_POLICY_INVALID')
    sender = scope['ses_sender']
    if not isinstance(sender, str) or (scope['allow_ses'] and not re.fullmatch(r'[^\s<>@]{1,120}@[^\s<>@]{1,120}', sender)):
        raise Failure('SES_POLICY_INVALID')
    if not scope['allow_ses'] and sender != '': raise Failure('SES_POLICY_INVALID')
    return scope


def receipt(directory, state, reason=None):
    result = {key: state[key] for key in ('run_id', 'scope_sha256', 'binary_sha256', 'phase')}
    result.update(schema=1, qualified=state['phase'] == 'COMPLETE',
                  s3_qualified=state.get('s3_qualified', False), secrets_logged=False,
                  ses_selected=state['allow_ses'])
    if reason: result['reason'] = reason
    for key in ('last_result', 'put_result', 'delete_result', 'ses_result'):
        if key in state: result[key] = state[key]
    atomic(directory, 'receipt.json', result)
    return result


def plan(args):
    resource = read(args.resource_plan)
    if (type(resource.get('schema')) is not int or resource['schema'] != 1 or
            resource.get('phase') != 'READY' or resource.get('public_access_block_verified') is not True or
            resource.get('encryption') != 'AES256'):
        raise Failure('RESOURCES_NOT_READY')
    scope = {'schema': 1, **{name: resource[name] for name in
             ('bucket', 'region', 'prefix', 'profile', 'expected_account')},
             'allow_write': args.allow_write, 'allow_ses': bool(args.ses_sender), 'ses_sender': args.ses_sender}
    if args.ses_sender and not args.ses_identity_verified: raise Failure('VERIFIED_SES_IDENTITY_REQUIRED')
    scope_valid(scope)
    digest = binary_hash(args.binary)
    with locked(args.state_dir):
        if (args.state_dir/'state.json').exists() or (args.state_dir/'scope.json').exists():
            raise Failure('RUN_ALREADY_EXISTS')
        atomic(args.state_dir, 'scope.json', scope)
        state = {'schema': 1, 'run_id': secrets.token_hex(16), 'phase': 'PREPARED',
                 'scope_sha256': hashlib.sha256((args.state_dir/'scope.json').read_bytes()).hexdigest(),
                 'binary': str(args.binary), 'binary_sha256': digest,
                 'allow_ses': scope['allow_ses'], 's3_qualified': False}
        atomic(args.state_dir, 'state.json', state)
        return receipt(args.state_dir, state)


def capture(argv, env, deadline, limit=MAX_BYTES):
    child = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, start_new_session=True)
    output = bytearray(); selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ)
    try:
        while selector.get_map():
            remaining = deadline-time.monotonic()
            if remaining <= 0: raise Failure('CHILD_DEADLINE')
            for key, _ in selector.select(min(remaining, 1)):
                data = os.read(key.fd, 4096)
                if not data: selector.unregister(child.stdout); continue
                output.extend(data)
                if len(output) > limit: raise Failure('CHILD_OUTPUT_LIMIT')
        code = child.wait(timeout=max(0.01, deadline-time.monotonic()))
        return code, bytes(output)
    finally:
        selector.close()
        try: os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        child.wait(timeout=5); child.stdout.close()


def credentials(args, scope, deadline):
    executable = args.aws_cli or shutil.which('aws')
    if not executable: raise Failure('AWS_CLI_REQUIRED')
    base = {key: os.environ[key] for key in ('PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'TMPDIR') if key in os.environ}
    base['AWS_EC2_METADATA_DISABLED'] = 'true'
    code, data = capture([str(executable), 'configure', 'export-credentials', '--format', 'process',
                          '--profile', scope['profile']], base, min(deadline, time.monotonic()+30))
    if code: raise Failure('CREDENTIAL_EXPORT_FAILED')
    value = decode(data)
    if not isinstance(value, dict) or type(value.get('Version')) is not int or value['Version'] != 1:
        raise Failure('CREDENTIAL_EXPORT_INVALID')
    env = {key: base[key] for key in ('PATH', 'LANG', 'LC_ALL', 'TMPDIR') if key in base}
    for key, source, bound in (('AWS_ACCESS_KEY_ID', 'AccessKeyId', 128),
                               ('AWS_SECRET_ACCESS_KEY', 'SecretAccessKey', 256),
                               ('AWS_SESSION_TOKEN', 'SessionToken', 8192)):
        text = value.get(source, '')
        if source == 'SessionToken' and text is None: text = ''
        if not isinstance(text, str) or len(text) > bound or any(ord(c) < 33 for c in text):
            raise Failure('CREDENTIAL_EXPORT_INVALID')
        if text: env[key] = text
    if not env.get('AWS_ACCESS_KEY_ID') or not env.get('AWS_SECRET_ACCESS_KEY'):
        raise Failure('CREDENTIAL_EXPORT_INVALID')
    if value.get('Expiration'):
        if not isinstance(value['Expiration'], str): raise Failure('CREDENTIAL_EXPORT_INVALID')
        expiration = datetime.datetime.fromisoformat(value['Expiration'].replace('Z', '+00:00'))
        if expiration.tzinfo is None or expiration.timestamp() <= time.time()+TOTAL_SECONDS:
            raise Failure('CREDENTIALS_NEAR_EXPIRY')
    env.update(AWS_EC2_METADATA_DISABLED='true', AWS_REGION=scope['region'])
    code, identity = capture([str(executable), 'sts', 'get-caller-identity', '--region', scope['region'],
                             '--output', 'json', '--no-cli-pager'], env,
                             min(deadline, time.monotonic()+30))
    identified = decode(identity) if code == 0 else None
    if not isinstance(identified, dict) or identified.get('Account') != scope['expected_account']:
        raise Failure('ACCOUNT_NOT_VERIFIED')
    return env


def native(args, state, action, env, deadline):
    scope_path = args.state_dir/'scope.json'
    if hashlib.sha256(scope_path.read_bytes()).hexdigest() != state['scope_sha256']:
        raise Failure('SCOPE_CHANGED')
    if binary_hash(Path(state['binary'])) != state['binary_sha256']: raise Failure('BINARY_CHANGED')
    argv = [state['binary'], '--scope', str(scope_path), '--run-id', state['run_id'],
            '--action', action, '--scope-sha256', state['scope_sha256']]
    code, data = capture(argv, env, min(deadline, time.monotonic()+90), 8192)
    value = decode(data)
    if not isinstance(value, dict) or set(value) != RESULT_KEYS: raise Failure('NATIVE_RESULT_INVALID')
    if type(value['ok']) is not bool or code not in (0, 2) or value['ok'] != (code == 0):
        raise Failure('NATIVE_RESULT_INVALID')
    if value['schema'] != 1 or type(value['schema']) is not int: raise Failure('NATIVE_RESULT_INVALID')
    for key, allowed in (('reason', REASONS), ('object', {'Unverified', 'Absent', 'Owned', 'Foreign'}),
                         ('credential_kind', CREDENTIAL_KINDS), ('s3_kind', S3_KINDS), ('ses_kind', SES_KINDS),
                         ('put_effect', EFFECTS), ('delete_effect', EFFECTS), ('ses_effect', EFFECTS)):
        if value[key] not in allowed: raise Failure('NATIVE_RESULT_INVALID')
    if type(value['mutation_status']) is not int or not 0 <= value['mutation_status'] <= 599:
        raise Failure('NATIVE_RESULT_INVALID')
    return value


def save(args, state, phase, result=None):
    state['phase'] = phase
    if phase.endswith('_INTENT') and result is None: state.pop('last_result', None)
    if result is not None: state['last_result'] = result
    atomic(args.state_dir, 'state.json', state)


def action(args, state, verb, phase, success, env, deadline, launcher):
    save(args, state, phase)
    try: result = launcher(args, state, verb, env, deadline)
    except (Failure, OSError, ValueError, TypeError, subprocess.SubprocessError):
        return receipt(args.state_dir, state, 'NATIVE_OUTCOME_UNKNOWN')
    if verb in ('put', 'delete', 'ses'): state[verb+'_result'] = result
    expected = 'Owned' if verb == 'put' else 'Absent' if verb == 'delete' else None
    if not result['ok'] or expected is not None and result['object'] != expected:
        save(args, state, phase, result)
        return receipt(args.state_dir, state, 'NATIVE_ACTION_NOT_VERIFIED')
    save(args, state, success, result)
    return None


def s3_complete(args, state):
    state['s3_qualified'] = True
    save(args, state, 'S3_COMPLETE' if state['allow_ses'] else 'COMPLETE')


def run(args, launcher=native, credential_loader=credentials):
    if not args.live: raise Failure('LIVE_OPT_IN_REQUIRED')
    with locked(args.state_dir):
        scope = scope_valid(read(args.state_dir/'scope.json')); state = read(args.state_dir/'state.json')
        if (hashlib.sha256((args.state_dir/'scope.json').read_bytes()).hexdigest() != state['scope_sha256'] or
                binary_hash(Path(state['binary'])) != state['binary_sha256'] or
                not re.fullmatch(r'[0-9a-f]{32}', state['run_id']) or state['allow_ses'] is not scope['allow_ses']):
            raise Failure('RUN_BINDING_MISMATCH')
        permitted = {'run': ('PREPARED',), 'reconcile': ('PUT_INTENT', 'PUT_VERIFIED', 'DELETE_INTENT'),
                     'cleanup': ('PUT_VERIFIED',), 'send': ('S3_COMPLETE',)}
        if state['phase'] not in permitted.get(args.command, ()): raise Failure('RUN_REQUIRES_REVIEW')
        deadline = time.monotonic()+TOTAL_SECONDS
        env = credential_loader(args, scope, deadline)
        if args.command == 'reconcile':
            value = launcher(args, state, 'reconcile', env, deadline)
            if value['ok'] and value['object'] == 'Owned' and state['phase'] != 'DELETE_INTENT':
                save(args, state, 'PUT_VERIFIED', value)
            elif value['ok'] and value['object'] == 'Absent' and state['phase'] == 'DELETE_INTENT':
                s3_complete(args, state)
            return receipt(args.state_dir, state, 'READ_ONLY_RECONCILIATION')
        if args.command == 'run':
            failure = action(args, state, 'read', 'READ_INTENT', 'READ_CHECKED', env, deadline, launcher)
            if failure: return failure
            if not scope['allow_write']:
                save(args, state, 'READ_ONLY_CHECKED'); return receipt(args.state_dir, state)
            failure = action(args, state, 'put', 'PUT_INTENT', 'PUT_VERIFIED', env, deadline, launcher)
            if failure: return failure
        if args.command != 'send':
            failure = action(args, state, 'delete', 'DELETE_INTENT', 'S3_COMPLETE', env, deadline, launcher)
            if failure: return failure
            s3_complete(args, state)
        if state['allow_ses'] and args.command != 'cleanup':
            failure = action(args, state, 'ses', 'SES_INTENT', 'COMPLETE', env, deadline, launcher)
            if failure: return failure
        return receipt(args.state_dir, state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('plan', 'run', 'reconcile', 'cleanup', 'send', 'status'))
    parser.add_argument('--state-dir', type=Path, required=True)
    parser.add_argument('--resource-plan', type=Path)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--aws-cli', type=Path)
    parser.add_argument('--allow-write', action='store_true')
    parser.add_argument('--ses-sender', default='')
    parser.add_argument('--ses-identity-verified', action='store_true')
    parser.add_argument('--live', action='store_true')
    args = parser.parse_args()
    try:
        if args.command == 'plan':
            if args.resource_plan is None or args.binary is None: raise Failure('PLAN_INPUT_REQUIRED')
            result = plan(args)
        elif args.command == 'status':
            with locked(args.state_dir): result = receipt(args.state_dir, read(args.state_dir/'state.json'))
        else: result = run(args)
        print(json.dumps(result, separators=(',', ':')))
        return 0 if result['phase'] in ('PREPARED', 'READ_ONLY_CHECKED', 'PUT_VERIFIED', 'S3_COMPLETE', 'COMPLETE') else 2
    except (Failure, OSError, ValueError, TypeError, KeyError, RecursionError, subprocess.SubprocessError):
        print('{"schema":1,"phase":"FAILED","reason":"QUALIFICATION_GUARD_FAILED"}')
        return 2


if __name__ == '__main__': sys.exit(main())
