#!/usr/bin/env python3
"""Finite native AWS qualification with explicit scratch resources and durable intent.

Credentials come from the selected profile or an explicitly planned temporary environment;
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


def credential_policy(resource, account):
    source = resource.get('credential_source', 'profile')
    if source == 'profile' and 'expected_role_arn' not in resource:
        return None
    role = resource.get('expected_role_arn')
    pattern = r'arn:aws:iam::' + re.escape(account) + r':role/[A-Za-z0-9_+=,.@-]{1,64}'
    if source != 'environment' or not isinstance(role, str) or not re.fullmatch(pattern, role):
        raise Failure('CREDENTIAL_POLICY_INVALID')
    return dict(schema=1, credential_source=source, expected_role_arn=role)


def bound_credential_scope(args, state, scope):
    path = args.state_dir/'credential-policy.json'
    expected = state.get('credential_policy_sha256')
    if expected is None:
        if path.exists() or path.is_symlink(): raise Failure('UNBOUND_CREDENTIAL_POLICY')
        return scope
    policy = read(path)
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise Failure('CREDENTIAL_POLICY_CHANGED')
    if set(policy) != {'schema', 'credential_source', 'expected_role_arn'} or \
            type(policy['schema']) is not int or policy['schema'] != 1:
        raise Failure('CREDENTIAL_POLICY_INVALID')
    validated = credential_policy(policy, scope['expected_account'])
    if validated is None: raise Failure('CREDENTIAL_POLICY_INVALID')
    return {**scope, **{key: policy[key] for key in ('credential_source', 'expected_role_arn')}}


def safe_attestation(value):
    expected = {'principal_type', 'role_match', 'session_present', 'expiry_guard',
                'expected_role_arn_sha256'}
    required_true = ('role_match', 'session_present', 'expiry_guard')
    if not isinstance(value, dict) or set(value) != expected or \
            value['principal_type'] != 'AssumedRole' or \
            any(value[key] is not True for key in required_true) or \
            not isinstance(value['expected_role_arn_sha256'], str) or \
            not re.fullmatch(r'[0-9a-f]{64}', value['expected_role_arn_sha256']):
        raise Failure('ROLE_ATTESTATION_INVALID')
    return value


def receipt(directory, state, reason=None):
    result = {key: state[key] for key in ('run_id', 'scope_sha256', 'binary_sha256', 'phase')}
    result.update(schema=1, qualified=state['phase'] == 'COMPLETE',
                  s3_qualified=state.get('s3_qualified', False), secrets_logged=False,
                  ses_selected=state['allow_ses'])
    if reason: result['reason'] = reason
    for key in ('last_result', 'put_result', 'delete_result', 'ses_result',
                'credential_attestation'):
        if key in state:
            result[key] = (safe_attestation(state[key])
                           if key == 'credential_attestation' else state[key])
    atomic(directory, 'receipt.json', result)
    return result


def plan(args):
    resource = read(args.resource_plan)
    if (type(resource.get('schema')) is not int or resource['schema'] != 1 or
            resource.get('phase') != 'READY' or resource.get('public_access_block_verified') is not True or
            resource.get('encryption') != 'AES256'):
        raise Failure('RESOURCES_NOT_READY')
    policy = credential_policy(resource, resource['expected_account'])
    scope = {'schema': 1, **{name: resource[name] for name in
             ('bucket', 'region', 'prefix', 'expected_account')},
             'profile': 'environment' if policy else resource['profile'],
             'allow_write': args.allow_write, 'allow_ses': bool(args.ses_sender), 'ses_sender': args.ses_sender}
    if args.ses_sender and not args.ses_identity_verified: raise Failure('VERIFIED_SES_IDENTITY_REQUIRED')
    scope_valid(scope)
    digest = binary_hash(args.binary)
    with locked(args.state_dir):
        if any((args.state_dir/name).exists() or (args.state_dir/name).is_symlink()
               for name in ('state.json', 'scope.json', 'credential-policy.json')):
            raise Failure('RUN_ALREADY_EXISTS')
        atomic(args.state_dir, 'scope.json', scope)
        state = {'schema': 1, 'run_id': secrets.token_hex(16), 'phase': 'PREPARED',
                 'scope_sha256': hashlib.sha256((args.state_dir/'scope.json').read_bytes()).hexdigest(),
                 'binary': str(args.binary), 'binary_sha256': digest,
                 'allow_ses': scope['allow_ses'], 's3_qualified': False}
        if policy:
            atomic(args.state_dir, 'credential-policy.json', policy)
            state['credential_policy_sha256'] = hashlib.sha256(
                (args.state_dir/'credential-policy.json').read_bytes()).hexdigest()
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


class VerifiedEnvironment(dict):
    def __init__(self, environment, attestation):
        super().__init__(environment)
        self.attestation = attestation


def temporary_environment(base):
    env = {key: base[key] for key in ('PATH', 'LANG', 'LC_ALL', 'TMPDIR') if key in base}
    for key, bound in [('AWS_ACCESS_KEY_ID', 128), ('AWS_SECRET_ACCESS_KEY', 256),
                       ('AWS_SESSION_TOKEN', 8192)]:
        value = os.environ.get(key, '')
        if not value or len(value) > bound or any(not 33 <= ord(c) <= 126 for c in value):
            raise Failure('TEMPORARY_CREDENTIALS_REQUIRED')
        env[key] = value
    try:
        value = os.environ['AWS_CREDENTIAL_EXPIRATION']
        if len(value) > 64: raise ValueError()
        expiry = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
        if expiry.tzinfo is None: raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise Failure('TEMPORARY_EXPIRATION_REQUIRED') from None
    if expiry.timestamp() <= time.time()+TOTAL_SECONDS:
        raise Failure('CREDENTIALS_NEAR_EXPIRY')
    env.update(AWS_EC2_METADATA_DISABLED='true', AWS_CONFIG_FILE=os.devnull,
               AWS_SHARED_CREDENTIALS_FILE=os.devnull)
    return env, expiry.timestamp()


def environment_credentials(executable, scope, base, deadline):
    env, expiry = temporary_environment(base)
    env['AWS_REGION'] = scope['region']
    code, data = capture([str(executable), 'sts', 'get-caller-identity',
        '--region', scope['region'], '--output', 'json', '--no-cli-pager'], env,
        min(deadline, time.monotonic()+30))
    identity = decode(data) if code == 0 else None
    role = scope['expected_role_arn']
    if not isinstance(identity, dict) or identity.get('Account') != scope['expected_account']:
        raise Failure('ACCOUNT_NOT_VERIFIED')
    name = role.rsplit('/', 1)[1]
    assumed = ('arn:aws:sts::' + scope['expected_account'] + ':assumed-role/' + re.escape(name) +
               r'/[A-Za-z0-9_+=,.@-]{2,64}')
    if not isinstance(identity.get('Arn'), str) or not re.fullmatch(assumed, identity['Arn']):
        raise Failure('EXPECTED_ROLE_NOT_VERIFIED')
    if time.monotonic() >= deadline: raise Failure('CAMPAIGN_DEADLINE')
    if expiry <= time.time()+max(0, deadline-time.monotonic()):
        raise Failure('CREDENTIALS_NEAR_EXPIRY')
    safe = dict(principal_type='AssumedRole', role_match=True, session_present=True,
                expiry_guard=True,
                expected_role_arn_sha256=hashlib.sha256(role.encode()).hexdigest())
    return VerifiedEnvironment(env, safe)


def credentials(args, scope, deadline):
    executable = args.aws_cli or shutil.which('aws')
    if not executable: raise Failure('AWS_CLI_REQUIRED')
    base = {key: os.environ[key] for key in ('PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'TMPDIR') if key in os.environ}
    base['AWS_EC2_METADATA_DISABLED'] = 'true'
    if scope.get('credential_source') == 'environment':
        return environment_credentials(executable, scope, base, deadline)
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
        credential_scope = bound_credential_scope(args, state, scope)
        env = credential_loader(args, credential_scope, deadline)
        if credential_scope.get('credential_source') == 'environment':
            if not isinstance(env, VerifiedEnvironment): raise Failure('ROLE_ATTESTATION_REQUIRED')
            safe = safe_attestation(env.attestation)
            if safe['expected_role_arn_sha256'] != hashlib.sha256(
                    credential_scope['expected_role_arn'].encode()).hexdigest():
                raise Failure('ROLE_ATTESTATION_INVALID')
            state['credential_attestation'] = safe
            atomic(args.state_dir, 'state.json', state)
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
