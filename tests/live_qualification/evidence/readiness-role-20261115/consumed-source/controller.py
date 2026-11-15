"""Offline-review controller. No AWS transport or executable live entry point.

Backend contract is explicit: existing ownership-checked lifecycle + maintained
runner, bound to one session. A live adapter requires subsequent root review.
"""
import re
from types import MappingProxyType

TRIPLE = ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN')
CODES = frozenset(('NoSuchKey', 'NoSuchBucket', 'AccessDenied', 'InvalidAccessKeyId',
    'SignatureDoesNotMatch', 'ExpiredToken', 'InvalidToken', 'RequestTimeTooSkewed',
    'AuthorizationHeaderMalformed', 'SlowDown', 'RequestTimeout', 'PermanentRedirect',
    'TemporaryRedirect', 'RequestExpired'))
LAYERS = {
    'IdentityPolicy': ('identity-based policy',),
    'ResourcePolicy': ('resource-based policy',),
    'ServiceControlPolicy': ('service control policy',),
    'PermissionsBoundary': ('permissions boundary',),
    'SessionPolicy': ('session policy',),
    'VpcEndpointPolicy': ('VPC endpoint policy',),
}

class Stop(Exception):
    pass


def cli_observation(returncode, stderr):
    # Inspect bounded bytes only in memory. Never return provider prose.
    if len(stderr) > 16384:
        return {'code': 'Unknown', 'status': None, 'deny_layer': 'Unknown'}
    if returncode == 0:
        return {'code': 'ObjectPresent', 'status': None, 'deny_layer': 'NotApplicable'}
    matches = re.findall(rb'An error occurred \(([A-Za-z0-9]+)\) when calling the GetObject operation:', stderr)
    code = matches[0].decode('ascii') if len(matches) == 1 else 'Unknown'
    if code not in CODES:
        code = 'Unknown'
    layers = [name for name, phrases in LAYERS.items()
              if any(phrase.encode() in stderr for phrase in phrases)]
    layer = layers[0] if code == 'AccessDenied' and len(layers) == 1 else 'Unknown'
    if code != 'AccessDenied':
        layer = 'NotApplicable'
    return {'code': code, 'status': None, 'deny_layer': layer}


def cli_request(executable, resources, key, env):
    if not key.startswith(resources['prefix']) or not re.fullmatch(
            re.escape(resources['prefix']) + r'[0-9a-f]{32}\.txt', key):
        raise Stop('KEY_SCOPE')
    if any(not isinstance(env.get(name), str) or not env[name] for name in TRIPLE):
        raise Stop('TEMPORARY_TRIPLE_REQUIRED')
    # No ambient profiles, endpoints, proxies, credential providers or CLI debug.
    safe = {k: env[k] for k in ('PATH', 'LANG', 'LC_ALL', 'TMPDIR', *TRIPLE) if k in env}
    safe.update(AWS_CONFIG_FILE='/dev/null', AWS_SHARED_CREDENTIALS_FILE='/dev/null',
                AWS_EC2_METADATA_DISABLED='true', AWS_MAX_ATTEMPTS='1', AWS_PAGER='')
    argv = [executable, 's3api', 'get-object', '--bucket', resources['bucket'],
            '--key', key, '--range', 'bytes=0-0', '/dev/null', '--region',
            resources['region'], '--output', 'json', '--no-cli-pager',
            '--cli-connect-timeout', '5', '--cli-read-timeout', '10']
    return argv, safe


def native_observation(result):
    status = result.get('read_status')
    code = result.get('read_error_code')
    if type(status) is not int or not 100 <= status <= 599 or code not in CODES | {'None', 'Unknown'}:
        raise Stop('NATIVE_OBSERVATION_INVALID')
    if any(result.get(name) != 'Not_Sent' for name in ('put_effect', 'delete_effect', 'ses_effect')):
        raise Stop('READ_MUTATION_UNEXPECTED')
    absent = (result.get('ok') is True and result.get('object') == 'Absent'
              and status == 404 and code == 'NoSuchKey')
    return {'code': code, 'status': status, 'deny_layer':
            'Unknown' if code == 'AccessDenied' else 'NotApplicable', 'absent': absent}


def assume_ready(backend, clock, save, report):
    deadline = clock() + 45
    for attempt in range(1, 7):
        if clock() >= deadline: break
        started = clock()
        save({'phase': 'ASSUME_ROLE_INTENT', 'attempt': attempt,
              'started_monotonic_seconds': started})
        try:
            outcome, env = backend.assume_attempt(900, deadline)
        except BaseException:
            outcome, env = 'Unknown', None
        if clock() >= deadline and outcome == 'Issued':
            # A late successful reply can still have issued a session: never retry.
            report.update(session_count=1, issuance='Issued')
            save({'phase': 'ASSUME_ROLE_OBSERVED', 'attempt': attempt, 'outcome': 'IssuedLate',
                  'elapsed_seconds': max(0, clock()-started)})
            raise Stop('STS_READINESS_DEADLINE')
        if outcome not in ('Denied', 'Issued'):
            report['issuance'] = 'Unknown'
            save({'phase': 'ASSUME_ROLE_OBSERVED', 'attempt': attempt, 'outcome': 'Unknown',
                  'elapsed_seconds': max(0, clock()-started)})
            raise Stop('STS_ISSUANCE_UNKNOWN')
        save({'phase': 'ASSUME_ROLE_OBSERVED', 'attempt': attempt, 'outcome': outcome,
              'code': 'AccessDenied' if outcome == 'Denied' else 'None',
              'elapsed_seconds': max(0, clock()-started)})
        if outcome == 'Issued':
            report.update(session_count=1, issuance='Issued')
            return env
        report['issuance'] = 'NotIssued'
        if attempt == 6 or clock() + 5 >= deadline: break
        backend.pause(5)
    raise Stop('STS_READINESS_EXHAUSTED')


def readiness(backend, env, clock, save):
    """Only confirmed CLI AccessDenied can retry; one native read, no mutations."""
    deadline = clock() + 45
    frozen = MappingProxyType(dict(env))
    def check():
        if clock() >= deadline: raise Stop('READINESS_DEADLINE')
    for attempt in range(1, 7):
        check()
        started = clock()
        save({'phase': 'CLI_READ_INTENT', 'attempt': attempt,
              'started_monotonic_seconds': started})
        try:
            cli = backend.cli_read(frozen, deadline)
        except BaseException:
            save({'phase': 'CLI_READ_OBSERVED', 'attempt': attempt, 'code': 'Unknown',
                  'elapsed_seconds': max(0, clock()-started)})
            raise Stop('CLI_READ_UNKNOWN') from None
        if not isinstance(cli, dict) or set(cli) != {'code', 'status', 'deny_layer'} or \
                cli.get('code') not in CODES | {'Unknown', 'ObjectPresent'} or \
                cli.get('status') is not None or cli.get('deny_layer') not in set(LAYERS) | {'Unknown', 'NotApplicable'}:
            raise Stop('CLI_OBSERVATION_INVALID')
        save({'phase': 'CLI_READ_OBSERVED', 'attempt': attempt, 'cli': cli,
              'elapsed_seconds': max(0, clock()-started)})
        check()
        if cli['code'] == 'NoSuchKey': break
        if cli['code'] != 'AccessDenied': raise Stop('CLI_NOT_EXPLICIT_ABSENCE')
        if attempt == 6 or clock() + 5 >= deadline: raise Stop('CLI_READINESS_EXHAUSTED')
        backend.pause(5)
    check()
    save({'phase': 'NATIVE_READ_INTENT', 'cli': cli})
    native = native_observation(backend.native_read(frozen, deadline))
    save({'phase': 'NATIVE_READ_OBSERVED', 'cli': cli, 'native': native})
    check()
    if not native['absent']: raise Stop('NATIVE_DENIAL_OR_DIVERGENCE')
    save({'phase': 'READINESS_COMPLETE', 'cli': cli, 'native': native,
          'same_literal_triple': True})
    return frozen


def campaign(backend, clock, save):
    """Injected-only lifecycle state machine; backend may never persist secrets.

    verify_owned_cleanup must implement exact tag/RoleId/trust/policy matching and
    both absence confirmations. Called even when create outcome is uncertain.
    """
    created_intent = False
    report = {'passed': False, 'phase': 'PREFLIGHT', 'session_count': 0, 'issuance': 'NotAttempted'}
    try:
        backend.preflight()  # exact principal + role NoSuchEntity + pinned sources
        backend.fresh_state()  # refuses any old ownership/readiness/campaign state
        save({'phase': 'ROLE_CREATE_INTENT'})
        created_intent = True
        backend.create_and_verify_owned_role()
        report['phase'] = 'ASSUME_ROLE_READINESS'
        env = assume_ready(backend, clock, save, report)
        backend.guard_role(env, 180 + 45)  # exact triple, account, role and expiry
        verified = readiness(backend, env, clock, save)
        report['phase'] = 'NATIVE_CAMPAIGN_INTENT'
        save({'phase': report['phase']})
        result = backend.maintained_campaign(verified, 180)
        if result != {'qualified': True, 'phase': 'COMPLETE', 's3_qualified': True}:
            raise Stop('NATIVE_CAMPAIGN_INCOMPLETE')
        report.update(passed=True, phase='COMPLETE')
    except BaseException as error:
        # Fixed local labels only; never stringify arbitrary exception messages.
        report['error'] = str(error) if type(error) is Stop else 'BACKEND_FAILURE'
        if report['error'] not in {'READINESS_DEADLINE', 'CLI_NOT_EXPLICIT_ABSENCE',
                'NATIVE_DENIAL_OR_DIVERGENCE', 'NATIVE_OBSERVATION_INVALID',
                'READ_MUTATION_UNEXPECTED', 'NATIVE_CAMPAIGN_INCOMPLETE', 'STS_READINESS_DEADLINE',
                'STS_READINESS_EXHAUSTED', 'STS_ISSUANCE_UNKNOWN', 'CLI_READ_UNKNOWN',
                'CLI_READINESS_EXHAUSTED'}:
            report['error'] = 'BACKEND_FAILURE'
    finally:
        if created_intent:
            try:
                cleanup = backend.verify_owned_cleanup()
                if cleanup != {'inline_policy_absent': True, 'role_absent': True}:
                    raise Stop('CLEANUP_UNCONFIRMED')
                report['cleanup'] = cleanup
            except BaseException:
                report.update(passed=False, cleanup_unknown=True)
        save({'phase': 'CONTROLLER_STOPPED', 'report': report})
    return report

if __name__ == '__main__':
    raise SystemExit('OFFLINE_REVIEW_ONLY: no live backend or cloud entry point')
