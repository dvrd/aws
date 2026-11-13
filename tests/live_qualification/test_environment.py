"""Environment-mode qualification with synthetic keys and an owned fake CLI only."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import test_runner as existing

R = existing.R
ACCOUNT = '123456789012'
ROLE = 'arn:aws:iam::' + ACCOUNT + ':role/webtools-qualification-s3'
ASSUMED = 'arn:aws:sts::' + ACCOUNT + ':assumed-role/webtools-qualification-s3/owned-session'


class Environment(unittest.TestCase):
    def fixture(self, tmp, arn=ASSUMED, account=ACCOUNT, role=ROLE):
        helper = existing.Tests(); args = helper.fixture(tmp)
        resource = R.read(args.resource_plan)
        resource.update(credential_source='environment', expected_role_arn=role)
        resource.pop('profile')
        helper.write(args.resource_plan, resource)
        script = ('#!' + sys.executable + '\nimport os,json,pathlib,sys\n'
            'assert sys.argv[1:]==["sts","get-caller-identity","--region","us-east-1",'
            '"--output","json","--no-cli-pager"]\n'
            'assert os.environ["AWS_ACCESS_KEY_ID"]=="owned-access"\n'
            'assert os.environ["AWS_SECRET_ACCESS_KEY"]=="owned-secret"\n'
            'assert os.environ["AWS_SESSION_TOKEN"]=="owned-session-token"\n'
            'assert "AWS_PROFILE" not in os.environ and "AWS_ENDPOINT_URL" not in os.environ\n'
            'assert os.environ["AWS_CONFIG_FILE"]==os.devnull\n'
            'assert os.environ["AWS_SHARED_CREDENTIALS_FILE"]==os.devnull\n'
            'with (pathlib.Path(os.environ["TMPDIR"])/"cli-calls").open("a") as out:\n'
            ' out.write("sts-only\\n")\n'
            'print(' + repr(json.dumps(dict(Account=account, Arn=arn))) + ')\n')
        args.aws_cli = Path(tmp)/'fake-aws'; args.aws_cli.write_text(script)
        args.aws_cli.chmod(0o700)
        env = dict(PATH=os.defpath, TMPDIR=tmp, AWS_ACCESS_KEY_ID='owned-access',
            AWS_SECRET_ACCESS_KEY='owned-secret', AWS_SESSION_TOKEN='owned-session-token',
            AWS_CREDENTIAL_EXPIRATION='2099-01-01T00:00:00Z',
            AWS_PROFILE='must-not-override', AWS_ENDPOINT_URL='https://must-not-use.invalid')
        return args, env

    def test_planning_binds_policy_without_keys_cli_or_native_scope_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, env = self.fixture(tmp)
            with mock.patch.dict(R.os.environ, env, clear=True), \
                 mock.patch.object(R, 'capture', side_effect=AssertionError('no child')):
                prepared = R.plan(args)
            scope = R.read(args.state_dir/'scope.json'); state = R.read(args.state_dir/'state.json')
            self.assertEqual(set(scope), R.SCOPE_KEYS)
            self.assertEqual(scope['profile'], 'environment')
            self.assertEqual(state['credential_policy_sha256'], hashlib.sha256(
                (args.state_dir/'credential-policy.json').read_bytes()).hexdigest())
            self.assertNotIn('credential_attestation', prepared)
            self.assertNotIn('owned-secret', (args.state_dir/'state.json').read_text())

    def test_real_fake_cli_validates_exact_triple_role_before_native_and_redacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, env = self.fixture(tmp); R.plan(args); actions = []
            def launch(args, state, verb, child_env, deadline):
                self.assertEqual((Path(tmp)/'cli-calls').read_text(), 'sts-only\n')
                self.assertEqual(child_env['AWS_SESSION_TOKEN'], 'owned-session-token')
                self.assertTrue(state['credential_attestation']['role_match'])
                actions.append(verb)
                return existing.result(object='Owned' if verb == 'put' else 'Absent',
                    verb=verb if verb in ('put', 'delete') else None)
            with mock.patch.dict(R.os.environ, env, clear=True):
                result = R.run(args, launch)
            self.assertEqual(actions, ['read', 'put', 'delete'])
            self.assertTrue(result['qualified'])
            safe = result['credential_attestation']
            self.assertEqual(safe, dict(principal_type='AssumedRole', role_match=True,
                session_present=True, expiry_guard=True,
                expected_role_arn_sha256=hashlib.sha256(ROLE.encode()).hexdigest()))
            for name in ('state.json', 'receipt.json'):
                stored = (args.state_dir/name).read_text()
                for forbidden in ['owned-access', 'owned-secret',
                                  'owned-session-token', ASSUMED, ROLE]:
                    self.assertNotIn(forbidden, stored)

    def test_wrong_role_iam_user_or_account_stops_before_any_native_action(self):
        for arn, account in [(ASSUMED.replace('/webtools-', '/wrong-'), ACCOUNT),
                ('arn:aws:iam::'+ACCOUNT+':user/owned-user', ACCOUNT), (ASSUMED, '000000000000')]:
            with self.subTest(arn=arn), tempfile.TemporaryDirectory() as tmp:
                args, env = self.fixture(tmp, arn, account); R.plan(args); calls = []
                with mock.patch.dict(R.os.environ, env, clear=True), self.assertRaises(R.Failure):
                    R.run(args, lambda *a: calls.append(a))
                self.assertEqual(calls, [])
                self.assertEqual(R.read(args.state_dir/'state.json')['phase'], 'PREPARED')
                self.assertEqual((Path(tmp)/'cli-calls').read_text(), 'sts-only\n')

    def test_missing_token_or_near_expiry_never_invokes_cli_or_native(self):
        near = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=179)
        for update in [{'AWS_SESSION_TOKEN': ''}, {'AWS_CREDENTIAL_EXPIRATION': near.isoformat()},
                       {'AWS_CREDENTIAL_EXPIRATION': ''}, {'AWS_CREDENTIAL_EXPIRATION': 'invalid'}]:
            with self.subTest(update=update), tempfile.TemporaryDirectory() as tmp:
                args, env = self.fixture(tmp); R.plan(args); calls = []; env.update(update)
                with mock.patch.dict(R.os.environ, env, clear=True), self.assertRaises(R.Failure):
                    R.run(args, lambda *a: calls.append(a))
                self.assertEqual(calls, [])
                self.assertFalse((Path(tmp)/'cli-calls').exists())
                self.assertEqual(R.read(args.state_dir/'state.json')['phase'], 'PREPARED')

    def test_role_name_metacharacters_are_matched_literally(self):
        role = ROLE.rsplit('/', 1)[0] + '/qa.role+'
        arn = ASSUMED.replace('webtools-qualification-s3', 'qaXroleZ')
        with tempfile.TemporaryDirectory() as tmp:
            args, env = self.fixture(tmp, arn=arn, role=role); R.plan(args)
            with mock.patch.dict(R.os.environ, env, clear=True), \
                 self.assertRaisesRegex(R.Failure, 'ROLE_NOT_VERIFIED'):
                R.run(args, lambda *a: self.fail('no native action'))

    def test_identity_returning_after_campaign_deadline_cannot_start_native(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, env = self.fixture(tmp); R.plan(args)
            def capture(*_):
                clock[0] = 181
                return 0, json.dumps(dict(Account=ACCOUNT, Arn=ASSUMED)).encode()
            clock = [0]
            with mock.patch.dict(R.os.environ, env, clear=True), \
                 mock.patch.object(R.time, 'monotonic', side_effect=lambda: clock[0]), \
                 mock.patch.object(R, 'capture', side_effect=capture), \
                 self.assertRaisesRegex(R.Failure, 'CAMPAIGN_DEADLINE'):
                R.run(args, lambda *a: self.fail('no native action'))
            self.assertEqual(R.read(args.state_dir/'state.json')['phase'], 'PREPARED')

    def test_policy_change_or_cross_account_role_is_refused(self):
        for role in [ROLE.replace(ACCOUNT, '000000000000'), ROLE+'/path', 'not-an-arn']:
            with self.subTest(role=role), tempfile.TemporaryDirectory() as tmp:
                args, _ = self.fixture(tmp, role=role)
                with self.assertRaisesRegex(R.Failure, 'POLICY_INVALID'): R.plan(args)
        with tempfile.TemporaryDirectory() as tmp:
            args, env = self.fixture(tmp); R.plan(args); helper = existing.Tests()
            policy = R.read(args.state_dir/'credential-policy.json')
            helper.write(args.state_dir/'credential-policy.json', {**policy,
                'expected_role_arn': ROLE.replace('webtools-', 'wrong-')})
            with mock.patch.dict(R.os.environ, env, clear=True), \
                 mock.patch.object(R, 'capture', side_effect=AssertionError('no child')), \
                 self.assertRaisesRegex(R.Failure, 'POLICY_CHANGED'):
                R.run(args)

    def test_receipt_refuses_unapproved_attestation_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, _ = self.fixture(tmp); R.plan(args)
            state = R.read(args.state_dir/'state.json')
            state['credential_attestation'] = {'provider_body': 'owned-secret'}
            with self.assertRaisesRegex(R.Failure, 'ATTESTATION_INVALID'):
                R.receipt(args.state_dir, state)
            self.assertNotIn('owned-secret', (args.state_dir/'receipt.json').read_text())

    def test_completed_state_and_unknown_intent_do_not_load_credentials_or_replay(self):
        for phase in ['COMPLETE', 'PUT_INTENT', 'DELETE_INTENT', 'SES_INTENT']:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as tmp:
                args, env = self.fixture(tmp); R.plan(args)
                state = R.read(args.state_dir/'state.json'); state['phase'] = phase
                existing.Tests().write(args.state_dir/'state.json', state)
                with mock.patch.dict(R.os.environ, env, clear=True), \
                     mock.patch.object(R, 'capture', side_effect=AssertionError('no child')), \
                     self.assertRaisesRegex(R.Failure, 'REQUIRES_REVIEW'):
                    R.run(args)
                self.assertFalse((Path(tmp)/'cli-calls').exists())


if __name__ == '__main__':
    unittest.main()
