"""Owned offline fixtures only: no AWS CLI/provider requests or real keys."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('aws_qualification', Path(__file__).with_name('run.py'))
R = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(R)


def result(ok=True, object='Absent', effect='Response_Received', verb=None):
    value = {'schema': 1, 'ok': ok, 'reason': 'None' if ok else 'Read_Failed',
        'object': object, 'credential_kind': 'None', 's3_kind': 'None', 'ses_kind': 'None',
        'put_effect': 'Not_Sent', 'delete_effect': 'Not_Sent', 'ses_effect': 'Not_Sent',
        'mutation_status': 200 if ok else 0}
    if verb: value[verb+'_effect'] = effect
    return value


class Tests(unittest.TestCase):
    def write(self, path, value):
        path.write_text(json.dumps(value)); path.chmod(0o600)

    def fixture(self, tmp, write=True, ses=False, script=None):
        root = Path(tmp); resource = root/'resources.json'
        self.write(resource, {'schema': 1, 'phase': 'READY', 'bucket': 'webtools-qualification-fixture',
            'prefix': 'qualification/'+'a'*32+'/', 'profile': 'fixture', 'region': 'us-east-1',
            'expected_account': '123456789012', 'public_access_block_verified': True, 'encryption': 'AES256'})
        binary = root/'probe'; binary.write_text(script or '#!/bin/sh\nexit 0\n'); binary.chmod(0o700)
        return types.SimpleNamespace(resource_plan=resource, binary=binary, state_dir=root/'state',
            command='run', live=True, allow_write=write, aws_cli=None,
            ses_sender='qualification@example.test' if ses else '', ses_identity_verified=ses)

    def credentials(self, *_):
        return {'AWS_ACCESS_KEY_ID': 'fixture-access', 'AWS_SECRET_ACCESS_KEY': 'fake-private-material'}

    def success(self, actions):
        def launch(args, state, verb, env, deadline):
            actions.append(verb)
            durable = R.read(args.state_dir/'state.json')
            self.assertEqual(durable['phase'], {'read': 'READ_INTENT', 'put': 'PUT_INTENT',
                'delete': 'DELETE_INTENT', 'ses': 'SES_INTENT'}[verb])
            return result(object='Owned' if verb == 'put' else 'Absent',
                          verb=verb if verb in ('put', 'delete', 'ses') else None)
        return launch

    def test_plan_is_private_and_does_not_launch_or_reissue_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(tmp)
            with mock.patch.object(R.subprocess, 'Popen', side_effect=AssertionError('no child')):
                value = R.plan(args)
            self.assertEqual(value['phase'], 'PREPARED'); self.assertFalse(value['qualified'])
            self.assertEqual((args.state_dir/'scope.json').stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(R.Failure, 'ALREADY_EXISTS'): R.plan(args)

    def test_scope_refuses_business_resource_paths_and_missing_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(tmp); original = R.read(args.resource_plan)
            for update in ({'bucket': 'business-data'}, {'prefix': 'qualification/../business/'},
                           {'expected_account': 'wrong'}, {'public_access_block_verified': False},
                           {'encryption': 'none'}):
                self.write(args.resource_plan, {**original, **update})
                with self.assertRaises(R.Failure): R.plan(args)

    def test_exact_roundtrip_intents_keep_secrets_out_of_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(tmp); R.plan(args); actions = []
            value = R.run(args, self.success(actions), self.credentials)
            self.assertEqual(actions, ['read', 'put', 'delete'])
            self.assertTrue(value['qualified'] and value['s3_qualified'])
            self.assertEqual(value['put_result']['put_effect'], 'Response_Received')
            self.assertEqual(value['delete_result']['delete_effect'], 'Response_Received')
            for name in ('state.json', 'receipt.json'):
                self.assertNotIn('fake-private-material', (args.state_dir/name).read_text())

    def test_readonly_miss_is_not_full_roundtrip_qualification(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(tmp, False); R.plan(args); actions = []
            value = R.run(args, self.success(actions), self.credentials)
            self.assertEqual(actions, ['read']); self.assertEqual(value['phase'], 'READ_ONLY_CHECKED')
            self.assertFalse(value['qualified'])

    def test_unknown_put_requires_readonly_reconcile_and_never_resends(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(tmp); R.plan(args); actions = []
            def launch(args, state, verb, env, deadline):
                actions.append(verb)
                if verb == 'put': return result(False, 'Unverified', 'Unknown', 'put')
                return result(object='Owned' if verb == 'reconcile' else 'Absent',
                              verb='delete' if verb == 'delete' else None)
            value = R.run(args, launch, self.credentials); self.assertEqual(value['phase'], 'PUT_INTENT')
            with self.assertRaisesRegex(R.Failure, 'REQUIRES_REVIEW'): R.run(args, launch, self.credentials)
            args.command = 'reconcile'
            unknown = R.run(args, lambda *_: result(), self.credentials)
            self.assertEqual(unknown['phase'], 'PUT_INTENT')
            self.assertEqual(R.run(args, launch, self.credentials)['phase'], 'PUT_VERIFIED')
            args.command = 'cleanup'; self.assertTrue(R.run(args, launch, self.credentials)['qualified'])
            self.assertEqual(actions.count('put'), 1)

    def test_prior_put_evidence_survives_delete_verification_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(tmp); R.plan(args)
            def launch(args, state, verb, env, deadline):
                if verb == 'delete': return result(False, 'Unverified', 'Response_Received', 'delete')
                return result(object='Owned' if verb == 'put' else 'Absent', verb='put' if verb == 'put' else None)
            value = R.run(args, launch, self.credentials)
            self.assertEqual(value['phase'], 'DELETE_INTENT')
            self.assertEqual(value['put_result']['put_effect'], 'Response_Received')
            self.assertEqual(value['delete_result']['delete_effect'], 'Response_Received')
            self.assertFalse(value['qualified']); args.command = 'reconcile'
            self.assertTrue(R.run(args, lambda *_: result(), self.credentials)['qualified'])

    def test_ses_needs_verified_sender_and_unknown_send_never_retries(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(tmp, True, True); args.ses_identity_verified = False
            with self.assertRaisesRegex(R.Failure, 'VERIFIED_SES'): R.plan(args)
            args.ses_identity_verified = True; R.plan(args); actions = []; normal = self.success(actions)
            def launch(args, state, verb, env, deadline):
                if verb == 'ses': actions.append(verb); return result(False, 'Unverified', 'Unknown', 'ses')
                return normal(args, state, verb, env, deadline)
            value = R.run(args, launch, self.credentials)
            self.assertEqual(value['phase'], 'SES_INTENT')
            self.assertTrue(value['s3_qualified']); self.assertFalse(value['qualified'])
            args.command = 'send'
            with self.assertRaisesRegex(R.Failure, 'REQUIRES_REVIEW'): R.run(args, launch, self.credentials)
            self.assertEqual(actions.count('ses'), 1)

    def test_sts_checks_the_exported_triple_and_rejects_wrong_account(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(tmp); R.plan(args); args.aws_cli = Path('/fixture/aws')
            scope = R.read(args.state_dir/'scope.json'); calls = []
            def capture(argv, env, deadline, limit=R.MAX_BYTES):
                calls.append(argv)
                if 'export-credentials' in argv:
                    self.assertNotIn('AWS_SECRET_ACCESS_KEY', env)
                    return 0, b'{"Version":1,"AccessKeyId":"fixture-access","SecretAccessKey":"fake-private-material","SessionToken":null}'
                self.assertEqual(env['AWS_SECRET_ACCESS_KEY'], 'fake-private-material')
                return 0, b'{"Account":"123456789012"}'
            with mock.patch.dict(R.os.environ, {'LINEAR_API': 'fake-linear-secret'}):
                with mock.patch.object(R, 'capture', side_effect=capture):
                    env = R.credentials(args, scope, R.time.monotonic()+10)
            self.assertNotIn('LINEAR_API', env); self.assertEqual(len(calls), 2)
            export = {'Version': 1, 'AccessKeyId': 'fixture-access', 'SecretAccessKey': 'fake-private-material'}
            with mock.patch.object(R, 'capture', side_effect=[(0, json.dumps(export).encode()), (0, b'{"Account":"000000000000"}')]):
                with self.assertRaisesRegex(R.Failure, 'ACCOUNT_NOT_VERIFIED'): R.credentials(args, scope, R.time.monotonic()+10)
            export['Expiration'] = '2000-01-01T00:00:00Z'
            with mock.patch.object(R, 'capture', return_value=(0, json.dumps(export).encode())):
                with self.assertRaisesRegex(R.Failure, 'NEAR_EXPIRY'): R.credentials(args, scope, R.time.monotonic()+10)

    def test_live_binary_singleton_and_false_success_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(tmp); R.plan(args); args.live = False
            with self.assertRaisesRegex(R.Failure, 'LIVE_OPT_IN'): R.run(args)
            args.live = True
            with R.locked(args.state_dir):
                with self.assertRaises(BlockingIOError): R.run(args)
            actions = []
            def unverified(args, state, verb, env, deadline): actions.append(verb); return result(object='Unverified' if verb == 'put' else 'Absent')
            value = R.run(args, unverified, self.credentials)
            self.assertEqual(value['phase'], 'PUT_INTENT'); self.assertEqual(actions, ['read', 'put'])
            args.binary.write_text('#!/bin/sh\nexit 1\n')
            with self.assertRaisesRegex(R.Failure, 'BINDING_MISMATCH'): R.run(args)

    def test_real_child_output_limit_redacts_before_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(tmp, script='#!'+sys.executable+'\nprint("fake-private-material"*2000)\n')
            R.plan(args); value = R.run(args, credential_loader=self.credentials)
            self.assertEqual(value['phase'], 'READ_INTENT'); self.assertFalse(value['qualified'])
            self.assertNotIn('fake-private-material', (args.state_dir/'receipt.json').read_text())


if __name__ == '__main__': unittest.main()
