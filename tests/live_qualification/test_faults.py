"""Offline campaign failures; no AWS CLI, provider requests, or real credentials."""
import tempfile
import unittest
import test_runner as existing

R = existing.R


class FaultControls(unittest.TestCase):
    def test_credential_rejection_or_expiry_stops_before_any_native_action(self):
        for reason in ('CREDENTIAL_EXPORT_EXPIRED', 'CREDENTIAL_ACCOUNT_MISMATCH'):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as temporary:
                args = existing.Tests().fixture(temporary)
                R.plan(args)
                initial = R.read(args.state_dir/'state.json')['run_id']
                calls = []
                def credentials(*_): raise R.Failure(reason)
                with self.assertRaises(R.Failure):
                    R.run(args, lambda *a: calls.append(a), credentials)
                state = R.read(args.state_dir/'state.json')
                self.assertEqual(state['phase'], 'PREPARED')
                self.assertEqual(state['run_id'], initial)
                self.assertEqual(calls, [])

    def test_read_denial_or_throttle_is_not_absence_and_cannot_start_put(self):
        for kind in ('Rejected', 'Unavailable'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                helper = existing.Tests()
                args = helper.fixture(temporary)
                R.plan(args)
                calls = []
                def launch(args, state, verb, env, deadline):
                    calls.append(verb)
                    return {**existing.result(False, 'Unverified', 'Not_Sent'), 's3_kind': kind}
                result = R.run(args, launch, helper.credentials)
                self.assertEqual(calls, ['read'])
                self.assertEqual(result['phase'], 'READ_INTENT')
                self.assertFalse(result['qualified'])
                with self.assertRaisesRegex(R.Failure, 'REQUIRES_REVIEW'):
                    R.run(args, launch, helper.credentials)
                self.assertEqual(calls, ['read'])

    def test_http_mutation_failures_retain_status_and_intent_without_resending(self):
        phases = {'put': 'PUT_INTENT', 'delete': 'DELETE_INTENT', 'ses': 'SES_INTENT'}
        reasons = {'put': 'Put_Failed', 'delete': 'Delete_Failed', 'ses': 'SES_Failed'}
        for verb in phases:
            for status in (403, 429, 503):
                with self.subTest(verb=verb, status=status), tempfile.TemporaryDirectory() as temporary:
                    helper = existing.Tests()
                    args = helper.fixture(temporary, ses=verb == 'ses')
                    R.plan(args)
                    initial = R.read(args.state_dir/'state.json')['run_id']
                    calls = []
                    def launch(args, state, action, env, deadline):
                        calls.append(action)
                        if action == verb:
                            return {**existing.result(False, 'Unverified', verb=verb),
                                    'reason': reasons[verb], 'mutation_status': status,
                                    'ses_kind': 'Rejected' if verb == 'ses' else 'None'}
                        return existing.result(object='Owned' if action == 'put' else 'Absent',
                                               verb=action if action in phases else None)
                    result = R.run(args, launch, helper.credentials)
                    self.assertEqual(result['phase'], phases[verb])
                    self.assertFalse(result['qualified'])
                    self.assertEqual(result[verb+'_result']['mutation_status'], status)
                    self.assertEqual(result[verb+'_result'][verb+'_effect'], 'Response_Received')
                    before = list(calls)
                    with self.assertRaisesRegex(R.Failure, 'REQUIRES_REVIEW'):
                        R.run(args, launch, helper.credentials)
                    self.assertEqual(calls, before)
                    self.assertEqual(R.read(args.state_dir/'state.json')['run_id'], initial)
                    self.assertNotIn('fake-private-material', (args.state_dir/'state.json').read_text())
