"""Safe per-read receipts using owned fake native children, never a provider."""
import json
import sys
import tempfile
import unittest
from unittest import mock
import test_runner as existing

R = existing.R


class ReadObservation(unittest.TestCase):
    def fixture(self, tmp, read, put=None, write=True):
        read = dict(read); put = dict(put or read)
        script = '#!'+sys.executable+'\nimport json,sys\n'
        script += 'read='+repr(read)+'\nput='+repr(put)+'\n'
        script += 'value=read if sys.argv[6]=="read" else put\n'
        script += 'print(json.dumps(value))\nsys.exit(0 if value["ok"] else 2)\n'
        helper = existing.Tests(); args = helper.fixture(tmp, write=write, script=script)
        R.plan(args)
        return args, helper

    def test_initial_read_and_later_precondition_denial_remain_distinct(self):
        read = {**existing.result(), 'read_status': 404, 'read_error_code': 'NoSuchKey'}
        put = {**existing.result(False, 'Unverified', 'Not_Sent', 'put'),
               'read_status': 403, 'read_error_code': 'AccessDenied',
               'reason': 'Read_Failed', 's3_kind': 'Rejected'}
        with tempfile.TemporaryDirectory() as tmp:
            args, helper = self.fixture(tmp, read, put)
            receipt = R.run(args, credential_loader=helper.credentials)
            self.assertEqual(receipt['phase'], 'PUT_INTENT')
            self.assertEqual(receipt['read_result'], read)
            self.assertEqual(receipt['put_result'], put)
            self.assertEqual(receipt['put_result']['put_effect'], 'Not_Sent')
            with mock.patch.object(R, 'capture', side_effect=AssertionError('no replay')), \
                 self.assertRaisesRegex(R.Failure, 'REQUIRES_REVIEW'):
                R.run(args, credential_loader=helper.credentials)

    def test_reconciliation_observation_does_not_erase_original_read_or_put(self):
        read = {**existing.result(), 'read_status': 404, 'read_error_code': 'NoSuchKey'}
        put = {**existing.result(False, 'Unverified', 'Not_Sent', 'put'),
               'read_status': 403, 'read_error_code': 'AccessDenied',
               'reason': 'Read_Failed', 's3_kind': 'Rejected'}
        with tempfile.TemporaryDirectory() as tmp:
            args, helper = self.fixture(tmp, read, put)
            first = R.run(args, credential_loader=helper.credentials)
            args.command = 'reconcile'
            later = R.run(args, credential_loader=helper.credentials)
            self.assertEqual(later['phase'], 'PUT_INTENT')
            self.assertEqual(later['read_result'], first['read_result'])
            self.assertEqual(later['put_result'], first['put_result'])
            self.assertEqual(later['reconcile_result']['read_status'], 403)
            self.assertEqual(later['reconcile_result']['read_error_code'], 'AccessDenied')

    def test_initial_read_survives_later_unparseable_child_output(self):
        read = {**existing.result(), 'read_status': 404, 'read_error_code': 'NoSuchKey'}
        put = {**existing.result(False, 'Unverified', 'Not_Sent', 'put'),
               'read_status': 403, 'read_error_code': 'private-untrusted-value'}
        with tempfile.TemporaryDirectory() as tmp:
            args, helper = self.fixture(tmp, read, put)
            receipt = R.run(args, credential_loader=helper.credentials)
            self.assertEqual(receipt['read_result'], read)
            self.assertEqual(receipt['phase'], 'PUT_INTENT')
            self.assertEqual(receipt['reason'], 'NATIVE_OUTCOME_UNKNOWN')
            self.assertNotIn('private-', (args.state_dir/'receipt.json').read_text())

    def test_real_child_unknown_allowlisted_enum_is_safe_and_legacy_schema_remains_valid(self):
        for fields in ({}, {'read_status': 404, 'read_error_code': 'Unknown'}):
            with self.subTest(fields=fields), tempfile.TemporaryDirectory() as tmp:
                args, helper = self.fixture(tmp, {**existing.result(), **fields}, write=False)
                receipt = R.run(args, credential_loader=helper.credentials)
                self.assertEqual(receipt['phase'], 'READ_ONLY_CHECKED')
                self.assertEqual(receipt['read_result'], {**existing.result(), **fields})

    def test_provider_text_partial_fields_and_invalid_status_never_enter_receipts(self):
        cases = [{'read_status': 403, 'read_error_code': 'private-provider-code'},
                 {'read_status': True, 'read_error_code': 'AccessDenied'},
                 {'read_status': -1, 'read_error_code': 'Unknown'},
                 {'read_status': 99, 'read_error_code': 'Unknown'},
                 {'read_status': 600, 'read_error_code': 'Unknown'},
                 {'read_status': 403}, {'read_error_code': 'AccessDenied'},
                 {'read_status': 403, 'read_error_code': 'Unknown', 'headers': 'private-token'}]
        for fields in cases:
            with self.subTest(fields=fields), tempfile.TemporaryDirectory() as tmp:
                args, helper = self.fixture(tmp, {**existing.result(), **fields})
                receipt = R.run(args, credential_loader=helper.credentials)
                self.assertEqual(receipt['phase'], 'READ_INTENT')
                self.assertEqual(receipt['reason'], 'NATIVE_OUTCOME_UNKNOWN')
                self.assertNotIn('read_result', receipt)
                self.assertNotIn('private-', (args.state_dir/'receipt.json').read_text())

    def test_explicit_missing_bucket_is_failed_and_false_absence_is_refused(self):
        for success in [True, False]:
            response = {**existing.result(success, 'Absent' if success else 'Unverified'),
                        'read_status': 404, 'read_error_code': 'NoSuchBucket',
                        'reason': 'None' if success else 'Read_Failed', 's3_kind': 'Not_Found'}
            with self.subTest(success=success), tempfile.TemporaryDirectory() as tmp:
                args, helper = self.fixture(tmp, response)
                receipt = R.run(args, credential_loader=helper.credentials)
                self.assertEqual(receipt['phase'], 'READ_INTENT')
                self.assertFalse(receipt['qualified'])
                if success:
                    self.assertNotIn('read_result', receipt)
                else:
                    self.assertEqual(receipt['read_result']['read_error_code'], 'NoSuchBucket')
                self.assertNotIn('put_result', receipt)


if __name__ == '__main__':
    unittest.main()
