import json,os,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest import mock
import held_capture as H

class CaptureControls(unittest.TestCase):
    def assert_private(self,result):
        safe=result.safe();text=json.dumps(safe)
        self.assertNotIn('synthetic-secret',text)
        for key in safe:
            self.assertFalse(any(token in key for token in ['stdout','stderr','hash','length','token','expiration']))
        self.assertLess(len(text),1024)

    def test_actual_owned_clean_nonzero_and_exception_reaped(self):
        for mode,code in [('ok',0),('nonzero',254),('exception',1)]:
            result=H.capture([sys.executable,str(Path(__file__).with_name('owned_stub.py')),mode],
                {'PATH':'/usr/bin:/bin'},time.monotonic()+3)
            self.assertTrue(result.completed,result.safe());self.assertEqual(result.returncode,code)
            self.assertEqual(result.wait_state,'VerifiedReaped');self.assertEqual(H.live_members(result.pid),[])
            self.assert_private(result)

    def test_actual_owned_timeout_limit_and_closed_streams_reaped(self):
        for mode,failure in [('sleep','Deadline'),('limit','OutputLimit'),('closed','Deadline'),('descendant','Deadline')]:
            result=H.capture([sys.executable,str(Path(__file__).with_name('owned_stub.py')),mode],
                {'PATH':'/usr/bin:/bin'},time.monotonic()+.15)
            self.assertFalse(result.completed);self.assertEqual(result.failure_type,failure)
            self.assertEqual(result.wait_state,'VerifiedReaped');self.assertEqual(H.live_members(result.pid),[])
            self.assertEqual((result.stdout,result.stderr),(b'',b''));self.assert_private(result)

    def test_actual_permission_denied_has_no_child(self):
        with tempfile.TemporaryDirectory(prefix='owned-aws416-permission-') as directory:
            path=Path(directory)/'not-executable';path.write_text('synthetic');path.chmod(0o600)
            result=H.capture([str(path)],{},time.monotonic()+2)
        self.assertEqual((result.phase,result.failure_type,result.wait_state,result.pid),
                         ('Spawn','PermissionDenied','NotSpawned',None))
        self.assert_private(result)

    def fixture(self):
        child=mock.Mock(pid=123,returncode=None)
        selector=mock.Mock();selector.get_map.return_value={1:True}
        selector.select.side_effect=OSError('synthetic-secret')
        return child,selector

    def test_signal_permission_still_attempts_actual_reap(self):
        child,selector=self.fixture();order=[]
        def kill(*args):order.append('kill');raise PermissionError('synthetic-secret')
        def reap(*args):order.append('waitpid');child.returncode=-9;return -9
        with mock.patch.object(H.subprocess,'Popen',return_value=child),mock.patch.object(H.selectors,'DefaultSelector',return_value=selector),mock.patch.object(H,'observe',return_value=None),mock.patch.object(H,'live_members',return_value=[123]),mock.patch.object(H.os,'killpg',side_effect=kill),mock.patch.object(H,'reap',side_effect=reap):
            result=H.capture(['never-executed'],{},time.monotonic()+1)
        self.assertEqual(order,['kill','waitpid']);self.assertEqual(result.wait_state,'VerifiedReaped')
        self.assertEqual(result.cleanup_failure_type,'PermissionDenied');self.assertFalse(result.completed)
        self.assert_private(result)

    def test_wait_failure_does_not_attest_reap(self):
        child,selector=self.fixture()
        with mock.patch.object(H.subprocess,'Popen',return_value=child),mock.patch.object(H.selectors,'DefaultSelector',return_value=selector),mock.patch.object(H,'observe',return_value=None),mock.patch.object(H,'live_members',return_value=[123]),mock.patch.object(H.os,'killpg'),mock.patch.object(H,'reap',side_effect=TimeoutError()):
            result=H.capture(['never-executed'],{},time.monotonic()+1)
        self.assertEqual(result.wait_state,'Unverified');self.assertFalse(result.completed)

    def test_mock_echild_no_lookup_signal_wait_or_fabricated_code(self):
        for known_code in [None,0]:
            child,selector=self.fixture();child.returncode=known_code
            with mock.patch.object(H.subprocess,'Popen',return_value=child),mock.patch.object(H.selectors,'DefaultSelector',return_value=selector),mock.patch.object(H,'observe',side_effect=H.ReservationLost()),mock.patch.object(H,'live_members') as members,mock.patch.object(H.os,'killpg') as kill,mock.patch.object(H,'reap') as reap:
                result=H.capture(['never-executed'],{},time.monotonic()+1)
            members.assert_not_called();kill.assert_not_called();reap.assert_not_called()
            self.assertEqual((result.returncode,result.wait_state,result.reservation_state),(None,'Unverified','Lost'))
            self.assertEqual(child.returncode,-255);self.assertFalse(result.completed)

    def test_real_externally_reaped_child_echild_is_lost_not_verified(self):
        child=subprocess.Popen([sys.executable,'-c','pass'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        os.waitpid(child.pid,0)  # Deliberately external reap; Popen status remains unknown.
        self.assertIsNone(child.returncode)
        with mock.patch.object(H.subprocess,'Popen',return_value=child),mock.patch.object(H,'live_members') as members,mock.patch.object(H.os,'killpg') as kill,mock.patch.object(H,'reap') as reap:
            result=H.capture(['already-reaped-owned-stub'],{},time.monotonic()+1)
        members.assert_not_called();kill.assert_not_called();reap.assert_not_called()
        self.assertEqual((result.returncode,result.wait_state,result.reservation_state),(None,'Unverified','Lost'))
        self.assertEqual(child.returncode,-255);self.assert_private(result)

    def test_echild_during_wait_never_attests_or_signals_again(self):
        child,selector=self.fixture()
        with mock.patch.object(H.subprocess,'Popen',return_value=child),mock.patch.object(H.selectors,'DefaultSelector',return_value=selector),mock.patch.object(H,'observe',return_value=None),mock.patch.object(H,'live_members',return_value=[]) as members,mock.patch.object(H.os,'killpg') as kill,mock.patch.object(H,'reap',side_effect=H.ReservationLost()) as reap:
            result=H.capture(['never-executed'],{},time.monotonic()+1)
        self.assertEqual(members.call_count,1);kill.assert_not_called();self.assertEqual(reap.call_count,1)
        self.assertEqual((result.returncode,result.wait_state,result.reservation_state),(None,'Unverified','Lost'))

    def test_foreign_or_unknown_metadata_never_signals_but_owned_wait_attempted(self):
        child,selector=self.fixture()
        with mock.patch.object(H.subprocess,'Popen',return_value=child),mock.patch.object(H.selectors,'DefaultSelector',return_value=selector),mock.patch.object(H,'observe',return_value=None),mock.patch.object(H,'live_members',side_effect=H.MetadataFailure('Other')),mock.patch.object(H.os,'killpg') as kill,mock.patch.object(H,'reap',return_value=-9) as reap:
            result=H.capture(['never-executed'],{},time.monotonic()+1)
        kill.assert_not_called();reap.assert_called_once();self.assertFalse(result.completed)

    def test_ps_helper_close_faults_still_reap(self):
        for selector_fault,stream_fault in [(True,False),(False,True),(True,True)]:
            child=mock.Mock(pid=123,returncode=None);selector=mock.Mock();selector.get_map.return_value={}
            if selector_fault:selector.close.side_effect=OSError('synthetic-secret')
            if stream_fault:child.stdout.close.side_effect=OSError('synthetic-secret')
            with mock.patch.object(H.subprocess,'Popen',return_value=child),mock.patch.object(H.selectors,'DefaultSelector',return_value=selector),mock.patch.object(H,'observe',return_value=object()),mock.patch.object(H.os,'kill') as kill,mock.patch.object(H,'reap',return_value=0) as reap:
                with self.assertRaises(H.MetadataFailure):H.live_members(123)
            reap.assert_called_once();kill.assert_not_called()
            selector.close.assert_called_once();child.stdout.close.assert_called_once()

    def test_ps_helper_signal_and_wait_faults_are_contained(self):
        child=mock.Mock(pid=123,returncode=None);selector=mock.Mock();selector.get_map.return_value={}
        with mock.patch.object(H.subprocess,'Popen',return_value=child),mock.patch.object(H.selectors,'DefaultSelector',return_value=selector),mock.patch.object(H,'observe',side_effect=[object(),None]),mock.patch.object(H.os,'kill',side_effect=PermissionError()),mock.patch.object(H,'reap',side_effect=TimeoutError()) as reap:
            with self.assertRaises(H.MetadataFailure):H.live_members(123)
        reap.assert_called_once()

    def test_ps_helper_echild_never_signals_or_waits(self):
        child=mock.Mock(pid=123,returncode=None);selector=mock.Mock();selector.get_map.return_value={}
        with mock.patch.object(H.subprocess,'Popen',return_value=child),mock.patch.object(H.selectors,'DefaultSelector',return_value=selector),mock.patch.object(H,'observe',side_effect=H.ReservationLost()),mock.patch.object(H.os,'kill') as kill,mock.patch.object(H,'reap') as reap:
            with self.assertRaises(H.MetadataFailure):H.live_members(123)
        kill.assert_not_called();reap.assert_not_called();self.assertEqual(child.returncode,-255)

    def test_actual_reap_observes_echild_without_fabricating_status(self):
        child=mock.Mock(pid=123,returncode=None)
        with mock.patch.object(H.os,'waitpid',side_effect=ChildProcessError()):
            with self.assertRaises(H.ReservationLost):H.reap(child,time.monotonic()+1)
        self.assertIsNone(child.returncode)

class ObservationFaultControls(unittest.TestCase):
    def test_primary_non_echild_observation_fault_retains_owned_wait(self):
        for failure in [PermissionError(),OSError('synthetic')]:
            for location in ['try','finally']:
                child=mock.Mock(pid=123,returncode=None);selector=mock.Mock()
                selector.get_map.return_value={} if location=='try' else {1:True}
                selector.select.side_effect=OSError('synthetic read failure')
                with mock.patch.object(H.subprocess,'Popen',return_value=child),mock.patch.object(H.selectors,'DefaultSelector',return_value=selector),mock.patch.object(H,'observe',side_effect=failure),mock.patch.object(H,'live_members') as members,mock.patch.object(H.os,'killpg') as kill,mock.patch.object(H,'disown') as disown,mock.patch.object(H,'reap',return_value=0) as reap:
                    result=H.capture(['never-executed'],{},time.monotonic()+1)
                members.assert_not_called();kill.assert_not_called();disown.assert_not_called();reap.assert_called_once()
                self.assertFalse(result.completed);self.assertEqual(result.wait_state,'VerifiedReaped')
                self.assertEqual(result.reservation_state,'Reaped')

    def test_ps_helper_non_echild_observation_fault_retains_owned_wait(self):
        for failure in [PermissionError(),OSError('synthetic')]:
            for location in ['try','finally']:
                child=mock.Mock(pid=123,returncode=None);selector=mock.Mock();selector.get_map.return_value={}
                outcomes=[failure] if location=='try' else [object(),failure]
                with mock.patch.object(H.subprocess,'Popen',return_value=child),mock.patch.object(H.selectors,'DefaultSelector',return_value=selector),mock.patch.object(H,'observe',side_effect=outcomes),mock.patch.object(H.os,'kill') as kill,mock.patch.object(H,'disown') as disown,mock.patch.object(H,'reap',return_value=0) as reap:
                    with self.assertRaises(H.MetadataFailure):H.live_members(123)
                kill.assert_not_called();disown.assert_not_called();reap.assert_called_once()

if __name__=='__main__':unittest.main()
