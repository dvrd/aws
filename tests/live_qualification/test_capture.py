"""Mocked process-ownership controls: no CLI, native binary or network execution."""
import subprocess
import types
import unittest
from unittest import mock
import test_runner

R = test_runner.R


class Capture(unittest.TestCase):
    def fixture(self):
        child = mock.Mock(pid=123, returncode=None)
        def wait(timeout):
            child.returncode = 0
            return 0
        child.wait.side_effect = wait
        selector = mock.Mock()
        selector.get_map.side_effect = [{1: True}, {1: True}, {}]
        selector.select.return_value = [(types.SimpleNamespace(fd=17), None)]
        return child, selector

    def launch(self, child, selector, chunks=(b'owned', b''), clock=0, limit=32):
        return mock.patch.multiple(R, subprocess=mock.Mock(Popen=mock.Mock(return_value=child),
            DEVNULL=subprocess.DEVNULL, PIPE=subprocess.PIPE),
            selectors=mock.Mock(DefaultSelector=mock.Mock(return_value=selector), EVENT_READ=1)), \
            mock.patch.object(R.os, 'read', side_effect=chunks), \
            mock.patch.object(R.time, 'monotonic', return_value=clock)

    def test_success_reaped_child_is_never_signalled(self):
        child, selector = self.fixture()
        patches = self.launch(child, selector)
        with patches[0], patches[1], patches[2], mock.patch.object(R.os, 'killpg') as kill:
            self.assertEqual(R.capture(['synthetic'], {}, 10), (0, b'owned'))
        kill.assert_not_called()
        child.wait.assert_called_once()
        child.stdout.close.assert_called_once()

    def test_timeout_signals_unreaped_child_before_wait(self):
        child, selector = self.fixture(); order = []
        def wait(timeout):
            order.append('wait'); child.returncode = -9; return -9
        child.wait.side_effect = wait
        patches = self.launch(child, selector, clock=10)
        with patches[0], patches[1], patches[2], \
             mock.patch.object(R.os, 'killpg', side_effect=lambda *a: order.append('kill')):
            with self.assertRaisesRegex(R.Failure, 'CHILD_DEADLINE'):
                R.capture(['synthetic'], {}, 10)
        self.assertEqual(order, ['kill', 'wait'])
        child.stdout.close.assert_called_once()

    def test_output_overflow_reaps_owned_child_without_replay(self):
        child, selector = self.fixture()
        patches = self.launch(child, selector, chunks=(b'x' * 33,))
        with patches[0], patches[1], patches[2], mock.patch.object(R.os, 'killpg') as kill:
            with self.assertRaisesRegex(R.Failure, 'CHILD_OUTPUT_LIMIT'):
                R.capture(['synthetic'], {}, 10, 32)
        kill.assert_called_once_with(child.pid, R.signal.SIGKILL)
        child.wait.assert_called_once_with(timeout=5)
        child.stdout.close.assert_called_once()

    def test_already_exited_group_still_reaps_held_child(self):
        child, selector = self.fixture(); patches = self.launch(child, selector, clock=10)
        with patches[0], patches[1], patches[2], \
             mock.patch.object(R.os, 'killpg', side_effect=ProcessLookupError):
            with self.assertRaisesRegex(R.Failure, 'CHILD_DEADLINE'):
                R.capture(['synthetic'], {}, 10)
        child.wait.assert_called_once_with(timeout=5)
        child.stdout.close.assert_called_once()

    def test_exception_after_wait_reaped_child_cannot_signal_reused_pid(self):
        child, selector = self.fixture()
        def wait(timeout):
            child.returncode = 0
            raise ValueError('synthetic post-reap observer error')
        child.wait.side_effect = wait
        patches = self.launch(child, selector)
        with patches[0], patches[1], patches[2], mock.patch.object(R.os, 'killpg') as kill:
            with self.assertRaises(ValueError): R.capture(['synthetic'], {}, 10)
        kill.assert_not_called()
        child.stdout.close.assert_called_once()

    def test_failed_cleanup_wait_still_closes_pipe(self):
        child, selector = self.fixture()
        child.wait.side_effect = subprocess.TimeoutExpired('synthetic', 5)
        patches = self.launch(child, selector, clock=10)
        with patches[0], patches[1], patches[2], mock.patch.object(R.os, 'killpg'):
            with self.assertRaises(subprocess.TimeoutExpired): R.capture(['synthetic'], {}, 10)
        child.stdout.close.assert_called_once()


if __name__ == '__main__': unittest.main()
