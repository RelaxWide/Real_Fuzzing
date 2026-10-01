"""Action attribution and readiness diagnostics without device operations."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from test_v11_exceptions import options
import fuzzer_target                                       # noqa: F401,E402  (파일 경로로 대상 퍼저 로드)
from fuzzer_active_test import ExceptionController, ExceptionFailure


class Diagnostics(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.now = 0.0
        self.c = ExceptionController(options(), {}, str(self.root / 'device'), '',
                                     self.root / 'events', clock=lambda: self.now)
        self.c.serial, self.c.bdf = 'DUT', '0000:02:00.0'
        self.c.sysfs = self.root / 'sysfs'
        self.c.sysfs.mkdir()
        for name, value in (('serial', 'DUT'), ('address', self.c.bdf), ('state', 'connecting')):
            (self.c.sysfs / name).write_text(value)
        Path(self.c.device).touch()
        self.c.runner = Mock()
        self.c.active = 'preflight-flr'
        self.c.last_result = dict(event_id=self.c.active, profile='flr', stage='ready_after_profile',
                                  action='flr', index=0)

    def sleep(self, seconds):
        self.now += seconds

    def test_timeout_identifies_gate_and_last_state(self):
        cases = [('connecting', True, 0, b'{"csts":0}', 'driver_not_live'),
                 ('live', False, 0, b'{"csts":0}', 'device_node_missing'),
                 ('live', True, 0, b'{"csts":0}', 'controller_rdy'),
                 ('live', True, 1, b'', 'show_regs_failed')]
        for state, exists, rc, out, gate in cases:
            with self.subTest(gate=gate):
                self.now = 0
                (self.c.sysfs / 'state').write_text(state)
                if exists:
                    Path(self.c.device).touch()
                else:
                    Path(self.c.device).unlink()
                self.c.runner.reset_mock()
                self.c.runner.run.return_value = (rc, out, b'probe-error' if rc else b'')
                with patch('fuzzer_active_test.time.sleep', side_effect=self.sleep):
                    with self.assertLogs('pcfuzz', level='WARNING') as logs:
                        with self.assertRaisesRegex(ExceptionFailure, gate):
                            self.c.wait_ready(0.1)
                text = '\n'.join(logs.output)
                self.assertIn('[ready]', text)
                self.assertIn('한도 초과', text)
                # 사람용 줄에 JSON 덤프가 새지 않는다
                self.assertNotIn('{"', text)
                self.assertNotIn('\\"', text)
                if state != 'live' or not exists:
                    self.c.runner.run.assert_not_called()
                rows = [json.loads(line) for line in self.c.log_path.read_text().splitlines()]
                self.assertEqual(rows[-1]['phase'], 'ready_timeout')
                self.assertEqual(rows[-1]['profile'], 'flr')
                if rc:
                    self.assertEqual(rows[-1]['stderr'], 'probe-error')

    def test_capture_keeps_event_after_active_cleared(self):
        self.c.active = None
        with self.assertLogs('pcfuzz', level='WARNING') as logs:
            self.c.emit('capture', reason='timeout', directory='out/crashes/exception_x')
        self.assertIn('증거 폴더: out/crashes/exception_x', '\n'.join(logs.output))
        row = json.loads(self.c.log_path.read_text())
        self.assertEqual(row['event_id'], 'preflight-flr')
        self.assertEqual(row['action'], 'flr')

    def test_action_command_is_logged_before_launch(self):
        def execute(argv, deadline, **kwargs):
            rows = [json.loads(line) for line in self.c.log_path.read_text().splitlines()]
            self.assertEqual(rows[-1]['phase'], 'action_command')
            self.assertEqual(rows[-1]['argv'], argv)
            raise ExceptionFailure('helper stopped')
        self.c.runner.run.side_effect = execute
        with self.assertLogs('pcfuzz', level='WARNING') as logs:
            with self.assertRaisesRegex(ExceptionFailure, 'helper stopped'):
                self.c._action('controller_reset', 1)
        self.assertIn('controller_reset : nvme reset', '\n'.join(logs.output))
