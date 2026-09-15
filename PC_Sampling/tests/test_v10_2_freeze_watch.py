"""Independent observer and best-effort instrumentation, without SSD access."""
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_v10_2_learning import fuzzer


class FreezeWatchTests(unittest.TestCase):
    def test_disabled_does_nothing(self):
        with patch.object(fuzzer, '_freeze_trace', None):
            fuzzer._freeze_emit('test', argv=['nvme'])

    def test_delivery_failure_preserves_return_and_exception(self):
        trace = fuzzer._FreezeTrace(47471)
        trace.sock.close()
        trace.sock = Mock()
        trace.sock.sendto.side_effect = BlockingIOError()
        obj = SimpleNamespace(work=Mock(return_value=42))
        trace.wrap(obj, 'work', 'work')
        self.assertEqual(obj.work('a', x=1), 42)
        obj.work.__wrapped__.assert_called_once_with('a', x=1)
        self.assertEqual(trace.dropped, 2)
        self.assertEqual(trace.local.stack, [])
        obj.work.__wrapped__.side_effect = ValueError('actual failure')
        with self.assertRaisesRegex(ValueError, 'actual failure'):
            obj.work()
        self.assertEqual(trace.local.stack, [])

    def test_oversized_payload_is_dropped_not_queued(self):
        trace = fuzzer._FreezeTrace(47471)
        try:
            with patch.object(trace, 'sock') as sock:
                trace.emit('oversize', value='a' * 9000)
                sock.sendto.assert_not_called()
            self.assertEqual(trace.dropped, 1)
        finally:
            trace.close()

    def test_proc_snapshot_includes_host_and_child_limits(self):
        result = fuzzer._freeze_proc_snapshot(os.getpid())
        self.assertTrue(result['main']['alive'])
        self.assertIn('MemAvailable', result['memory'])
        self.assertLessEqual(len(result['threads']), 32)
        self.assertLessEqual(len(result['children']), 16)
        self.assertFalse(fuzzer._freeze_proc_snapshot(2147483647)['main']['alive'])

    def test_watcher_runs_without_config_and_keeps_reporting_when_sender_stops(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / 'fuzzer.py'
            script.write_text(Path(fuzzer.__file__).read_text())
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
                reserve.bind(('127.0.0.1', 0))
                port = reserve.getsockname()[1]
            proc = subprocess.Popen([sys.executable, str(script), '--freeze-watch', '--port', str(port)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            trace = fuzzer._FreezeTrace(port)
            try:
                ready, _, _ = select.select([proc.stdout], [], [], 5)
                self.assertTrue(ready, 'watcher startup timed out')
                self.assertIn(b'ready port=', proc.stdout.readline())
                trace.emit('nvme.before_popen', argv=['nvme', 'io-passthru', '--opcode=2'])
                # No more sender events: independent heartbeats must continue.
                time.sleep(2.3)
                proc.send_signal(signal.SIGINT)
                out, err = proc.communicate(timeout=5)
                self.assertEqual(proc.returncode, 0, err.decode())
                rows = [json.loads(line) for line in out.splitlines()]
                self.assertGreaterEqual(len(rows), 2)
                self.assertEqual(rows[-1]['received'], 1)
                self.assertGreater(rows[-1]['age_s'], rows[0]['age_s'])
                self.assertEqual(rows[-1]['last_nvme']['argv'][-1], '--opcode=2')
                self.assertTrue(rows[-1]['host']['main']['alive'])
            finally:
                trace.close()
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate()
