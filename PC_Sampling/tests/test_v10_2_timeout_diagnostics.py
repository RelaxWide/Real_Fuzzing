"""Timeout diagnostics with fake PC reads and ordinary host subprocesses only."""
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import tracemalloc
import unittest
from unittest.mock import Mock, patch

from test_v10_2_learning import fuzzer


class TimeoutDiagnosticsTests(unittest.TestCase):
    def make_fuzzer(self):
        inst = fuzzer.NVMeFuzzer.__new__(fuzzer.NVMeFuzzer)
        inst._log_process_memory = Mock()
        return inst

    def test_monitor_caps_failures_and_successes_at_twenty(self):
        for pcs in (None, [0x1000]):
            with self.subTest(pcs=pcs):
                inst = self.make_fuzzer()
                read = Mock(return_value=pcs)
                stop = Mock()
                stop.is_set.return_value = False
                stop.wait.return_value = False
                inst._monitor_timeout_pc(read, stop, {0x1000})
                self.assertEqual(read.call_count, 20)
                self.assertEqual(stop.wait.call_count, 19)
                stop.wait.assert_called_with(30.0)
                self.assertEqual(inst._log_process_memory.call_count, 40)

    def test_monitor_stop_before_read_and_during_wait(self):
        inst = self.make_fuzzer()
        read = Mock(return_value=None)
        stop = threading.Event()
        stop.set()
        inst._monitor_timeout_pc(read, stop, set())
        read.assert_not_called()
        stop = Mock()
        stop.is_set.return_value = False
        stop.wait.return_value = True
        inst._monitor_timeout_pc(read, stop, set())
        read.assert_called_once()
        stop.wait.assert_called_once()

    def test_newline_free_output_has_bounded_python_memory(self):
        # 32 MiB without a newline; do not allocate the whole input in the test.
        with tempfile.TemporaryFile() as stream:
            for _ in range(8192):
                stream.write(b'x' * 4096)
            stream.seek(0)
            tracemalloc.start()
            try:
                total = 0
                for line in fuzzer._bounded_output_lines(stream.fileno()):
                    self.assertLessEqual(len(line), 8192)
                    total += len(line)
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            self.assertEqual(total, 32 * 1024 * 1024)
            self.assertLess(peak, 256 * 1024)

    def test_stream_preserves_cr_lf_partial_lines_and_pty_eof(self):
        chunks = iter([b'a\rb\npar', b'tial', b''])
        with patch.object(fuzzer.os, 'read', side_effect=lambda *args: next(chunks)):
            self.assertEqual(list(fuzzer._bounded_output_lines(123)), [b'a', b'b', b'partial'])
        with patch.object(fuzzer.os, 'read', side_effect=[b'tail', OSError(5, 'PTY EOF')]):
            self.assertEqual(list(fuzzer._bounded_output_lines(123)), [b'tail'])
        with patch.object(fuzzer.os, 'read', side_effect=OSError(9, 'bad FD')):
            with self.assertRaises(OSError):
                list(fuzzer._bounded_output_lines(123))

    def test_dump_output_goes_to_disk_without_parent_pipes(self):
        inst = self.make_fuzzer()
        with tempfile.TemporaryDirectory() as folder:
            inst.output_dir = Path(folder)
            code = "import os; os.write(1,b'x'*1048576); os.write(2,b'END')"
            proc = inst._spawn_dump_logged([sys.executable, '-c', code], 'TEST_DUMP')
            try:
                self.assertIsNone(proc.stdout)
                self.assertIsNone(proc.stderr)
                self.assertEqual(proc.wait(timeout=10), 0)
                files = list(Path(folder).glob('TEST_DUMP_*.log'))
                self.assertEqual(len(files), 1)
                self.assertEqual(files[0].stat().st_size, 1048579)
                with files[0].open('rb') as stream:
                    stream.seek(-3, io.SEEK_END)
                    self.assertEqual(stream.read(), b'END')
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=5)

    def test_process_memory_records_pid_and_rss_without_hardware(self):
        inst = fuzzer.NVMeFuzzer.__new__(fuzzer.NVMeFuzzer)
        with tempfile.TemporaryDirectory() as folder:
            inst.output_dir = Path(folder)
            inst._log_process_memory('timeout-entry')
            row = json.loads((inst.output_dir / 'process_memory.jsonl').read_text())
            self.assertEqual(row['processes']['fuzzer']['pid'], os.getpid())
            self.assertGreater(row['processes']['fuzzer']['VmRSS'], 0)
            self.assertEqual(row['stage'], 'timeout-entry')


if __name__ == '__main__':
    unittest.main()
