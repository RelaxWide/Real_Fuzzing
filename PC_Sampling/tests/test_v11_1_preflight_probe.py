"""v11.1 — Pre-flight 첫 장치 명령 전 응답 확인.

최신 FW BM9K1: 'LBA size 자동 감지' 다음 id-ctrl 이 무응답 장치에서 커널(D 상태)에 묶이면
subprocess.run(timeout) 이 kill 뒤 끝없이 기다려 Pre-flight 가 멈췄다. 첫 장치 명령 전에
D 상태 안전 래퍼로 nvme_timeouts.command 안에 응답하는지 묻고, 없으면 중단한다.
"""
import ast
import time
import unittest

from fuzzer_target import FUZZER_FILE
from test_v10_2_learning import fuzzer


def _run_source():
    src = FUZZER_FILE.read_text(encoding='utf-8')
    tree = ast.parse(src)
    run = next(n for c in tree.body if isinstance(c, ast.ClassDef)
               for n in c.body if isinstance(n, ast.FunctionDef) and n.name == 'run'
               and any(isinstance(a, ast.Call) and getattr(a.func, 'attr', '') == '_snapshot_ctrl_info'
                       for a in ast.walk(n)))
    return ast.get_source_segment(src, run)


class PreflightProbe(unittest.TestCase):
    def test_probe_runs_before_any_device_command(self):
        body = _run_source()
        probe = body.find("_run_nvme_state_cmd(['nvme', 'id-ctrl', self._ctrl_device()]")
        self.assertGreater(probe, 0, 'Pre-flight 응답 확인이 없다')
        for later in ('self._discover_active_nsids()', 'self._detect_lba_size()',
                      'self._snapshot_ctrl_info()'):
            self.assertGreater(body.find(later), probe, f'{later} 가 응답 확인보다 앞에 있다')

    def test_probe_uses_config_command_timeout_and_aborts(self):
        body = _run_source()
        start = body.find("_probe_ms = self.config.nvme_timeouts.get('command'")
        self.assertGreater(start, 0, 'timeout 이 nvme_timeouts.command 가 아니다')
        block = body[start:body.find('if (NSID_OVERRIDE_POLICY', start)]
        self.assertIn('timeout_sec=_probe_ms / 1000.0', block)
        self.assertIn('return', block)                     # 무응답이면 중단

    def test_wrapper_returns_without_waiting_for_hung_child(self):
        t0 = time.monotonic()
        r = fuzzer._run_nvme_state_cmd(['sleep', '30'], timeout_sec=0.3)
        self.assertLess(time.monotonic() - t0, 5.0)
        self.assertEqual((r.returncode, r.stderr), (-1, b'timeout'))


if __name__ == '__main__':
    unittest.main()
