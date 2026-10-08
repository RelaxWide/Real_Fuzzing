"""v11.2 — PM preflight 무응답 멈춤 방지와 실패 시 중단·현상 보존.

예전: 장치 nvme 호출이 subprocess.run(timeout) 이라 D 상태에 묶이면 kill 뒤 wait 에서 영원히 멈췄고,
복귀 실패·NVMe 무응답이어도 다음 조합으로 넘어가 결국 퍼징까지 들어갔다(항상 True).
지금: D 상태 안전 래퍼(_pm_nvme_run)로 보내고, 복귀 실패·복귀 뒤 NVMe 실패·무응답이면
_pm_preflight_fail 로 crash_<ts>/ 에 증거를 남기고 False — run() 은 그 자리에서 return 한다.
진입 실패만 난 조합(복귀·NVMe 정상)은 예전처럼 FAIL 표시 후 계속한다.
"""
import ast
import json
import tempfile
import time
import unittest
from collections import deque
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fuzzer_target import FUZZER_FILE, fuzzer as v

TIMEOUT = v._StateProc(-1, b'', b'timeout')
OK = v._StateProc(0, b'', b'')
ERR = v._StateProc(1, b'', b'NVMe status: INTERNAL')


def _engine(tmp):
    f = v.NVMeFuzzer.__new__(v.NVMeFuzzer)
    f.config = SimpleNamespace(pm_inject_prob=0.1, nvme_device='/dev/nvme0',
                               enable_jlink_dump=False, enable_ufas=False,
                               enable_debug_tool_dump=False)
    f._ps_settle = dict(v._PS_SETTLE_FALLBACK)
    f._pm_unresponsive = None
    f._timeout_crash = False
    f._fw_hang_captured = False
    f.crashes_dir = Path(tmp)
    f._cmd_history = deque(maxlen=100)
    f._log_file = None
    f.sampler = MagicMock(USES_JLINK_USB=False)
    f._pcie_bdf = '0000:01:00.0'
    f._pcie_cap_offset = 0x70
    for name in ('_init_ps_settle', '_generate_replay_sh', '_collect_crash_artifacts',
                 '_shutdown_openocd_for_jlink', '_snapshot_crash_context'):
        setattr(f, name, MagicMock())
    f._dump_snapshot = MagicMock(return_value={})
    f._pm_d3_safe_restore = MagicMock(return_value=True)
    f._set_pcie_l_state = MagicMock(return_value=True)
    f._pm_set_state = MagicMock(return_value=True)
    f._pm_verify_combo = MagicMock(return_value={'pmu': '1', 'nvme_ps': 'PS0 OK'})
    f._pm_nvme_run = MagicMock(return_value=OK)
    return f


def _capture(tmp):
    dirs = [d for d in Path(tmp).iterdir() if d.name.startswith('crash_')]
    return json.loads((dirs[0] / 'pm_preflight.json').read_text(encoding='utf-8')) if dirs else None


@patch('fuzzer_active_test.time.sleep')
class ComboPreflight(unittest.TestCase):
    def test_all_ok_continues(self, _):
        with tempfile.TemporaryDirectory() as tmp:
            f = _engine(tmp)
            f._set_power_combo = MagicMock(return_value=True)
            self.assertTrue(f._pm_preflight_check())
            self.assertFalse(f._timeout_crash)
            self.assertIsNone(_capture(tmp))

    def test_entry_fail_only_is_reported_and_continues(self, _):
        # 진입 실패지만 복귀·NVMe 정상 → 예전처럼 다음 조합으로(모든 조합을 돈다)
        with tempfile.TemporaryDirectory() as tmp:
            f = _engine(tmp)
            f._set_power_combo = MagicMock(side_effect=lambda c: c is v.POWER_COMBOS[0])
            self.assertTrue(f._pm_preflight_check())
            self.assertFalse(f._timeout_crash)
            entered = [c.args[0] for c in f._set_power_combo.call_args_list
                       if c.args[0] is not v.POWER_COMBOS[0]]
            self.assertEqual(len(entered), len(v.POWER_COMBOS) - 1)

    def test_hang_on_entry_stops_without_more_device_commands(self, _):
        with tempfile.TemporaryDirectory() as tmp:
            f = _engine(tmp)

            def hang(combo):
                f._pm_unresponsive = 'nvme admin-passthru 가 5s 안에 응답하지 않음'
                return False
            f._set_power_combo = MagicMock(side_effect=hang)
            self.assertFalse(f._pm_preflight_check())
            self.assertEqual(f._set_power_combo.call_count, 1)      # 복귀(baseline) 안 보냄
            f._pm_verify_combo.assert_not_called()
            f._pm_d3_safe_restore.assert_not_called()               # 최종 복귀도 안 보냄
            f._pm_nvme_run.assert_not_called()                      # id-ctrl 폴백도 안 보냄
            self.assertTrue(f._timeout_crash)
            meta = _capture(tmp)
            self.assertEqual((meta['crash_reason'], meta['stage']), ('pm_preflight', '진입'))
            self.assertIn('응답하지 않음', meta['reason'])
            f._generate_replay_sh.assert_called_once()

    def test_restore_failure_stops_at_that_combo(self, _):
        with tempfile.TemporaryDirectory() as tmp:
            f = _engine(tmp)
            f._set_power_combo = MagicMock(side_effect=lambda c: c is not v.POWER_COMBOS[0])
            self.assertFalse(f._pm_preflight_check())
            self.assertEqual(f._set_power_combo.call_count, 2)      # 첫 조합 진입 + 복귀 실패
            meta = _capture(tmp)
            self.assertEqual(meta['stage'], '복귀')
            self.assertEqual(len(meta['results']), 1)
            self.assertFalse(meta['results'][0]['restore'])

    def test_nvme_dead_after_restore_stops(self, _):
        with tempfile.TemporaryDirectory() as tmp:
            f = _engine(tmp)
            f._set_power_combo = MagicMock(return_value=True)
            f._pm_verify_combo = MagicMock(return_value={'pmu': '1', 'nvme_ps': 'FAIL(rc=1) x'})
            f._pm_nvme_run = MagicMock(return_value=ERR)            # id-ctrl 폴백도 실패
            self.assertFalse(f._pm_preflight_check())
            self.assertEqual(_capture(tmp)['stage'], '복귀 확인')

    def test_unresponsive_settle_probe_stops_before_any_combo(self, _):
        with tempfile.TemporaryDirectory() as tmp:
            f = _engine(tmp)
            f._set_power_combo = MagicMock(return_value=True)
            f._init_ps_settle = MagicMock(
                side_effect=lambda: setattr(f, '_pm_unresponsive', 'nvme id-ctrl 무응답'))
            self.assertFalse(f._pm_preflight_check())
            f._set_power_combo.assert_not_called()
            self.assertEqual(_capture(tmp)['stage'], 'PS settle 계산(id-ctrl)')

    def test_dumps_follow_product_flags(self, _):
        with tempfile.TemporaryDirectory() as tmp:
            f = _engine(tmp)
            f.config.enable_ufas = True
            f._run_ufas_dump = MagicMock()
            f._run_jlink_dump = MagicMock()
            f._set_power_combo = MagicMock(side_effect=lambda c: c is not v.POWER_COMBOS[0])
            f._pm_preflight_check()
            f._run_ufas_dump.assert_called_once()
            f._run_jlink_dump.assert_not_called()
            f._collect_crash_artifacts.assert_called_once()


@patch('fuzzer_active_test.time.sleep')
class S1S2Preflight(unittest.TestCase):
    def _s1s2(self, tmp):
        f = _engine(tmp)
        f._pm_perturb_target_cap_offset = MagicMock(return_value=0x100)
        f._setpci_read = MagicMock(return_value=0)
        f._setpci_write = MagicMock(return_value=True)
        f._pm_perturb_pmcsr_forced = MagicMock(return_value=True)
        f._pm_perturb_clkreq = MagicMock(return_value=True)
        return f

    def test_alive_returns_true(self, _):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(self._s1s2(tmp)._pm_preflight_s1_s2())

    def test_item_failure_with_live_device_continues(self, _):
        with tempfile.TemporaryDirectory() as tmp:
            f = self._s1s2(tmp)
            f._setpci_write = MagicMock(return_value=False)        # 쓰기 실패 = 항목 FAIL 만
            self.assertTrue(f._pm_preflight_s1_s2())
            self.assertFalse(f._timeout_crash)

    def test_dead_device_stops(self, _):
        with tempfile.TemporaryDirectory() as tmp:
            f = self._s1s2(tmp)
            f._pm_nvme_run = MagicMock(side_effect=lambda cmd, t: (
                setattr(f, '_pm_unresponsive', 'nvme id-ctrl 무응답') or TIMEOUT))
            self.assertFalse(f._pm_preflight_s1_s2())
            self.assertEqual(f._pm_nvme_run.call_count, 1)          # 첫 항목에서 멈춤
            meta = _capture(tmp)
            self.assertEqual(meta['kind'], 'PM-Preflight S1/S2')
            self.assertIn('무응답', meta['reason'])


class Runner(unittest.TestCase):
    def test_hung_child_is_abandoned_and_recorded(self):
        f = v.NVMeFuzzer.__new__(v.NVMeFuzzer)
        f._pm_unresponsive = None
        f._cmd_history = v._CmdHistory()
        t0 = time.monotonic()
        r = f._pm_nvme_run(['sleep', '30'], 0.3)
        self.assertLess(time.monotonic() - t0, 5.0)
        self.assertTrue(f._pm_timed_out(r))
        self.assertIn('응답하지 않음', f._pm_unresponsive)

    def test_error_is_not_unresponsive(self):
        f = v.NVMeFuzzer.__new__(v.NVMeFuzzer)
        f._pm_unresponsive = None
        f._cmd_history = v._CmdHistory()
        f._pm_nvme_run(['false'], 5.0)
        self.assertIsNone(f._pm_unresponsive)
        self.assertEqual((f._cmd_history[-1]['argv'], f._cmd_history[-1]['rc']), (['false'], 1))

    def test_set_state_timeout_returns_false(self):
        f = v.NVMeFuzzer.__new__(v.NVMeFuzzer)
        f._pm_unresponsive = None
        f._cmd_history = v._CmdHistory()
        f.config = SimpleNamespace(nvme_device='/dev/nvme0')
        f._cmd_history = deque(maxlen=10)
        with patch('fuzzer_active_test._run_nvme_state_cmd', return_value=TIMEOUT):
            self.assertFalse(f._pm_set_state(4))
        self.assertIsNotNone(f._pm_unresponsive)


class Wiring(unittest.TestCase):
    SRC = FUZZER_FILE.read_text(encoding='utf-8')

    def _func(self, name):
        tree = ast.parse(self.SRC)
        return next(n for c in tree.body if isinstance(c, ast.ClassDef)
                    for n in c.body if isinstance(n, ast.FunctionDef) and n.name == name)

    def test_pm_preflight_paths_do_not_use_subprocess_run(self):
        for name in ('_pm_set_state', '_init_ps_settle', '_pm_preflight_check',
                     '_pm_preflight_s1_s2'):
            calls = [(n.func.value.id, n.func.attr) for n in ast.walk(self._func(name))
                     if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                     and isinstance(n.func.value, ast.Name)]
            self.assertNotIn(('subprocess', 'run'), calls, name)
        verify = ast.get_source_segment(self.SRC, self._func('_pm_verify_combo'))
        self.assertIn("self._pm_nvme_run(\n                    ['nvme', 'get-feature'", verify)

    def test_run_returns_when_preflight_fails(self):
        run = next(n for c in ast.parse(self.SRC).body if isinstance(c, ast.ClassDef)
                   for n in c.body if isinstance(n, ast.FunctionDef) and n.name == 'run'
                   and '_pm_preflight_check' in ast.get_source_segment(self.SRC, n))
        body = ast.get_source_segment(self.SRC, run)
        self.assertIn('if not self._pm_preflight_check():\n                return', body)
        self.assertIn('and not self._pm_preflight_s1_s2():\n                return', body)

    @patch('fuzzer_active_test.time.sleep')
    def test_pm_test_mode_stops_on_failure(self, _):
        f = v.NVMeFuzzer.__new__(v.NVMeFuzzer)
        f.config = SimpleNamespace(pm_inject_prob=0.1, enable_por=False, pm_test_cycles=5)
        f._pcie_bdf = None
        f._pcie_cap_offset = None
        for name in ('_detect_pcie_info', '_apst_disable', '_keepalive_disable',
                     '_pm_preflight_s1_s2', '_set_power_combo'):
            setattr(f, name, MagicMock())
        f._pm_preflight_check = MagicMock(return_value=False)
        f._run_pm_openocdless_test()
        f._pm_preflight_s1_s2.assert_not_called()
        f._set_power_combo.assert_not_called()


if __name__ == '__main__':
    unittest.main()
