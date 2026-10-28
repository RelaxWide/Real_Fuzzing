"""v11.2.1 — BM9K1: PM 동작 중 디버그 세션 분리.

디버거 세션이 열린 채 PS4 에 들어가면 admin 명령이 멈췄다(--no-jlink 면 정상, 퍼저를 끄고 J-Link 가 닫힌
뒤의 replay 도 정상). 모든 PM 동작을 세션을 닫고(sampler.close) 한 뒤 기존 재연결 경로(sampler._reconnect)로
다시 붙인다. 동작 상태 조합은 그 상태로 퍼징을 잇고, 깊은 상태(PS3/PS4·D3·L1.2)는 붙이기 전에 빠져나온다.
복귀·APST 해제가 실패하거나 무응답이면 다시 붙이지 않고 현상 보존·중단한다(리뷰 P1 2건).
"""
import ast
import json
from collections import defaultdict
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from fuzzer_target import FUZZER_FILE, fuzzer as v

C = v.POWER_COMBOS
PS4_L0 = next(c for c in C if c.nvme_ps == 4 and c.pcie_l == v.PCIeLState.L0 and c.pcie_d == v.PCIeDState.D0)
PS4_L12 = next(c for c in C if c.nvme_ps == 4 and c.pcie_l == v.PCIeLState.L1_2 and c.pcie_d == v.PCIeDState.D0)
PS1_D3 = next(c for c in C if c.nvme_ps == 1 and c.pcie_d == v.PCIeDState.D3)
OP = next(c for c in C if c.nvme_ps == 1 and c.pcie_l == v.PCIeLState.L1 and c.pcie_d == v.PCIeDState.D0)
OP2 = next(c for c in C if c.nvme_ps == 2 and c.pcie_l == v.PCIeLState.L0 and c.pcie_d == v.PCIeDState.D0)
PS1_L12 = next(c for c in C if c.nvme_ps == 1 and c.pcie_l == v.PCIeLState.L1_2 and c.pcie_d == v.PCIeDState.D0)
OK = v._StateProc(0, b'', b'')


def engine(enabled=True, reconnect_ok=True, reauth=0, close_ok=True):
    f = v.NVMeFuzzer.__new__(v.NVMeFuzzer)
    ev = []
    f.config = SimpleNamespace(pm_detach_sampler=enabled, nvme_device='/dev/nvme0')
    f._pm_detached = False
    f._pm_unresponsive = None
    f._pm_detach_stats = dict(count=0, reattach_fail=0, reattach_s=0.0, reauth=0)
    f._sampler_recovery_failed = False
    f._ps_settle = {4: 2.0, 3: 0.5}
    f._prev_op_combo, f._prev_op_ps = OP, 1
    f._current_combo, f._current_ps = OP, 1
    f.ps_enter_counts = defaultdict(int)
    f.combo_enter_counts = defaultdict(int)
    f._orig_apst_cdw11 = 0
    f._pcie_bdf = None
    f._record_setfeature_history = MagicMock()

    def close():
        ev.append('detach')
        if close_ok:
            f.sampler.session.lk.jl = None

    def reconnect():
        ev.append('attach')
        f.sampler.session = SimpleNamespace(auth_count=reauth, lk=SimpleNamespace(jl=object()))
        return reconnect_ok
    f.sampler = SimpleNamespace(close=close, _reconnect=reconnect,
                                session=SimpleNamespace(auth_count=0, lk=SimpleNamespace(jl=object())),
                                start_sampling=lambda: ev.append('SAMPLING'))
    f._set_power_combo = MagicMock(side_effect=lambda c: ev.append(('set', c.label)) or True)
    f._pm_set_state = MagicMock(side_effect=lambda ps: ev.append(('ps', ps)) or True)
    f._set_pcie_l_state = MagicMock(side_effect=lambda st: ev.append(('L', int(st))) or True)
    f._pm_d3_safe_restore = MagicMock(side_effect=lambda: ev.append('d3_restore') or True)
    f._record_pcie_state_history = MagicMock()
    f._apst_enable_short_itpt = MagicMock(side_effect=lambda a, b: ev.append('apst_on') or True)
    f._pm_perturb_pcie_bit = MagicMock(side_effect=lambda: ev.append('pcie_bit') or True)
    f._pm_perturb_clkreq = MagicMock(side_effect=lambda: ev.append('clkreq') or True)
    f._pm_preflight_fail = MagicMock(side_effect=lambda *a: ev.append(('PRESERVE', a[1])) or False)
    f._nvme_calls = []

    def nvme(cmd, timeout, record=True):
        f._nvme_calls.append(list(cmd))
        if cmd[:2] == ['nvme', 'get-feature'] and '0x0c' in cmd:
            ev.append('apst_readback')
            return v._StateProc(0, b'get-feature:0x0c, Current value:0x00000000', b'')
        if cmd[:2] == ['nvme', 'set-feature'] and '0x0C' in cmd:
            ev.append('apst_off')
        return OK
    f._pm_nvme_run = MagicMock(side_effect=nvme)
    return f, ev


@patch('fuzzer_active_test.time.sleep')
class DetachedCombo(unittest.TestCase):
    def test_ps4_enter_and_leave_while_detached(self, sleep):
        f, ev = engine()
        self.assertTrue(f._pm_detached_combo(PS4_L0))
        self.assertEqual(ev, ['detach', ('set', PS4_L0.label), ('set', OP.label), 'attach'])
        sleep.assert_any_call(2.0)
        self.assertEqual(f._current_combo, OP)
        self.assertNotIn('SAMPLING', ev)

    def test_operational_combo_is_entered_detached_and_kept(self, sleep):
        f, ev = engine()
        self.assertTrue(f._pm_detached_combo(OP2))
        self.assertEqual(ev, ['detach', ('set', OP2.label), 'attach'])
        self.assertEqual((f._current_combo, f._prev_op_combo, f._prev_op_ps), (OP2, OP2, 2))
        sleep.assert_not_called()

    def test_operational_ps_nonop_link_is_left_and_not_restore_target(self, _):
        f, ev = engine()
        f._pm_detached_combo(PS1_L12)
        self.assertEqual(ev, ['detach', ('set', PS1_L12.label), ('L', 0), 'attach'])
        self.assertEqual((f._prev_op_combo, f._prev_op_ps), (OP, 1))
        self.assertEqual(f._current_combo.pcie_l, v.PCIeLState.L0)

    def test_l12_restore_also_leaves_ps4_before_attach(self, _):
        f, ev = engine()
        f._pm_detached_combo(PS4_L12)
        self.assertEqual(ev, ['detach', ('set', PS4_L12.label), ('L', 0), ('ps', 1), 'attach'])
        self.assertEqual(f._current_ps, 1)

    def test_entry_failure_returns_ps_without_nonop_restore(self, _):
        f, ev = engine()
        f._set_power_combo = MagicMock(side_effect=lambda c: ev.append(('set', c.label)) and False)
        f._pm_detached_combo(PS4_L12)
        self.assertEqual(ev, ['detach', ('set', PS4_L12.label), ('ps', 1), 'attach'])
        f._set_pcie_l_state.assert_not_called()
        self.assertEqual(f._current_combo, OP)


@patch('fuzzer_active_test.time.sleep')
class RestoreFailureDoesNotReattach(unittest.TestCase):
    """리뷰 P1-2: 복귀 실패를 무시하고 재연결하던 문제."""

    def assert_preserved(self, f, ev, combo):
        self.assertFalse(f._pm_detached_combo(combo))
        self.assertNotIn('attach', ev)
        self.assertEqual(ev[-1][0], 'PRESERVE')
        self.assertEqual(f._current_combo, combo)              # 복귀 목표로 기록하지 않는다

    def test_ps4_back_to_op_fails(self, _):
        f, ev = engine()
        f._set_power_combo = MagicMock(side_effect=lambda c: ev.append(('set', c.label)) or c is PS4_L0)
        self.assert_preserved(f, ev, PS4_L0)

    def test_l12_link_restore_fails(self, _):
        f, ev = engine()
        f._set_pcie_l_state = MagicMock(side_effect=lambda st: ev.append(('L', int(st))) and False)
        self.assert_preserved(f, ev, PS4_L12)

    def test_l12_ps_restore_fails(self, _):
        f, ev = engine()
        f._pm_set_state = MagicMock(side_effect=lambda ps: ev.append(('ps', ps)) and False)
        self.assert_preserved(f, ev, PS4_L12)

    def test_d3_restore_fails(self, _):
        f, ev = engine()
        f._pm_d3_safe_restore = MagicMock(side_effect=lambda: ev.append('d3_restore') and False)
        self.assert_preserved(f, ev, PS1_D3)

    def test_unresponsive_during_restore(self, _):
        f, ev = engine()

        def back(c):
            ev.append(('set', c.label))
            if c is OP:
                f._pm_unresponsive = 'nvme admin-passthru 가 5s 안에 응답하지 않음'
            return True
        f._set_power_combo = MagicMock(side_effect=back)
        self.assert_preserved(f, ev, PS4_L0)

    def test_entry_failure_and_ps_return_fails(self, _):
        f, ev = engine()
        f._set_power_combo = MagicMock(side_effect=lambda c: ev.append(('set', c.label)) and False)
        f._pm_set_state = MagicMock(side_effect=lambda ps: ev.append(('ps', ps)) and False)
        self.assertFalse(f._pm_detached_combo(PS4_L0))
        self.assertNotIn('attach', ev)

    def test_nonop_restore_checked_reports_failure(self, _):
        f, _ev = engine()
        f._pm_d3_safe_restore = MagicMock(return_value=False)
        back, ok = f._nonop_restore_checked(PS1_D3)
        self.assertFalse(ok)
        self.assertEqual(f._nonop_restore(PS1_D3), back)       # 기존 호출부용 래퍼는 그대로


@patch('fuzzer_active_test.time.sleep')
class ForcedIdle(unittest.TestCase):
    """리뷰 P1-1: 원래 APST=0 이면 _apst_disable 이 해제를 생략해 APST 가 켜진 채 재연결되던 문제."""

    def test_original_apst_off_still_sends_disable_and_reads_back(self, _):
        f, ev = engine()                                        # _orig_apst_cdw11 == 0
        self.assertTrue(f._pm_detached_forced_idle(500, 2000, 3.5))
        self.assertEqual(ev, ['detach', 'apst_on', 'apst_off', 'apst_readback', ('ps', 0), 'attach'])
        self.assertTrue(any(c[:2] == ['nvme', 'set-feature'] and '0x0C' in c for c in f._nvme_calls))

    def test_apst_still_enabled_on_readback_preserves(self, _):
        f, ev = engine()
        nvme = f._pm_nvme_run.side_effect

        def still_on(cmd, timeout, record=True):
            if cmd[:2] == ['nvme', 'get-feature'] and '0x0c' in cmd:
                return v._StateProc(0, b'Current value:0x00000001', b'')
            return nvme(cmd, timeout, record)
        f._pm_nvme_run = MagicMock(side_effect=still_on)
        self.assertFalse(f._pm_detached_forced_idle(500, 2000, 3.5))
        self.assertNotIn('attach', ev)
        self.assertEqual(ev[-1][0], 'PRESERVE')

    def test_apst_disable_failure_preserves(self, _):
        f, ev = engine()
        f._pm_nvme_run = MagicMock(return_value=v._StateProc(1, b'', b'NVMe status: INTERNAL'))
        self.assertFalse(f._pm_detached_forced_idle(500, 2000, 3.5))
        self.assertNotIn('attach', ev)

    def test_apst_disable_return_ignores_sysfs_fallback(self, _):
        # sysfs power/control=on 은 런타임 PM 해제지 APST 해제가 아니다 — 반환값은 set-feature 결과
        f, _ev = engine()
        f._pcie_bdf = '0000:01:00.0'
        f._pm_nvme_run = MagicMock(return_value=v._StateProc(1, b'', b'err'))
        with patch.object(v.Path, 'exists', return_value=True), \
                patch.object(v.Path, 'write_text', return_value=None):
            self.assertFalse(f._apst_disable(force=True))
        cur0 = MagicMock(returncode=0, stdout='Current value:0x00000000', stderr='')
        with patch.object(v.subprocess, 'run', return_value=cur0):
            self.assertTrue(f._apst_disable())                  # force 없이 지금 0 이면 생략 = True


@patch('fuzzer_active_test.time.sleep')
class ApstEnableTimeout(unittest.TestCase):
    """리뷰 2차 P1: APST 활성화가 subprocess.run(timeout) 이라 무응답을 남기지 않아 그대로 재연결됐다.
    실제 _apst_enable_short_itpt·_pm_nvme_run 을 돌리고 프로세스 경계(_run_nvme_state_cmd)만 가짜로 둔다."""

    def run_slot(self, proc):
        f, ev = engine()
        del f._apst_enable_short_itpt, f._pm_nvme_run          # 실제 함수
        f._ctrl_device = lambda: '/dev/nvme0'
        calls = []

        def run(cmd, timeout_sec=None, **kw):
            calls.append(list(cmd))
            return proc
        with patch('fuzzer_active_test._run_nvme_state_cmd', side_effect=run), \
                patch('fuzzer_active_test.subprocess.run', side_effect=AssertionError('subprocess.run')):
            ret = f._pm_detached_forced_idle(500, 2000, 3.5)
        return f, ev, calls, ret

    def test_timeout_preserves_without_more_commands(self, _):
        f, ev, calls, ret = self.run_slot(v._StateProc(-1, b'', b'timeout'))
        self.assertFalse(ret)
        self.assertNotIn('attach', ev)
        self.assertEqual(ev[-1][0], 'PRESERVE')
        self.assertEqual(len(calls), 1)                         # 활성화 한 번뿐 — 해제·PS 복귀 안 보냄
        self.assertIn('응답하지 않음', f._pm_unresponsive)

    def test_rejected_enable_skips_slot_and_reattaches(self, _):
        # 거절(rc≠0)은 APST 가 켜지지 않은 것이라 건너뛰고 붙인다
        f, ev, calls, ret = self.run_slot(v._StateProc(1, b'', b'NVMe status: INVALID_FIELD'))
        self.assertTrue(ret)
        self.assertEqual(ev, ['detach', 'attach'])
        self.assertEqual(len(calls), 1)


@patch('fuzzer_active_test.time.sleep')
class EntryUnresponsive(unittest.TestCase):
    """리뷰 2차 P2: 진입 명령이 무응답인데 PS 복귀 명령을 더 보냈다."""

    def test_no_ps_command_after_unresponsive_entry(self, _):
        f, ev = engine()

        def enter(c):
            ev.append(('set', c.label))
            f._pm_unresponsive = 'nvme admin-passthru 가 5s 안에 응답하지 않음'
            return False
        f._set_power_combo = MagicMock(side_effect=enter)
        self.assertFalse(f._pm_detached_combo(PS4_L0))
        self.assertEqual(ev, ['detach', ('set', PS4_L0.label), ('PRESERVE', '진입')])
        f._pm_set_state.assert_not_called()

class DetachAndPerturb(unittest.TestCase):
    def test_close_failure_skips_pm_and_reconnects(self):
        f, ev = engine(close_ok=False)
        self.assertTrue(f._pm_detached_combo(PS4_L0))
        self.assertEqual(ev, ['detach', 'attach'])              # PM 동작 생략
        f._set_power_combo.assert_not_called()

    def test_perturb_ok(self):
        for kind in ('pcie_bit', 'clkreq'):
            with self.subTest(kind=kind):
                f, ev = engine()
                self.assertTrue(f._pm_detached_perturb(kind))
                self.assertEqual(ev, ['detach', kind, 'attach'])

    def test_perturb_false_with_live_device_reattaches(self):
        f, ev = engine()
        f._pm_perturb_pcie_bit = MagicMock(side_effect=lambda: ev.append('pcie_bit') and False)
        self.assertTrue(f._pm_detached_perturb('pcie_bit'))
        self.assertEqual(ev, ['detach', 'pcie_bit', 'attach'])
        self.assertEqual(f._nvme_calls[-1][:2], ['nvme', 'id-ctrl'])

    def test_perturb_false_with_dead_device_preserves(self):
        # S1 PMCSR D0 readback 실패 등 — 장치가 응답하지 않으면 다시 붙이지 않는다
        f, ev = engine()
        f._pm_perturb_pcie_bit = MagicMock(side_effect=lambda: ev.append('pcie_bit') and False)
        f._pm_nvme_run = MagicMock(return_value=v._StateProc(1, b'', b'No such device'))
        self.assertFalse(f._pm_detached_perturb('pcie_bit'))
        self.assertNotIn('attach', ev)


@patch('fuzzer_active_test.time.sleep')
class Attach(unittest.TestCase):
    def test_reattach_failure_stops_like_sampler_failure(self, _):
        f, _ev = engine(reconnect_ok=False)
        self.assertFalse(f._pm_detached_combo(PS4_L0))
        self.assertTrue(f._sampler_recovery_failed)

    def test_reauth_is_counted(self, _):
        f, _ev = engine(reauth=1)
        with self.assertLogs('pcfuzz', level='WARNING') as logs:
            f._pm_detached_combo(PS4_L0)
        self.assertEqual(f._pm_detach_stats['reauth'], 1)
        self.assertIn('재인증 수행', '\n'.join(logs.output))

    def test_attach_without_detach_is_noop(self, _):
        f, ev = engine()
        self.assertTrue(f._pm_sampler_attach('x'))
        self.assertEqual(ev, [])

    def test_config_flag(self, _):
        self.assertFalse(engine(enabled=False)[0]._pm_detach_wanted())
        self.assertTrue(engine()[0]._pm_detach_wanted())

    def test_monitor_skips_closed_session(self, _):
        f, _ev = engine()
        f.sampler.close()
        f.sampler.session.dap = object()
        f.sampler._cores = {0: {}}
        f.sampler._valid_bit = 1
        f.sampler.session.burst = MagicMock(return_value=[])
        self.assertIsNone(f._read_bm9k1_monitor_pc())
        f.sampler.session.burst.assert_not_called()             # 닫힌 핸들로 읽기를 시도하지 않는다


class Wiring(unittest.TestCase):
    SRC = FUZZER_FILE.read_text(encoding='utf-8')

    def test_only_bm9k1_enabled_in_config(self):
        cfg = json.loads((FUZZER_FILE.parent / 'fuzzer_config.json').read_text(encoding='utf-8-sig'))
        on = {n: p.get('family', n) for n, p in cfg['products'].items() if p.get('pm_detach_sampler')}
        self.assertIn('BM9K1', on)
        # v11.5: BM9K1 파생형(BM9K1_LENOVO·BM9K1_HP)도 같은 계열이라 켠다. 다른 계열은 끈다.
        self.assertEqual(set(on.values()), {'BM9K1'}, on)

    def test_no_jlink_disables(self):
        self.assertIn("pm_detach_sampler=bool(_profile.get('pm_detach_sampler', False)) and not args.no_jlink",
                      self.SRC)

    def test_preflight_runs_detached_and_reattaches(self):
        run = next(n for c in ast.parse(self.SRC).body if isinstance(c, ast.ClassDef)
                   for n in c.body if isinstance(n, ast.FunctionDef) and n.name == 'run'
                   and '_pm_preflight_check' in ast.get_source_segment(self.SRC, n))
        body = ast.get_source_segment(self.SRC, run)
        d = body.index("if _pf_detach and not self._pm_sampler_detach('PM preflight'):")
        pf = body.index('if not self._pm_preflight_check():')
        s12 = body.index('not self._pm_preflight_s1_s2()')
        a = body.index("not self._pm_sampler_attach('PM preflight')")
        self.assertLess(d, pf)
        self.assertLess(s12, a)

    def test_main_loop_uses_detached_paths(self):
        self.assertIn("if _next_combo is not None and self._pm_detach_wanted():", self.SRC)
        self.assertIn("if not self._pm_detached_combo(_next_combo):", self.SRC)
        self.assertIn("elif _pm_slot in ('pcie_bit', 'clkreq') and self._pm_detach_wanted():", self.SRC)
        self.assertIn("if not self._pm_detached_perturb(_pm_slot):", self.SRC)
        self.assertIn("if not self._pm_detached_forced_idle(_ps3_ms, _ps4_ms, _idle_total_s):", self.SRC)


if __name__ == '__main__':
    unittest.main()
