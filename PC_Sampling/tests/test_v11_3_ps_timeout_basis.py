"""BM9K1 timeout 배율 — 추적 PS 가 PS3/PS4 일 때는 직전 operational PS 기준.

PS3/PS4(non-operational)에서 I/O 가 오면 장치는 '가장 최근 operational PS' 로 스스로 돌아간다(NVMe Base
§8.15). 예전엔 추적 PS 가 4 로 남아 ×1(8s)로 나갔는데 장치는 PS2 에서 명령을 처리했다(맞는 값 80s).
실제 송신 경로·PM 함수를 태우고, 장치는 규격대로 흉내 낸다(SetFeatures FID2 PS<=4 성공, I/O 가 NOPS 를
깨움, admin 은 NOPS 유지, APST idle → PS4).
"""
import unittest
from unittest.mock import Mock, patch

import test_v11_exceptions as integration
import test_v11_2_pm_detach as pmh


class Dev:
    def __init__(self):
        self.ps, self.last_op = 0, 0

    def run(self, argv):
        a = dict(x[2:].split('=', 1) for x in argv if x.startswith('--') and '=' in x)
        admin = argv[1] == 'admin-passthru'
        op, c10, c11 = (int(a[k], 0) for k in ('opcode', 'cdw10', 'cdw11'))
        if not admin and self.ps in (3, 4):
            self.ps = self.last_op
        ps_exec, rc = self.ps, 0
        if admin and op == 0x09 and (c10 & 0xff) == 2:
            ps = c11 & 0x1f
            if ps > 4:
                rc = 1
            else:
                self.ps = ps
                if ps not in (3, 4):
                    self.last_op = ps
        return rc, ps_exec


class Base(unittest.TestCase):
    setUp_transport = integration.RealTransportIntegration.setUp

    def setUp(self):
        self.setUp_transport()
        f, self.v = self.f, self.base
        f.config.product = 'BM9K1'
        f._exception_controller = None
        f._exception_on_spawn = None
        f.config.nvme_timeouts['command'] = 8000
        self.dev = Dev()
        f._current_ps = 0

    def fuzz(self, cmd='Identify', opcode=None, force_admin=None, cdw10=0, cdw11=0):
        """보내고 (쓴 timeout 초, 명령이 실행된 순간 장치 PS) 를 준다."""
        seed = self.v.Seed(data=b'', cmd=next(c for c in self.v.NVME_COMMANDS if c.name == cmd))
        seed.opcode_override, seed.force_admin = opcode, force_admin
        seed.cdw10, seed.cdw11, seed.nsid_override = cdw10, cdw11, 1
        seen = {}

        def popen(argv, **kw):
            self.proc.returncode, seen['ps'] = self.dev.run(argv)
            return self.proc
        with patch.object(self.v.subprocess, 'Popen', side_effect=popen):
            self.f._send_nvme_command(b'', seed)
        return self.proc.communicate.call_args.kwargs['timeout'], seen['ps']

    def assertRight(self, got):
        used, ps = got
        self.assertEqual(used, 80 if ps in (1, 2) else 8, f'장치 PS{ps} 인데 timeout {used}s')
        return used


class FuzzedSetFeatures(Base):
    def test_io_after_fuzzed_ps4_uses_previous_operational_ps(self):
        self.fuzz('SetFeatures', cdw10=2, cdw11=2)
        self.fuzz('SetFeatures', cdw10=2, cdw11=4)
        self.assertEqual(self.assertRight(self.fuzz('Read')), 80)
        self.assertEqual(self.assertRight(self.fuzz('Read')), 80)

    def test_ps3_then_ps4_keeps_the_operational_ps_before_both(self):
        self.fuzz('SetFeatures', cdw10=2, cdw11=1)
        self.fuzz('SetFeatures', cdw10=2, cdw11=3)
        self.fuzz('SetFeatures', cdw10=2, cdw11=4)
        self.assertEqual(self.assertRight(self.fuzz('Read')), 80)

    def test_from_ps0_deep_state_stays_base_timeout(self):
        self.fuzz('SetFeatures', cdw10=2, cdw11=4)
        self.assertEqual(self.assertRight(self.fuzz('Read')), 8)

    def test_rejected_ps_and_io_dsm_do_not_move_the_basis(self):
        self.fuzz('SetFeatures', cdw10=2, cdw11=2)
        self.fuzz('SetFeatures', cdw10=2, cdw11=7)                  # 거절
        self.fuzz('Read', opcode=0x09, force_admin=False, cdw10=2)   # io DSM
        self.assertEqual(self.assertRight(self.fuzz('Read')), 80)

    def test_back_to_ps0_returns_to_base(self):
        self.fuzz('SetFeatures', cdw10=2, cdw11=2)
        self.fuzz('SetFeatures', cdw10=2, cdw11=4)
        self.fuzz('SetFeatures', cdw10=2, cdw11=0)
        self.assertEqual(self.assertRight(self.fuzz('Read')), 8)

    def test_log_names_tracked_and_basis(self):
        self.fuzz('SetFeatures', cdw10=2, cdw11=2)
        self.fuzz('SetFeatures', cdw10=2, cdw11=4)
        with self.assertLogs('pcfuzz', level='INFO') as logs:
            self.fuzz('Read')
        self.assertIn('tracked_ps=PS4(직전 operational PS2 기준) base=8000ms factor=10',
                      '\n'.join(logs.output))


class PmSlots(Base):
    """--pm: 디버거 연결(pm_detach_sampler=true) 경로는 실제 함수, 기존 경로(--no-jlink)는 메인 루프 순서."""

    def setUp(self):
        super().setUp()
        f, v = self.f, self.v
        eng, _ = pmh.engine()
        for k in ('_pm_detach_stats', '_ps_settle', 'ps_enter_counts', 'combo_enter_counts',
                  '_orig_apst_cdw11', '_pcie_bdf', '_record_setfeature_history', '_set_pcie_l_state',
                  '_pm_d3_safe_restore', '_record_pcie_state_history', '_sampler_recovery_failed'):
            setattr(f, k, getattr(eng, k))
        f._pm_detached, f._pm_unresponsive = False, None
        f._pm_sampler_detach = f._pm_sampler_attach = lambda why: True
        f._set_pcie_d_state = Mock(return_value=True)
        f._pmu_clkreq_deassert = Mock(return_value=True)
        f._pm_nvme_run = lambda argv, t, record=False: v._StateProc(self.dev.run(argv)[0], b'', b'')
        f._pm_set_state = v._V101Fuzzer._pm_set_state.__get__(f)
        f._set_power_combo = v._V101Fuzzer._set_power_combo.__get__(f)
        f._unresp_ok = lambda: True
        f._apst_off_confirmed = lambda: True
        f._apst_disable = Mock(return_value=True)
        f._apst_enable_short_itpt = lambda *a: setattr(self.dev, 'ps', 4) or True
        f.config.nvme_device = '/dev/nvme0'
        C = v.POWER_COMBOS
        f._prev_op_ps, f._current_combo, f._prev_op_combo = 0, C[0], C[0]
        L, D = v.PCIeLState, v.PCIeDState
        self.combo = lambda ps, l=L.L0, d=D.D0: next(
            c for c in C if c.nvme_ps == ps and c.pcie_l == l and c.pcie_d == d)
        self.L = L

    def legacy_combo(self, combo):      # 메인 루프 기존 경로(:POWER_COMBO slot) 순서 그대로
        f = self.f
        if combo.nvme_ps not in (3, 4):
            f._prev_op_ps, f._prev_op_combo = combo.nvme_ps, combo
        with patch.object(self.v.time, 'sleep'):
            if f._set_power_combo(combo):
                f._current_combo, f._current_ps = combo, combo.nvme_ps
        if f._is_nonop_combo(f._current_combo):
            r = f._nonop_restore(f._current_combo)
            f._current_combo, f._current_ps = r, r.nvme_ps

    def test_detached_combo_and_fuzzed_ps4(self):
        self.f.config.pm_detach_sampler = True
        with patch.object(self.v.time, 'sleep'):
            self.assertTrue(self.f._pm_detached_combo(self.combo(2)))
            self.assertRight(self.fuzz('Read'))
            self.assertTrue(self.f._pm_detached_combo(self.combo(4)))   # 깊음 → PS2 로 복귀 후 붙임
        self.assertEqual(self.assertRight(self.fuzz('Read')), 80)
        self.fuzz('SetFeatures', cdw10=2, cdw11=4)
        self.assertEqual(self.assertRight(self.fuzz('Read')), 80)

    def test_legacy_deep_combo_left_in_ps4(self):
        self.legacy_combo(self.combo(2))
        self.legacy_combo(self.combo(4))
        self.assertEqual(self.f._current_ps, 4)
        # admin 도 직전 operational PS 기준(80s) — admin 에 깨어나는 펌웨어여도 맞도록 길게 잡는 쪽
        self.assertEqual(self.fuzz('Identify')[0], 80)
        self.assertEqual(self.assertRight(self.fuzz('Read')), 80)

    def test_legacy_l12_combo_keeps_ps(self):
        self.legacy_combo(self.combo(4, self.L.L1_2))
        self.legacy_combo(self.combo(2, self.L.L1_2))
        self.assertEqual(self.assertRight(self.fuzz('Read')), 80)


class LegacyForcedIdleSource(unittest.TestCase):
    """기존 경로 forced_idle 뒤 추적값이 PS0 이 아니라 PS4(깨어날 PS 기준)여야 한다 — 메인 루프 소스 확인."""

    def test_main_loop_sets_ps4_after_legacy_apst_idle(self):
        import ast, inspect
        from fuzzer_target import fuzzer as v
        src = inspect.getsource(v._V101Fuzzer.run)
        i = src.index("self._current_combo = POWER_COMBOS[0]")
        tail = src[i:i + 1200]
        self.assertIn("elif _apst_ok:\n", tail)
        self.assertIn("self._current_ps = 4", tail)
        self.assertNotIn("self._current_ps    = 0", tail[:200])


class ApstDisableUsesCurrentValue(unittest.TestCase):
    """_apst_disable 생략은 시작 때 원본이 아니라 지금 읽은 값 기준. 원본 0(이전 실행이 불량 보존으로
    APST=0 을 남김) 뒤 실행 중 POR 재연결로 커널이 APST 를 다시 켜면, 예전엔 '이미 비활성화' 로 생략했다."""

    def setUp(self):
        from fuzzer_target import fuzzer as v
        self.v = v
        o = v.NVMeFuzzer.__new__(v.NVMeFuzzer)
        o._orig_apst_cdw11 = None
        o._ctrl_device = lambda: '/dev/nvme0'
        o._record_setfeature_history = lambda *a, **k: None
        o._pm_unresponsive = None
        o._pcie_bdf = None
        self.o, self.sent = o, []
        self.cur = 0

    def call(self, **kw):
        read = lambda *a, **k: Mock(returncode=0, stdout=f'Current value:{self.cur:#010x}', stderr='')

        def setf(cmd, *a, **k):
            self.sent.append(cmd)
            self.cur = 0
            return self.v._StateProc(0, b'', b'')
        with patch.object(self.v.subprocess, 'run', side_effect=read), \
                patch.object(self.v, '_run_nvme_state_cmd', side_effect=setf):
            return self.o._apst_disable(**kw)

    def test_kernel_reenable_after_original_zero_is_disabled(self):
        self.assertTrue(self.call())                 # 시작: 원본 0 → 생략
        self.assertEqual(self.sent, [])
        self.assertEqual(self.o._orig_apst_cdw11, 0)
        self.cur = 1                                  # POR 재연결 → 커널이 APST 켬
        self.assertTrue(self.call())
        self.assertEqual(len(self.sent), 1, '켜진 APST 를 생략했다')
        self.assertEqual(self.cur, 0)
        self.assertEqual(self.o._orig_apst_cdw11, 0, '원본(복원용)을 덮어썼다')

    def test_currently_off_is_skipped(self):
        self.o._orig_apst_cdw11 = 1                  # 원본은 켜져 있었어도 지금 꺼져 있으면 생략
        self.cur = 0
        self.assertTrue(self.call())
        self.assertEqual(self.sent, [])

    def test_read_failure_still_disables(self):
        self.o._orig_apst_cdw11 = 0
        with patch.object(self.v.subprocess, 'run', side_effect=OSError('nvme')), \
                patch.object(self.v, '_run_nvme_state_cmd',
                             side_effect=lambda c, *a, **k: self.sent.append(c) or self.v._StateProc(0, b'', b'')):
            self.assertTrue(self.o._apst_disable())
        self.assertEqual(len(self.sent), 1)


if __name__ == '__main__':
    unittest.main()
