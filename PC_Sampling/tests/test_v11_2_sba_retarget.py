"""v11.2.1 — BM9K1 코어 전환·bank 읽기를 주소만 바꾸는 짧은 경로(sba_retarget)로.

실제 dap_access.Dap · sjtag_unlock(sba_pin/sba_unpin/sba_retarget/_sba_read) · riscv_cov.PcsrSession 을
돌리고, 그 아래 J-Link(coresight_read/write)만 RISC-V SBA 레지스터 모형으로 바꾼다. 주소는 시험용 임의값.
모형: sbreadonaddr 면 sbaddress0 쓰기가, sbreadondata 면 sbdata0 읽기가 read 를 시작하고, read 는
sbcs 를 BUSY_READS 번 읽을 동안 busy. busy 중 sbaddress0 쓰기는 sbbusyerror(연속 sbdata0 읽기는 실기처럼
완료된 값을 본다).
"""
import sys
import unittest
from pathlib import Path

from fuzzer_target import fuzzer as v   # noqa: F401 — 경로 설정
import riscv_cov                         # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'risc-v'))
import dap_access as da                  # noqa: E402
import sjtag_unlock as sj                # noqa: E402

AP, CB = 0x40000, 0x1000                 # 시험용 DM AP · DM base
PCSR = {0: 0x10000, 1: 0x30000, 2: 0x50000, 3: 0x70000}   # sbcs 상태·에러 비트와 겹치지 않는 값(오독이 우연히 걸러지지 않게)
PROBE = 0x90000
BUSY_READS = 2


class FakeSba:
    def __init__(self):
        self.ops = 0
        self.select = 0
        self.csw = self.tar = 0
        self.sbcs, self.sbaddr, self.sbdata = 0, 0, 0
        self.busy = 0
        self.mem = {a: (c << 4) | 1 for c, a in PCSR.items()}   # PCSR: valid bit + 코어 표시
        self.mem[PROBE] = 0x4F564C02
        self.mem_reads = []
        self.ctrl = 0                    # DP CTRL/STAT (STICKYERR = bit5)
        self.drop = None                 # drop(reg, val, tar) → True 면 그 AP 쓰기를 적용하지 않는다(결함 주입)
        self.drw = []                    # DRW 접근 기록 (tar, 'r'|'w')

    # J-Link API
    def coresight_read(self, idx, ap=True):
        self.ops += 1
        if not ap:
            return self.ctrl if idx == da.DP_CTRL_STAT else 0
        return self._ap(idx, None)

    def coresight_write(self, idx, val, ap=True):
        self.ops += 1
        if not ap:
            if idx == da.DP_SELECT:
                self.select = val
            elif idx == da.DP_ABORT:
                self.ctrl = 0
            return
        if self.drop is not None and self.drop((self.select & 0xFFF) + idx * 4, val, self.tar):
            return
        self._ap(idx, val)

    def _ap(self, idx, val):
        reg = (self.select & 0xFFF) + idx * 4
        assert self.select & ~0xFFF == AP, 'AP 밖 접근'
        if reg == da.OFF_CSW:
            if val is None:
                return self.csw
            self.csw = val
        elif reg == da.OFF_TAR:
            if val is None:
                return self.tar
            self.tar = val
        elif reg == da.OFF_DRW:
            self.drw.append((self.tar, 'r' if val is None else 'w'))
            return self._mem(self.tar - CB, val)
        return 0

    def _start_read(self):
        if self.busy:
            self.sbcs |= sj._SB_BUSYERR
            return
        self.sbdata = self.mem.get(self.sbaddr, 0)
        self.mem_reads.append(self.sbaddr)
        self.busy = BUSY_READS

    def _mem(self, off, val):
        if off == sj.SBCS_OFF:
            if val is None:
                cs = self.sbcs | (sj._SB_BUSY if self.busy else 0)
                if self.busy:
                    self.busy -= 1
                return cs
            self.sbcs = (self.sbcs & ~(val & sj._SB_ERRMASK) & sj._SB_ERRMASK) | (val & ~sj._SB_ERRMASK)
        elif off == sj.SBADDR0_OFF:
            if val is None:
                return self.sbaddr
            if self.busy:
                self.sbcs |= sj._SB_BUSYERR
                return
            self.sbaddr = val
            if self.sbcs & (1 << 20):
                self._start_read()
        elif off == sj.SBDATA0_OFF and val is None:
            # 실기에선 system bus read 가 USB 왕복보다 훨씬 빨라 연속 DRW 읽기는 항상 완료된 값을 본다
            self.busy = 0
            d = self.sbdata
            if self.sbcs & (1 << 15):
                self._start_read()
            return d
        return 0

    def settle(self):
        """버스트 사이 시간 경과 — 진행 중 read 완료."""
        self.busy = 0


def session(fast=True):
    hw = FakeSba()
    s = riscv_cov.PcsrSession(cores={})
    s._sj = sj
    s.dap = sj.MemDap(hw, verbose=False)
    s._ap, s._cb = AP, CB
    s._pcsr_addr = lambda c: PCSR[c]
    s.fast_switch = fast
    return s, hw


def burst(s, hw, core, n=4):
    hw.settle()
    return s.burst(core, n)


class ShortPath(unittest.TestCase):
    def test_core_switch_reads_new_core_with_far_fewer_ops(self):
        cost = {}
        for fast in (True, False):
            s, hw = session(fast)
            burst(s, hw, 0)
            hw.settle()
            before = hw.ops
            obs = s.burst(1, 4)
            cost[fast] = hw.ops - before - 4                 # 버스트 읽기 4회 제외 = 전환 비용
            self.assertEqual([o.pc for o in obs], [1 << 4] * 4)
            self.assertEqual(hw.sbcs & sj._SB_ERRMASK, 0)
        self.assertLessEqual(cost[True], 16)                 # 검증 포함(TAR·posted write·sbaddress0 되읽기)
        self.assertGreaterEqual(cost[False], 2 * cost[True])
        self.assertEqual(s.switch_full, 2)                   # 예전 경로: 첫 핀 + 전환

    def test_fast_counters(self):
        s, hw = session()
        burst(s, hw, 0)
        burst(s, hw, 2)
        burst(s, hw, 0)
        self.assertEqual((s.switch_fast, s.switch_fast_fail, s.switch_full), (2, 0, 1))

    def test_switch_right_after_burst_waits_for_outstanding_read(self):
        # 버스트 마지막 sbdata0 읽기가 시작한 read 가 아직 busy — 기다린 뒤 주소를 바꿔야 sbbusyerror 가 없다
        s, hw = session()
        burst(s, hw, 0)
        self.assertTrue(hw.busy)
        obs = s.burst(3, 3)
        self.assertEqual({o.pc for o in obs}, {3 << 4})
        self.assertEqual(hw.sbcs & sj._SB_ERRMASK, 0)
        self.assertEqual(s.switch_fast, 1)

    def test_overlay_word_via_short_path_then_back_to_pcsr(self):
        s, hw = session()
        burst(s, hw, 0)
        hw.settle()
        before = hw.ops
        w = s.read_word(PROBE)
        self.assertEqual(w, hw.mem[PROBE])
        self.assertLessEqual(hw.ops - before, 17)
        self.assertEqual(s._pinned, ('word', PROBE))
        obs = s.burst(0, 3)                                  # 프로브 읽기가 시작한 read 를 기다렸다가 복귀
        self.assertEqual({o.pc for o in obs}, {0})
        self.assertEqual(hw.sbcs & sj._SB_ERRMASK, 0)
        self.assertEqual(s.switch_fast, 2)

    def test_disabled_uses_full_path(self):
        s, hw = session(fast=False)
        burst(s, hw, 0)
        self.assertEqual(s.read_word(PROBE), hw.mem[PROBE])
        burst(s, hw, 0)
        self.assertEqual((s.switch_fast, s.switch_fast_fail), (0, 0))
        self.assertEqual(s.switch_full, 3)


class FallsBackToFullPath(unittest.TestCase):
    def test_sba_error_falls_back_and_full_path_clears_it(self):
        s, hw = session()
        burst(s, hw, 0)
        hw.settle()
        hw.sbcs |= 0x2 << 12                                 # sberror 래치
        obs = s.burst(1, 2)
        self.assertEqual({o.pc for o in obs}, {1 << 4})
        self.assertEqual((s.switch_fast_fail, s.switch_full), (1, 2))
        self.assertEqual(hw.sbcs & sj._SB_ERRMASK, 0)

    def test_not_in_fifo_mode_falls_back(self):
        s, hw = session()
        burst(s, hw, 0)
        hw.settle()
        hw.sbcs &= ~(1 << 15)                                 # 누군가 FIFO 를 껐다
        self.assertFalse(sj.sba_retarget(s.dap, AP, CB, PCSR[1]))
        self.assertEqual(hw.mem_reads[-1], PCSR[0])           # 주소를 건드리지 않았다

    def test_transport_failure_falls_back(self):
        s, hw = session()
        burst(s, hw, 0)
        real = hw.coresight_write

        def flaky(idx, val, ap=True):
            if ap and (hw.select & 0xFFF) + idx * 4 == da.OFF_TAR and val == CB + sj.SBADDR0_OFF:
                raise RuntimeError('WAIT/FAULT')
            return real(idx, val, ap)
        hw.coresight_write = flaky
        self.assertFalse(sj.sba_retarget(s.dap, AP, CB, PCSR[2]))
        hw.coresight_write = real
        obs = s.burst(2, 2)
        self.assertEqual({o.pc for o in obs}, {2 << 4})

    def test_exception_in_retarget_is_contained(self):
        s, hw = session()
        burst(s, hw, 0)
        s._sj = type('M', (), {k: getattr(sj, k) for k in dir(sj) if not k.startswith('__')})
        s._sj.sba_retarget = staticmethod(lambda *a, **k: (_ for _ in ()).throw(RuntimeError('x')))
        hw.settle()
        obs = s.burst(1, 2)
        self.assertEqual({o.pc for o in obs}, {1 << 4})
        self.assertEqual(s.switch_fast_fail, 1)


class ReviewInjections(unittest.TestCase):
    """리뷰: 검증을 빼면 주소 변경이 조용히 실패해 이전 코어의 PC 를 새 코어 값으로 받았다.
    결함을 한 번 주입하고, 짧은 경로가 실패 → 전체 경로로 새 코어 값을 읽는지 본다."""

    def switch_with(self, drop):
        s, hw = session()
        burst(s, hw, 0)
        hw.settle()
        fired = []

        def once(reg, val, tar):
            if not fired and drop(hw, reg, val, tar):
                fired.append(1)
                return True
            return False
        hw.drop = once
        obs = s.burst(1, 3)
        self.assertTrue(fired)
        return s, obs

    def assert_safe(self, s, obs):
        self.assertEqual({o.pc for o in obs}, {1 << 4})      # 코어 0 값(0)이 섞이지 않는다
        self.assertEqual((s.switch_fast, s.switch_fast_fail), (0, 1))

    def test_tar_to_sbaddress_not_applied(self):
        self.assert_safe(*self.switch_with(
            lambda hw, reg, val, tar: reg == da.OFF_TAR and val == CB + sj.SBADDR0_OFF))

    def test_address_write_lost_with_sticky(self):
        def drop(hw, reg, val, tar):
            if reg == da.OFF_DRW and tar == CB + sj.SBADDR0_OFF:
                hw.ctrl = 1 << 5                              # STICKYERR
                return True
            return False
        self.assert_safe(*self.switch_with(drop))

    def test_address_write_lost_silently(self):
        # sticky 없이 쓰기만 사라져도 sbaddress0 되읽기가 잡는다
        self.assert_safe(*self.switch_with(
            lambda hw, reg, val, tar: reg == da.OFF_DRW and tar == CB + sj.SBADDR0_OFF))

    def test_tar_back_to_sbcs_not_applied(self):
        # 주소 쓰기 뒤 TAR→sbcs 가 안 되면 sbaddress0 를 sbcs 로 오독할 수 있다 — 되읽기가 막는다
        seen = []

        def drop(hw, reg, val, tar):
            if reg == da.OFF_TAR and val == CB + sj.SBADDR0_OFF:
                seen.append(1)
                return False
            return bool(seen) and reg == da.OFF_TAR and val == CB + sj.SBCS_OFF
        self.assert_safe(*self.switch_with(drop))

    def test_tar_to_sbdata_not_applied(self):
        seen = []

        def drop(hw, reg, val, tar):
            if reg == da.OFF_DRW and tar == CB + sj.SBADDR0_OFF:
                seen.append(1)
                return False
            return bool(seen) and reg == da.OFF_TAR and val == CB + sj.SBDATA0_OFF
        self.assert_safe(*self.switch_with(drop))

class RetargetStopsAtFailedStep(unittest.TestCase):
    """실패한 단계 뒤로 DRW 접근을 하지 않는다 — TAR 이 틀린 채 DRW 를 쓰면 엉뚱한 레지스터(sbcs 등)에
    주소값을 쓰거나, sbdata0 를 읽어 read 를 하나 더 시작한다."""

    def run_inject(self, nth_tar_write):
        s, hw = session()
        burst(s, hw, 0)
        hw.settle()
        n = {'tar': 0}

        def drop(reg, val, tar):
            if reg == da.OFF_TAR:
                n['tar'] += 1
                return n['tar'] == nth_tar_write
            return False
        hw.drop = drop
        hw.drw.clear()
        ok = sj.sba_retarget(s.dap, AP, CB, PCSR[1])
        return ok, hw

    def test_first_tar_to_sbcs(self):
        ok, hw = self.run_inject(1)
        self.assertFalse(ok)
        self.assertEqual(hw.drw, [])

    def test_tar_to_sbaddress(self):
        ok, hw = self.run_inject(2)
        self.assertFalse(ok)
        self.assertNotIn('w', [k for _, k in hw.drw])       # 주소값을 sbcs 에 쓰지 않는다

    def test_tar_back_to_sbcs(self):
        ok, hw = self.run_inject(3)
        self.assertFalse(ok)
        self.assertEqual(hw.drw[-1], (CB + sj.SBADDR0_OFF, 'r'))   # 주소 되읽기 뒤로 DRW 없음

    def test_tar_to_sbdata(self):
        ok, _hw = self.run_inject(4)
        self.assertFalse(ok)

class AbortsWhenCommandEnds(unittest.TestCase):
    """버스트 전 준비(pin·시작 bank 읽기)는 명령이 끝나면 USB 왕복 하나 단위로 그만둔다. 검증은 그대로이고,
    중단된 상태는 '미상'으로 남겨 다음 전환이 처음부터 재확인한다. 명령 종료 뒤 전체 경로로 넘어가지 않는다."""

    def setUp(self):
        self.s, self.hw = session()
        burst(self.s, self.hw, 0)
        self.hw.settle()

    def abort_after(self, k):
        start = self.hw.ops
        return lambda: self.hw.ops - start >= k

    def test_abort_before_start_costs_nothing(self):
        before = self.hw.ops
        self.assertFalse(self.s.pin(1, abort=lambda: True))
        self.assertEqual(self.hw.ops, before)
        self.assertEqual(self.s._pinned, 0)                   # 상태 그대로

    def test_abort_mid_switch_stops_and_marks_unknown(self):
        # 짧은 경로의 마지막 중단 지점(새 주소 read 완료 확인 전)보다 앞에서 명령이 끝나는 경우들
        for k in range(1, 10):
            with self.subTest(k=k):
                self.setUp()
                full0 = self.s.switch_full
                before = self.hw.ops
                ok = self.s.pin(1, abort=self.abort_after(k))
                self.assertFalse(ok)                          # 전체 경로로 이어 붙지 않는다
                # 진행 중이던 단계까지만 — 가장 긴 구간은 주소 쓰기→posted write·sticky 확인→되읽기(4)
                self.assertLessEqual(self.hw.ops - before, k + 4)
                self.assertEqual(self.s.switch_full, full0)          # 전체 경로로 넘어가지 않음
                self.assertEqual(self.s._pinned, self.s._DIRTY)
                self.assertGreaterEqual(self.s.setup_aborted, 1)
                # 다음 전환은 처음부터 재확인해 올바른 코어를 읽는다
                self.hw.settle()
                obs = self.s.burst(2, 3)
                self.assertEqual({o.pc for o in obs}, {2 << 4})
                self.assertEqual(self.hw.sbcs & sj._SB_ERRMASK, 0)

    def test_burst_with_abort_returns_empty_as_aborted(self):
        obs = self.s.burst(1, 4, abort=lambda: True)
        self.assertEqual(obs, [])
        self.assertEqual(self.s.last_fail_kind, 'aborted')

    def test_read_word_abort(self):
        self.assertIsNone(self.s.read_word(PROBE, abort=self.abort_after(3)))
        self.assertEqual(self.s._pinned, self.s._DIRTY)
        self.hw.settle()
        self.assertEqual(self.s.read_word(PROBE), self.hw.mem[PROBE])   # 다음엔 정상

    def test_end_bank_read_without_abort_is_not_interrupted(self):
        self.assertEqual(self.s.read_word(PROBE), self.hw.mem[PROBE])

    def test_timers_accumulate(self):
        t_s, t_r = self.s.t_setup, self.s.t_read
        self.hw.settle()
        self.s.burst(3, 4)
        self.s.read_word(PROBE)
        self.assertGreater(self.s.t_setup, t_s)
        self.assertGreater(self.s.t_read, t_r)

class Wiring(unittest.TestCase):
    def test_config_flag(self):
        src = Path(v.__file__).read_text(encoding='utf-8')
        self.assertIn("self.session.fast_switch = bool(((rv.get('sample_plan') or {}).get('fast_switch', True)))", src)
        self.assertIn("sw: fast", src)

    def test_counters_survive_reconnect(self):
        o = v.RiscvPcsrSampler.__new__(v.RiscvPcsrSampler)
        o._cores, o.config = {}, type('C', (), {'jlink_vtref_mv': None})()
        old = riscv_cov.PcsrSession(cores={})
        old.switch_fast, old.switch_full, old.setup_aborted, old.t_setup, old.t_read = 5, 2, 3, 1.5, 2.5
        old.close = lambda: None
        o.session = old
        new = riscv_cov.PcsrSession(cores={})
        new.open = lambda: True
        o._rc = type('R', (), {'PcsrSession': staticmethod(lambda **k: new)})
        self.assertTrue(o._open_session({}))
        self.assertIs(o.session, new)
        self.assertEqual((new.switch_fast, new.switch_full, new.setup_aborted, new.t_setup, new.t_read),
                         (5, 2, 3, 1.5, 2.5))

if __name__ == '__main__':
    unittest.main()
