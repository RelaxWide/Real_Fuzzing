#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PCSR 고속 폴링 경로 단위테스트.  실행: python3 -m unittest -v test_pcsr_fastpath

실측(2026-09) 제약을 코드가 실제로 지키는지 고정한다:
  - 핫루프는 DRW 를 정확히 1회. retry/sticky/SELECT/sleep 금지.
  - 셋업은 fail-closed.
  - 세션 재생성은 순서·핸들 정리·strict 기본값을 지킨다.
"""
import unittest
from unittest import mock

import sjtag_unlock as sj


class FakeJL:
    """coresight_read/write 호출을 전부 기록하는 가짜 J-Link."""

    def __init__(self, reads=None):
        self.calls = []
        self._reads = list(reads or [])

    def coresight_read(self, idx, ap=True):
        self.calls.append(('read', idx, ap))
        if not self._reads:
            return 0
        v = self._reads.pop(0)
        if isinstance(v, Exception):
            raise v
        return v

    def coresight_write(self, idx, val, ap=True):
        self.calls.append(('write', idx, ap))


class FakeDap:
    """Dap 대역 — 호출 기록 + 단계별 성공/실패 주입."""

    def __init__(self, jl=None, csw=0x23, tar_readback=None, fail_on=()):
        self.jl = jl or FakeJL()
        self.calls = []
        self._csw = csw
        self._tar_readback = tar_readback
        self._fail_on = set(fail_on)
        self.sticky_cleared = 0

    def __init_fail_seq(self):
        pass

    def mem_write32(self, ap, addr, val):
        self.calls.append(('mem_write32', addr, val))
        self._mw_n = getattr(self, '_mw_n', 0) + 1
        if 'mem_write32' in self._fail_on:
            return False
        if f'mem_write32#{self._mw_n}' in self._fail_on:   # n번째만 실패 주입
            return False
        return True

    def mem_read32(self, ap, addr):
        self.calls.append(('mem_read32', addr))
        return 0            # _sba_clear_err 가 에러비트 없음으로 보게

    def ap_read(self, ap, off, retry=1):
        self.calls.append(('ap_read', off))
        if off == sj.OFF_CSW:
            return None if 'csw_read' in self._fail_on else self._csw
        if off == sj.OFF_TAR:
            return self._tar_readback
        return 0

    def ap_write(self, ap, off, val):
        self.calls.append(('ap_write', off, val))
        if off == sj.OFF_CSW and 'csw_write' in self._fail_on:
            return False
        if off == sj.OFF_TAR:
            if 'tar_write' in self._fail_on:
                return False
            self._tar_readback = val        # 성공 시 리드백이 일치하도록
        return True

    def clear_sticky(self):
        self.sticky_cleared += 1


class TestFastPathPurity(unittest.TestCase):
    """★ 핫루프 순수성 — 이 테스트가 실측 제약을 지키는 유일한 방어선."""

    def test_exactly_one_drw_read(self):
        jl = FakeJL(reads=[0x1234ABCD])
        dap = FakeDap(jl)
        self.assertEqual(sj.sba_read_pinned(dap), 0x1234ABCD)
        self.assertEqual(jl.calls, [('read', sj.AP_IDX_DRW, True)],
                         "성공 1회당 DRW 읽기 정확히 1회여야 한다")

    def test_no_recovery_on_failure(self):
        """실패해도 clear_sticky/DP_ABORT/SELECT/retry 가 있으면 안 된다."""
        for bad in (None, -1, RuntimeError("boom")):
            with self.subTest(bad=bad):
                jl = FakeJL(reads=[bad])
                dap = FakeDap(jl)
                self.assertIsNone(sj.sba_read_pinned(dap))
                self.assertEqual(len(jl.calls), 1, "실패해도 재시도하면 안 된다")
                self.assertEqual(dap.sticky_cleared, 0, "clear_sticky 호출 금지")
                self.assertEqual(dap.calls, [], "SELECT/ap_read 등 부가 트랜잭션 금지")

    def test_does_not_use_ap_read(self):
        """Dap.ap_read 경로(retry+clear_sticky 내장)를 타면 안 된다."""
        jl = FakeJL(reads=[0x2000])
        dap = FakeDap(jl)
        sj.sba_read_pinned(dap)
        self.assertNotIn('ap_read', [c[0] for c in dap.calls])

    def test_masks_to_32bit(self):
        dap = FakeDap(FakeJL(reads=[0x1FFFFFFFF]))
        self.assertEqual(sj.sba_read_pinned(dap), 0xFFFFFFFF)


class TestPinSetup(unittest.TestCase):
    """셋업은 fail-closed — 핫루프에 검사를 못 넣으므로 여기서 걸러야 한다."""

    def _ok_dap(self):
        return FakeDap(csw=0x23)

    def test_success_pins_tar_and_disables_increment(self):
        dap = self._ok_dap()
        self.assertTrue(sj.sba_pin(dap, 0x1000, 0x8000, 0xFD00017C))
        ops = [(c[0], c[1]) for c in dap.calls]
        self.assertIn(('ap_write', sj.OFF_TAR), ops)
        self.assertIn(('ap_write', sj.OFF_CSW), ops)

    def test_rejects_suspect_csw(self):
        """SUSPECT(0x80000000) CSW 를 정상값처럼 가공하면 안 된다."""
        dap = FakeDap(csw=0x80000000)
        self.assertFalse(sj.sba_pin(dap, 0x1000, 0x8000, 0xFD00017C))

    def test_fail_closed_each_step(self):
        for step in ('mem_write32', 'csw_read', 'csw_write', 'tar_write'):
            with self.subTest(step=step):
                dap = FakeDap(csw=0x23, fail_on=(step,))
                self.assertFalse(sj.sba_pin(dap, 0x1000, 0x8000, 0xFD00017C),
                                 f"{step} 실패인데 True 를 반환했다")

    def test_tar_readback_mismatch_fails(self):
        dap = FakeDap(csw=0x23)
        dap.ap_write = lambda ap, off, val: True     # TAR 이 실제로 안 박히는 상황
        self.assertFalse(sj.sba_pin(dap, 0x1000, 0x8000, 0xFD00017C))


class TestPinExactValues(unittest.TestCase):
    """설정값 자체를 고정한다 — 호출 유무만 보면 잘못된 값이 통과한다."""

    CB, ADDR = 0x8000, 0xFD00017C

    def _pin(self):
        dap = FakeDap(csw=0x23)
        ok = sj.sba_pin(dap, 0x1000, self.CB, self.ADDR)
        return ok, dap

    def test_sbcs_fifo_mode_bits(self):
        """SBCS = 32bit access | sbreadonaddr(20) | sbreadondata(15)."""
        ok, dap = self._pin(); self.assertTrue(ok)
        w = [c for c in dap.calls if c[0] == 'mem_write32' and c[1] == self.CB + sj.SBCS_OFF]
        self.assertTrue(w, "SBCS write 가 없다")
        self.assertEqual(w[0][2], sj._SB32 | (1 << 20) | (1 << 15))

    def test_sbaddr0_is_target_pcsr(self):
        ok, dap = self._pin(); self.assertTrue(ok)
        w = [c for c in dap.calls if c[0] == 'mem_write32' and c[1] == self.CB + sj.SBADDR0_OFF]
        self.assertEqual(w[0][2], self.ADDR)

    def test_csw_word_size_and_no_autoinc(self):
        """Size=word(0b010), AddrInc=off — 0x37 마스크로 지우고 0x02 만 세운다."""
        ok, dap = self._pin(); self.assertTrue(ok)
        w = [c for c in dap.calls if c[0] == 'ap_write' and c[1] == sj.OFF_CSW]
        val = w[0][2]
        self.assertEqual(val & 0x07, 0x02, "Size 가 word(2)가 아니다")
        self.assertEqual(val & 0x30, 0x00, "AddrInc 가 꺼져있지 않다")

    def test_tar_points_at_sbdata0(self):
        ok, dap = self._pin(); self.assertTrue(ok)
        w = [c for c in dap.calls if c[0] == 'ap_write' and c[1] == sj.OFF_TAR]
        self.assertEqual(w[0][2], self.CB + sj.SBDATA0_OFF)

    def test_each_mem_write_failure_separately(self):
        """SBCS write 실패와 SBADDR0 write 실패를 각각 주입."""
        for n in (1, 2):
            with self.subTest(write=n):
                dap = FakeDap(csw=0x23, fail_on=(f'mem_write32#{n}',))
                self.assertFalse(sj.sba_pin(dap, 0x1000, self.CB, self.ADDR))

    def test_first_raw_read_after_pin(self):
        """pin 직후 첫 raw DRW 가 정상 경로로 값을 준다."""
        dap = FakeDap(FakeJL(reads=[0x0001234D]), csw=0x23)
        self.assertTrue(sj.sba_pin(dap, 0x1000, self.CB, self.ADDR))
        self.assertEqual(sj.sba_read_pinned(dap), 0x0001234D)


class TestCollapseContract(unittest.TestCase):
    """붕괴 임계는 '단일 코어 streak' 으로 오용되면 안 된다."""

    def test_single_core_threshold_constant_removed(self):
        self.assertFalse(hasattr(sj, 'PCSR_COLLAPSE_INVALIDS'),
                         "단일 코어 연속무효 임계로 오용되기 쉬운 상수는 두지 않는다")

    def test_two_part_contract_present(self):
        self.assertGreater(sj.PCSR_COLLAPSE_MIN_ALL_CORE_CYCLES, 0)
        self.assertGreater(sj.PCSR_COLLAPSE_MIN_SECONDS, 0)


class FakeLink:
    def __init__(self, open_fail=False):
        self.events = []
        self.jl = FakeJL()
        self._open_fail = open_fail

    def close(self):
        self.events.append('close')

    def open(self, tap_script=True):
        self.events.append(f'open(tap_script={tap_script})')
        if self._open_fail:
            raise RuntimeError("open failed")


class TestReopenSession(unittest.TestCase):
    def test_order_and_returns_dap(self):
        lk = FakeLink()
        with mock.patch.object(sj, 'prepare_session') as ps:
            dap = sj.reopen_session(lk, 'both')
        self.assertIsNotNone(dap)
        self.assertEqual(lk.events, ['close', 'open(tap_script=False)'])
        self.assertTrue(ps.called)

    def test_strict_defaults_true(self):
        """전원 ACK 실패 세션을 성공으로 돌려주면 붕괴 감지가 무한 재연결로 발산한다."""
        lk = FakeLink()
        with mock.patch.object(sj, 'prepare_session') as ps:
            sj.reopen_session(lk, 'both')
        self.assertIs(ps.call_args.kwargs['strict'], True)

    def test_preserves_tap_mode(self):
        lk = FakeLink()
        with mock.patch.object(sj, 'prepare_session'):
            sj.reopen_session(lk, 'both', tap_script=True)
        self.assertIn('open(tap_script=True)', lk.events)

    def test_closes_handle_when_prepare_fails(self):
        """prepare 실패 시 열어둔 handle 을 흘리면 안 된다."""
        lk = FakeLink()
        with mock.patch.object(sj, 'prepare_session', side_effect=RuntimeError("no power")):
            self.assertIsNone(sj.reopen_session(lk, 'both'))
        self.assertEqual(lk.events.count('close'), 2, "open 후 실패했으면 다시 close")

    def test_open_failure_returns_none_and_cleans_up(self):
        """Link.open 은 self.jl 을 먼저 만들고 USB open 을 시도한다 — 도중 실패해도
        부분 생성된 DLL 객체가 남으므로 best-effort close 로 정리해야 한다."""
        lk = FakeLink(open_fail=True)
        with mock.patch.object(sj, 'prepare_session'):
            self.assertIsNone(sj.reopen_session(lk, 'both'))
        self.assertEqual(lk.events.count('close'), 2,
                         "open 실패 경로에서도 close 로 정리해야 한다")

    def test_tap_note_matches_mode(self):
        """진단 로그가 실제 TAP mode 와 어긋나면 원인 분석이 틀어진다."""
        for tap, note in ((True, 'on'), (False, 'off')):
            with self.subTest(tap=tap):
                lk = FakeLink()
                with mock.patch.object(sj, 'prepare_session') as ps:
                    sj.reopen_session(lk, 'both', tap_script=tap)
                self.assertEqual(ps.call_args.args[2], note)

if __name__ == '__main__':
    unittest.main(verbosity=2)
