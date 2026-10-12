"""v11.2.1 — PM 분리 뒤 가벼운 재연결, 실행 시간 분해([Timing]).

리뷰: PM 슬롯마다(100명령마다) 전체 재연결(settle 0.5s, 코어마다 PC 200개 정합성 게이트, 오버레이 재검사)이
돌아 평균 처리량을 깎을 수 있다. 같은 펌웨어·전원 구간이므로 세션 열기 + 핀 + 짧은 확인 버스트로 줄이고,
실패하면 전체 경로로 간다. 병목을 실측으로 가르기 위해 실행당 시간을 나눠 찍는다.
"""
import unittest
from types import SimpleNamespace as NS
from unittest.mock import MagicMock, patch

from fuzzer_target import fuzzer as v

IN, OUT = 0x1000, 0x9000


def sampler(pcs_by_core=None, open_ok=True, pin_ok=True, transport=False, ranges=True):
    o = v.RiscvPcsrSampler.__new__(v.RiscvPcsrSampler)
    o.config = NS(riscv={'gate_threshold': 95.0})
    o._weights = {0: 8, 1: 1}
    o._valid_bit = 1
    o._ranges = {0: 'r', 1: 'r'} if ranges else {}
    o._in_core_range = lambda c, pc: pc == IN
    pcs = pcs_by_core or {0: [IN] * 32, 1: [IN] * 32}
    ses = NS(pin=MagicMock(return_value=pin_ok), last_fail_kind='transport' if transport else None)
    ses.burst = MagicMock(side_effect=lambda c, n, vb: [
        NS(valid=p is not None, pc=p) for p in pcs.get(c, [])])
    o.session = ses
    o._open_session = MagicMock(return_value=open_ok)
    o._verify_ranges = MagicMock(side_effect=AssertionError('정합성 게이트를 돌리면 안 된다'))
    o._init_overlay_probe = MagicMock(side_effect=AssertionError('프로브 재검사를 하면 안 된다'))
    return o


class LightReattach(unittest.TestCase):
    def test_ok_without_gate_or_probe_recheck(self):
        o = sampler()
        self.assertTrue(o.reattach())
        self.assertEqual([c.args[1] for c in o.session.burst.call_args_list],
                         [o._REATTACH_CHECK_SAMPLES] * 2)

    def test_wfi_core_is_fine_if_another_core_has_valid_pcs(self):
        self.assertTrue(sampler({0: [IN] * 32, 1: [None] * 32}).reattach())

    def test_bad_core_not_hidden_by_good_core(self):
        # 정상 코어 32개 + 범위 밖 1개·무효 31개 코어 — 합산이면 97% 로 통과하던 경우(리뷰)
        o = sampler({0: [IN] * 32, 1: [OUT] + [None] * 31})
        with self.assertLogs('pcfuzz', level='WARNING') as cm:
            self.assertFalse(o.reattach())
        self.assertIn('core1', '\n'.join(cm.output))

    def test_failures_fall_back(self):
        cases = {
            'no first-connect info': dict(ranges=False),
            'open fails': dict(open_ok=False),
            'pin fails': dict(pin_ok=False),
            'transport': dict(transport=True),
            'no valid pcs': dict(pcs_by_core={0: [None] * 32, 1: [None] * 32}),
            'out of range': dict(pcs_by_core={0: [IN] * 16 + [OUT] * 16, 1: []}),
        }
        for name, kw in cases.items():
            with self.subTest(name):
                self.assertFalse(sampler(**kw).reattach())


def fuzzer_with(light):
    f = v.NVMeFuzzer.__new__(v.NVMeFuzzer)
    f._pm_detached = True
    f._sampler_recovery_failed = False
    f._pm_detach_stats = dict(count=1, reattach_fail=0, reattach_s=0.0, reauth=0)
    f.sampler = NS(reattach=MagicMock(return_value=light), _reconnect=MagicMock(return_value=True),
                   session=NS(auth_count=0))
    return f


class AttachUsesLightPathFirst(unittest.TestCase):
    def test_light_ok_skips_full_reconnect(self):
        f = fuzzer_with(True)
        self.assertTrue(f._pm_sampler_attach('x'))
        f.sampler._reconnect.assert_not_called()
        self.assertEqual(f._pm_detach_stats['light'], 1)

    def test_light_fail_falls_back_to_full(self):
        f = fuzzer_with(False)
        with self.assertLogs('pcfuzz', level='WARNING'):
            self.assertTrue(f._pm_sampler_attach('x'))
        f.sampler._reconnect.assert_called_once()
        self.assertEqual(f._pm_detach_stats.get('light', 0), 0)

    def test_light_exception_falls_back(self):
        f = fuzzer_with(True)
        f.sampler.reattach.side_effect = RuntimeError('x')
        with self.assertLogs('pcfuzz', level='WARNING'):
            self.assertTrue(f._pm_sampler_attach('x'))
        f.sampler._reconnect.assert_called_once()


class TimingLine(unittest.TestCase):
    def test_breakdown(self):
        f = v.NVMeFuzzer.__new__(v.NVMeFuzzer)
        ses = NS(t_setup=0.0, t_read=0.0, setup_aborted=0)
        f.sampler = NS(session=ses)
        f._pm_detach_stats = dict(count=0, reattach_s=0.0)
        self.assertIsNone(f._timing_line())                    # 첫 호출: 기준만 잡는다
        clock = iter([10.0, 10.004, 10.004, 10.006,            # 전송 4ms, 종료 대기 2ms
                      10.010, 10.014, 10.014, 10.016])         # 다음 실행: 시작 간격 10ms
        with patch('fuzzer_active_test.time.monotonic', side_effect=lambda: next(clock)), \
                patch.object(v.ExceptionFuzzerMixin, '_send_nvme_command', return_value=0), \
                patch.object(v.ExceptionFuzzerMixin, '_stop_sampling_checked', return_value=(0, True)):
            for _ in range(2):
                f._send_nvme_command(b'', None)
                f._stop_sampling_checked()
        ses.t_setup, ses.t_read, ses.setup_aborted = 0.006, 0.002, 1
        f._pm_detach_stats.update(count=1, reattach_s=0.003)         # 실행 간격 10ms 중 3ms
        line = f._timing_line()
        self.assertIn('실행 2건', line)
        self.assertIn('전송(명령 실행) 4.0ms', line)
        self.assertIn('종료 대기 2.0ms', line)
        self.assertIn('기타(회계·변이·PM 동작) 1.0ms', line)   # 간격 10 − PM 3 − 전송 4 − 종료 대기 2
        self.assertIn('SBA 준비 3.0ms · PC 읽기 1.0ms', line)
        self.assertIn('준비 중단 1회', line)
        self.assertIn('PM 재연결 1회 평균 0.00s', line)
        self.assertIsNone(f._timing_line())                    # 창을 비웠다

    def test_first_line_without_prior_baseline(self):
        # 기준값을 미리 잡지 않은 실제 초기 경로 — 첫 출력에서도 SBA·PM 값이 나와야 한다(리뷰)
        f = v.NVMeFuzzer.__new__(v.NVMeFuzzer)
        ses = NS(t_setup=10.0, t_read=20.0, setup_aborted=4)     # 측정 전 누적(연결·부팅 수집)
        f.sampler = NS(session=ses)
        f._pm_detach_stats = dict(count=2, reattach_s=9.0)
        with patch.object(v.ExceptionFuzzerMixin, '_send_nvme_command', return_value=0), \
                patch.object(v.ExceptionFuzzerMixin, '_stop_sampling_checked', return_value=(0, True)):
            f._send_nvme_command(b'', None)
            f._stop_sampling_checked()
        ses.t_setup, ses.t_read, ses.setup_aborted = 12.0, 23.0, 5
        f._pm_detach_stats.update(count=3, reattach_s=10.5)
        line = f._timing_line()
        self.assertIn('SBA 준비 2000.0ms · PC 읽기 3000.0ms', line)
        self.assertIn('준비 중단 1회', line)
        self.assertIn('PM 재연결 1회 평균 1.50s', line)

    def test_snapshot_never_raises_on_odd_sampler(self):
        # 전송 경로에서 불린다 — Mock·None 샘플러여도 예외 없이 0 (v11 예외 시험들이 Mock 샘플러를 쓴다)
        from unittest.mock import Mock
        f = v.NVMeFuzzer.__new__(v.NVMeFuzzer)
        for smp in (Mock(), None, NS(session=None), NS(session=NS(t_setup='x'))):
            f.sampler = smp
            f._pm_detach_stats = Mock() if smp is None else None
            snap = f._timing_snapshot()
            self.assertEqual(snap['setup'], 0.0)

    def test_exception_in_timing_does_not_break_status(self):
        f = v.NVMeFuzzer.__new__(v.NVMeFuzzer)
        f._timing_line = MagicMock(side_effect=RuntimeError('x'))
        with patch.object(v._V101Fuzzer, '_print_status', return_value=None) as base:
            f._print_status({}, 0, 0.0)
        base.assert_called_once()


if __name__ == '__main__':
    unittest.main()
