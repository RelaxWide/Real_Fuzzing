"""v11.2.1 — BM9K1 샘플링이 명령 실행 속도에 영향을 주지 않게.

예전 RiscvPcsrSampler 는 (1) stop_event 를 버스트(약 200~300회 읽기) 경계에서만 봐서 명령이 끝나도
진행 중인 버스트를 다 읽을 때까지 stop_sampling 이 기다렸고 (2) 세션 붕괴 시 워커가 명령 실행 도중에
재오픈·재인증을 했다. 포화 조기 종료는 넣지 않는다 — 명령이 끝나면 멈추므로 실행 속도와 무관하고
커버리지만 줄인다.
진짜 PcsrSession.burst 와 진짜 워커를 돌리고 DAP 읽기만 가짜로 둔다.
"""
import random
import threading
import unittest
from types import SimpleNamespace as NS
from unittest.mock import Mock

from fuzzer_target import fuzzer as v
import riscv_cov   # noqa: E402 — fuzzer_target 이 경로를 잡은 뒤

NEW = 0x2000


def session(read, pin_ok=lambda core: True):
    """read(core) → raw 값(None=읽기 실패). 읽은 횟수는 s.reads[core]."""
    s = riscv_cov.PcsrSession(cores={})
    s.reads = {}
    cur = {}

    def pin(core, abort=None):
        cur['c'] = core
        return pin_ok(core)

    def raw(_dap):
        c = cur['c']
        s.reads[c] = s.reads.get(c, 0) + 1
        return read(c)
    s.pin = pin
    s._sj = NS(sba_read_pinned=raw)
    s.dap = object()
    s.read_word = Mock(return_value=7)
    return s


def sampler(read, cores=(0,), limit=2000, burst=256, overlay=False):
    o = v.RiscvPcsrSampler.__new__(v.RiscvPcsrSampler)
    o.stop_event, o.openocd_error = threading.Event(), threading.Event()
    o._weights = {c: 1 for c in cores}
    o._rng = random.Random(0)
    o._rc = riscv_cov
    o.config = NS(max_samples_per_run=limit)
    o._burst_len, o._jitter_pct, o._valid_bit = burst, 0, 1
    o._ovl_probe = {c: 0x40 for c in cores} if overlay else {}
    o._ovl_dropped = o._ovl_kept = o.total_samples = 0
    o._ovl_fail_streak = {}
    o._resolve_bank = lambda c, w: w
    o._in_core_range = lambda c, pc: True
    o.collapse_count = 0
    o._sj_mod = lambda: NS(PCSR_COLLAPSE_MIN_ALL_CORE_CYCLES=3, PCSR_COLLAPSE_MIN_SECONDS=0.0)
    o.session = session(read)
    o.session.recover = Mock()
    return o


def pc(x):
    return x | 1          # valid bit


class StopsAtCommandEnd(unittest.TestCase):
    def test_burst_stops_on_the_read_after_stop(self):
        # 명령이 10번째 읽기 도중 끝났다 — 버스트(256)의 나머지를 읽지 않는다
        o = None

        def read(c):
            if o.session.reads[c] == 10:
                o.stop_event.set()
            return pc(NEW)
        o = sampler(read)
        o._sampling_worker()
        self.assertEqual(o.session.reads, {0: 10})
        self.assertEqual(o._stopped_reason, 'stop_event')

    def test_stop_from_main_thread_reads_at_most_one_more(self):
        gate, release, after = threading.Event(), threading.Event(), {}

        def read(c):
            n = o.session.reads[c]
            if n == 50:
                gate.set()           # 메인: 이 시점에 stop_sampling
                release.wait(5)
            return pc(NEW)
        o = sampler(read, limit=10 ** 6)
        t = threading.Thread(target=o._sampling_worker)
        t.start()
        self.assertTrue(gate.wait(5))
        o.stop_event.set()
        release.set()
        t.join(5)
        self.assertFalse(t.is_alive())
        self.assertEqual(o.session.reads[0], 50)   # 진행 중이던 읽기 하나로 끝

    def test_overlay_core_truncated_burst_keeps_samples_after_end_check(self):
        # 끊긴 버스트도 끝 bank 를 확인해 같으면 살린다 — 버리면 빠른 명령에서 H 코어 샘플이 전부 사라진다
        o = None

        def read(c):
            if o.session.reads[c] == 5:
                o.stop_event.set()
            return pc(NEW)
        o = sampler(read, overlay=True)
        o._sampling_worker()
        self.assertEqual(o.session.read_word.call_count, 2)   # 시작·끝 bank 확인
        self.assertEqual((o._ovl_dropped, o._ovl_kept), (0, 5))
        self.assertEqual(len(o._observations), 5)

    def test_only_pre_burst_bank_read_is_abortable(self):
        # 시작 bank 읽기·pin 은 명령 종료로 중단 가능, 끝 bank 확인은 샘플을 살리는 단계라 중단하지 않는다
        o = None

        def read(c):
            if o.session.reads[c] == 3:
                o.stop_event.set()
            return pc(NEW)
        o = sampler(read, overlay=True)
        o._sampling_worker()
        calls = o.session.read_word.call_args_list
        self.assertEqual(len(calls), 2)
        self.assertIs(calls[0].kwargs.get('abort').__self__, o.stop_event)
        self.assertNotIn('abort', calls[1].kwargs)

    def test_overlay_core_truncated_burst_dropped_on_swap(self):
        o = None

        def read(c):
            if o.session.reads[c] == 5:
                o.stop_event.set()
            return pc(NEW)
        o = sampler(read, overlay=True)
        o.session.read_word = Mock(side_effect=[7, 8])           # 버스트 사이 스왑
        o._sampling_worker()
        self.assertEqual((o._ovl_dropped, o._ovl_kept), (5, 0))

    def test_stop_before_burst_after_bank_read_reads_nothing(self):
        o = sampler(lambda c: pc(NEW), overlay=True)
        o.session.read_word = Mock(side_effect=lambda a: o.stop_event.set() or 7)
        o._sampling_worker()
        self.assertEqual(o.session.reads, {})

    def test_truncated_failed_burst_is_not_transport(self):
        # 명령 종료로 한두 샘플 만에 끊긴 버스트의 일시 실패로 재연결을 돌리지 않는다
        o = None

        def read(c):
            o.stop_event.set()
            return None
        o = sampler(read)
        o._sampling_worker()
        self.assertFalse(o.openocd_error.is_set())

    def test_full_failed_burst_is_still_transport(self):
        o = sampler(lambda c: None, burst=16)
        o._sampling_worker()
        self.assertTrue(o.openocd_error.is_set())
        self.assertEqual(o._stopped_reason, 'transport')


class FailuresAccumulateAcrossWindows(unittest.TestCase):
    """리뷰 2차 P1: 짧은 명령만 이어지면 모든 버스트가 끊겨 전송 장애가 영영 판정되지 않았다."""

    def windows(self, o, n, per_window):
        """창 n개 — 각 창은 읽기 per_window 회 만에 명령이 끝난다(stop)."""
        out = []
        for _ in range(n):
            o.stop_event.clear()
            o._win_reads = 0
            o._sampling_worker()
            out.append(o.openocd_error.is_set())
            if o.openocd_error.is_set():
                break
        return out

    def short_window_sampler(self, read, per_window=2):
        o = None

        def r(c):
            o._win_reads += 1
            if o._win_reads >= per_window:
                o.stop_event.set()
            return read(o, c)
        o = sampler(r)
        return o

    def test_all_failed_short_windows_become_transport(self):
        o = self.short_window_sampler(lambda o, c: None)
        flags = self.windows(o, 5, 2)
        self.assertEqual(flags, [False] * (o._STOPPED_FAIL_LIMIT - 1) + [True])
        self.assertEqual(o._stopped_reason, 'transport')

    def test_any_successful_read_resets(self):
        n = iter(range(10 ** 6))
        o = self.short_window_sampler(lambda o, c: None if next(n) % 4 < 3 else pc(NEW), per_window=2)
        self.assertEqual(self.windows(o, 10, 2), [False] * 10)  # 창 두 개마다 성공 읽기가 섞인다

    def test_pin_failures_accumulate_across_windows(self):
        o = sampler(lambda c: pc(NEW))
        pins = {'n': 0}

        def pin_fail(core):
            pins['n'] += 1
            if pins['n'] % 3 == 0:
                o.stop_event.set()                 # 창마다 pin 3번 만에 명령이 끝난다
            return False
        o.session = session(lambda c: pc(NEW), pin_ok=pin_fail)
        o.session.recover = Mock()
        flags = []
        for _ in range(5):
            o.stop_event.clear()
            o._sampling_worker()
            flags.append(o.openocd_error.is_set())
            if flags[-1]:
                break
        # 창마다 pin 3번 중 마지막은 명령 종료와 겹쳐 '중단된 준비'로 보고 세지 않는다 → 2+2+2+2 = 한도 8
        self.assertEqual(flags, [False, False, False, True])
        self.assertEqual(o._stopped_reason, 'pin_fail')

    def test_successful_pin_resets_pin_failure_count(self):
        # pin 성공이 섞이면 연속이 아니다 — 오버레이 폐기(continue)로 끝나는 버스트도 성공으로 친다
        o = sampler(lambda c: pc(NEW), burst=1, overlay=True)
        o._resolve_bank = lambda c, w: None                     # 매번 bank 미검출 → 폐기 continue
        o._OVL_FAIL_LIMIT = 10 ** 6
        o._ovl_note_fail = lambda *a: None
        pins = {'n': 0}

        def pin_alt(core):
            pins['n'] += 1
            if pins['n'] % 4 == 0:
                o.stop_event.set()
            return pins['n'] % 2 == 0                           # 실패·성공 번갈아
        o.session = session(lambda c: pc(NEW), pin_ok=pin_alt)
        for _ in range(10):
            o.stop_event.clear()
            o._sampling_worker()
        self.assertFalse(o.openocd_error.is_set())

class CollapseIsNotRecoveredDuringCommand(unittest.TestCase):
    def test_collapse_hands_over_to_main_loop(self):
        o = sampler(lambda c: 0, cores=(0,))
        o._invalid_streak = {0: 3}
        o._all_invalid_since = 0.0
        self.assertTrue(o._maybe_recover())
        o.session.recover.assert_not_called()                     # 워커는 재오픈·재인증 안 함
        self.assertTrue(o.openocd_error.is_set())
        self.assertEqual((o.collapse_count, o._stopped_reason), (1, 'collapse'))
        # 넘겨받은 장애는 명령 뒤 _stop_sampling_checked 가 APST 를 끄고 재초기화한다
        #   (test_v11_1_run_compare.test_sampling_failure_reinit_disables_apst_first)

    def test_all_invalid_window_hands_over_collapse(self):
        o = sampler(lambda c: 0, cores=(0, 1))
        o._sampling_worker()
        self.assertEqual(o._stopped_reason, 'collapse')
        self.assertTrue(o.openocd_error.is_set())
        o.session.recover.assert_not_called()

    def test_window_runs_to_max_samples_without_saturation(self):
        o = sampler(lambda c: pc(NEW), cores=(0, 1), limit=600)
        o._sampling_worker()
        self.assertEqual(sum(o.session.reads.values()), 600)
        self.assertEqual(o._stopped_reason, 'max_samples')


if __name__ == '__main__':
    unittest.main()
