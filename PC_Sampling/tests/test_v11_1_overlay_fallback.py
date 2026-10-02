"""v11.1 — 오버레이 bank 판별이 계속 실패하면 그 코어 샘플을 전부 버리지 않고 bank 판별을 끈다.

2026-10 실측: 복구 후 프로브 읽기가 계속 실패해 ovl-drop 100% → PC 수집 0 처럼 보였다.
"""
import random
import threading
import time
import unittest
from types import SimpleNamespace as NS
from unittest.mock import Mock

from test_v10_2_learning import fuzzer


def make(read_words, bank_of, samples=200):
    s = fuzzer.RiscvPcsrSampler.__new__(fuzzer.RiscvPcsrSampler)
    s.stop_event, s.openocd_error = threading.Event(), threading.Event()
    s._weights = {0: 1}
    s._rng = random.Random(0)
    s._rc = NS(build_burst_schedule=lambda *a, **kw: [0])
    s.config = NS(max_samples_per_run=samples)
    s._burst_len, s._jitter_pct, s._valid_bit = 1, 0, 1
    s._ovl_probe = {0: 0x1000}
    s._ovl_dropped = s._ovl_kept = s.total_samples = 0
    s._observations = []
    s._ranges = {0: [(0, 0xFFFFFFFF)]}
    s._in_core_range = lambda c, pc: True
    s._resolve_bank = lambda c, w: bank_of(w)
    s.session = NS(burst=Mock(return_value=[NS(valid=True, pc=0x10, core_id=0,
                                                _replace=lambda **k: NS(valid=True, pc=0x10,
                                                                        core_id=0, **k))]),
                   read_word=Mock(side_effect=read_words), last_fail_kind=None)
    s._maybe_recover = lambda: None
    return s


class OverlayFallback(unittest.TestCase):
    def test_persistent_read_failure_disables_probe_and_collects(self):
        s = make(lambda a: None, lambda w: None)
        with self.assertLogs(fuzzer.log, 'ERROR') as cm:
            s._sampling_worker()
        self.assertNotIn(0, s._ovl_probe)                       # 판별 꺼짐
        self.assertEqual(s._ovl_dropped, s._OVL_FAIL_LIMIT)     # 한도까지만 버림
        self.assertGreater(len(s.current_trace), 0)             # 이후 bank 0 으로 수집
        self.assertTrue(any('bank 판별 끔' in m for m in cm.output))

    def test_normal_swap_does_not_count_as_failure(self):
        it = iter(range(10 ** 6))
        s = make(lambda a: next(it), lambda w: w)               # 앞뒤 bank 가 매번 다름 = 스왑
        s._sampling_worker()
        self.assertIn(0, s._ovl_probe)
        self.assertEqual(s._ovl_dropped, 200)

    def test_success_resets_streak(self):
        seq = iter([None, None] * (fuzzer.RiscvPcsrSampler._OVL_FAIL_LIMIT - 1) + [7, 7] * 1000)
        s = make(lambda a: next(seq), lambda w: w)
        s._sampling_worker()
        self.assertIn(0, s._ovl_probe)
        self.assertEqual(s._ovl_fail_streak[0], 0)
        self.assertGreater(s._ovl_kept, 0)


if __name__ == '__main__':
    unittest.main()
