"""Hardware-free regression tests; extract sampler methods without fuzzer startup I/O."""
import ast
import logging
from pathlib import Path
import random
import threading
import time
import unittest
from types import SimpleNamespace as NS
from unittest.mock import Mock


SOURCE = Path(__file__).resolve().parents[1] / 'pc_sampling_fuzzer_v10.1.py'
tree = ast.parse(SOURCE.read_text())
sampler = next(n for n in tree.body
               if isinstance(n, ast.ClassDef) and n.name == 'RiscvPcsrSampler')
methods = {'_sampling_worker', '_maybe_recover', '_track_collapse', 'connect'}
namespace = {'log': logging.getLogger(__name__), 'time': time}
exec(compile(ast.Module(body=[n for n in sampler.body
                             if isinstance(n, ast.FunctionDef) and n.name in methods],
                        type_ignores=[]), str(SOURCE), 'exec'), namespace)
Sampler = type('SamplerUnderTest', (), {name: namespace[name] for name in methods})


class SamplerRecoveryTests(unittest.TestCase):
    def test_failed_connect_does_not_poison_next_retry(self):
        s = Sampler()
        s.config = NS(riscv={})
        s._cores = {0: {}, 1: {}}
        s._weights = {0: 3, 1: 1}
        s._primary, s._seed = 0, 123
        s.session = None
        sessions = [NS(open=Mock(return_value=True), close=Mock(),
                       pin=Mock(return_value=True), auth_count=0, auth_ms=0)
                    for _ in range(2)]
        s._rc = NS(PcsrSession=Mock(side_effect=sessions))
        s.close = lambda: s.session.close()
        s._verify_ranges = Mock(side_effect=[[0, 1], []])
        s._init_overlay_probe = Mock()
        self.assertFalse(s.connect())
        self.assertEqual(s._weights, {0: 3, 1: 1})
        sessions[0].close.assert_called_once()
        s._init_overlay_probe.assert_not_called()
        self.assertTrue(s.connect())
        self.assertEqual(s._weights, {0: 3, 1: 1})
        s._init_overlay_probe.assert_called_once()

    def make_sampler(self, transport=False, overlay=False):
        s = Sampler()
        s.stop_event = threading.Event()
        s.openocd_error = threading.Event()
        s._all_invalid_since = time.time() - 1000
        s._invalid_streak = {}
        s._weights = {0: 1}
        s._rng = random.Random(0)
        s._rc = NS(build_burst_schedule=lambda *a, **kw: [0])
        s.config = NS(max_samples_per_run=1)
        s._burst_len, s._jitter_pct = 1, 0
        s._valid_bit = 1
        s._EMPTY_BURST_LIMIT = 8
        s._ovl_probe = {0: 1234} if overlay else {}
        s._resolve_bank = lambda *a: None
        s._ovl_dropped = s.total_samples = 0
        s._observations = []
        s._reset_window_extra = lambda: s._observations.clear()
        s.session = NS(
            burst=Mock(return_value=[NS(valid=False, pc=None)]),
            read_word=Mock(return_value=None),
            last_fail_kind='transport' if transport else None,
            recover=Mock())
        s._sj_mod = Mock(return_value=NS(
            PCSR_COLLAPSE_MIN_ALL_CORE_CYCLES=1,
            PCSR_COLLAPSE_MIN_SECONDS=100))
        return s

    def test_transport_failure_is_reported_before_overlay_discard(self):
        s = self.make_sampler(transport=True, overlay=True)
        s._sampling_worker()
        self.assertTrue(s.openocd_error.is_set())
        self.assertEqual(s._stopped_reason, 'transport')
        self.assertEqual(s._ovl_dropped, 0)
        self.assertEqual(s.session.read_word.call_count, 1)
        s.session.recover.assert_not_called()

    def test_invalid_pc_is_not_a_transport_failure(self):
        s = self.make_sampler()
        s._sampling_worker()
        self.assertFalse(s.openocd_error.is_set())
        self.assertEqual(s._stopped_reason, 'max_samples')
        self.assertEqual(len(s._observations), 1)
        s.session.recover.assert_not_called()

    def test_empty_pin_failures_keep_bounded_retry(self):
        s = self.make_sampler(transport=True)
        s.session.burst.return_value = []
        s._sampling_worker()
        self.assertEqual(s.session.burst.call_count, 8)
        self.assertTrue(s.openocd_error.is_set())
        self.assertEqual(s._stopped_reason, 'pin_fail')
        s.session.recover.assert_not_called()

    def test_new_window_does_not_inherit_old_collapse_timer(self):
        s = self.make_sampler()
        started = time.time()
        s._sampling_worker()
        self.assertGreaterEqual(s._all_invalid_since, started)
        self.assertFalse(s.openocd_error.is_set())

    def test_stop_or_transport_error_prevents_worker_recovery(self):
        for event in ('stop_event', 'openocd_error'):
            with self.subTest(event=event):
                s = self.make_sampler()
                getattr(s, event).set()
                s._maybe_recover()
                s._sj_mod.assert_not_called()
                s.session.recover.assert_not_called()


if __name__ == '__main__':
    unittest.main()
