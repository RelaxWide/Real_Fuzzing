"""io_patterns 프롬프트 — 규칙 대신 패턴별 실측 성과표.

실행 중 LLM 이 14개 패턴 중 overwrite_churn 만 계속 골랐다. 원인은 예시 한 줄이 아니라
프롬프트 전체였다: 목표 문단("DIRTY FTL", WAF 가 직접 신호, 작은 랜덤 overwrite 권장),
예시(free_blocks high → overwrite_churn), 피드백 처방("Keep this pattern", "Use smaller
random overwrites") 이 모두 같은 패턴을 가리켰고, 나머지 12개는 이름만 있었다.

지금은 판단 규칙을 주지 않고 (1) 패턴별 누적 성과표 (2) 직전 버스트 수치 (3) 파라미터가
실제로 먹는 패턴 목록만 준다.
"""
import random
import unittest
import unittest.mock

from test_v10_2_learning import fuzzer, harness   # noqa: F401

PATTERNS = fuzzer.IO_WL_PATTERNS
LIM = {'lba': 512, 'nsze': 1_000_000, 'max_nlb': 63,
       'working_set_lbas': 20_000, 'hot_lbas': 2_048}


def obj():
    o = harness({'enabled': True})
    o._wl_pattern_stats = {}
    o._wl_burst_seq = 0
    o._wl_base = 0
    o._last_workload_result = None
    return o


class ParamApplicabilityMatchesGenerator(unittest.TestCase):
    """프롬프트에 싣는 '파라미터가 먹는 패턴' 목록이 생성기와 어긋나면 LLM 을 속인다."""

    A = {'lba_span': 5000, 'block_size': 3, 'hot_fraction': 0.3, 'read_ratio': 0.2}
    B = {'lba_span': 9000, 'block_size': 9, 'hot_fraction': 0.6, 'read_ratio': 0.7}

    def gen(self, pattern, desc):
        o = obj()
        random.seed(1234)
        return o._gen_workload_block(pattern, dict(LIM), desc)

    def test_every_param_listing_is_exact(self):
        for param in self.A:
            listed = set(fuzzer.IO_WL_PARAM_PATTERNS[param])
            for pattern in PATTERNS:
                varied = dict(self.A, **{param: self.B[param]})
                changed = self.gen(pattern, self.A) != self.gen(pattern, varied)
                self.assertEqual(changed, pattern in listed,
                                 f'{param} 이 {pattern} 에 {"먹는데 목록에 없다" if changed else "안 먹는데 목록에 있다"}')

    def test_listed_patterns_exist(self):
        for param, pats in fuzzer.IO_WL_PARAM_PATTERNS.items():
            for p in pats:
                self.assertIn(p, fuzzer._IW_DEFAULT_PATTERNS, f'{param}: 없는 패턴 {p}')


class ResultsTable(unittest.TestCase):
    def test_empty(self):
        t = obj()._llm_workload_table()
        self.assertIn('(no bursts yet)', t)
        self.assertIn('never tried: ' + ', '.join(PATTERNS), t)

    def test_rate_is_normalized_and_sorted(self):
        o = obj()
        # 총량은 churn 이 크지만 명령당으로는 hot_cold 가 높다 — 긴 버스트가 이기면 안 된다.
        o._wl_record_pattern('overwrite_churn', 20, 5000, 1, 30)
        o._wl_record_pattern('overwrite_churn', 0, 5000, 0, 40)
        o._wl_record_pattern('hot_cold', 8, 1000, 0, None)
        t = o._llm_workload_table().splitlines()
        rows = [l for l in t if l.startswith('  ') and 'never tried' not in l]
        self.assertTrue(rows[0].lstrip().startswith('hot_cold'), rows)
        self.assertIn('cov/1k=8.00', rows[0])
        self.assertIn('avg_dWAF=n/a', rows[0])
        self.assertIn('last=latest', rows[0])
        self.assertIn('n=2', rows[1])
        self.assertIn('cov/1k=2.00', rows[1])
        self.assertIn('avg_dWAF=+35', rows[1])
        self.assertIn('last=1 ago', rows[1])
        never = [l for l in t if 'never tried' in l][0]
        self.assertNotIn('overwrite_churn', never)
        self.assertNotIn('hot_cold', never)
        self.assertIn('boundary', never)

    def test_table_is_short(self):
        # 패턴 하나 고르는 데 프롬프트가 길어지면 안 된다 — 전 패턴을 써도 한 줄씩.
        o = obj()
        for p in PATTERNS:
            o._wl_record_pattern(p, 3, 1000, 0, 5)
        t = o._llm_workload_table()
        self.assertEqual(len(t.splitlines()), 1 + len(PATTERNS))
        self.assertLess(len(t), 2000)


class FeedbackHasNoPrescription(unittest.TestCase):
    def test_numbers_only(self):
        o = obj()
        o._last_workload_result = dict(
            pattern='read_disturb', desc={'lba_span': 10}, blocks=50, cov=0, cmds=5000,
            new_states=0, waf_start=100, waf_peak=100, waf_delta=0, ffm_start=3,
            ffm_peak=3, ffm_trough=3, ffm_delta=0, ffm_range=0, stop='walltime')
        fb = o._llm_workload_feedback()
        self.assertIn('pattern=read_disturb', fb)
        self.assertIn('new_cov=0 over 5000 cmds', fb)
        for bad in ('Keep this pattern', 'random overwrites', 'NO EFFECT', 'WEAK', 'SUCCESS'):
            self.assertNotIn(bad, fb)


class PromptIsNeutral(unittest.TestCase):
    def build(self, o):
        o._llm_exercised_names = lambda: set()
        o._llm_coverage_context = lambda: ''
        o._llm_grounding_block = lambda: ''
        o._llm_telemetry_block = lambda: '  waf_x100 = 120  [write amplification]'
        return o._llm_build_request('io_patterns')

    def test_no_overwrite_bias_and_table_present(self):
        o = obj()
        o._wl_record_pattern('overwrite_churn', 5, 1000, 0, 10)
        _, user = self.build(o)
        for bad in ('DIRTY FTL', 'free_blocks is high', 'Small random OVERWRITES',
                    'THIS is the direct signal'):
            self.assertNotIn(bad, user)
        self.assertIn('I/O pattern results this run', user)
        self.assertIn('never tried:', user)
        self.assertIn('lba_span -> overwrite_churn, hot_cold', user)
        self.assertIn('"io_workload"', user)


class BurstRecordsStats(unittest.TestCase):
    """실제 _run_llm_workload_burst 를 돌려 성과가 패턴별로 쌓이는지."""

    def test_burst(self):
        o = obj()
        o._wl_write_cmd = o._wl_read_cmd = object()
        o._io_workload_limits = lambda: dict(LIM)
        o.config = unittest.mock.Mock(pm_inject_prob=0, prefill=True)
        o._state_capture_safe = lambda: {}
        o._state_seen = set()
        o._timeout_crash = o._sampler_recovery_failed = False
        o._wl_blocks_done = 0
        o._cov_by_src = {}
        o.executions = 0
        o._telemetry_delta_summary = lambda a, b: ''
        o._gen_workload_block = lambda p, lim, d: [('w', 0, 0), ('w', 1, 0)]

        def send(op, slba, nlb, lba, seed_class=None, prov_id=None):
            o.executions += 1
            if o.executions % 10 == 0:
                o._cov_credit('llm/iowl', 'edge', 1)
            return 0
        o._wl_send_one = send
        o._run_llm_workload_burst({'pattern': 'boundary'})
        cmds = 2 * fuzzer.IO_WL_BURST_BLOCKS_MAX
        st = o._wl_pattern_stats['boundary']
        self.assertEqual((st['n'], st['cmds'], st['cov']), (1, cmds, cmds // 10))
        self.assertEqual(o._last_workload_result['cov'], cmds // 10)
        self.assertEqual(o._wl_burst_seq, 1)


if __name__ == '__main__':
    unittest.main()
