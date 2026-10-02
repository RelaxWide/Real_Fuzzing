"""v11.1 — 실행 기록(run_record) · LLM 몫 · CSFuzz p 갱신 · 실행 비교 도구.

1) 퍼저가 실행 기록 파일을 쓴다: 조건·시계열(출처별 발견/명령 수)·최종 커버리지 집합, 1분 간격, 종료 시 final.
2) CSFuzz: C2 보상이 '재생 명령당 새 edge'(C1 과 같은 단위)이고, 효율이 같으면 p 가 움직이지 않는다
   (예전 식은 작은 corpus 쪽이 늘 이겨 p 가 0.1 에 붙었다).
3) compare_runs: 그룹별 중앙값·배속·A12·고유 BB 를 계산하고 그래프 3장 + 요약을 만든다.
"""
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from test_v10_2_learning import ROOT, fuzzer, harness   # noqa: F401

sys.path.insert(0, str(ROOT / 'tools'))
import compare_runs                                       # noqa: E402


def fuzz_obj(tmp):
    o = harness({'enabled': False})
    o.output_dir = Path(tmp)
    o.start_time = datetime.now() - timedelta(hours=2)
    o.config = SimpleNamespace(nvme_device='/dev/nvme0', rag_enabled=True, rag_module_path='rag.vllm_client',
                               product='PM9M1', io_workload_enabled=True, pm_inject_prob=0.0,
                               state_enabled=True)
    o.commands = [fuzzer._NAME_TO_CMD['Identify'], fuzzer._NAME_TO_CMD['Read']]
    o._run_id = 'out_20261001_000000'
    o._cov_by_src = {'llm/cmd': {'edge': 30, 'sc': 0, 'state': 0},
                     'mutation/cmd': {'edge': 70, 'sc': 0, 'state': 0}}
    o._exec_by_src = {'llm/cmd': 100, 'mutation/cmd': 900}
    o._fz_found = {'llm': 30, 'mutation': 70}
    o._fz_sel_new = {'llm': 30, 'mutation': 70}
    o._fz_sel_cmd = {'llm': 100, 'mutation': 900}
    o._bb_at_start = 1
    o._run_record_series, o._run_record_last_t = [], -1e18
    o._run_record_cond, o._run_record_warned = None, False
    o._sa_loaded, o._sa_covered_bbs = True, {0x100, 0x200}
    o._sa_total_bbs, o._sa_total_funcs = 10, 4
    o._sa_entered_funcs = {1}
    o._sc_seen, o._state_seen = set(), set()
    o.llm = Mock(enabled=True)
    return o


class RunRecord(unittest.TestCase):
    def test_written_throttled_and_final(self):
        with tempfile.TemporaryDirectory() as d:
            o = fuzz_obj(d)
            row = dict(elapsed_s=60.0, exec=1000, bb_pct=20.0, func_pct=25.0, bb_count=2,
                       sc_count=3, state_count=1, by_src=o._cov_by_src, exec_by_src=o._exec_by_src)
            o._run_record_update(row)
            o._run_record_update(dict(row, exec=1100))           # 1분 안 — 시계열에 안 더함
            files = list(Path(d).glob('run_record_*.json'))
            self.assertEqual(len(files), 1)
            path = files[0]
            rec = json.loads(path.read_text())
            self.assertEqual(rec['schema'], 'pcfuzz-run/1')
            self.assertEqual(len(rec['series']), 1)
            pt = rec['series'][0]
            self.assertEqual(pt['new_edge'], {'llm': 30, 'mutation': 70})
            self.assertEqual(pt['cmds'], {'llm': 100, 'mutation': 900})
            self.assertEqual(pt['sel'], {'llm': [30, 100], 'mutation': [70, 900]})
            self.assertEqual(pt['found'], {'llm': 30, 'mutation': 70})
            self.assertTrue(rec['conditions']['llm'])
            self.assertEqual(rec['conditions']['product'], 'PM9M1')
            self.assertEqual(rec['covered_kind'], 'bb_start')
            self.assertEqual(rec['covered'], [0x100, 0x200])
            self.assertFalse(rec['final'])
            o._run_record_update(None, final=True)               # 종료: 끝점 추가 + final
            rec = json.loads(path.read_text())
            self.assertTrue(rec['final'])
            self.assertEqual(len(rec['series']), 2)
            self.assertEqual(rec['final_coverage']['bb'], 2)
            self.assertAlmostEqual(rec['final_coverage']['bb_pct'], 20.0)

    def test_write_failure_never_breaks_fuzzing(self):
        o = fuzz_obj('/nonexistent/dir')
        with self.assertLogs('pcfuzz', level='WARNING'):
            o._run_record_update(None, final=True)               # 예외 없이 경고 1회


class FuzzPhaseAttribution(unittest.TestCase):
    """효율 비교는 퍼징 시작 후·corpus 에서 골라 실행한 명령(cmd|seq)만 — 시작 전 보정이 찾은 BB 와
    LLM 이 패턴만 고른 워크로드(iowl)는 섞지 않는다(그래프에서 LLM 이 예산만 쓰는 것처럼 보이던 원인)."""

    def obj(self):
        o = fuzzer.NVMeFuzzer.__new__(fuzzer.NVMeFuzzer)
        o._cov_by_src, o._boost_gain = {}, {}
        o._fz_found = {'llm': 0, 'mutation': 0}
        o._fz_sel_new = {'llm': 0, 'mutation': 0}
        o._fz_sel_cmd = {'llm': 0, 'mutation': 0}
        return o

    def test_calibration_before_start_is_not_attributed(self):
        o = self.obj()
        o.start_time = None
        o._cov_credit('mutation/cmd', 'edge', 500, affect_boost=False)
        self.assertEqual(o._fz_found, {'llm': 0, 'mutation': 0})
        self.assertEqual(o._cov_by_src['mutation/cmd']['edge'], 500)      # 원래 누적은 그대로

    def test_after_start_iowl_counts_as_found_but_not_selected(self):
        o = self.obj()
        o.start_time = datetime.now()
        o._cov_credit('llm/iowl', 'edge', 4)
        o._cov_credit('llm/cmd', 'edge', 3)
        o._cov_credit('mutation/seq', 'edge', 2)
        self.assertEqual(o._fz_found, {'llm': 7, 'mutation': 2})
        self.assertEqual(o._fz_sel_new, {'llm': 3, 'mutation': 2})


class CsfuzzP(unittest.TestCase):
    def obj(self, c1, c2, nc1=1000, nc2=50):
        o = fuzzer.NVMeFuzzer.__new__(fuzzer.NVMeFuzzer)
        o.corpus, o.state_corpus = [0] * nc1, [0] * nc2
        o._csfuzz_a = o._csfuzz_b = 1.0
        o._csfuzz_p, o._csfuzz_history = 0.5, []
        o._csfuzz_c1_rewards, o._csfuzz_c2_rewards = list(c1), list(c2)
        o.executions = 10000
        return o

    def test_depth_only_corpus_admission_has_no_edge_reward(self):
        for gain in (0, 1):
            with self.subTest(gain=gain), tempfile.TemporaryDirectory() as d:
                cfg = fuzzer.FuzzConfig(no_jlink=True, rag_enabled=False, state_enabled=False,
                                       output_dir=d, vmon_enabled=False)
                with patch.object(fuzzer.NVMeFuzzer, '_load_static_analysis'), \
                     patch.object(fuzzer.NVMeFuzzer, '_load_riscv_coverage'):
                    obj = fuzzer.NVMeFuzzer(cfg)
                obj.config.state_enabled = True
                obj._learning_window_valid = True
                seed = fuzzer.Seed(data=b'input', cmd=fuzzer._NAME_TO_CMD['Write'])
                obj._last_nvme_status = 0
                obj._last_wire = {'opcode': 1, 'queue': 'io', 'nsid': 1, 'xfer_len': 5}
                obj._learning_last_send = (seed, 0.5)
                obj._credit_seed = seed
                obj.sampler.current_trace = {100}
                obj.sampler.evaluate_coverage = Mock(return_value=(bool(gain), gain))
                obj._ledger_write = Mock()
                obj._account_command(seed, seed.data, 0, 1)
                self.assertTrue(obj._last_depth_adv)
                self.assertTrue(obj.corpus)  # SC-depth admission remains intact
                self.assertEqual(obj._csfuzz_c1_rewards, [gain])

    def test_equal_efficiency_keeps_p_even_with_unequal_corpus(self):
        o = self.obj([1] + [0] * 99, [1] + [0] * 99)
        o._update_csfuzz_p()
        self.assertAlmostEqual(o._csfuzz_p, 0.5)

    def test_better_side_wins_but_bounded(self):
        o = self.obj([1] * 10 + [0] * 90, [0] * 100)        # C1 만 성과
        o._update_csfuzz_p()
        self.assertAlmostEqual(o._csfuzz_p, 0.6)
        o = self.obj([0] * 100, [1] * 10 + [0] * 90)        # C2 만 성과
        o._update_csfuzz_p()
        self.assertAlmostEqual(o._csfuzz_p, 0.4)

    def test_too_few_samples_holds_and_keeps_samples(self):
        o = self.obj([1] * 100, [0] * 10)
        o._update_csfuzz_p()
        self.assertAlmostEqual(o._csfuzz_p, 0.5)
        self.assertEqual(len(o._csfuzz_c2_rewards), 10)       # 버리지 않고 이어서 센다


def record(run_id, llm, series, covered, product='PM9M1'):
    return dict(schema='pcfuzz-run/1', run_id=run_id, final=True, elapsed_s=series[-1][0] * 3600,
                conditions=dict(llm=llm, product=product, commands=['Identify'], fw={'firmware_rev': 'X'}),
                coverage_unit='BB', totals=dict(bb_total=1000, func_total=100),
                final_coverage={}, llm_status=dict(active_at_end=llm),
                series=[dict(t=h * 3600, exec=int(h * 1000), bb_pct=v,
                             new_edge={'llm': int(v * 4) if llm else 0, 'mutation': int(v * 6)},
                             cmds={'llm': 100 if llm else 0, 'mutation': 900}) for h, v in series],
                covered_kind='bb_start', covered=covered)


class CompareTool(unittest.TestCase):
    def test_speedup_a12_unique_and_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            # OFF: 8h 에 20%. ON: 같은 20% 를 4h 에 도달 → 배속 2x
            off = [(0, 0), (2, 8), (4, 14), (8, 20)]
            on = [(0, 0), (2, 14), (4, 20), (8, 24)]
            for i, (llm, s) in enumerate([(False, off), (False, off), (False, off),
                                          (True, on), (True, on), (True, on)]):
                cov = [1, 2, 3] + ([99] if llm else [])
                (d / f'run_record_r{i}.json').write_text(json.dumps(record(f'r{i}', llm, s, cov)))
            rows, unique, out = compare_runs.compare(compare_runs.load_records([str(d)]),
                                                     out_dir=d / 'cmp')
            by = {r['group']: r for r in rows}
            self.assertEqual(by['LLM OFF']['final_median'], 20)
            self.assertEqual(by['LLM ON']['final_median'], 24)
            self.assertAlmostEqual(by['LLM ON']['reach_ref_final'], 4.0)
            self.assertAlmostEqual(by['LLM ON']['speedup'], 2.0)
            self.assertEqual(by['LLM ON']['a12'], 1.0)
            self.assertEqual(unique, {'LLM ON': 1, 'LLM OFF': 0})
            for f in ('compare_coverage.png', 'compare_speedup.png', 'compare_llm_share.png',
                      'compare_summary.md'):
                self.assertTrue((out / f).stat().st_size > 0, f)
            md = (out / 'compare_summary.md').read_text()
            self.assertIn('2.00x', md)

    def compare_fake(self, runs, xaxis='time'):
        for r in runs:
            r['_file'] = r['run_id'] + '.json'
        with tempfile.TemporaryDirectory() as d, patch.object(compare_runs, '_plots'):
            rows, unique, _ = compare_runs.compare(runs, out_dir=d, strict=True, xaxis=xaxis)
        return {r['group']: r for r in rows}, unique

    def test_non_reachers_prevent_survivor_only_speedup(self):
        runs = [record('off'+str(i), False, [(0, 0), (8, 20)], [1]) for i in range(3)]
        runs += [record('on'+str(i), True, [(0, 0), (1, 20 if i == 0 else 5),
                                          (8, 20 if i == 0 else 5)], [1]) for i in range(3)]
        rows, _ = self.compare_fake(runs)
        self.assertEqual(rows['LLM ON']['reached'], '1/3')
        self.assertIsNone(rows['LLM ON']['speedup'])
        self.assertIsNone(rows['LLM ON']['reach_ref_final'])
        self.assertIsNone(compare_runs.reach_median([([0, 1], [0, 20]),
                                                     ([0, 8], [0, 5])], 20)[0])

    def test_common_budget_removes_longer_run_advantage(self):
        for axis, horizon in (('time', 1), ('exec', 1000)):
            with self.subTest(axis=axis):
                runs = [record('off', False, [(0, 0), (1, 10)], [1]),
                        record('on', True, [(0, 0), (1, 10), (10, 20)], [1, 2])]
                rows, unique = self.compare_fake(runs, axis)
                self.assertEqual(rows['LLM ON']['final_median'], 10)
                self.assertEqual(rows['LLM ON']['a12'], .5)
                self.assertEqual(rows['LLM ON']['duration'], horizon)
                self.assertEqual(unique, {})

    def test_common_budget_uses_past_observation_not_future_interpolation(self):
        data, horizon = compare_runs.common_budget({'off': [([0, 1], [0, 10])],
                                                    'on': [([0, .5, 2], [0, 4, 20])]})
        self.assertEqual(horizon, 1)
        self.assertEqual(data['on'][0], ([0, .5, 1], [0, 4, 4]))
        with self.assertRaises(SystemExit):
            compare_runs.common_budget({'a': [([0, 1], [0, 5])], 'b': [([2, 3], [4, 6])]})

    def realistic(self, ends=(28800.4, 28801.2, 28799.8, 28800.9, 28800.1, 28802.0)):
        """같은 8시간 설정 — 종료 시각이 몇 초씩 다르고 최종값에 편차가 있다(실제 데이터 모양)."""
        runs = []
        for i, (llm, fin) in enumerate([(False, 19), (False, 20), (False, 21), (True, 24), (True, 25), (True, 26)]):
            end = ends[i]
            pts = [(t, fin * t / (4 * 3600) if t < 4 * 3600 else fin) for t in range(0, int(end), 60)] + [(end, fin)]
            if llm:     # LLM 쪽은 2배 빨리 오른다
                pts = [(t, min(fin, fin * t / (2 * 3600))) for t, _ in pts]
            runs.append(dict(schema='pcfuzz-run/1', run_id=f'r{i}', final=True, elapsed_s=end,
                             conditions=dict(llm=llm, product='P', commands=['x'], fw={}),
                             coverage_unit='BB', totals=dict(bb_total=1000), final_coverage={},
                             llm_status={}, covered_kind='bb_start', covered=[1, 2] + ([99] if llm else []),
                             series=[dict(t=t, exec=int(t), bb_pct=v) for t, v in pts]))
        return runs

    def test_reference_median_target_still_yields_speedup(self):
        # 리뷰 재검토: 목표가 기준 그룹 최종값 '중앙값'이라 기준 실행 일부는 정의상 도달 못 한다.
        #   전원 도달을 요구하면 배속이 늘 None — 미도달=∞ 중앙값(과반 도달)이면 값이 나온다.
        rows, unique = self.compare_fake(self.realistic())
        self.assertEqual(rows['LLM OFF']['reached'], '2/3')
        self.assertIsNotNone(rows['LLM ON']['speedup'])
        # 목표 20: OFF 도달 [3.81h, 4h, ∞] → 중앙값 4h, ON 도달 [1.67h, 1.6h, 1.54h] → 1.6h
        self.assertAlmostEqual(rows['LLM OFF']['reach_ref_final'], 4.0, places=2)
        self.assertAlmostEqual(rows['LLM ON']['reach_ref_final'], 1.6, places=2)
        self.assertAlmostEqual(rows['LLM ON']['speedup'], 2.5, places=2)
        # 종료 시각이 몇 초씩 달라도 같은 종료로 보고 고유 BB 를 계산한다
        self.assertEqual(unique, {'LLM ON': 1, 'LLM OFF': 0})

    def test_censored_median_needs_majority(self):
        c = [([0, 1], [0, 20]), ([0, 2], [0, 20]), ([0, 8], [0, 5])]
        self.assertEqual(compare_runs.reach_median(c, 20)[0], 2)        # 2/3 도달 → 중앙값 2
        self.assertIsNone(compare_runs.reach_median(c[1:], 20)[0])      # 1/2 → None

    def test_run_without_series_is_skipped_and_short_run_named(self):
        runs = self.realistic()
        runs.append(dict(runs[0], run_id='crashed', series=[]))
        runs[1] = dict(runs[1], run_id='short', series=runs[1]['series'][:60])
        for r in runs:
            r['_file'] = r['run_id'] + '.json'
        with tempfile.TemporaryDirectory() as d, patch.object(compare_runs, '_plots'):
            rows, unique, out = compare_runs.compare(runs, out_dir=d)
            md = (Path(d) / 'compare_summary.md').read_text()
        self.assertIn('시계열이 없어 뺀 실행: crashed', md)
        self.assertIn('`short` 이 정했습니다', md)
        self.assertEqual(unique, {})                                     # 공통 시점 집합 없음

    def test_mismatched_product_warns_and_strict_stops(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / 'run_record_a.json').write_text(json.dumps(record('a', False, [(0, 0), (1, 5)], [1])))
            (d / 'run_record_b.json').write_text(json.dumps(record('b', True, [(0, 0), (1, 6)], [1], 'BM9K1')))
            runs = compare_runs.load_records([str(d)])
            with self.assertRaises(SystemExit):
                compare_runs.compare(runs, out_dir=d / 'cmp', strict=True)

    def test_same_run_copied_twice_uses_longest(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / 'x').mkdir()
            (d / 'run_record_a.json').write_text(json.dumps(record('a', False, [(0, 0), (1, 5)], [1])))
            (d / 'x' / 'run_record_a.json').write_text(json.dumps(record('a', False, [(0, 0), (3, 9)], [1])))
            runs = compare_runs.load_records([str(d)])
            self.assertEqual(len(runs), 1)
            self.assertEqual(runs[0]['series'][-1]['bb_pct'], 9)


if __name__ == '__main__':
    unittest.main()


class ReviewFixes(unittest.TestCase):
    """2026-10-02 리뷰: 런타임 calibration 뒤 중단, 초기화 이후 전체가 정리 범위, C1·C2 보상 모집단."""

    def test_runtime_calibration_crash_stops_before_next_send(self):
        import re
        from fuzzer_target import FUZZER_FILE
        src = FUZZER_FILE.read_text(encoding='utf-8')
        m = re.search(r"base_seed = self\._calibrate_seed\(base_seed\)\n((?:\s*#[^\n]*\n)*)"
                      r"\s*if self\._timeout_crash or self\._sampler_recovery_failed:\n\s*break", src)
        self.assertIsNotNone(m, '런타임 calibration 직후 중단 확인이 없다')

    def test_startup_device_changes_are_inside_cleanup_scope(self):
        import ast
        from fuzzer_target import FUZZER_FILE
        tree = ast.parse(FUZZER_FILE.read_text(encoding='utf-8'))
        run = next(n for c in tree.body if isinstance(c, ast.ClassDef)
                   for n in c.body if isinstance(n, ast.FunctionDef) and n.name == 'run'
                   and any(isinstance(a, ast.Call) and getattr(a.func, 'attr', '') == '_calibrate_seed'
                           for a in ast.walk(n)))

        def calls(nodes):
            return {getattr(c.func, 'attr', '') for n in nodes for c in ast.walk(n) if isinstance(c, ast.Call)}
        tries = [t for t in run.body if isinstance(t, ast.Try) and '_restore_nvme_timeouts' in calls(t.finalbody)]
        self.assertEqual(len(tries), 1)
        body = calls(tries[0].body)
        for name in ('_apst_disable', '_keepalive_disable', '_configure_nvme_timeouts', '_calibrate_seed',
                     '_learning_baseline'):
            self.assertIn(name, body, f'{name} 이 정리 범위 밖에 있다')
        # 정리 범위 앞(샘플러 연결 전)에는 장치·호스트 설정 변경이 없다
        before = calls(run.body[:run.body.index(tries[0])])
        for name in ('_apst_disable', '_configure_nvme_timeouts', '_calibrate_seed'):
            self.assertNotIn(name, before)

    def test_blocked_and_interrupted_commands_reward_neither_corpus(self):
        from collections import Counter, defaultdict
        from test_v11_exceptions import RealTransportIntegration
        tc = RealTransportIntegration('test_actual_transport_injects_and_next_normal_timeout_is_restored')
        tc.setUp()
        self.addCleanup(tc.tmp.cleanup)
        f = tc.f
        f.config.state_enabled = True
        f.cmd_stats = defaultdict(lambda: {'exec': 0})
        f.rc_stats = defaultdict(Counter)
        f._fw_commit_reset_pending = False
        for source in ('c1', 'c2'):
            f._csfuzz_c1_rewards, f._csfuzz_c2_rewards = [], []
            f._account_command(tc.seed, b'', f.RC_SKIP, 0, source=source)            # 가드 차단
            f._exception_interrupted = True
            f._account_command(tc.seed, b'', f.RC_EXCEPTION, 0, source=source)       # 예외 주입
            f._exception_window_truncated = True
            f._account_command(tc.seed, b'', 0, 0, source=source)                    # 복구 관측 구간
            self.assertEqual((f._csfuzz_c1_rewards, f._csfuzz_c2_rewards), ([], []), source)

    def test_reward_helper_routes_by_source(self):
        o = fuzzer.NVMeFuzzer.__new__(fuzzer.NVMeFuzzer)
        o.config = SimpleNamespace(state_enabled=True)
        o._csfuzz_c1_rewards, o._csfuzz_c2_rewards = [], []
        for src, n in (('c1', 3), ('c1', 0), ('c2', 1), ('c2', 0), ('workload', 5)):
            o._csfuzz_reward(src, n)
        self.assertEqual((o._csfuzz_c1_rewards, o._csfuzz_c2_rewards), ([1, 0], [1, 0]))
        src = Path(fuzzer.__file__).read_text(encoding='utf-8')
        self.assertEqual(src.count('_csfuzz_c2_rewards.append'), 0)          # 재생 루프에서 따로 쌓지 않음
