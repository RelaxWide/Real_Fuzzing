"""v11.2 — coverage_growth 'LLM 돌파' 표시.

mutation 이 자기 명령으로 평소보다 한참(기준 = max(최소 명령 수, 배수 × 평소 발견 간격 중앙값)) 새 BB 를
못 찾던 구간에 LLM 계보가 새 BB 를 찾으면 돌파. 같은 스냅샷에 mutation 도 찾았거나, mutation 이 명령을
거의 못 받아 정체가 짧으면 돌파가 아니다.
"""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fuzzer_target import fuzzer as v


def rows(spec):
    """spec: [(d_llm, d_mut, mut_cmds), ...] 스냅샷별 증가분 → 누적 _cov_share_hist 행."""
    out, fl, fm, cm = [(0, 0, 0, 0, 0, 0, 0)], 0, 0, 0
    for i, (dl, dm, mc) in enumerate(spec, 1):
        fl += dl
        fm += dm
        cm += mc
        out.append((i * 100, fl, fm, fl, fm, i * 25, cm))
    return out


REGULAR = [(0, 1, 100)] * 10          # mutation 이 100명령마다 찾음 → 평소 간격 100


class Detect(unittest.TestCase):
    def test_llm_find_after_long_mutation_stall(self):
        r = rows(REGULAR + [(0, 0, 100)] * 12 + [(5, 0, 100), (3, 0, 100), (0, 1, 100)])
        events, thr, typical = v._llm_breakthroughs(r, min_cmds=0, gap_factor=5)
        self.assertEqual((typical, thr), (100, 500))
        self.assertEqual(len(events), 1)
        e = events[0]
        self.assertEqual(e['start_exec'], 1000)                 # mutation 마지막 발견
        self.assertEqual(e['exec'], 2300)                       # LLM 첫 발견
        self.assertEqual(e['stall_cmds'], 1300)
        self.assertEqual(e['llm_bb'], 8)                        # 정체 끝까지 합
        self.assertEqual(e['end_exec'], 2500)                   # mutation 재발견

    def test_short_stall_is_not_breakthrough(self):
        r = rows(REGULAR + [(0, 0, 100)] * 2 + [(5, 0, 100)])
        self.assertEqual(v._llm_breakthroughs(r, min_cmds=0, gap_factor=5)[0], [])

    def test_same_snapshot_mutation_find_is_not_breakthrough(self):
        r = rows(REGULAR + [(0, 0, 100)] * 12 + [(5, 1, 100)])
        self.assertEqual(v._llm_breakthroughs(r, min_cmds=0, gap_factor=5)[0], [])

    def test_mutation_without_commands_is_not_stalled(self):
        # LLM 이 명령을 다 가져가 mutation 명령이 늘지 않은 구간 — 오래 걸려도 정체가 아니다
        r = rows(REGULAR + [(0, 0, 0)] * 30 + [(5, 0, 0)])
        self.assertEqual(v._llm_breakthroughs(r, min_cmds=0, gap_factor=5)[0], [])

    def test_min_cmds_floor(self):
        r = rows(REGULAR + [(0, 0, 100)] * 12 + [(5, 0, 100)])
        self.assertEqual(v._llm_breakthroughs(r, min_cmds=5000, gap_factor=5)[0], [])

    def test_separate_stalls_are_separate_events(self):
        stall = [(0, 0, 100)] * 12 + [(4, 0, 100), (0, 1, 100)]
        r = rows(REGULAR + stall + stall)
        self.assertEqual(len(v._llm_breakthroughs(r, min_cmds=0, gap_factor=5)[0]), 2)

    def test_empty_history(self):
        self.assertEqual(v._llm_breakthroughs([], min_cmds=0)[0], [])


class Chart(unittest.TestCase):
    def render(self, share):
        inst = v.NVMeFuzzer.__new__(v.NVMeFuzzer)
        folder = tempfile.mkdtemp()
        inst.output_dir = Path(folder)
        inst._sa_loaded, inst._sa_total_bbs, inst._sa_total_funcs = True, 1000, 100
        inst._sa_covered_bbs, inst._sa_entered_funcs, inst._sa_func_entries = set(), set(), []
        inst.cov, inst._bb_at_start = None, 100
        inst._cov_share_hist = share
        inst._sa_cov_history = [(r[0], r[0] / 10, 10 + (r[1] + r[2]) / 10, 10) for r in share]
        import matplotlib.pyplot as plt
        original, seen = plt.savefig, {}

        def save(*a, **k):
            ax = plt.gcf().axes[0]
            seen['labels'] = [t.get_text() for t in ax.get_legend().get_texts()]
            seen['notes'] = [c.get_text() for c in ax.texts]
            seen['stars'] = [float(c.get_offsets()[0][0]) for c in ax.collections
                             if type(c).__name__ == 'PathCollection']
            return original(*a, **k)
        with patch.object(plt, 'savefig', side_effect=save), \
                patch.object(v, 'GRAPH_BREAKTHROUGH_MIN_CMDS', 0):
            inst._generate_static_coverage_graphs()
        self.assertTrue((Path(folder) / 'graphs' / 'coverage_growth.png').exists())
        return seen

    def test_breakthrough_is_marked_and_labelled(self):
        seen = self.render(rows(REGULAR + [(0, 0, 100)] * 12 + [(5, 0, 100), (0, 1, 100)]))
        self.assertTrue(any(l.startswith('LLM breakthrough x1 (+5 BB)') for l in seen['labels']))
        self.assertTrue(any(l.startswith('mutation stall') for l in seen['labels']))
        self.assertTrue(any('LLM +5 BB' in n and '1.3k cmds' in n for n in seen['notes']))
        self.assertEqual(seen['stars'], [2300.0])           # 돌파 지점(LLM 첫 발견)에 별

    def test_no_breakthrough_no_mark(self):
        seen = self.render(rows(REGULAR + [(2, 1, 100)] * 5))
        self.assertFalse(any('breakthrough' in l for l in seen['labels']))
        self.assertFalse(any('LLM +' in n for n in seen['notes']))
        self.assertEqual(seen['stars'], [])


if __name__ == '__main__':
    unittest.main()
