"""종료 요약이 긴 캠페인에서 폭발하지 않는지.

nsid 는 퍼징 대상이라 값 종류가 계속 늘어난다. 전량 나열하면 이 한 줄이 요약을
통째로 덮는다(1,300종이면 2.5만 자). 상위만 보이고 꼬리는 종수·합계로 접는다.
"""
import ast
import json
import random
import unittest
from pathlib import Path

from test_v10_2_learning import ROOT, fuzzer      # noqa: F401


def render(dist, top=None):
    """**실제 구현**을 부른다 — 규칙을 복제하면 구현이 바뀌어도 시험이 통과한다."""
    return fuzzer._fmt_nsid_dist(dist, top)


class NsidDistributionIsCapped(unittest.TestCase):
    def big(self, n=1300):
        """최다 사용 nsid 를 **큰 값**에도 둔다.

        값 순으로 자르면 작은 값만 남으므로, 최다 항목이 작은 값이기만 하면
        정렬 기준이 틀려도 시험이 통과해 버린다.
        """
        random.seed(7)
        d = {1: 120394, 0: 512, 0xFFFFFFF0: 99999, 0xFFFFFFFF: 88}
        for _ in range(n):
            d[random.randint(2, 2**32 - 1)] = random.randint(1, 4)
        return d

    def test_config_ships_a_cap(self):
        g = json.loads((ROOT / 'fuzzer_config.json').read_text(encoding='utf-8'))['globals']
        self.assertEqual(g['summary_nsid_top'], fuzzer.SUMMARY_NSID_TOP)
        self.assertGreater(fuzzer.SUMMARY_NSID_TOP, 0, '기본값이 0 이면 전량 나열이다')

    def test_long_campaign_line_stays_short(self):
        line = render(self.big())
        self.assertLess(len(line), 400, f'요약 한 줄이 너무 길다: {len(line)}자')

    def test_it_keeps_the_most_frequent_values(self):
        line = render(self.big())
        self.assertIn('nsid=1:120394회', line, '가장 많이 쓴 nsid 가 빠졌다')
        self.assertIn('nsid=0:512회', line)
        # 값은 크지만 횟수가 많은 항목 — 값 순으로 자르면 여기서 탈락한다
        self.assertIn('nsid=4294967280:99999회', line,
                      '횟수가 아니라 값 순으로 자르고 있다')

    def test_tail_is_summarised_not_dropped(self):
        d = self.big()
        line = render(d)
        self.assertIn('그 외', line, '꼬리를 조용히 버리면 분포를 못 읽는다')
        self.assertIn(f'({len(d):,}종)', line, '총 종수가 없으면 얼마나 퍼졌는지 모른다')
        body = line.split('): ', 1)[1]          # 접두사(총 종수)를 떼고 항목만
        shown = sum(int(t.split(':')[1].rstrip('회'))
                    for t in body.split(', ') if t.startswith('nsid='))
        tail = int(line.split('그 외 ')[1].split('종 ')[1].rstrip('회').replace(',', ''))
        self.assertEqual(shown + tail, sum(d.values()), '합계가 맞지 않는다')

    def test_short_campaign_prints_everything(self):
        line = render({1: 10, 2: 5})
        self.assertNotIn('그 외', line)
        self.assertIn('nsid=2:5회', line)

    def test_zero_means_no_cap(self):
        d = self.big(30)
        self.assertNotIn('그 외', render(d, 0))


class SummaryCodeUsesTheCap(unittest.TestCase):
    def test_summary_path_uses_the_helper(self):
        src = (ROOT / 'pc_sampling_fuzzer_v10.3.py').read_text(encoding='utf-8')
        self.assertIn('_fmt_nsid_dist(stats.get(', src, '요약이 헬퍼를 안 쓴다')
        self.assertNotIn("for n, count in sorted(stats['actual_nsid_dist'].items())", src,
                         '여전히 전량 나열한다')

    def test_empty_distribution_yields_no_line(self):
        self.assertEqual(fuzzer._fmt_nsid_dist({}), '')
        self.assertEqual(fuzzer._fmt_nsid_dist(None), '')


if __name__ == '__main__':
    unittest.main()
