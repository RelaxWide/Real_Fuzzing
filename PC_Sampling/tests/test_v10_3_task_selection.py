"""LLM task 선택 편중 시험 — 보상 1건으로 탐욕 결정을 내리지 않는지.

관측된 증상: 퍼저 기동 후 첫 11회 요청이 new_group_seeds 8 / sequences 2 /
corpus_eval 1 로 쏠리고 io_patterns 는 한 번도 안 나왔다.

원인은 라운드로빈이 아니라 그 뒤의 적응 선택이다. startup seeding 이
new_group_seeds 를 제일 먼저 보내므로 그 task 가 제일 먼저 완료 평가를 채우고,
`rewards` 가 비어 있지 않은 유일한 task 가 되어 `max(ranked)` 를 영구히 독점한다.
가중 라운드로빈은 연속 상한과 탐색 턴에서만 살아난다.

min_reward_samples 는 표본이 그만큼 쌓이기 전에는 그 task 를 순위 경쟁에서 빼고
폴백(가중 라운드로빈)이 결정하게 한다.
"""
import json
import sys
import unittest
from collections import Counter
from pathlib import Path

from test_v10_2_learning import ROOT          # noqa: F401

sys.path.insert(0, str(ROOT))
from llm_learning import DEFAULTS, LearningState   # noqa: E402

ACTIVE = ['new_group_seeds', 'sequences', 'corpus_eval', 'io_patterns']


def picks(min_reward_samples, rounds=11):
    """실제 choose() 를 그대로 돌린다. 폴백은 호출부와 같은 가중 라운드로빈(가중치 1)."""
    state = LearningState({'enabled': True, 'min_reward_samples': min_reward_samples})
    rr, out = 0, []
    for _ in range(rounds):
        fallback = ACTIVE[rr % len(ACTIVE)]
        task = state.choose(ACTIVE, fallback, 3)
        if task == fallback:
            rr += 1
        out.append(task)
        state.submitted(task, [], 0)
        # new_group_seeds 가 가장 높은 보상을 받는 상황(= 관측된 조건)을 재현한다.
        state._task(task)['rewards'].append(1.0 if task == 'new_group_seeds' else 0.5)
    return out


class SingleSampleGreedyIsTheCause(unittest.TestCase):
    def test_one_sample_reproduces_the_observed_skew(self):
        # min_reward_samples=1 = 수정 전 동작. 실제 관측값과 같아야 원인 규명이 맞다.
        self.assertEqual(Counter(picks(1)),
                         Counter({'new_group_seeds': 8, 'sequences': 2, 'corpus_eval': 1}),
                         '수정 전 동작이 관측된 8/2/1 을 재현하지 못한다')


class MinimumSamplesSpreadsEarlyRequests(unittest.TestCase):
    def test_no_task_dominates_the_first_eleven(self):
        got = Counter(picks(DEFAULTS['min_reward_samples']))
        self.assertLessEqual(got['new_group_seeds'], 5,
                             f'new_group_seeds 가 여전히 편중된다: {dict(got)}')

    def test_every_active_task_is_reached_early(self):
        got = Counter(picks(DEFAULTS['min_reward_samples']))
        self.assertEqual(set(got), set(ACTIVE),
                         f'초반 11회 안에 안 나온 task 가 있다: {dict(got)}')

    def test_ranking_resumes_once_samples_accumulate(self):
        # 게이트는 '영구 비활성' 이 아니라 '표본 대기' 다. 충분히 쌓이면 다시 최고 보상을 고른다.
        state = LearningState({'enabled': True, 'min_reward_samples': 2})
        for _ in range(4):
            state._task('new_group_seeds')['rewards'].append(9.0)
            state._task('sequences')['rewards'].append(0.1)
        state.turn = 1          # 탐색 턴(turn % exploration_every == 0)을 피한다
        self.assertEqual(state.choose(ACTIVE, 'sequences', 3), 'new_group_seeds')


class ConfigurationIsWired(unittest.TestCase):
    def test_default_requires_more_than_one_sample(self):
        self.assertGreaterEqual(DEFAULTS['min_reward_samples'], 2)

    def test_shipped_config_sets_it(self):
        cfg = json.loads((ROOT / 'fuzzer_config.json').read_text(encoding='utf-8'))
        self.assertEqual(cfg['rag']['learning']['min_reward_samples'],
                         DEFAULTS['min_reward_samples'])

    def test_zero_is_rejected(self):
        with self.assertRaises(ValueError):
            LearningState({'enabled': True, 'min_reward_samples': 0})


if __name__ == '__main__':
    unittest.main()
