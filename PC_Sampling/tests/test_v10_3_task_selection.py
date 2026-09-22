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
import unittest.mock
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


class StartupSeedingSharesTheRotation(unittest.TestCase):
    """기동 시딩이 회전판 밖에서 new_group_seeds 를 하드코딩하던 문제.

    커서를 소비하지 않아 1건째(시딩)와 2건째(회전판 0번)가 둘 다 new_group_seeds 였다.
    """

    @staticmethod
    def _startup_source():
        import ast
        from test_v10_2_learning import FUZZER_FILE
        text = FUZZER_FILE.read_text(encoding='utf-8')
        tree = ast.parse(text)
        for node in ast.walk(tree):
            # `_startup_active = ... if RAG_SEED_AT_STARTUP else []` 바로 뒤의 블록
            if isinstance(node, ast.If) and isinstance(node.test, ast.Name) \
                    and node.test.id == '_startup_active':
                return ast.get_source_segment(text, node)
        raise AssertionError('기동 시딩 블록을 못 찾았다')

    def test_startup_task_comes_from_the_rotation(self):
        src = self._startup_source()
        self.assertIn('_llm_rr_next', src, '기동 시딩이 회전판을 쓰지 않는다')
        self.assertNotIn("'new_group_seeds'", src, '기동 시딩이 task 를 하드코딩한다')
        self.assertNotIn('"new_group_seeds"', src, '기동 시딩이 task 를 하드코딩한다')

    def test_periodic_path_uses_the_same_rotation(self):
        import ast
        from test_v10_2_learning import FUZZER_FILE, fuzzer
        src = ast.get_source_segment(
            FUZZER_FILE.read_text(encoding='utf-8'),
            [n for n in ast.walk(ast.parse(FUZZER_FILE.read_text(encoding='utf-8')))
             if isinstance(n, ast.FunctionDef) and n.name == '_llm_maybe_submit'][0])
        self.assertIn('_llm_rr_next', src)
        # 회전판 구현이 두 군데로 갈라지면 또 어긋난다.
        self.assertNotIn('RAG_TASK_WEIGHTS', src,
                         '주기 선택이 회전판을 자체 구현하고 있다')


class RotationConsumesSlots(unittest.TestCase):
    def _obj(self, weights):
        from test_v10_2_learning import fuzzer, harness
        obj = harness({'enabled': True})
        obj._llm_task_rr = 0
        self._patch = unittest.mock.patch.object(fuzzer, 'RAG_TASK_WEIGHTS', weights)
        self._patch.start()
        self.addCleanup(self._patch.stop)
        return obj

    def test_weighted_order_and_cursor_advance(self):
        obj = self._obj({'new_group_seeds': 1, 'sequences': 2,
                         'corpus_eval': 1, 'io_patterns': 2})
        active = ['new_group_seeds', 'sequences', 'corpus_eval', 'io_patterns']
        got = [obj._llm_rr_next(active) for _ in range(6)]
        self.assertEqual(got, ['new_group_seeds', 'sequences', 'sequences',
                               'corpus_eval', 'io_patterns', 'io_patterns'])
        self.assertEqual(obj._llm_task_rr, 6, '커서가 소비되지 않았다')

    def test_startup_slot_is_not_handed_out_twice(self):
        obj = self._obj({})
        active = ['new_group_seeds', 'sequences', 'corpus_eval', 'io_patterns']
        first = obj._llm_rr_next(active)       # 기동 시딩이 쓰는 칸
        second = obj._llm_rr_next(active)      # 첫 주기 선택
        self.assertNotEqual(first, second, '기동 시딩과 첫 선택이 같은 칸을 쓴다')


class ActiveListIsShared(unittest.TestCase):
    def test_pending_workload_excludes_io_patterns(self):
        from test_v10_2_learning import fuzzer, harness
        obj = harness({'enabled': True})
        obj.config = unittest.mock.Mock(io_workload_enabled=True)
        obj._pending_workload = None
        self.assertIn('io_patterns', obj._llm_active_tasks())
        obj._pending_workload = {'anything': 1}
        self.assertNotIn('io_patterns', obj._llm_active_tasks())
