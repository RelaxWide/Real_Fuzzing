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


def picks(min_reward_samples, rounds=11, rewarded=('new_group_seeds',)):
    """실제 choose() 를 그대로 돌린다.

    폴백은 호출부와 같은 가중 라운드로빈(가중치 1)이고, 순번은 그 칸이 **실제로 나갔을
    때만** 올린다 — production 의 _llm_rr_peek/_llm_rr_consume 와 같은 규칙.
    """
    state = LearningState({'enabled': True, 'min_reward_samples': min_reward_samples})
    rr, out = 0, []
    for _ in range(rounds):
        fallback = ACTIVE[rr % len(ACTIVE)]
        task = state.choose(ACTIVE, fallback, 3)
        if task == fallback:
            rr += 1
        out.append(task)
        state.submitted(task, [], 0)
        # 관측된 조건 그대로: startup seeding 이 먼저 나간 new_group_seeds 만 평가를 끝내
        #   보상을 갖는다. 나머지는 아직 evaluation_commands 를 못 채웠다.
        if task in rewarded:
            state._task(task)['rewards'].append(1.0)
    return out


class GreedyBranchIsWhatConcentrated(unittest.TestCase):
    """원인 기록. 보상 표본 1건으로 순위를 매기면 먼저 완료된 task 가 계속 이긴다.

    관측값은 첫 11회가 new_group_seeds 8 / sequences 2 / corpus_eval 1, io_patterns 0
    이었다. 지금은 warm-up(ColdStartReachesEveryTask)이 앞에 붙어 그 숫자 그대로는
    재현되지 않는다 — 그래서 여기서는 **집중이 일어나는 메커니즘**만 고정한다.
    """
    def test_one_sample_lets_the_first_finisher_dominate(self):
        # 보상이 있는 task 가 하나뿐이면 max(ranked) 는 늘 그것이다 — 관측된 증상.
        got = Counter(picks(1, rounds=16))
        self.assertGreater(got['new_group_seeds'], sum(got.values()) // 2,
                           f'탐욕 집중이 재현되지 않는다: {dict(got)}')

    # min_reward_samples 의 효과는 분포 총계가 아니라 **순위 진입 자격**이다. 분포로 재면
    #   보상 패턴에 따라 숫자가 흔들려 임계값을 맞추게 된다 — 게이트를 직접 본다.
    @staticmethod
    def _warm(**rewards):
        state = LearningState({'enabled': True, 'min_reward_samples': 2})
        for task, vals in rewards.items():
            state._task(task)['rewards'].extend(vals)
            state._task(task)['requests'] = 4      # warm-up 은 끝난 상태
        for task in ACTIVE:
            state._task(task)['requests'] = 4
        state.turn = 1                              # 탐색 턴을 피한다
        return state

    def test_a_task_with_one_sample_does_not_enter_the_ranking(self):
        # 표본 1건짜리가 아무리 높아도 2건짜리를 이기면 안 된다.
        state = self._warm(new_group_seeds=[9.0], sequences=[0.1, 0.1])
        self.assertEqual(state.choose(ACTIVE, 'io_patterns', 3), 'sequences')

    def test_the_second_sample_admits_it(self):
        state = self._warm(new_group_seeds=[9.0, 9.0], sequences=[0.1, 0.1])
        self.assertEqual(state.choose(ACTIVE, 'io_patterns', 3), 'new_group_seeds')

    def test_every_active_task_is_reached_early(self):
        got = Counter(picks(DEFAULTS['min_reward_samples']))
        self.assertEqual(set(got), set(ACTIVE),
                         f'초반 11회 안에 안 나온 task 가 있다: {dict(got)}')

    def test_ranking_resumes_once_samples_accumulate(self):
        # 게이트는 '영구 비활성' 이 아니라 '표본 대기' 다. 충분히 쌓이면 다시 최고 보상을 고른다.
        #   warm-up 은 요청 수로 끝나므로 requests 도 같이 채워야 탐욕 분기까지 간다.
        state = LearningState({'enabled': True, 'min_reward_samples': 2})
        for task, reward in (('new_group_seeds', 9.0), ('sequences', 0.1),
                             ('io_patterns', 0.2)):
            for _ in range(4):
                state._task(task)['rewards'].append(reward)
            state._task(task)['requests'] = 4
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
        self.assertIn('_llm_rr_peek', src, '기동 시딩이 회전판을 쓰지 않는다')
        self.assertIn('_llm_rr_consume', src, '기동 시딩이 순번을 소비하지 않는다')
        self.assertNotIn("'new_group_seeds'", src, '기동 시딩이 task 를 하드코딩한다')
        self.assertNotIn('"new_group_seeds"', src, '기동 시딩이 task 를 하드코딩한다')

    def test_periodic_path_uses_the_same_rotation(self):
        import ast
        from test_v10_2_learning import FUZZER_FILE, fuzzer
        src = ast.get_source_segment(
            FUZZER_FILE.read_text(encoding='utf-8'),
            [n for n in ast.walk(ast.parse(FUZZER_FILE.read_text(encoding='utf-8')))
             if isinstance(n, ast.FunctionDef) and n.name == '_llm_maybe_submit'][0])
        self.assertIn('_llm_rr_peek', src)
        # 회전판 구현이 두 군데로 갈라지면 또 어긋난다.
        self.assertNotIn('RAG_TASK_WEIGHTS', src,
                         '주기 선택이 회전판을 자체 구현하고 있다')
        # 순번 소비는 **제출 성공 뒤**여야 한다. 앞에 있으면 버려진 칸이 소비된다.
        self.assertLess(src.index('self.llm.submit'), src.index('_llm_rr_consume'),
                        '제출 전에 순번을 소비한다')


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
        got = []
        for _ in range(6):
            got.append(obj._llm_rr_peek(active))
            obj._llm_rr_consume()
        self.assertEqual(got, ['new_group_seeds', 'sequences', 'sequences',
                               'corpus_eval', 'io_patterns', 'io_patterns'])
        self.assertEqual(obj._llm_task_rr, 6, '커서가 소비되지 않았다')

    def test_startup_slot_is_not_handed_out_twice(self):
        obj = self._obj({})
        active = ['new_group_seeds', 'sequences', 'corpus_eval', 'io_patterns']
        first = obj._llm_rr_peek(active)       # 기동 시딩이 쓰는 칸
        obj._llm_rr_consume()
        second = obj._llm_rr_peek(active)      # 첫 주기 선택
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


class StartupTaskPinIsOptional(unittest.TestCase):
    """rag.startup_task — 1건째만 고정. 기본은 off(회전판이 정함)."""

    def test_default_is_off(self):
        from test_v10_2_learning import fuzzer
        self.assertEqual(fuzzer.RAG_STARTUP_TASK.lower(), 'off')

    def test_shipped_config_ships_it_off(self):
        import json
        from test_v10_2_learning import ROOT
        cfg = json.loads((ROOT / 'fuzzer_config.json').read_text(encoding='utf-8'))
        self.assertEqual(cfg['rag']['startup_task'], 'off')

    def test_missing_key_falls_back_to_off(self):
        # 설정에 없거나 null 이어도 켜지면 안 된다.
        for supplied in ({}, {'startup_task': None}, {'startup_task': ''}):
            self.assertEqual(
                str(supplied.get('startup_task', 'off') or 'off').strip().lower(), 'off',
                f'{supplied} 에서 고정이 켜진다')

    def test_pin_is_applied_after_the_slot_is_consumed(self):
        # 고정이 순번 소비를 건너뛰면 2건째가 1건째와 겹친다 — 바로 그 버그로 돌아간다.
        src = StartupSeedingSharesTheRotation._startup_source()
        self.assertIn('RAG_STARTUP_TASK', src, '기동 블록이 startup_task 를 안 본다')
        self.assertLess(src.index('_llm_rr_peek'), src.index('RAG_STARTUP_TASK'),
                        '고정이 회전판 조회보다 먼저다')
        self.assertLess(src.index('RAG_STARTUP_TASK'), src.index('_llm_rr_consume'),
                        '고정보다 순번 소비가 먼저다 — 제출 성공 뒤여야 한다')

    def test_unknown_or_inactive_name_is_ignored_not_fatal(self):
        src = StartupSeedingSharesTheRotation._startup_source()
        self.assertIn('in _startup_active', src, '활성 여부를 확인하지 않는다')
        self.assertIn('log.warning', src, '무시할 때 경고가 없다')


class StartupBlockRunsAsShipped(unittest.TestCase):
    """기동 블록 소스를 그대로 실행해 동작을 본다(문자열 대조가 아니라)."""

    @staticmethod
    def _block():
        import ast, textwrap
        from test_v10_2_learning import FUZZER_FILE
        text = FUZZER_FILE.read_text(encoding='utf-8')
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.If) and isinstance(node.test, ast.Name) \
                    and node.test.id == '_startup_active':
                src = ' ' * node.col_offset + ast.get_source_segment(text, node)
                return compile(textwrap.dedent(src), '<startup>', 'exec')
        raise AssertionError('기동 시딩 블록을 못 찾았다')

    def _run(self, startup_task, active, rr=0):
        sent = {}

        class Stub:
            _llm_pending_ctx = None
            _llm_task_rr = rr

            def _llm_rr_peek(self, act):
                from test_v10_2_learning import fuzzer
                return fuzzer.NVMeFuzzer._llm_rr_peek(self, act)

            def _llm_rr_consume(self):
                from test_v10_2_learning import fuzzer
                return fuzzer.NVMeFuzzer._llm_rr_consume(self)

            def _llm_build_request(self, task):
                return ('sys', 'usr')

            def _llm_backend_meta(self, task, ctx):
                return {}

            def _learning_submitted(self, task, s, u, ctx):
                sent['task'] = task

            class llm:
                @staticmethod
                def submit(task, s, u, n, ctx=None, meta=None):
                    return True

        ns = {'_startup_active': active, 'self': Stub(),
              'RAG_STARTUP_TASK': startup_task,
              '_LLM_TASK_CONTAINERS': {'new_group_seeds': (), 'sequences': (),
                                       'corpus_eval': (), 'io_patterns': ()},
              'log': unittest.mock.Mock()}
        exec(self._block(), ns)
        return sent.get('task'), ns['self']._llm_task_rr, ns['log']

    ACTIVE = ['new_group_seeds', 'sequences', 'corpus_eval', 'io_patterns']

    def test_off_follows_the_rotation(self):
        task, rr, _ = self._run('off', self.ACTIVE)
        self.assertEqual(task, 'new_group_seeds')   # 회전판 0번
        self.assertEqual(rr, 1, '순번이 소비되지 않았다')

    def test_pin_overrides_the_task_but_still_consumes_the_slot(self):
        task, rr, _ = self._run('corpus_eval', self.ACTIVE)
        self.assertEqual(task, 'corpus_eval')
        self.assertEqual(rr, 1, '고정했다고 순번을 안 쓰면 2건째가 겹친다')

    def test_pin_to_a_disabled_task_is_ignored_with_a_warning(self):
        task, rr, log = self._run('io_patterns', ['new_group_seeds', 'sequences'])
        self.assertEqual(task, 'new_group_seeds', '비활성 task 로 고정돼 버렸다')
        self.assertEqual(rr, 1)
        self.assertTrue(log.warning.called, '무시했는데 경고가 없다')

    def test_pin_to_an_unknown_name_is_ignored(self):
        task, _, log = self._run('nonsense', self.ACTIVE)
        self.assertEqual(task, 'new_group_seeds')
        self.assertTrue(log.warning.called)

    def test_case_insensitive_off(self):
        self.assertEqual(self._run('OFF', self.ACTIVE)[0], 'new_group_seeds')


class OverriddenSlotsAreNotConsumed(unittest.TestCase):
    """회전판이 고른 task 를 choose 가 갈아치우면 그 칸은 **다시 와야 한다**.

    예전엔 꺼내는 순간 순번이 올라, 버려진 칸이 소비됐다. 실측 30건에서 회전판이
    io_patterns 를 10번 골랐는데 실제로 나간 건 5번뿐이었다.
    """
    ACTIVE = ['new_group_seeds', 'sequences', 'corpus_eval', 'io_patterns']

    def _obj(self):
        from test_v10_2_learning import fuzzer, harness
        obj = harness({'enabled': True})
        obj._llm_task_rr = 0
        p = unittest.mock.patch.object(fuzzer, 'RAG_TASK_WEIGHTS', {})
        p.start(); self.addCleanup(p.stop)
        return obj

    def test_peek_alone_never_advances(self):
        obj = self._obj()
        seen = {obj._llm_rr_peek(self.ACTIVE) for _ in range(5)}
        self.assertEqual(seen, {'new_group_seeds'}, 'peek 이 순번을 소비한다')
        self.assertEqual(obj._llm_task_rr, 0)

    def test_the_same_slot_returns_until_it_is_taken(self):
        obj = self._obj()
        obj._llm_rr_peek(self.ACTIVE)          # 골랐지만 choose 가 교체했다고 치고
        self.assertEqual(obj._llm_rr_peek(self.ACTIVE), 'new_group_seeds',
                         '버려진 칸이 소비돼 다시 오지 않는다')
        obj._llm_rr_consume()
        self.assertEqual(obj._llm_rr_peek(self.ACTIVE), 'sequences')


class ColdStartReachesEveryTask(unittest.TestCase):
    """보상이 없는 task 는 ranked 에 못 들어 탐욕 분기에 영원히 밀린다 — io_patterns 가 그랬다."""
    ACTIVE = ['new_group_seeds', 'sequences', 'corpus_eval', 'io_patterns']

    def _drive(self, rounds, reward_io=True, weights=None):
        from test_v10_2_learning import fuzzer, harness
        from llm_learning import LearningState
        obj = harness({'enabled': True})
        obj._llm_task_rr = 0
        p = unittest.mock.patch.object(fuzzer, 'RAG_TASK_WEIGHTS',
                                       weights if weights is not None else
                                       {'new_group_seeds': 1, 'sequences': 2,
                                        'corpus_eval': 1, 'io_patterns': 2})
        p.start(); self.addCleanup(p.stop)
        state = LearningState({'enabled': True})
        out = []
        for i in range(rounds):
            rr = obj._llm_rr_peek(self.ACTIVE)
            task = state.choose(self.ACTIVE, rr, 3)
            if task == rr:
                obj._llm_rr_consume()
            out.append(task)
            state.submitted(task, [], 0)
            if i >= 5 and task != 'corpus_eval' and (reward_io or task != 'io_patterns'):
                state._task(task)['rewards'].append(
                    {'new_group_seeds': 1.0, 'sequences': 0.8, 'io_patterns': 0.3}[task])
        return Counter(out)

    def test_all_four_tasks_appear_in_the_first_nine(self):
        got = self._drive(9)
        self.assertEqual(set(got), set(self.ACTIVE), f'초반에 빠진 task 가 있다: {dict(got)}')

    def test_no_task_runs_away_with_the_early_rounds(self):
        got = self._drive(9)
        self.assertLessEqual(max(got.values()), 4, f'초반이 한 task 에 쏠린다: {dict(got)}')

    def test_a_task_that_never_earns_a_reward_does_not_pin_selection(self):
        # 게이트를 보상 수로 걸면 여기서 livelock 한다 — io_patterns 가 영원히 cold 로 남아
        # 매 턴 자기를 고른다. 요청 수로 걸어야 끝난다.
        got = self._drive(40, reward_io=False)
        self.assertLess(got['io_patterns'], 20,
                        f'보상 없는 task 가 선택을 독점한다: {dict(got)}')
        self.assertGreater(got['io_patterns'], 0, '그렇다고 아예 굶어도 안 된다')

    def test_warm_up_terminates_within_its_bound(self):
        # 경쟁 task 3개 x min_reward_samples 2 = 최대 6턴이면 warm-up 이 끝나야 한다.
        from llm_learning import DEFAULTS
        got = self._drive(30)
        self.assertGreaterEqual(got['new_group_seeds'] + got['sequences'],
                                2 * DEFAULTS['min_reward_samples'],
                                f'warm-up 이 안 끝났다: {dict(got)}')


class MaybeSubmitKeepsTheSlotWhenItOverrides(unittest.TestCase):
    """실제 _llm_maybe_submit 을 돌려 순번 소비 조건을 본다.

    peek/consume 를 따로 시험해도 **호출부가 무조건 consume 하면** 원래 버그로 돌아간다.
    그 회귀는 여기서만 잡힌다.
    """
    ACTIVE = ['new_group_seeds', 'sequences', 'corpus_eval', 'io_patterns']

    def _obj(self, choose_returns=None):
        from test_v10_2_learning import fuzzer, harness
        obj = harness({'enabled': True})
        obj._llm_task_rr = 0
        obj.executions = 0
        obj._llm_last_cov = 0
        obj._llm_plateau_since = 0
        obj._llm_last_task = None
        obj._llm_task_consec = 0
        obj._pending_workload = None
        obj._llm_pending_ctx = None
        obj.config = unittest.mock.Mock(io_workload_enabled=True)
        obj._llm_cov_count = lambda: 0
        obj._llm_build_request = lambda task: ('sys', 'usr')
        obj._llm_backend_meta = lambda task, ctx: {}
        obj._learning_submitted = unittest.mock.Mock()
        obj.submitted_tasks = []
        obj.llm = unittest.mock.Mock(enabled=True)
        obj.llm.can_submit.return_value = True
        obj.llm.submit.side_effect = lambda task, *a, **k: (
            obj.submitted_tasks.append(task) or True)
        if choose_returns is not None:
            obj.learning.choose = lambda active, fb, cap: choose_returns
        p = unittest.mock.patch.object(fuzzer, 'RAG_TASK_WEIGHTS', {})
        p.start(); self.addCleanup(p.stop)
        return obj

    def _run(self, obj):
        from test_v10_2_learning import fuzzer
        fuzzer.NVMeFuzzer._llm_maybe_submit(obj)

    def test_slot_is_consumed_when_the_rotation_pick_goes_out(self):
        obj = self._obj(choose_returns=None)
        obj.learning.choose = lambda active, fb, cap: fb      # 회전판 그대로
        self._run(obj)
        self.assertEqual(obj.submitted_tasks, ['new_group_seeds'])
        self.assertEqual(obj._llm_task_rr, 1, '나갔는데 순번을 안 썼다')

    def test_slot_is_kept_when_choose_overrides(self):
        obj = self._obj(choose_returns='corpus_eval')          # 회전판=seeds 를 교체
        self._run(obj)
        self.assertEqual(obj.submitted_tasks, ['corpus_eval'])
        self.assertEqual(obj._llm_task_rr, 0,
                         '교체됐는데 순번을 소비했다 — 버려진 칸이 다시 오지 않는다')

    def test_slot_is_kept_when_the_request_never_goes_out(self):
        obj = self._obj()
        obj.learning.choose = lambda active, fb, cap: fb
        obj._llm_build_request = lambda task: None             # 빌드 실패
        self._run(obj)
        self.assertEqual(obj.submitted_tasks, [])
        self.assertEqual(obj._llm_task_rr, 0, '안 나갔는데 순번을 소비했다')

    def test_slot_is_kept_when_submit_is_refused(self):
        obj = self._obj()
        obj.learning.choose = lambda active, fb, cap: fb
        obj.llm.submit.side_effect = lambda *a, **k: False      # in-flight 거절
        self._run(obj)
        self.assertEqual(obj._llm_task_rr, 0, '거절됐는데 순번을 소비했다')


class WarmUpBeatsAStaleWinner(unittest.TestCase):
    """cold start 가 없으면, 보상을 가진 task 하나가 **아직 한 번도 안 돈** task 를 이긴다.

    캠페인을 이어받아 보상이 남아 있는 경우가 정확히 그 상황이다.
    """
    ACTIVE = ['new_group_seeds', 'sequences', 'corpus_eval', 'io_patterns']

    def test_untried_tasks_run_before_ranking_starts(self):
        state = LearningState({'enabled': True, 'min_reward_samples': 2})
        # new_group_seeds 만 이미 충분히 돌아 보상이 있다.
        state._task('new_group_seeds')['rewards'].extend([9.0, 9.0, 9.0])
        state._task('new_group_seeds')['requests'] = 3
        state.turn = 1                       # 탐색 턴을 피한다
        # 회전판이 아직 안 돈 sequences 를 가리키면 그것이 나가야 한다.
        self.assertEqual(state.choose(self.ACTIVE, 'sequences', 3), 'sequences',
                         '한 번도 안 돈 task 를 제치고 탐욕 선택이 이긴다')

    def test_ranking_takes_over_after_everyone_has_run(self):
        state = LearningState({'enabled': True, 'min_reward_samples': 2})
        for task in self.ACTIVE:
            state._task(task)['requests'] = 2
        state._task('new_group_seeds')['rewards'].extend([9.0, 9.0])
        state._task('sequences')['rewards'].extend([0.1, 0.1])
        state.turn = 1
        self.assertEqual(state.choose(self.ACTIVE, 'sequences', 3), 'new_group_seeds')
