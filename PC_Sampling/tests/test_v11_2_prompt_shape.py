"""v11.2.1 — io_patterns 응답이 {"seeds":[],"sequences":[],"evaluations":[]} 로 오던 문제.

스키마가 없는 백엔드(rag_bridge)에서는 프롬프트 문구만으로 출력 모양이 정해진다. 예전 io_patterns 프롬프트는
(1) 시스템 프롬프트가 seeds/sequences/evaluations 모양만 보여 주고 (2) 시드 few-shot 이 든 grounding 블록이
앞에 붙고 (3) 학습 evidence 블록이 맨 뒤에 붙어 'seed·sequence·generator 에 target_id' 로 끝났다.
io_workload 는 중간의 한 줄뿐이었다. 지금은 시스템 프롬프트에 io_workload 모양을 더하고(다른 키 모양은 그대로),
io_patterns 에서 grounding·evidence 를 빼고, 마지막에 완성된 출력 모양을 준다.
"""
import json
import re
import unittest
from unittest.mock import Mock, patch

from test_v10_2_learning import fuzzer, harness   # noqa: F401
from llm_learning import LearningMixin

GROUND = 'GROUNDING-MARK past seeds {"command":"Read","cdw10":1}'


def io_obj():
    o = harness({'enabled': True, 'evidence': True})
    o._wl_pattern_stats = {}
    o._wl_burst_seq = 0
    o._wl_base = 0
    o._last_workload_result = None
    o._llm_exercised_names = lambda: set()
    o._llm_coverage_context = lambda: ''
    o._llm_grounding_block = lambda: GROUND
    o._llm_telemetry_block = lambda: '  waf_x100 = 120  [write amplification]'
    o._learning_candidates = Mock(return_value=[])
    return o


class IoPatternsPrompt(unittest.TestCase):
    def build(self):
        o = io_obj()
        system, user = o._llm_build_request('io_patterns')
        return o, system, user

    def test_ends_with_complete_io_workload_shape(self):
        _, _, user = self.build()
        tail = user[user.rindex('Output EXACTLY'):]
        self.assertIn('the only top-level key is "io_workload"', tail)
        shape = tail[tail.index('{"io_workload"'):]
        self.assertTrue(shape.rstrip().endswith('}}'), shape)
        for key in ('pattern', 'lba_span', 'block_size', 'hot_fraction', 'read_ratio', 'direction'):
            self.assertIn(f'"{key}"', shape)
        # 출력 모양 뒤에 다른 지시가 붙지 않는다(학습 evidence 가 맨 뒤를 차지하던 문제)
        self.assertNotIn('target_id', user)
        self.assertNotIn('execution evidence', user)

    def test_no_seed_grounding(self):
        _, _, user = self.build()
        self.assertNotIn('GROUNDING-MARK', user)

    def test_rag_query_block_kept(self):
        # 검색 질의 블록은 그대로 붙는다. 학습 대상을 넘기지 않으므로 질의 명령은 커버리지 공백 명령
        #   (_llm_gap_cmds) — 학습을 끈 상태의 io_patterns 와 같은 경로다.
        o = io_obj()
        o._llm_gap_cmds = lambda: ['Write']
        _, user = o._llm_build_request('io_patterns')
        self.assertTrue(user.startswith('[RAG-QUERY]'), user[:40])
        self.assertIn('Write', user[:user.index('[/RAG-QUERY]')])

    def test_no_learning_targets_offered(self):
        o, system, _ = self.build()
        o._learning_candidates.assert_not_called()
        self.assertNotIn('learning_targets', o._llm_pending_ctx or {})
        self.assertNotIn('v10.2 JSON extensions', system)

    def test_other_tasks_still_get_learning_block(self):
        o = io_obj()
        with patch.object(LearningMixin, '_llm_build_learning_request',
                          return_value=('S', 'U')) as base:
            o._llm_build_learning_request('sequences')
            o._llm_build_learning_request('new_group_seeds')
            o._llm_build_learning_request('corpus_eval')
        self.assertEqual([c.args[-1] for c in base.call_args_list],
                         ['sequences', 'new_group_seeds', 'corpus_eval'])


class SystemPrompt(unittest.TestCase):
    S = fuzzer.NVMeFuzzer._LLM_SYSTEM

    def test_lists_io_workload_and_only_requested_keys(self):
        self.assertIn('"io_workload"', self.S)
        self.assertIn('output ONLY the key(s) the task asks for', self.S)
        self.assertIn('"io_workload":{"pattern":str', self.S)

    def test_existing_shapes_unchanged(self):
        # seeds·sequences·corpus_eval 은 필드 구조를 이 모양에서만 얻는다 — 빠지면 안 된다
        for frag in ('"seeds":[{"command":str,"cdw10":int,...,"seed_class":str}]',
                     '"sequences":[{"commands":[{"command":str,"cdw10":int,...}],"seed_class":str}]',
                     '"evaluations":[{"seed_id":int,"score":float,"keep":bool}]'):
            self.assertIn(frag, self.S)

    def test_shape_keys_match_parser_schema(self):
        # 시스템 프롬프트가 보여 주는 io_workload 필드 = 스키마 필드
        from rag import llm_schema
        shown = re.search(r'"io_workload":\{(.*?)\}', self.S).group(1)
        keys = set(re.findall(r'"(\w+)":', shown))
        self.assertEqual(keys, set(llm_schema._workload_props(['x'])))


class Rejection(unittest.TestCase):
    def test_seed_shaped_reply_is_still_rejected(self):
        # 동작 변경 없음 — 그래도 엉뚱한 모양이 오면 폐기된다
        o = harness({'enabled': True})
        data = json.loads('{"seeds": [], "sequences": [], "evaluations": []}')
        why = o._llm_response_rejection({'task': 'io_patterns'}, data)
        self.assertIn("['io_workload'] 중 아무것도 없음", why)


if __name__ == '__main__':
    unittest.main()
