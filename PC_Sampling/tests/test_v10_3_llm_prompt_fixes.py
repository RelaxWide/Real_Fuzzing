"""4일 평가에서 드러난 LLM 프롬프트/응답 처리 문제 3건.

1) "Under-explored command groups" 가 서술형 나열이라 내용이 갱신돼도 제안 비중이 안
   바뀜 → 요청마다 필수 명령을 돌아가며 명령형으로 지정하고 준수율을 센다.
2) {"cdw10": 128, "cdw10": 0} 같은 중복 키를 json.loads 가 마지막 값으로 받아 FID=0(예약)
   으로 검증 탈락 → 시퀀스 all-or-nothing 으로 멀쩡한 멤버까지 폐기. 모델이 쓴 후보 값 중
   검증을 통과하는 첫 값을 쓴다(값을 지어내지 않는다).
3) io_patterns 의 무효 패턴명(random_write)이 조용히 드롭 → 다음 요청에 되먹이고
   글자 그대로 복사하라고 지시한다. 별칭 추정은 하지 않는다.
"""
import json
import sys
import unittest
from unittest.mock import Mock

from test_v10_2_learning import ROOT, fuzzer, harness   # noqa: F401

sys.path.insert(0, str(ROOT))
from rag.rag_schema import SchemaBridge                   # noqa: E402

DUP = fuzzer._LLM_DUP_KEY


def seed_obj():
    o = harness({'enabled': True})
    o.llm = Mock(schema_bridge=SchemaBridge.from_dict(fuzzer._llm_schema_dict()))
    o._llm_stats = {'dropped': 0}
    o._llm_repairs = []
    o.executions = 0
    o._active_nsids = [1]
    o.__dict__.pop('_llm_repair_note', None)   # harness 가 Mock 으로 막아 둔 것 — 실제 메서드를 쓴다
    return o


class DuplicateKeys(unittest.TestCase):
    def test_parser_keeps_first_and_records_later_values(self):
        d = fuzzer._llm_extract_json(
            '{"seeds":[{"command":"GetFeatures","cdw10":0x80,"cdw10":0}]}')
        item = d['seeds'][0]
        self.assertEqual(item['cdw10'], 128)
        self.assertEqual(item[DUP], {'cdw10': [0]})

    def test_identical_duplicates_are_not_recorded(self):
        d = fuzzer._llm_extract_json('{"seeds":[{"command":"Identify","cdw10":1,"cdw10":1}]}')
        self.assertNotIn(DUP, d['seeds'][0])

    def test_alternatives_survive_learning_reserialization(self):
        # 학습 모듈은 파싱 결과를 json.dumps 로 다시 넘긴다 — 후보가 거기서 사라지면 안 된다.
        d = fuzzer._llm_extract_json('{"seeds":[{"command":"GetFeatures","cdw10":0,"cdw10":2}]}')
        again = fuzzer._llm_extract_json(json.dumps(d))
        self.assertEqual(again['seeds'][0][DUP], {'cdw10': [2]})

    def test_later_valid_value_is_used_when_first_is_reserved(self):
        o = seed_obj()
        item = fuzzer._llm_extract_json(
            '{"seeds":[{"command":"GetFeatures","cdw10":0,"cdw10":128}]}')['seeds'][0]
        why = []
        s = o._llm_make_seed(item, 'llm_seq', why=why)
        self.assertIsNotNone(s)
        self.assertEqual(s.cdw10, 128)
        self.assertEqual(o._llm_stats['dup_keys'], 1)
        self.assertTrue(any('duplicate key cdw10: used 128 of [0, 128]' in r for r in o._llm_repairs))

    def test_first_value_wins_when_both_valid(self):
        o = seed_obj()
        item = fuzzer._llm_extract_json(
            '{"seeds":[{"command":"GetFeatures","cdw10":2,"cdw10":128}]}')['seeds'][0]
        self.assertEqual(o._llm_make_seed(item, 'llm_seq').cdw10, 2)

    def test_no_valid_candidate_still_rejects_with_reason(self):
        o = seed_obj()
        item = {'command': 'GetFeatures', 'cdw10': 0, DUP: {'cdw10': [0x100]}}
        why = []
        self.assertIsNone(o._llm_make_seed(item, 'llm_seq', why=why))
        self.assertIn('no candidate valid', why[0])

    def test_valid_value_in_late_field_is_found_after_many_duplicates(self):
        # cdw2·cdw3·cdw14 가 각각 두 값(곱 8) → 예전엔 [:8] 이 이것만으로 차서 뒤의
        #   cdw10 대체값 128 을 한 번도 검사하지 않고 폐기했다.
        o = seed_obj()
        raw = ('{"seeds":[{"command":"GetFeatures","cdw2":1,"cdw2":2,"cdw3":1,"cdw3":2,'
               '"cdw14":0,"cdw14":1,"cdw10":0,"cdw10":128}]}')
        item = fuzzer._llm_extract_json(raw)['seeds'][0]
        s = o._llm_make_seed(item, 'llm_seq')
        self.assertIsNotNone(s)
        self.assertEqual(s.cdw10, 128)

    def test_field_order_does_not_change_the_outcome(self):
        o = seed_obj()
        a = ('{"seeds":[{"command":"GetFeatures","cdw2":1,"cdw2":2,"cdw3":1,"cdw3":2,'
             '"cdw14":0,"cdw14":1,"cdw10":0,"cdw10":128}]}')
        b = ('{"seeds":[{"command":"GetFeatures","cdw10":0,"cdw10":128,"cdw14":0,"cdw14":1,'
             '"cdw3":1,"cdw3":2,"cdw2":1,"cdw2":2}]}')
        sa = o._llm_make_seed(fuzzer._llm_extract_json(a)['seeds'][0], 'x')
        sb = o._llm_make_seed(fuzzer._llm_extract_json(b)['seeds'][0], 'x')
        self.assertEqual([getattr(sa, f) for f in ('cdw2', 'cdw3', 'cdw10', 'cdw14')],
                         [getattr(sb, f) for f in ('cdw2', 'cdw3', 'cdw10', 'cdw14')])

    def test_search_limit_is_reported_separately_from_all_invalid(self):
        o = seed_obj()
        dups = {f'cdw{w}': [7, 8] for w in (2, 3, 11, 12, 13, 14, 15)}   # 곱 2^8=256 > 한도
        item = {'command': 'GetFeatures', 'cdw10': 0, DUP: dict(dups, cdw10=[0x100])}
        for k, v in dups.items():
            item[k] = 6
        why = []
        self.assertIsNone(o._llm_make_seed(item, 'x', why=why))
        self.assertIn('candidate search limit reached', why[-1])
        why2 = []
        o._llm_make_seed({'command': 'GetFeatures', 'cdw10': 0, DUP: {'cdw10': [0x100]}},
                         'x', why=why2)
        self.assertIn('no candidate valid', why2[-1])

    def test_before_fix_last_value_would_have_been_used(self):
        # 대조군: 기본 json.loads 는 마지막 값(0)을 받는다 — 이 수정의 근거.
        self.assertEqual(json.loads('{"cdw10":128,"cdw10":0}')['cdw10'], 0)


class FocusCommands(unittest.TestCase):
    def test_pick_rotates_by_assignment_count(self):
        o = seed_obj()
        pool = ['A', 'B', 'C', 'D', 'E']
        self.assertEqual(o._llm_focus_pick(pool, 3), ['A', 'B', 'C'])
        o._llm_focus_hist = {'A': 1, 'B': 1, 'C': 1}
        self.assertEqual(o._llm_focus_pick(pool, 3), ['D', 'E', 'A'])

    def test_account_counts_seeds_and_sequence_triggers(self):
        o = seed_obj()
        o._llm_by_task = {}
        res = {'task': 'sequences', 'ctx': {'focus_commands': ['GetLogPage', 'Identify', 'Read']}}
        shape = {'sequences': [
            {'commands': [{'command': 'SetFeatures'}, {'command': 'GetLogPage'}]},
            {'commands': [{'command': 'Identify'}, {'command': 'Write'}]},   # Identify 는 trigger 아님
        ]}
        o._llm_focus_account(res, shape)
        bt = o._llm_by_task['sequences']
        self.assertEqual((bt['focus_hit'], bt['focus_req']), (1, 3))
        self.assertEqual(o._llm_focus_hist, {'GetLogPage': 1, 'Identify': 1, 'Read': 1})

    def test_sequences_request_answered_with_single_seed_is_not_compliant(self):
        o = seed_obj()
        o._llm_by_task = {}
        res = {'task': 'sequences', 'ctx': {'focus_commands': ['Identify']}}
        o._llm_focus_account(res, {'seeds': [{'command': 'Identify'}], 'sequences': []})
        bt = o._llm_by_task['sequences']
        self.assertEqual((bt['focus_hit'], bt['focus_req']), (0, 1))

    def test_malformed_trigger_does_not_drop_accounting(self):
        o = seed_obj()
        o._llm_by_task = {}
        res = {'task': 'sequences', 'ctx': {'focus_commands': ['Read', 'Write']}}
        shape = {'sequences': [{'commands': []}, {'commands': [{'command': ['x']}]},
                               {'commands': ['Read']}, 'bad',
                               {'commands': [{'command': 'Write'}]}]}
        o._llm_focus_account(res, shape)
        bt = o._llm_by_task['sequences']
        self.assertEqual((bt['focus_hit'], bt['focus_req']), (1, 2))

    def test_block_is_imperative(self):
        o = seed_obj()
        b = o._llm_focus_block(['GetLogPage', 'Read'], 'seeds')
        self.assertIn('MANDATORY', b)
        self.assertIn('MUST include at least one seed for EACH', b)
        self.assertIn('GetLogPage, Read', b)
        self.assertEqual(o._llm_focus_block([], 'seeds'), '')

    def build(self, task):
        o = seed_obj()
        o._llm_exercised_names = lambda: {'Identify', 'Read', 'Write', 'GetLogPage'}
        o._llm_coverage_context = lambda: ''
        o._llm_grounding_block = lambda: ''
        o._llm_contrastive_block = lambda: ''
        o._llm_reject_block = lambda: ''
        o._llm_data_directive = lambda: ''
        o._llm_unreachable_names = lambda sb: set()
        o._llm_schema_summary = lambda names: ','.join(names)
        o._llm_schema_pick = lambda names: names[:4]
        o._unimpl_cmds = set()
        o.cmd_stats = {'Identify': {'exec': 100, 'new_cov': 50}, 'Read': {'exec': 100, 'new_cov': 1},
                       'Write': {'exec': 100, 'new_cov': 5}, 'GetLogPage': {'exec': 100, 'new_cov': 0}}
        return o, o._llm_build_request(task)

    def test_seeds_prompt_names_mandatory_commands_and_ctx(self):
        o, (_, user) = self.build('new_group_seeds')
        focus = o._llm_pending_ctx['focus_commands']
        self.assertEqual(len(focus), fuzzer.RAG_FOCUS_COMMANDS)
        self.assertIn('MANDATORY', user)
        self.assertIn(', '.join(focus), user)
        # never-sent 가 먼저, 그다음 수확 낮은 순 → 고수확 Identify 는 뒤로 밀린다
        self.assertNotEqual(focus[0], 'Identify')
        self.assertIn('  - GetLogPage: exec=100, new_cov=0', user)   # 서술 목록은 읽기 쉬운 줄로
        self.assertIn('at most once per object', user)

    def test_sequences_prompt_now_has_priority_and_mandatory_block(self):
        o, (_, user) = self.build('sequences')
        focus = o._llm_pending_ctx['focus_commands']
        self.assertTrue(focus)
        self.assertIn('FINAL (trigger) command', user)
        self.assertIn(', '.join(focus), user)


class InvalidPatternFeedback(unittest.TestCase):
    def test_invalid_name_is_remembered_not_aliased(self):
        o = seed_obj()
        o._llm_wl_invalid_last = None
        self.assertIsNone(o._llm_make_workload_desc({'pattern': 'random_write'}))
        self.assertEqual(o._llm_wl_invalid_last, 'random_write')

    def test_next_prompt_reports_once_and_lists_exact_names(self):
        o = seed_obj()
        o._wl_pattern_stats = {}
        o._wl_burst_seq = 0
        o._last_workload_result = None
        o._llm_wl_invalid_last = 'random_write'
        o._llm_exercised_names = lambda: set()
        o._llm_coverage_context = lambda: ''
        o._llm_grounding_block = lambda: ''
        o._llm_telemetry_block = lambda: ''
        _, user = o._llm_build_request('io_patterns')
        self.assertIn('"random_write", which is NOT a valid name', user)
        self.assertIn('copied EXACTLY', user)
        self.assertIn(json.dumps(fuzzer.IO_WL_PATTERNS), user)
        _, again = o._llm_build_request('io_patterns')
        self.assertNotIn('random_write', again)


if __name__ == '__main__':
    unittest.main()
