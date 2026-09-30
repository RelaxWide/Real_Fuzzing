"""LLM 프롬프트·응답 위생 — data_hex 폭주, 잘린 응답 재시도, 프롬프트 중복·무의미 줄.

1) data_hex: 스키마 maxLength 와 프롬프트 상한이 같은 값(2KB)이고, 퍼저 실제 입력 상한
   (max_input_len)은 그대로다. "확신 없으면 생략" 지시가 있다.
2) finish_reason=length 로 잘린 응답은 JSON 교정 재시도를 하지 않는다.
3) SUCCESS 명령엔 'fix the exact field' 를 붙이지 않고, 가중치로 반복된 명령은 한 줄,
   evidence 에서 숫자 0 필드는 뺀다(불리언 False 는 유지).
"""
import json
import queue
import sys
import threading
import unittest
from unittest.mock import Mock

from test_v10_2_learning import ROOT, fuzzer, harness   # noqa: F401

sys.path.insert(0, str(ROOT))
from rag import llm_schema                               # noqa: E402
import llm_learning                                      # noqa: E402


class DataHexCap(unittest.TestCase):
    def test_schema_caps_every_data_hex(self):
        s = llm_schema.build_schema('new_group_seeds', ['seq_write'], True)
        text = json.dumps(s)
        n_data = text.count('"data_hex"')
        self.assertGreaterEqual(n_data, 2)
        self.assertEqual(text.count(f'"maxLength": {llm_schema.DATA_HEX_MAX_CHARS}'), n_data)
        self.assertEqual(llm_schema.DATA_HEX_MAX_CHARS, 4096)

    def test_prompt_uses_same_cap_and_allows_omission(self):
        o = harness({'enabled': True})
        write = fuzzer._NAME_TO_CMD['Write']
        dsm = fuzzer._NAME_TO_CMD['DatasetManagement']
        o.commands = [write] * 6 + [dsm]                  # 가중치로 반복된 목록
        o.cmd_stats = {'Write': {'reached_fw': 5}, 'DatasetManagement': {'reached_fw': 5}}
        o._unimpl_cmds = set()
        text = o._llm_data_directive()
        self.assertEqual(text.count('\n  Write:'), 1, text)
        self.assertIn('<= 2048 bytes = 4096 hex chars', text)
        self.assertNotIn(str(fuzzer.MAX_INPUT_LEN), text)
        self.assertIn('OMIT data_hex', text)
        # 퍼저 실제 입력 상한은 건드리지 않는다
        self.assertEqual(fuzzer.MAX_INPUT_LEN, 131072)


class NoRetryOnTruncation(unittest.TestCase):
    def run_once(self, finish_reason):
        b = fuzzer.LlmBridge.__new__(fuzzer.LlmBridge)
        b._stop, b._in_q, b._out_q, b._inflight = threading.Event(), queue.Queue(), queue.Queue(), True
        calls = []

        def call(system, user, meta=None):
            calls.append(user)
            return '{"seeds": [{"command": "Wr', {'finish_reason': finish_reason}
        b._call_llm = call
        b._in_q.put(dict(task='new_group_seeds', system='s', user='u', submitted_at=0,
                         ctx={}, meta={}, req_id=1))
        t = threading.Thread(target=b._run, daemon=True)
        t.start()
        res = b._out_q.get(timeout=10)
        b._stop.set()
        t.join(timeout=5)
        return calls, res

    def test_truncated_response_is_not_retried(self):
        calls, res = self.run_once('length')
        self.assertEqual(len(calls), 1)
        self.assertEqual(res['retries'], 0)

    def test_other_invalid_json_is_still_retried(self):
        calls, res = self.run_once('stop')
        self.assertEqual(len(calls), 1 + fuzzer.RAG_JSON_RETRIES)


class PromptLines(unittest.TestCase):
    def grounding(self, best_depth):
        o = harness({'enabled': True})
        o.cmd_stats = {'GetLogPage': {'reached_fw': 9, 'sc_hist': {0x0002: 5}, 'best_depth': best_depth}}
        o._unimpl_cmds = set()
        o._llm_depth_cmds = set()
        o.corpus = []
        o._active_nsids = [1]
        o._llm_command_frontier_hints = lambda *a, **k: []
        o.llm = Mock(schema_bridge=Mock(commands={'GetLogPage': {}}))
        return o._llm_grounding_block()

    def test_success_command_has_no_fix_instruction(self):
        text = self.grounding(3)
        line = [l for l in text.splitlines() if l.strip().startswith('GetLogPage :')]
        self.assertTrue(line, text)
        self.assertIn('at SUCCESS', line[0])
        self.assertNotIn('fix the exact field', line[0])

    def test_shallow_command_keeps_fix_instruction(self):
        text = self.grounding(1)
        line = [l for l in text.splitlines() if l.strip().startswith('GetLogPage :')][0]
        self.assertIn('fix the exact field', line)

    def test_evidence_drops_numeric_zero_keeps_false(self):
        ev = llm_learning._drop_zero({'id': 't1', 'executed': 0, 'observed': 3, 'size': 0.0,
                                      'unobservable': False,
                                      'recent': [{'new_coverage': 0, 'rc': 0, 'status': 5,
                                                  'observable': False, 'cdw': {'cdw10': 0, 'cdw11': 7}}]})
        self.assertEqual(ev, {'id': 't1', 'observed': 3, 'unobservable': False,
                              'recent': [{'status': 5, 'observable': False, 'cdw': {'cdw11': 7}}]})


if __name__ == '__main__':
    unittest.main()
