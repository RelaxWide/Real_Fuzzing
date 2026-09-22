"""운영 검색에서 순위·권한·실제 주입 기록을 함께 검증한다. API/장치 접근 없음."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
import numpy as np
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rag import rag_retrieval as rr


class HybridTests(unittest.TestCase):
    def retrieve(self, commands, groups=None, limit=1000):
        rows = [dict(doc_id='wrong', content='generic', permission_groups=['public']),
                dict(doc_id='right', content='Figure 1: Read - Command Dword 10', permission_groups=['private'])]
        cfg = dict(base_url='http://unused', retrieval=dict(command_tag_bonus=.3,
                   permission_groups=groups, context_max_chars=limit))
        index = ({'embed_model': 'bge-m3'}, rows, np.array([[1., 0], [.8, .6]]), Path('fixture'))
        with patch.object(rr, '_load', return_value=index), patch.object(rr, 'embed', return_value=[1, 0]):
            return rr.retrieve(dict(rag_query='NVMe Read', rag_query_commands=commands), cfg, 100)

    def test_bonus_and_injected_context(self):
        text, diag = self.retrieve(['Read'], limit=12)
        self.assertEqual(diag['hits'][0]['doc_id'], 'right')
        self.assertEqual(diag['hits'][0]['tag_bonus'], .3)
        self.assertEqual(diag['hits'][0]['injected_chars'], 12)
        self.assertEqual(diag['hits'][1]['injected_chars'], 0)
        self.assertEqual(diag['context'], text)
        self.assertTrue(diag['context_truncated'])

    def test_missing_commands_dense_fallback(self):
        _, diag = self.retrieve([])
        self.assertEqual(diag['hits'][0]['doc_id'], 'wrong')

    def test_permission_filter_preserved(self):
        _, diag = self.retrieve(['Read'], ['public'])
        self.assertEqual([h['doc_id'] for h in diag['hits']], ['wrong'])

    def test_multiple_commands(self):
        _, diag = self.retrieve(['Write', 'Read'])
        self.assertEqual(diag['hits'][0]['doc_id'], 'right')


class QueryIntegrationTests(unittest.TestCase):
    def test_actual_schema_examples_and_same_meta_block(self):
        from test_v10_2_learning import harness, fuzzer
        from rag.retrieval_policy import enhanced_query
        inst = harness({'enabled': False})
        from types import SimpleNamespace
        inst.config = SimpleNamespace(product='test')
        schemas = inst.llm.schema_bridge.schemas
        expectations = {'Lockdown': ['Command Dword 10', 'OFI Opcode or Feature Identifier', 'IFC Interface', 'PRHBT Prohibit', 'SCP Scope'],
                        'Sanitize': ['Command Dword 10', 'SANACT Sanitize Action'],
                        'GetFeatures': ['Get Features command', 'FID Feature Identifier', 'SEL Select']}
        for command, terms in expectations.items():
            query = enhanced_query([command], schemas)
            for term in terms:
                self.assertIn(term, query)
            ctx = {'rag_query_commands': [command]}
            inst._llm_pending_ctx = ctx
            with patch.object(fuzzer._V101Fuzzer, '_llm_build_request', return_value=('system', 'body')):
                _, user = inst._llm_build_request('new_group_seeds')
            self.assertEqual(rr.query_from({}, user, 8000)[0], query)
            self.assertEqual(inst._llm_backend_meta('new_group_seeds', ctx)['rag_query'], query)

    def test_unknown_fields_not_invented_and_aliases(self):
        from rag.retrieval_policy import enhanced_query, spec_name
        self.assertEqual(spec_name('FWCommit'), 'Firmware Commit')
        query = enhanced_query(['Unknown', 'Unknown'], {'Unknown': [{'name': 'XYZ', 'word': 12}]})
        self.assertEqual(query, 'Unknown command Command Dword 12 XYZ field encoding')

    def test_generation_diagnostics_record_actual_prompt(self):
        from rag import vllm_client as vc
        cfg = vc._config({'config': {'rag': {'vllm': {}}}})
        with patch.object(vc, '_config', return_value=cfg), patch.object(rr, 'retrieve', return_value=('SPEC TEXT', {'hits': []})), patch.object(vc, '_chat', return_value=('{}', {})) as chat:
            result = vc.generate_rag_response('system', 'original', {'task': 'io_patterns', 'correction_attempt': 1})
        diag = result['diagnostics']
        self.assertEqual(diag['effective_user_prompt'], chat.call_args.args[1])
        self.assertIn('SPEC TEXT', diag['effective_user_prompt'])
        self.assertEqual(diag['correction_attempt'], 1)
