"""Device-free smoke runner: exercise the real HTTP client and retrieval path."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_v10_3_backend import FakeServer, client_cfg, ok_completion
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import rag_smoke_test as smoke


class SmokeTests(unittest.TestCase):
    def test_all_stages_use_real_http_and_attach_context_only_with_rag(self):
        import numpy as np
        with tempfile.TemporaryDirectory() as tmp, FakeServer(
                lambda path, body: (200, {'data': [{'embedding': [1., 0.]}]})
                if path.endswith('/embeddings') else ok_completion('{"seeds": []}')) as srv:
            root = Path(tmp)
            (root / 'v1').mkdir()
            (root / 'current').write_text('v1')
            (root / 'v1/manifest.json').write_text(json.dumps({'embed_model': 'bge-m3'}))
            (root / 'v1/chunks.jsonl').write_text(json.dumps(
                {'doc_id': 'apst', 'title': 'APST', 'content': 'UNIQUE_REFERENCE_TEXT'}))
            np.save(root / 'v1/vectors.f16.npy', np.array([[1., 0.]], dtype=np.float16))
            cfg = client_cfg(srv.base, retrieval={'enabled': False, 'index_dir': tmp,
                                                  'embed_base_url': srv.base})
            original = copy.deepcopy(cfg)
            for stage in ['retrieval', 'generation', 'rag']:
                result = smoke.run_stage(stage, cfg, 'APST')
                self.assertEqual(result['status'], 'PASS', result)
            chats = [b for p, b in srv.seen if p.endswith('/chat/completions')]
            self.assertNotIn('UNIQUE_REFERENCE_TEXT', chats[0]['messages'][-1]['content'])
            self.assertIn('UNIQUE_REFERENCE_TEXT', chats[1]['messages'][-1]['content'])
            self.assertEqual(chats[0]['response_format']['type'], 'json_schema')
            self.assertEqual(cfg, original)

    def test_retrieval_fallback_is_a_failure_even_if_generation_succeeds(self):
        with FakeServer(lambda p, b: ok_completion('{"seeds": []}')) as srv:
            with patch.object(smoke.rag_retrieval, 'retrieve', side_effect=ValueError('broken index')):
                result = smoke.run_stage('rag', client_cfg(srv.base), 'APST')
            self.assertEqual(result['status'], 'FAIL')
            self.assertIn('broken index', result['error'])
            self.assertEqual(result['response']['raw'], '{"seeds": []}')

    def test_real_parser_rejects_truncation_wrong_container_and_invalid_json(self):
        for raw, finish in [('{"seeds": []}', 'length'), ('{"seeds": "bad"}', 'stop'),
                            ('{"evaluations": []}', 'stop'), ('no json', 'stop')]:
            with self.subTest(raw=raw, finish=finish), self.assertRaises(ValueError):
                smoke.validate_response({'raw': raw, 'diagnostics': {'finish_reason': finish}},
                                        'new_group_seeds')

    def test_cli_reports_failure_and_keeps_config_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / 'config.json'
            config.write_text(json.dumps(client_cfg('http://unused')))
            before = config.read_bytes()
            with patch.object(smoke, 'run_stage', return_value={
                    'stage': 'rag', 'status': 'FAIL', 'elapsed_sec': 0, 'error': 'test error'}):
                code = smoke.main(['--config', str(config), '--stage', 'rag',
                                   '--output', str(root / 'report')])
            self.assertEqual(code, 1)
            self.assertEqual(config.read_bytes(), before)
            self.assertEqual(json.loads((root / 'report/report.json').read_text())['stages'][0]['status'], 'FAIL')
