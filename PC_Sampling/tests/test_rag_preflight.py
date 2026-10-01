"""RAG mismatch must terminate CLI before device initialization; no NVMe/JTAG."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import numpy as np
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from rag import rag_retrieval as rr


class PreflightTests(unittest.TestCase):
    def test_disabled_and_other_backends_do_not_load_index(self):
        with patch.object(rr, '_load') as loader:
            rr.preflight({}, False, 'rag.vllm_client')
            rr.preflight({}, True, 'rag.rag_bridge_client')
            rr.preflight({'rag': {'vllm': {'retrieval': {'enabled': False}}}}, True, 'rag.vllm_client')
            loader.assert_not_called()

    def test_revision_validation(self):
        for revision in (None, 'old'):
            with self.assertRaisesRegex(ValueError, 'revision 불일치'):
                rr.validate_index_model({'embed_model_revision': revision},
                                        {'embed_model_revision': 'new'}, Path('v1'))
        rr.validate_index_model({'embed_model_revision': 'same'}, {'embed_model_revision': 'same'}, Path('v1'))
        rr.validate_index_model({}, {'embed_model_revision': None}, Path('v1'))

    def test_cli_exits_nonzero_on_revision_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            version = root / 'v1'
            version.mkdir()
            (root / 'current').write_text('v1')
            (version / 'manifest.json').write_text(json.dumps({'embed_model': 'bge-m3', 'embed_model_revision': 'old'}))
            (version / 'chunks.jsonl').write_text('{"doc_id":"a","content":"test"}\n')
            np.save(version / 'vectors.f16.npy', np.array([[1., 0.]], dtype=np.float16))
            config = json.loads((ROOT / 'fuzzer_config.json').read_text())
            config['rag']['vllm']['retrieval'].update(enabled=True, index_dir=str(root), embed_model_revision='new')
            path = root / 'config.json'
            path.write_text(json.dumps(config))
            result = subprocess.run([sys.executable, str(ROOT / 'pc_sampling_fuzzer_v11.py'),
                                     '--config', str(path), '--rag'], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('revision 불일치', result.stderr)
            self.assertIn('퍼저를 시작하지 않습니다', result.stderr)
            self.assertNotIn('Default commands', result.stdout)


class MissingIndexFallsBackToNoRetrieval(unittest.TestCase):
    """인덱스 파일이 없으면 시작은 하고 이번 실행만 검색 없이 생성한다."""

    def cfg(self, index_dir):
        return {'rag': {'vllm': {'base_url': 'http://x:8000/v1',
                                 'retrieval': {'enabled': True, 'index_dir': str(index_dir),
                                               'embed_base_url': 'http://x:8001/v1'}}}}

    def tearDown(self):
        rr._OFF_REASON = None

    def test_missing_index_turns_retrieval_off(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self.cfg(Path(d) / 'no_index')
            with self.assertLogs(level='WARNING') as logs:
                self.assertEqual(rr.preflight(cfg, True, 'rag.vllm_client'), 'off')
            self.assertIn('검색 없이 생성', '\n'.join(logs.output))
            text, diag = rr.retrieve({'rag_query': 'Identify'}, cfg['rag']['vllm'], 1e18)
            self.assertEqual(text, '')
            self.assertFalse(diag['enabled'])
            self.assertIn('FileNotFoundError', diag['disabled_at_start'])

    def test_missing_numpy_turns_retrieval_off(self):
        with tempfile.TemporaryDirectory() as d, \
                patch.object(rr, '_load', side_effect=ImportError('No module named numpy')):
            with self.assertLogs(level='WARNING'):
                self.assertEqual(rr.preflight(self.cfg(d), True, 'rag.vllm_client'), 'off')

    def test_existing_but_mismatched_index_still_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'v1').mkdir()
            (root / 'current').write_text('v1')
            (root / 'v1' / 'manifest.json').write_text(json.dumps({'embed_model': 'other-model'}))
            (root / 'v1' / 'chunks.jsonl').write_text('{"doc_id":"a","content":"t"}\n')
            np.save(root / 'v1' / 'vectors.f16.npy', np.array([[1., 0.]], dtype=np.float16))
            rr._PINNED.pop(str(root), None)
            with self.assertRaisesRegex(ValueError, '모델 불일치'):
                rr.preflight(self.cfg(root), True, 'rag.vllm_client')
            self.assertIsNone(rr._OFF_REASON)

    def test_shipped_config_enables_retrieval(self):
        cfg = json.loads((ROOT / 'fuzzer_config.json').read_text(encoding='utf-8-sig'))
        self.assertIs(cfg['rag']['vllm']['retrieval']['enabled'], True)
