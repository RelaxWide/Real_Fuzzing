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
            result = subprocess.run([sys.executable, str(ROOT / 'pc_sampling_fuzzer_v10.3.py'),
                                     '--config', str(path), '--rag'], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('revision 불일치', result.stderr)
            self.assertIn('퍼저를 시작하지 않습니다', result.stderr)
            self.assertNotIn('Default commands', result.stdout)
