"""기존 인덱스 파일의 메타데이터·캐싱·질의 확장 검증. 장치/API 접근 없음."""
import importlib.util
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import numpy as np
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from rag import retrieval_policy as policy, rag_retrieval as rr

BODY = ('Figure 10: Get Features – Command Dword 10\n'
        '07:00 Feature Identifier (FID): description\n'
        '| 10:08 | Select (SEL) | description\n'
        'Figure 11: Unrelated Table\nOther Name (BAD): not a command field')


class MetadataTests(unittest.TestCase):
    def test_scope_conflicts_and_permissions(self):
        rows = policy.extract_definitions(BODY, 'spec', 'a', ['private'])
        self.assertEqual([r['abbreviation'] for r in rows], ['FID', 'SEL'])
        lookup, conflicts = policy.definition_lookup(rows, ['public'])
        self.assertEqual(lookup, {})
        other = dict(rows[0], full_name='Conflicting Name')
        lookup, conflicts = policy.definition_lookup(rows + [other])
        self.assertEqual(conflicts, 1)
        self.assertNotIn(('getfeatures', 10, 'FID'), lookup)
        query = policy.enhanced_query(['GetFeatures'], {'GetFeatures': [{'word': 10, 'name': 'FID'}]}, lookup)
        self.assertNotIn('Feature Identifier', query)

    def test_old_index_tags_cached_once(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'current').write_text('v1')
            version = root / 'v1'
            version.mkdir()
            (version / 'manifest.json').write_text('{"embed_model":"bge-m3"}')
            (version / 'chunks.jsonl').write_text(json.dumps({'doc_id': 'a', 'content': BODY}) + '\n')
            np.save(version / 'vectors.f16.npy', np.array([[1., 0.]], dtype=np.float16))
            rr._PINNED.clear()
            with patch.object(policy, 'tags', wraps=policy.tags) as tagger, patch.object(rr, 'embed', return_value=[1, 0]):
                cfg = {'base_url': 'unused', 'retrieval': {'index_dir': d}}
                meta = {'rag_query': 'Get Features', 'rag_query_commands': ['GetFeatures']}
                first = rr.retrieve(meta, cfg, time.monotonic()+10)
                second = rr.retrieve(meta, cfg, time.monotonic()+10)
                self.assertEqual(tagger.call_count, 1)
                self.assertEqual(first, second)
            rr._PINNED.clear()

    def test_ingest_reuse_and_runtime_definition(self):
        spec = importlib.util.spec_from_file_location('metadata_ingest', ROOT / 'tools/rag_ingest.py')
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        body = BODY.replace('Feature Identifier (FID)', 'Custom Field Name (ABC)')
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            source = root / 'source.jsonl'
            source.write_text(json.dumps({'doc_id': 'a', 'content': body})+'\n')
            index = root / 'index'
            args = [str(source), '--index-dir', str(index), '--embed-base-url', 'http://unused/v1']
            with patch.object(mod, 'embed_all', return_value=[[1., 0.]]) as embedder:
                mod.main(args)
                mod.main(args)
                self.assertEqual(embedder.call_count, 1, 'metadata update must reuse vectors')
            version = index / (index / 'current').read_text().strip()
            self.assertEqual({p.name for p in version.iterdir()}, {'manifest.json', 'chunks.jsonl', 'vectors.f16.npy'})
            manifest = json.loads((version / 'manifest.json').read_text())
            self.assertEqual(len(manifest['field_definitions']), 2)
            row = json.loads((version / 'chunks.jsonl').read_text())
            self.assertEqual(row['covers_commands'], ['Get Features'])
            self.assertNotIn('_field_definitions', row)
            rr._PINNED.clear()
            with patch.object(rr, 'embed', return_value=[1., 0.]) as embedder:
                _, diag = rr.retrieve({'rag_query': 'original', 'rag_query_commands': ['GetFeatures'],
                    'rag_query_schemas': {'GetFeatures': [{'name': 'ABC', 'word': 10}]}},
                    {'base_url': 'unused', 'retrieval': {'index_dir': str(index)}}, time.monotonic()+10)
                self.assertIn('ABC Custom Field Name', embedder.call_args.args[0])
                self.assertEqual(diag['query_source'], 'index_field_definitions')
            rr._PINNED.clear()
