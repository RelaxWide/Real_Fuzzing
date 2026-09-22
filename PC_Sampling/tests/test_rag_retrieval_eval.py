import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
import numpy as np

spec = importlib.util.spec_from_file_location('rag_eval', Path(__file__).resolve().parents[1] / 'tools/rag_retrieval_eval.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class EvalTests(unittest.TestCase):
    def test_caption_variants(self):
        for dash in ('-', '–', '—'):
            self.assertEqual(m.tags(f'Figure 12: Get Features {dash}\nCommand Dword 10'), ['Get Features'])
        self.assertEqual(m.tags('Read Command Dword 10'), [])

    def test_recursive_prepare_does_not_invent_gold(self):
        chunks = [{'doc_id': 'indexed#0', 'content': 'Figure 1: Read - Command Dword 10'}]
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d) / 'spec' / 'nested'
            folder.mkdir(parents=True)
            (folder / 'part.jsonl').write_text(json.dumps(chunks[0]) + '\n')
            result = m.prepare(Path(d), chunks)
        case = next(c for c in result['cases'] if c['command'] == 'Read')
        self.assertEqual(result['source_files'], 1)
        self.assertEqual(case['candidates'][0]['doc_id'], 'indexed#0')
        self.assertFalse(case['reviewed'])
        self.assertEqual(case['relevant_doc_ids'], [])

    def test_ranking_ablation_cache_and_regression(self):
        chunks = [{'doc_id': 'wrong', 'content': 'generic'},
                  {'doc_id': 'right', 'content': 'Figure 1: Read - Command Dword 10'}]
        vectors = np.array([[1, 0], [.8, .6]], dtype=np.float32)
        calls = []
        def embed(q):
            calls.append(q)
            return [1, 0]
        case = dict(command='Read', reviewed=True, relevant_doc_ids=['right'],
                    baseline_query='NVMe Read', enhanced_query='NVMe Read')
        report = m.evaluate([case], chunks, vectors, embed, .3, 10)
        self.assertEqual(len(calls), 1)
        self.assertEqual(report['results'][0]['variants']['A']['rank'], 2)
        self.assertEqual(report['results'][0]['variants']['D']['rank'], 1)
        self.assertEqual(report['summary']['validation']['D_vs_A']['improved'], ['Read'])
        case['reviewed'] = False
        with self.assertRaises(ValueError):
            m.evaluate([case], chunks, vectors, embed, .3, 10)
        case['reviewed'] = True
        case['relevant_doc_ids'] = ['absent']
        with self.assertRaises(ValueError):
            m.evaluate([case], chunks, vectors, embed, .3, 10)

    def test_invalid_embedding_rejected(self):
        case = dict(command='Read', reviewed=True, relevant_doc_ids=['a'], baseline_query='a', enhanced_query='b')
        for vec in ([0, 0], [float('nan'), 1], [1]):
            with self.assertRaises(ValueError):
                m.evaluate([case], [{'doc_id': 'a', 'content': ''}], np.array([[1, 0]]), lambda q: vec, .1, 5)


if __name__ == '__main__':
    unittest.main()
