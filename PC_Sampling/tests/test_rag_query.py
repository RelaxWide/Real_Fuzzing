import importlib.util
from pathlib import Path
from types import SimpleNamespace as NS
import unittest
import sys
import tempfile
import subprocess
from unittest.mock import Mock, patch
from test_v10_2_learning import fuzzer, harness
from llm_learning import query_block
from rag_inline_support import (query_module, extract_query, prepare_query,
                           extract_search_context, generate_with_rag, RagSearchError)


class Tokenizer:
    # Deterministic char tokenizer for boundary/contract tests, not a BGE substitute.
    def encode(self, text, add_special_tokens=True):
        ids = list(map(ord, text))
        return [1] + ids + [2] if add_special_tokens else ids
    def decode(self, ids, skip_special_tokens=True):
        return ''.join(map(chr, ids))
    def num_special_tokens_to_add(self, pair=False):
        return 2


class QueryTests(unittest.TestCase):
    def test_real_fuzzer_adds_query_when_learning_disabled(self):
        inst = harness({'enabled': False})
        inst._llm_pending_ctx = {'rag_query_commands': ['FWCommit']}
        with patch.object(fuzzer._V101Fuzzer, '_llm_build_request',
                          return_value=('system unchanged', 'evidence unchanged')):
            system, user = inst._llm_build_request('new_group_seeds')
        self.assertEqual(system, 'system unchanged')
        self.assertTrue(user.endswith('evidence unchanged'))
        self.assertIn('FWCommit', extract_query(user)[0])

    def test_large_prompt_preserved_for_generation(self):
        prompt = query_block('new_group_seeds', ['FWCommit']) + 'evidence ' * 10000
        retrieve = Mock(return_value='reference')
        generate = Mock(return_value='answer')
        self.assertEqual(generate_with_rag(prompt, retrieve, generate, Tokenizer()), 'answer')
        query = retrieve.call_args.args[0]
        self.assertIn('FWCommit', query)
        self.assertNotIn('evidence', query)
        self.assertEqual(generate.call_args.args[0], prompt + '\n[참고 문서]\nreference')

    def test_budget_on_both_marker_and_legacy_queries(self):
        for query in ('x' * 8498, '[RAG-QUERY]' + 'x' * 8498 + '[/RAG-QUERY]'):
            out = prepare_query(query, Tokenizer(), budget=8000)
            self.assertEqual(len(Tokenizer().encode(out)), 8000)
        for size in (7998, 7999):
            out = prepare_query('x' * size, Tokenizer(), budget=8000)
            self.assertLessEqual(len(Tokenizer().encode(out)), 8000)

    def test_invalid_marker_uses_bounded_fallback(self):
        for text in ('abc', '[RAG-QUERY]x', '[RAG-QUERY][/RAG-QUERY]',
                     '[/RAG-QUERY][RAG-QUERY]', query_block('sequences') * 2):
            self.assertEqual(extract_query(text), (text, 'legacy'))
            self.assertLessEqual(len(Tokenizer().encode(prepare_query(text, Tokenizer(), 32))), 32)

    def test_response_errors_and_empty_result(self):
        def response(body, status=200):
            return NS(status_code=status, json=lambda: body)
        for status in (200, 400, 500):
            with self.assertRaises(RagSearchError) as ctx:
                extract_search_context(response({'error_code': 'QUERY_TOKEN_LIMIT_EXCEEDED',
                                                 'query_tokens': 8498, 'max_tokens': 8192}, status))
            self.assertIn('8498', str(ctx.exception))
            self.assertFalse(ctx.exception.retryable)
        for body in ({}, {'hits': []}, {'hits': {'hits': [{}]}}):
            with self.assertRaises(RagSearchError):
                extract_search_context(response(body))
        self.assertEqual(extract_search_context(response({'hits': {'hits': []}})), '')
        prompt = query_block('sequences') + 'original'
        generate = Mock(return_value='ok')
        generate_with_rag(prompt, lambda q: '', generate, Tokenizer())
        self.assertEqual(generate.call_args.args[0], prompt + '\n[RAG 문서 없음]')

    def test_installer_cli_preview_backup_and_apply(self):
        root = Path(__file__).resolve().parents[1]
        original = (root / 'rag' / 'srag_llm_guide.reference.py').read_bytes()
        with tempfile.TemporaryDirectory() as folder:
            guide = Path(folder) / 'srag_llm_guide.py'
            guide.write_bytes(original)
            standalone = Path(folder) / 'install_rag_query.py'
            standalone.write_bytes((root / 'tools' / 'install_rag_query.py').read_bytes())
            command = [sys.executable, str(standalone), str(guide)]
            preview = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(preview.returncode, 0, preview.stderr)
            self.assertIn('generate_with_rag', preview.stdout)
            self.assertEqual(guide.read_bytes(), original)
            self.assertFalse((guide.parent / 'rag_query.py').exists())
            applied = subprocess.run(command + ['--apply'], capture_output=True, text=True, timeout=10)
            self.assertEqual(applied.returncode, 0, applied.stderr)
            backups = list(guide.parent.glob('*.bak'))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_bytes(), original)
            self.assertFalse((guide.parent / 'rag_query.py').exists())
            self.assertNotIn('from rag_query import', guide.read_text())
            self.assertIn('# BEGIN INLINED RAG QUERY V1', guide.read_text())
            compile(guide.read_text(), str(guide), 'exec')

    def test_migrate_existing_split_guide_without_helper_file(self):
        from rag_inline_support import installer
        source = """from rag_query import generate_with_rag, extract_search_context
setting = 'preserved'
def retrieve_from_rag(query):
    return extract_search_context(response)
def generate_response(prompt):
    return prompt
def generate_rag_response(prompt):
    return generate_with_rag(prompt, retrieve_from_rag, generate_response)
"""
        patched = installer.patch_source(source)
        self.assertNotIn('from rag_query import', patched)
        env = {'response': NS(status_code=200, json=lambda: {'hits': {'hits': []}})}
        exec(compile(patched, '<migrated guide>', 'exec'), env)
        env['_rag_get_tokenizer'] = lambda: Tokenizer()
        prompt = query_block('sequences') + 'original prompt'
        self.assertEqual(env['generate_rag_response'](prompt), prompt + '\n[RAG 문서 없음]')
        self.assertEqual(env['setting'], 'preserved')
        self.assertEqual(installer.patch_source(patched), patched)

    def test_retrieval_logging_aliases_try_and_spelling_variants(self):
        from rag_inline_support import installer
        for wrapped in (False, True):
            for name in ('retrieve_from_rag', 'retreive_from_rag'):
                with self.subTest(wrapped=wrapped, name=name):
                    body = """    response = request({'query_text': prompt})
    result = response.json()
    record('parsed')
    hits = result['hits']['hits']
    first = hits[0]
    text = first['_source']['merge_title_content']
    return text
"""
                    if wrapped:
                        body = ('    try:\n' + ''.join('    ' + line for line in body.splitlines(True))
                                + "    finally:\n        record('cleanup')\n")
                    source = (f'def {name}(prompt):\n' + body +
                              'def generate_response(prompt):\n    return prompt\n' +
                              'def generate_rag_responses(prompt):\n    return prompt\n')
                    patched = installer.patch_source(source)
                    record = Mock()
                    response = NS(status_code=200, json=lambda: {'hits': {'hits': [
                        {'_source': {'merge_title_content': 'reference'}}]}})
                    env = {'request': Mock(return_value=response), 'record': record}
                    exec(compile(patched, '<guide variant>', 'exec'), env)
                    env['_rag_get_tokenizer'] = lambda: Tokenizer()
                    prompt = query_block('sequences') + 'full original'
                    self.assertEqual(env['generate_rag_responses'](prompt),
                                     prompt + '\n[참고 문서]\nreference')
                    record.assert_any_call('parsed')
                    if wrapped:
                        record.assert_any_call('cleanup')
                    response.json = lambda: {'hits': {'hits': []}}
                    self.assertEqual(env['generate_rag_responses'](prompt), prompt + '\n[RAG 문서 없음]')
                    response.json = lambda: {'error_code': 'QUERY_TOKEN_LIMIT_EXCEEDED', 'query_tokens': 8498}
                    with self.assertRaisesRegex(RuntimeError, 'QUERY_TOKEN_LIMIT_EXCEEDED'):
                        env['generate_rag_responses'](prompt)

    def test_installer_preserves_query_http_settings_and_original_prompt(self):
        path = Path(__file__).resolve().parents[1] / 'tools' / 'install_rag_query.py'
        spec = importlib.util.spec_from_file_location('install_query_test', path)
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        source = '''"""guide"""
from __future__ import annotations
setting = 'preserve me'
def generate_response(prompt):
    return prompt
def retrieve_from_rag(user_prompt):
    fields = {'query_text': user_prompt}
    response = request(fields)
    result = response.json()
    return result['hits']['hits'][0]['_source']['merge_title_content']
def generate_rag_response(user_prompt):
    rag_context = retrieve_from_rag(user_prompt)
    return generate_response(user_prompt + rag_context)
'''
        patched = installer.patch_source(source)
        self.assertIn("setting = 'preserve me'", patched)
        self.assertIn("fields = {'query_text': user_prompt}", patched)
        self.assertIn('_rag_checked_context = _rag_extract_search_context(response)', patched)
        self.assertIn('return _rag_generate_with_rag(user_prompt, retrieve_from_rag, generate_response)', patched)
        self.assertEqual(installer.patch_source(patched), patched)
        request = Mock(return_value=NS(status_code=200, json=lambda: {
            'hits': {'hits': [{'_source': {'merge_title_content': 'reference'}}]}}))
        env = {'request': request}
        exec(compile(patched, '<online guide>', 'exec'), env)
        env['_rag_get_tokenizer'] = lambda: Tokenizer()
        prompt = query_block('sequences') + 'full evidence ' * 2000
        output = env['generate_rag_response'](prompt)
        self.assertEqual(output, prompt + '\n[참고 문서]\nreference')
        self.assertNotIn('full evidence', request.call_args.args[0]['query_text'])

        with self.assertRaises(ValueError):
            installer.patch_source(source.replace("['hits'][0]", "['hits'][1]"))
