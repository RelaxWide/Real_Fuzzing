"""Exercise real service functions without importing the external online guide."""
import ast
import sys
from pathlib import Path
import threading
import traceback
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class ServiceErrorTests(unittest.TestCase):
    def service(self, call):
        path = Path(__file__).resolve().parents[1] / 'rag' / 'srag_llm_service.py'
        tree = ast.parse(path.read_text())
        names = {'_call_once', '_call_llm_resilient', '_log_call_error'}
        tree.body = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        ns = {'threading': threading, 'traceback': traceback, '_llm_call': call,
              '_CALL_TIMEOUT': 2, '_reload_llm': Mock(), '_log': Mock()}
        exec(compile(tree, str(path), 'exec'), ns)
        return ns

    def test_missing_hits_exposes_type_guide_frame_and_error_response(self):
        guide = {}
        exec(compile("def generate_rag_response(prompt):\n    return {}['hits']\n",
                     'online/srag_llm_guide.py', 'exec'), guide)
        ns = self.service(guide['generate_rag_response'])
        text, error = ns['_call_llm_resilient']('test prompt')
        self.assertEqual(text, '')
        self.assertIn("KeyError: 'hits'", error)
        self.assertIn('online/srag_llm_guide.py:2', error)
        logs = '\n'.join(call.args[0] for call in ns['_log'].call_args_list)
        self.assertIn('Traceback', logs)
        self.assertIn('generate_rag_response', logs)
        self.assertNotIn('연결이 끊긴 것으로 보고', logs)
        ns['_reload_llm'].assert_called_once()

    def test_transient_failure_still_retries_and_returns_success(self):
        call = Mock(side_effect=[ConnectionError('lost connection'), '{"seeds": []}'])
        ns = self.service(call)
        self.assertEqual(ns['_call_llm_resilient']('prompt'), ('{"seeds": []}', None))
        self.assertEqual(call.call_count, 2)
        ns['_reload_llm'].assert_called_once()

    def test_token_limit_does_not_repeat_identical_request(self):
        from rag_inline_support import RagSearchError
        call = Mock(side_effect=RagSearchError('QUERY_TOKEN_LIMIT_EXCEEDED: 8498 > 8192'))
        ns = self.service(call)
        text, error = ns['_call_llm_resilient']('prompt')
        self.assertEqual(text, '')
        self.assertIn('QUERY_TOKEN_LIMIT_EXCEEDED', error)
        call.assert_called_once()
        ns['_reload_llm'].assert_not_called()

    def test_success_does_not_reload(self):
        ns = self.service(Mock(return_value='ok'))
        self.assertEqual(ns['_call_llm_resilient']('prompt'), ('ok', None))
        ns['_reload_llm'].assert_not_called()
