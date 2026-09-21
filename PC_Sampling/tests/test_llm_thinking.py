"""Reasoning controls must reach HTTP; false must not disappear as a falsy value."""
import unittest
from test_v10_3_backend import FakeServer, client_cfg, ok_completion
from rag import vllm_client


class ThinkingTests(unittest.TestCase):
    def test_defaults_off_and_low_effort_reach_http_and_diagnostics(self):
        for template in [None, {'enable_thinking': False},
                         {'enable_thinking': True, 'low_effort': True}]:
            with self.subTest(template=template), FakeServer(
                    lambda p, b: ok_completion('{"seeds": []}')) as srv:
                result = vllm_client.generate_rag_response('system', 'user', {
                    'task': 'new_group_seeds', 'config': client_cfg(
                        srv.base, chat_template_kwargs=template, retrieval={'enabled': False})})
                self.assertNotIn('error', result)
                body = srv.seen[0][1]
                if template is None:
                    self.assertNotIn('chat_template_kwargs', body)
                else:
                    self.assertEqual(body['chat_template_kwargs'], template)
                self.assertEqual(result['diagnostics']['requested_chat_template_kwargs'], template)
                self.assertEqual(body['response_format']['type'], 'json_schema')

    def test_invalid_values_fail_before_http(self):
        for template in ['low', {'low_effort': 'true'}, {'enable_thinking': 0}]:
            with self.subTest(template=template), FakeServer(
                    lambda p, b: ok_completion('{"seeds": []}')) as srv:
                result = vllm_client.generate_rag_response('s', 'u', {
                    'task': 'new_group_seeds', 'config': client_cfg(
                        srv.base, chat_template_kwargs=template, retrieval={'enabled': False})})
                self.assertIn('chat_template_kwargs', result['error'])
                self.assertEqual(srv.seen, [])
