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

    def test_reasoning_aliases_are_measured_without_changing_final_content(self):
        cases = [
            ({'reasoning': 'abcde'}, 'reasoning', 5),
            ({'reasoning_content': 'abc'}, 'reasoning_content', 3),
            ({'reasoning_content': None, 'reasoning': 'abcde'}, 'reasoning', 5),
            ({'reasoning_content': '', 'reasoning': 'abcde'}, 'reasoning', 5),
            ({'reasoning_content': 'abc', 'reasoning': 'abcde'}, 'reasoning_content', 3),
            ({}, None, 0),
        ]
        for fields, field, count in cases:
            with self.subTest(fields=fields):
                def reply(path, body):
                    status, payload = ok_completion('{"seeds": []}')
                    payload['choices'][0]['message'].update(fields)
                    payload['usage'] = {'completion_tokens': 53}
                    return status, payload
                with FakeServer(reply) as srv:
                    result = vllm_client.generate_rag_response('s', 'u', {
                        'task': 'new_group_seeds', 'config': client_cfg(
                            srv.base, retrieval={'enabled': False})})
                self.assertEqual(result['raw'], '{"seeds": []}')
                diag = result['diagnostics']
                self.assertEqual(diag['reasoning_chars'], count)
                self.assertEqual(diag['reasoning_field'], field)
                self.assertEqual(diag['content_chars'], len(result['raw']))
                self.assertEqual(diag['usage']['completion_tokens'], 53)
