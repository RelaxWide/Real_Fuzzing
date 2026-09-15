"""v10.3 LLM 백엔드 이관 시험. NVMe/JTAG 조작 없음, DGX 서버 없이 돈다.

계획(docs/V10_3_LLM_BACKEND_PLAN.md §6 착수 전 통과 조건)의 항목을 시험으로 옮긴 것.
"""
import ast
import json
import re
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

from test_v10_2_learning import ROOT, FUZZER_FILE, fuzzer, harness

sys.path.insert(0, str(ROOT))
from rag import llm_schema                                  # noqa: E402


# ── 가짜 vLLM 서버 ────────────────────────────────────────────────────────
class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.seen.append((self.path, body))
        status, payload = self.server.reply(self.path, body)
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class FakeServer:
    """with 블록 안에서 사는 로컬 HTTP 서버. reply(path, body) -> (status, json)."""

    def __init__(self, reply):
        self.httpd = HTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.reply = reply
        self.httpd.seen = []

    def __enter__(self):
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_port}/v1"
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()

    @property
    def seen(self):
        return self.httpd.seen


def ok_completion(content, finish="stop"):
    return 200, {"choices": [{"message": {"content": content}, "finish_reason": finish}],
                 "usage": {"total_tokens": 12}, "model": "nemotron-3-super"}


def client_cfg(base, **over):
    cfg = {"rag": {"vllm": {"base_url": base, "timeout_sec": 10.0, "retries": 0}}}
    cfg["rag"]["vllm"].update(over)
    return cfg


class SchemaMatchesParsers(unittest.TestCase):
    """스키마는 표가 아니라 **파서가 실제로 읽는 키**와 일치해야 한다.

    계획 초안이 seeds[].data_len 을 빠뜨렸는데 그 값은 llm_learning 이
    data_len_override 로 반영하는 살아있는 필드였다. additionalProperties=false
    로 잠근 스키마에서 누락은 곧 기능이 조용히 사라지는 것을 뜻한다.
    """

    @staticmethod
    def keys_read_by(func_name, var, *sources):
        """해당 함수 본문에서 `var.get('X')` / `var['X']` 로 읽는 키만 모은다.

        파일 전체를 정규식으로 훑으면 무관한 dict 접근(history/workload 등)까지
        잡혀 시험이 무의미해진다.
        """
        keys = set()
        for src in sources:
            tree = ast.parse((ROOT / src).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not (isinstance(node, ast.FunctionDef) and node.name == func_name):
                    continue
                for sub in ast.walk(node):
                    name = None
                    if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
                            and sub.func.attr == 'get'
                            and isinstance(sub.func.value, ast.Name)
                            and sub.func.value.id == var and sub.args
                            and isinstance(sub.args[0], ast.Constant)):
                        name = sub.args[0].value
                    elif (isinstance(sub, ast.Subscript) and isinstance(sub.value, ast.Name)
                          and sub.value.id == var):
                        # Python 3.8 은 slice 를 ast.Index 로 감싼다(3.9+ 는 Constant 직접).
                        target = sub.slice
                        target = getattr(target, 'value', target) if type(
                            target).__name__ == 'Index' else target
                        if isinstance(target, ast.Constant):
                            name = target.value
                    elif (isinstance(sub, ast.Compare) and sub.ops
                          and isinstance(sub.ops[0], ast.In) and sub.comparators
                          and isinstance(sub.comparators[0], ast.Name)
                          and sub.comparators[0].id == var
                          and isinstance(sub.left, ast.Constant)):
                        name = sub.left.value      # `'data_len' in item` 형태도 읽기다
                    if isinstance(name, str) and not name.startswith('_'):
                        keys.add(name)
        return keys

    def test_seed_item_keys_are_all_present_in_schema(self):
        read = self.keys_read_by('_llm_make_seed', 'item',
                                 FUZZER_FILE.name, 'llm_learning.py')
        self.assertIn('data_len', read, '대조 기준이 비었다 — 파서 탐색이 깨졌다')
        props = set(llm_schema.top_level_properties(['seq_write'])['seeds']['items']['properties'])
        self.assertFalse(read - props,
                         f'파서가 읽는데 스키마에 없는 seeds 키: {read - props}')

    def test_sequence_and_eval_keys_are_present(self):
        seq = self.keys_read_by('_llm_apply_result', 'sq', FUZZER_FILE.name, 'llm_learning.py')
        ev = self.keys_read_by('_llm_apply_result', 'ev', FUZZER_FILE.name)
        props = llm_schema.top_level_properties(['seq_write'])
        self.assertFalse(seq - set(props['sequences']['items']['properties']),
                         f'sequences 누락: {seq}')
        self.assertFalse(ev - set(props['evaluations']['items']['properties']),
                         f'evaluations 누락: {ev}')

    def test_cdw_fields_match_the_parser_loop(self):
        text = (ROOT / FUZZER_FILE.name).read_text(encoding="utf-8")
        m = re.search(r"f'cdw\{w\}'.*?for w in \(([\d, ]+)\)", text, re.S)
        self.assertIsNotNone(m, '_llm_make_seed 의 CDW 루프를 찾지 못했습니다')
        expected = {f'cdw{n.strip()}' for n in m.group(1).split(',') if n.strip()}
        self.assertEqual(set(llm_schema.CDWS), expected)

    def test_workload_pattern_enum_comes_from_config(self):
        patterns = json.loads((ROOT / 'fuzzer_config.json').read_text(
            encoding='utf-8'))['io_workload']['patterns']
        props = llm_schema.top_level_properties(patterns)
        self.assertEqual(props['io_workload']['properties']['pattern']['enum'], patterns)

    def test_每_task_schema_requires_its_key_so_empty_object_is_invalid(self):
        for task, (required, _) in llm_schema.TASK_KEYS.items():
            schema = llm_schema.build_schema(task, ['seq_write'])
            self.assertEqual(schema['schema']['required'], required, task)
            self.assertTrue(schema['schema']['required'],
                            f'{task}: required 가 비면 {{}} 가 스키마상 정상이 된다')

    def test_generators_can_be_dropped_for_backends_without_nested_anyof(self):
        with_gen = llm_schema.build_schema('new_group_seeds', ['seq_write'], True)
        without = llm_schema.build_schema('new_group_seeds', ['seq_write'], False)
        self.assertIn('generators', with_gen['schema']['properties'])
        self.assertNotIn('generators', without['schema']['properties'])
        self.assertEqual(without['schema']['required'], ['seeds'])


class BackendContract(unittest.TestCase):
    def test_meta_caller_gets_diagnostics_and_meta_is_not_mutated(self):
        from rag import vllm_client
        with FakeServer(lambda p, b: ok_completion('{"seeds": []}')) as srv:
            meta = {'task': 'new_group_seeds', 'req_id': 7,
                    'config': client_cfg(srv.base)}
            before = json.dumps(meta, sort_keys=True)
            out = vllm_client.generate_rag_response('SYS', 'USER', meta)
            self.assertEqual(json.dumps(meta, sort_keys=True), before,
                             '백엔드가 입력 meta 를 수정했다')
        self.assertEqual(out['raw'], '{"seeds": []}')
        self.assertEqual(out['diagnostics']['req_id'], 7)
        self.assertEqual(out['diagnostics']['finish_reason'], 'stop')
        self.assertTrue(out['diagnostics']['schema_enforced'])
        path, body = srv.seen[0]
        self.assertEqual(path, '/v1/chat/completions')
        self.assertEqual([m['role'] for m in body['messages']], ['system', 'user'])
        self.assertEqual(body['response_format']['json_schema']['schema']['required'], ['seeds'])

    def test_legacy_caller_without_meta_still_gets_a_plain_string(self):
        """fuzzer_config.json 은 v10.2 와 공유된다 — 구버전도 이 백엔드를 써야 한다."""
        from rag import vllm_client
        with FakeServer(lambda p, b: ok_completion('{"seeds": []}')) as srv:
            with patch.dict('os.environ', {'RAG_VLLM_BASE_URL': srv.base}):
                out = vllm_client.generate_rag_response('SYS', 'USER')
        self.assertIsInstance(out, str)
        self.assertEqual(out, '{"seeds": []}')

    def test_http_error_body_is_preserved_not_swallowed(self):
        """이번 이관의 발단이 오류 본문을 버려 한 단어만 남은 사고였다."""
        from rag import vllm_client
        detail = {'error': {'code': 'QUERY_TOKEN_LIMIT_EXCEEDED', 'max_tokens': 8192}}
        with FakeServer(lambda p, b: (400, detail)) as srv:
            out = vllm_client.generate_rag_response(
                'S', 'U', {'task': 'new_group_seeds', 'config': client_cfg(srv.base)})
        self.assertEqual(out['raw'], '')
        self.assertIn('QUERY_TOKEN_LIMIT_EXCEEDED', out['error'])
        self.assertIn('HTTP 400', out['error'])

    def test_schema_rejection_does_not_silently_fall_back(self):
        from rag import vllm_client
        calls = []

        def reply(path, body):
            calls.append('response_format' in body)
            return (400, {'error': 'unsupported response_format'})

        with FakeServer(reply) as srv:
            out = vllm_client.generate_rag_response(
                'S', 'U', {'task': 'new_group_seeds', 'config': client_cfg(srv.base)})
        self.assertTrue(out.get('error'), '스키마 거부가 조용히 자유 형식으로 넘어갔다')
        self.assertTrue(all(calls), '설정을 켜지 않았는데 자유 형식으로 재시도했다')

    def test_freeform_retry_only_when_explicitly_enabled(self):
        from rag import vllm_client
        seen = []

        def reply(path, body):
            seen.append('response_format' in body)
            if 'response_format' in body:
                return 400, {'error': 'unsupported'}
            return ok_completion('{"seeds": []}')

        with FakeServer(reply) as srv:
            out = vllm_client.generate_rag_response(
                'S', 'U', {'task': 'new_group_seeds',
                           'config': client_cfg(srv.base, freeform_retry=True, retries=1)})
        self.assertEqual(out['raw'], '{"seeds": []}')
        self.assertEqual(seen, [True, False])
        self.assertIn('schema_rejected', out['diagnostics'])

    def test_truncated_output_is_reported_through_finish_reason(self):
        from rag import vllm_client
        with FakeServer(lambda p, b: ok_completion('{"seeds": [', finish='length')) as srv:
            out = vllm_client.generate_rag_response(
                'S', 'U', {'task': 'new_group_seeds', 'config': client_cfg(srv.base)})
        self.assertEqual(out['diagnostics']['finish_reason'], 'length')


class FuzzerSideNormalization(unittest.TestCase):
    def _llm(self, callable_, pass_system=True):
        cfg = Mock(rag_enabled=True, rag_module_path='x', rag_func_name='f',
                   rag_pass_system=pass_system)
        obj = fuzzer.LlmBridge.__new__(fuzzer.LlmBridge) if hasattr(fuzzer, 'LlmBridge') else None
        return obj, cfg

    def test_dict_and_string_returns_are_both_normalized(self):
        klass = type(harness().llm) if hasattr(harness(), 'llm') else None
        bridge = self._find_bridge_class()
        obj = bridge.__new__(bridge)
        obj._accepts_meta, obj._pass_system = True, True
        obj._callable = lambda s, u, m: {'raw': 'R', 'diagnostics': {'finish_reason': 'stop'}}
        raw, diag = obj._call_llm('s', 'u', {})
        self.assertEqual((raw, diag['finish_reason']), ('R', 'stop'))

        obj._accepts_meta = False
        obj._callable = lambda s, u: 'PLAIN'
        self.assertEqual(obj._call_llm('s', 'u', {}), ('PLAIN', {}))

    def test_backend_reported_error_becomes_an_exception(self):
        bridge = self._find_bridge_class()
        obj = bridge.__new__(bridge)
        obj._accepts_meta, obj._pass_system = True, True
        obj._callable = lambda s, u, m: {'raw': '', 'error': 'HTTP 500 boom'}
        with self.assertRaises(RuntimeError) as ctx:
            obj._call_llm('s', 'u', {})
        self.assertIn('HTTP 500', str(ctx.exception))

    @staticmethod
    def _find_bridge_class():
        for value in vars(fuzzer).values():
            if isinstance(value, type) and '_call_llm' in vars(value):
                return value
        raise AssertionError('_call_llm 을 가진 클래스를 찾지 못했습니다')


class FailureAccounting(unittest.TestCase):
    """'채택 0개'를 실패로 세면 정상 동작 중에 LLM 이 꺼진다."""

    def obj(self):
        o = harness()
        o._llm_fail = fuzzer.NVMeFuzzer._llm_fail.__get__(o)
        o._llm_archive = Mock()
        o.llm = Mock(enabled=True)
        o.config = Mock(rag_module_path='rag.vllm_client')
        return o

    def test_valid_response_with_zero_adoptions_is_not_a_failure(self):
        o = self.obj()
        o._llm_fail_streak = 3
        fuzzer.NVMeFuzzer._llm_apply_result(o, {
            'task': 'new_group_seeds', 'raw': '{"seeds": []}', 'submitted_at': 1,
            'error': None, 'req_id': 1, 'diagnostics': {}})
        self.assertEqual(o._llm_fail_streak, 0, '정상 응답인데 실패로 셌다')
        self.assertEqual(o._llm_funnel['json_ok'], 1)
        self.assertEqual(o._llm_funnel['adopted'], 0)
        self.assertEqual(o._llm_funnel['empty_ok'], 1)
        self.assertTrue(o.llm.enabled)

    def test_repeated_unparsable_responses_do_trip_the_breaker(self):
        """v10.2 는 백엔드가 반환만 하면 파싱 성패와 무관하게 연속 실패를 0 으로 되돌렸다."""
        o = self.obj()
        for _ in range(fuzzer.RAG_FAIL_LIMIT):
            fuzzer.NVMeFuzzer._llm_apply_result(o, {
                'task': 'new_group_seeds', 'raw': 'not json at all',
                'submitted_at': 1, 'error': None, 'req_id': 1, 'diagnostics': {}})
        self.assertGreaterEqual(o._llm_fail_streak, fuzzer.RAG_FAIL_LIMIT)
        self.assertFalse(o.llm.enabled, '무효 응답이 반복돼도 서킷브레이커가 안 걸렸다')

    def test_transport_failure_counts_and_names_the_backend(self):
        o = self.obj()
        fuzzer.NVMeFuzzer._llm_apply_result(o, {
            'task': 'new_group_seeds', 'raw': None, 'submitted_at': 1,
            'error': '연결 실패', 'req_id': 1,
            'diagnostics': {'backend': 'vllm', 'base_url': 'http://x/v1'}})
        self.assertEqual(o._llm_fail_streak, 1)
        self.assertEqual(o._llm_funnel['transport_ok'], 0)


class RetrievalQueryLadder(unittest.TestCase):
    def test_meta_query_wins_then_prompt_block_then_skip(self):
        from rag import rag_retrieval as rr
        self.assertEqual(rr.query_from({'rag_query': 'A B'}, 'x', 100), ('A B', 'meta'))
        self.assertEqual(rr.query_from({}, 'pre [RAG-QUERY] C D [/RAG-QUERY] post', 100),
                         ('C D', 'prompt_block'))
        self.assertEqual(rr.query_from({}, 'a very long prompt with no marker', 100),
                         (None, 'no_query'))

    def test_no_tokenizer_dependency_is_imported(self):
        """퍼징 PC 에 transformers/sentencepiece 를 다시 들이지 않는다."""
        for name in ('rag/rag_retrieval.py', 'rag/vllm_client.py', 'rag/llm_schema.py',
                     'tools/rag_ingest.py'):
            text = (ROOT / name).read_text(encoding='utf-8')
            tree = ast.parse(text)
            for node in ast.walk(tree):
                mods = []
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    mods = [node.module or '']
                for m in mods:
                    self.assertFalse(m.split('.')[0] in ('transformers', 'sentencepiece',
                                                         'tokenizers', 'torch'),
                                     f'{name} 이 {m} 을 import 한다')


class IngestIndex(unittest.TestCase):
    def setUp(self):
        spec = __import__('importlib.util', fromlist=['util']).spec_from_file_location(
            'rag_ingest', ROOT / 'tools/rag_ingest.py')
        self.mod = __import__('importlib.util', fromlist=['util']).module_from_spec(spec)
        spec.loader.exec_module(self.mod)

    def jsonl(self, d, rows):
        p = Path(d) / 'docs.jsonl'
        p.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows),
                     encoding='utf-8')
        return str(p)

    def test_long_records_are_split_under_the_char_limit(self):
        row = {'doc_id': 'd1', 'title': 't', 'content': 'x' * 25000,
               'permission_groups': ['rag-public']}
        pieces = self.mod.split_record(row, 6000)
        self.assertTrue(len(pieces) >= 5)
        self.assertTrue(all(len(p) <= 6000 for p in pieces))
        self.assertEqual(''.join(pieces), row['content'])

    def test_pointer_swap_publishes_only_a_verified_index(self):
        with tempfile.TemporaryDirectory() as d:
            src = self.jsonl(d, [{'doc_id': 'a', 'title': 'A', 'content': 'hello',
                                  'permission_groups': ['rag-public']}])
            index = Path(d) / 'index'
            with FakeServer(lambda p, b: (200, {'data': [
                    {'index': i, 'embedding': [0.1, 0.2, 0.3]}
                    for i in range(len(b['input']))]})) as srv:
                self.mod.main([src, '--index-dir', str(index),
                               '--embed-base-url', srv.base])
            version = (index / 'current').read_text().strip()
            self.assertTrue((index / version / 'vectors.f16.npy').is_file())
            manifest = json.loads((index / version / 'manifest.json').read_text())
            self.assertEqual(manifest['normalization'], 'l2')
            self.assertEqual(manifest['dim'], 3)
            self.assertIn('토큰 수 보장이 아니다', manifest['note'])
            self.assertFalse(list(index.glob('*.staging')), 'staging 이 남았다')

    def test_embedding_failure_publishes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            src = self.jsonl(d, [{'doc_id': 'a', 'title': 'A', 'content': 'hello',
                                  'permission_groups': []}])
            index = Path(d) / 'index'
            with FakeServer(lambda p, b: (500, {'error': 'boom'})) as srv:
                with self.assertRaises(Exception):
                    self.mod.main([src, '--index-dir', str(index),
                                   '--embed-base-url', srv.base])
            self.assertFalse((index / 'current').exists(),
                             '임베딩이 실패했는데 인덱스가 게시됐다')
            self.assertFalse(list(index.glob('v*')), '불완전한 버전이 남았다')

    def test_second_run_reuses_vectors_for_unchanged_sources(self):
        with tempfile.TemporaryDirectory() as d:
            src = self.jsonl(d, [{'doc_id': 'a', 'title': 'A', 'content': 'hello',
                                  'permission_groups': []}])
            index = Path(d) / 'index'
            calls = []

            def reply(path, body):
                calls.append(len(body['input']))
                return 200, {'data': [{'index': i, 'embedding': [1.0, 0.0]}
                                      for i in range(len(body['input']))]}

            with FakeServer(reply) as srv:
                self.mod.main([src, '--index-dir', str(index), '--embed-base-url', srv.base])
                first = (index / 'current').read_text().strip()
                self.mod.main([src, '--index-dir', str(index), '--embed-base-url', srv.base])
                second = (index / 'current').read_text().strip()
            self.assertNotEqual(first, second, '새 버전이 만들어지지 않았다')
            self.assertTrue((index / first).is_dir(), '이전 버전을 지웠다 — 캠페인이 쓰고 있을 수 있다')
            self.assertEqual(len(calls), 1, '변경 없는 소스를 다시 임베딩했다')


if __name__ == '__main__':
    unittest.main()
