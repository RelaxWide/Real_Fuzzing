"""v10.3 LLM 백엔드 이관 시험. NVMe/JTAG 조작 없음, DGX 서버 없이 돈다.

계획(docs/V10_3_LLM_BACKEND_PLAN.md §6 착수 전 통과 조건)의 항목을 시험으로 옮긴 것.
"""
import ast
import json
import logging
import queue
import re
import shutil
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

from test_v10_2_learning import ROOT, FUZZER_FILE, add_target, fuzzer, harness, recipe

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


# ── 리뷰 반영 회귀 시험 ────────────────────────────────────────────────────
class DiagnosticsBelongToTheirRequest(unittest.TestCase):
    """_diag 는 워커 루프를 가로질러 사는 지역변수였다. 초기화하지 않으면
    실패한 요청에 **직전 요청의** req_id·finish_reason 이 붙는다."""

    def bridge(self, callable_):
        klass = FuzzerSideNormalization._find_bridge_class()
        obj = klass.__new__(klass)
        obj._accepts_meta, obj._pass_system = True, True
        obj._callable = callable_
        obj._in_q, obj._out_q = queue.Queue(), queue.Queue()
        obj._stop = threading.Event()
        obj._inflight = False
        return obj

    def drive(self, obj, requests):
        for r in requests:
            obj._in_q.put(r)
        worker = threading.Thread(target=obj._run, daemon=True)
        worker.start()
        try:
            return [obj._out_q.get(timeout=10) for _ in requests]
        finally:
            obj._stop.set()
            worker.join(timeout=5)

    @staticmethod
    def req(n):
        return {'task': 'new_group_seeds', 'system': 's', 'user': 'u',
                'submitted_at': 0, 'ctx': None, 'req_id': n, 'meta': {}}

    def test_failure_after_a_success_does_not_inherit_the_previous_diagnostics(self):
        def backend(system, user, meta):
            if meta['req_id'] == 1:
                return {'raw': '{"seeds": []}',
                        'diagnostics': {'req_id': 1, 'finish_reason': 'stop'}}
            raise fuzzer._LlmBackendFailure('연결 실패', {'req_id': 2, 'base_url': 'http://x/v1'})

        out = self.drive(self.bridge(backend), [self.req(1), self.req(2)])
        self.assertIsNone(out[0]['error'])
        self.assertEqual(out[0]['diagnostics']['req_id'], 1)
        self.assertEqual(out[1]['diagnostics'].get('req_id'), 2,
                         '실패한 요청에 직전 요청의 진단이 붙었다')
        self.assertNotEqual(out[1]['diagnostics'].get('finish_reason'), 'stop')

    def test_first_request_failing_carries_the_backend_diagnostics(self):
        def backend(system, user, meta):
            raise fuzzer._LlmBackendFailure('HTTP 500 boom',
                                            {'backend': 'vllm', 'base_url': 'http://y/v1'})

        out = self.drive(self.bridge(backend), [self.req(1)])
        self.assertEqual(out[0]['diagnostics'].get('base_url'), 'http://y/v1',
                         '백엔드가 준 진단을 버렸다')

    def test_backend_error_dict_keeps_its_diagnostics_through_call_llm(self):
        klass = FuzzerSideNormalization._find_bridge_class()
        obj = klass.__new__(klass)
        obj._accepts_meta, obj._pass_system = True, True
        obj._callable = lambda s, u, m: {'raw': '', 'error': 'HTTP 500',
                                         'diagnostics': {'base_url': 'http://z/v1'}}
        with self.assertRaises(RuntimeError) as ctx:
            obj._call_llm('s', 'u', {})
        self.assertEqual(getattr(ctx.exception, 'diagnostics', {}).get('base_url'),
                         'http://z/v1')

    def test_correction_call_failure_is_attributed_as_a_correction(self):
        calls = []

        def backend(system, user, meta):
            calls.append(user)
            if len(calls) == 1:
                return {'raw': 'not json', 'diagnostics': {'req_id': 1,
                                                           'finish_reason': 'stop'}}
            raise fuzzer._LlmBackendFailure('교정 중 연결 끊김', {'stage': 'correction'})

        out = self.drive(self.bridge(backend), [self.req(1)])
        self.assertGreaterEqual(len(calls), 2, '교정 호출이 일어나지 않았다')
        diag = out[0]['diagnostics']
        self.assertEqual(diag.get('req_id'), 1)
        self.assertEqual(diag.get('correction', {}).get('stage'), 'correction')

    def test_final_finish_reason_prefers_the_correction_call(self):
        self.assertEqual(fuzzer._llm_final_finish_reason(
            {'finish_reason': 'stop', 'correction': {'finish_reason': 'length'}}), 'length')
        self.assertEqual(fuzzer._llm_final_finish_reason({'finish_reason': 'stop'}), 'stop')
        self.assertIsNone(fuzzer._llm_final_finish_reason(None))


class TimeBudget(unittest.TestCase):
    """urlopen(timeout=) 은 소켓 연산별 상한이라 총 경과 시간을 막지 못한다."""

    class _Trickle(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            raw = json.dumps(ok_completion('{"seeds": []}')[1]).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            for i in range(0, len(raw), 16):      # 조금씩 흘려보낸다
                try:
                    self.wfile.write(raw[i:i + 16])
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    return
                time.sleep(0.05)

    def test_slow_dribbling_response_is_discarded_not_returned(self):
        httpd = HTTPServer(('127.0.0.1', 0), self._Trickle)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = f'http://127.0.0.1:{httpd.server_port}/v1'
        try:
            from rag import vllm_client
            started = time.monotonic()
            out = vllm_client.generate_rag_response(
                's', 'u', {'task': 'new_group_seeds',
                           'config': client_cfg(base, timeout_sec=0.2)})
            elapsed = time.monotonic() - started
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertTrue(out.get('error'), '예산을 넘긴 응답이 성공으로 돌아왔다')
        self.assertIn('예산', out['error'])
        self.assertLess(elapsed, 2.0, f'예산을 한참 넘겨서야 끝났다 ({elapsed:.2f}s)')

    def test_correction_calls_share_one_budget_with_the_first_call(self):
        """budget_started 를 주면 최초 호출과 교정 호출이 예산을 나눠 쓴다."""
        with FakeServer(lambda p, b: ok_completion('{"seeds": []}')) as srv:
            from rag import vllm_client
            cfg = client_cfg(srv.base, timeout_sec=30.0)
            spent = time.monotonic() - 29.5        # 예산이 0.5초만 남은 상태
            out = vllm_client.generate_rag_response(
                's', 'u', {'task': 'new_group_seeds', 'config': cfg,
                           'budget_started': spent})
            self.assertIn('raw', out)
            drained = time.monotonic() - 100.0     # 예산이 이미 소진된 상태
            out2 = vllm_client.generate_rag_response(
                's', 'u', {'task': 'new_group_seeds', 'config': cfg,
                           'budget_started': drained})
        self.assertTrue(out2.get('error'), '소진된 예산으로도 요청을 보냈다')
        self.assertIn('예산', out2['error'])

    def test_worker_stamps_one_budget_start_shared_by_the_correction_call(self):
        """최초 호출과 교정 호출이 **같은** budget_started 를 받아야 한다."""
        seen = []

        def backend(system, user, meta):
            seen.append(meta.get('budget_started'))
            return {'raw': 'still not json' if len(seen) <= fuzzer.RAG_JSON_RETRIES
                    else '{"seeds": []}', 'diagnostics': {}}

        driver = DiagnosticsBelongToTheirRequest()
        obj = driver.bridge(backend)
        driver.drive(obj, [driver.req(1)])
        self.assertGreaterEqual(len(seen), 2, '교정 호출이 일어나지 않았다')
        self.assertTrue(all(isinstance(v, float) for v in seen), 'budget_started 가 없다')
        self.assertEqual(len(set(seen)), 1,
                         '교정 호출이 새 예산을 받았다 — 요청 하나가 timeout_sec 의 '
                         '몇 배를 붙들 수 있다')


class TaskAwareFailureAccounting(unittest.TestCase):
    """잘림·잘못된 task·잘못된 타입은 실패다. 정상 빈 결과·중복은 아니다."""

    def obj(self):
        o = harness()
        o._llm_fail = fuzzer.NVMeFuzzer._llm_fail.__get__(o)
        o._llm_archive = Mock()
        o.llm = Mock(enabled=True)
        o.config = Mock(rag_module_path='rag.vllm_client')
        o._llm_fail_streak = 0
        return o

    def apply(self, o, raw, task='new_group_seeds', diagnostics=None):
        fuzzer.NVMeFuzzer._llm_apply_result(o, {
            'task': task, 'raw': raw, 'submitted_at': 1, 'error': None,
            'req_id': 1, 'diagnostics': diagnostics or {}})

    def test_truncated_but_parsable_response_is_a_failure(self):
        o = self.obj()
        self.apply(o, '{"seeds": []}', diagnostics={'finish_reason': 'length'})
        self.assertEqual(o._llm_fail_streak, 1, '잘린 응답이 정상으로 집계됐다')
        self.assertEqual(o._llm_funnel['json_ok'], 0)

    def test_truncation_in_the_correction_call_is_also_caught(self):
        o = self.obj()
        self.apply(o, '{"seeds": []}',
                   diagnostics={'finish_reason': 'stop',
                                'correction': {'finish_reason': 'length'}})
        self.assertEqual(o._llm_fail_streak, 1, '교정 호출의 잘림을 놓쳤다')

    def test_response_for_a_different_task_is_a_failure(self):
        o = self.obj()
        self.apply(o, '{"evaluations": []}', task='new_group_seeds')
        self.assertEqual(o._llm_fail_streak, 1, '엉뚱한 task 컨테이너가 통과했다')

    def test_wrong_container_type_is_a_failure(self):
        o = self.obj()
        self.apply(o, '{"seeds": "bad"}')
        self.assertEqual(o._llm_fail_streak, 1,
                         '학습 모듈이 빈 배열로 정규화해 조용히 0개 주입이 됐다')

    def test_io_patterns_expects_an_object_not_a_list(self):
        o = self.obj()
        self.apply(o, '{"io_workload": []}', task='io_patterns')
        self.assertEqual(o._llm_fail_streak, 1)

    def test_a_genuinely_empty_but_correct_response_still_resets_the_streak(self):
        o = self.obj()
        o._llm_fail_streak = 3
        self.apply(o, '{"seeds": []}', diagnostics={'finish_reason': 'stop'})
        self.assertEqual(o._llm_fail_streak, 0, '정상 빈 응답을 실패로 셌다')
        self.assertTrue(o.llm.enabled)

    def test_repeated_wrong_task_responses_trip_the_breaker(self):
        o = self.obj()
        for _ in range(fuzzer.RAG_FAIL_LIMIT):
            self.apply(o, '{"evaluations": []}', task='new_group_seeds')
        self.assertFalse(o.llm.enabled, '무효 응답이 반복돼도 서킷브레이커가 안 걸렸다')


class FunnelCountsEveryKindOfAdoption(unittest.TestCase):
    """seed·sequence 만 세면 정상 적용된 corpus_eval·io_patterns 가 '정상0건' 이 된다."""

    def test_applied_workload_counts_as_an_adoption(self):
        o = harness()
        o._llm_fail = Mock()
        o._llm_archive = Mock()
        o.llm = Mock(enabled=True)
        o.config = Mock(rag_module_path='rag.vllm_client')
        pattern = sorted(fuzzer.IO_WL_PATTERNS)[0]
        fuzzer.NVMeFuzzer._llm_apply_result(o, {
            'task': 'io_patterns', 'submitted_at': 1, 'error': None, 'req_id': 1,
            'raw': json.dumps({'io_workload': {'pattern': pattern}}),
            'diagnostics': {'finish_reason': 'stop'}})
        self.assertEqual(o._llm_funnel['workloads'], 1)
        self.assertEqual(o._llm_funnel['adopted'], 1, '적용된 워크로드를 채택으로 안 셌다')
        self.assertEqual(o._llm_funnel['empty_ok'], 0, '정상 적용을 정상0건으로 셌다')


class RagQueryUsesTheRequestsOwnCommands(unittest.TestCase):
    def test_ctx_commands_are_preferred_over_the_generic_gap_list(self):
        o = fuzzer.NVMeFuzzer.__new__(fuzzer.NVMeFuzzer)
        o.learning = Mock(targets={})
        o._llm_gap_cmds = lambda: ['GenericA', 'GenericB']
        q = fuzzer.NVMeFuzzer._llm_rag_query(
            o, 'new_group_seeds', {'rag_query_commands': ['FWCommit', 'Sanitize']})
        self.assertIn('FWCommit', q)
        self.assertNotIn('GenericA', q, '요청이 겨냥한 명령 대신 일반 목록을 썼다')

    def test_falls_back_to_the_gap_list_when_ctx_has_none(self):
        o = fuzzer.NVMeFuzzer.__new__(fuzzer.NVMeFuzzer)
        o.learning = Mock(targets={})
        o._llm_gap_cmds = lambda: ['GenericA']
        self.assertIn('GenericA', fuzzer.NVMeFuzzer._llm_rag_query(o, 'sequences', {}))


class IndexIntegrity(unittest.TestCase):
    def setUp(self):
        spec = __import__('importlib.util', fromlist=['util']).spec_from_file_location(
            'rag_ingest_integrity', ROOT / 'tools/rag_ingest.py')
        self.mod = __import__('importlib.util', fromlist=['util']).module_from_spec(spec)
        spec.loader.exec_module(self.mod)

    def jsonl(self, d, rows, name='docs.jsonl'):
        p = Path(d) / name
        p.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows),
                     encoding='utf-8')
        return str(p)

    @staticmethod
    def _load(index):
        version = (index / 'current').read_text().strip()
        chunks = [json.loads(l) for l in
                  (index / version / 'chunks.jsonl').read_text().splitlines() if l.strip()]
        import numpy as np
        return chunks, np.load(index / version / 'vectors.f16.npy'), \
            json.loads((index / version / 'manifest.json').read_text())

    def test_oversize_chunk_is_split_so_no_text_loses_its_vector(self):
        """앞부분만 임베딩하고 원문을 그대로 저장하면 뒷부분이 검색에 영영 안 걸린다."""
        with tempfile.TemporaryDirectory() as d:
            body = ('alpha ' * 100) + ('omega ' * 100)
            src = self.jsonl(d, [{'doc_id': 'a', 'title': 'A', 'content': body,
                                  'permission_groups': []}])
            index = Path(d) / 'index'
            state = {'rejected': False}

            def reply(path, body_json):
                texts = body_json['input']
                if not state['rejected'] and any(len(t) > 600 for t in texts):
                    state['rejected'] = True
                    return 400, {'error': {'code': 'QUERY_TOKEN_LIMIT_EXCEEDED'}}
                return 200, {'data': [{'index': i, 'embedding': [1.0, 0.0]}
                                      for i in range(len(texts))]}

            with FakeServer(reply) as srv:
                self.mod.main([src, '--index-dir', str(index),
                               '--embed-base-url', srv.base, '--max-chars', '100000'])
            chunks, vectors, _ = self._load(index)
            self.assertTrue(state['rejected'], '상한 초과 경로를 타지 않았다')
            self.assertEqual(len(chunks), vectors.shape[0], '본문과 벡터 수가 어긋났다')
            self.assertEqual(''.join(c['content'] for c in chunks).replace(' ', ''),
                             body.replace(' ', ''), '분할에서 본문 일부가 사라졌다')
            self.assertEqual(len({c['doc_id'] for c in chunks}), len(chunks))

    def test_unsplittable_chunk_publishes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            src = self.jsonl(d, [{'doc_id': 'a', 'title': 'A', 'content': 'tiny',
                                  'permission_groups': []}])
            index = Path(d) / 'index'
            with FakeServer(lambda p, b: (400, {'error': 'maximum context length'})) as srv:
                with self.assertRaises((SystemExit, ValueError, Exception)):
                    self.mod.main([src, '--index-dir', str(index),
                                   '--embed-base-url', srv.base])
            self.assertFalse((index / 'current').exists(), '불완전한 인덱스를 게시했다')

    def test_changing_chunk_size_reembeds_instead_of_reusing_other_text(self):
        """재사용 키에 본문이 없으면 같은 doc_id 에 예전 본문의 벡터가 붙는다."""
        with tempfile.TemporaryDirectory() as d:
            src = self.jsonl(d, [{'doc_id': 'a', 'title': 'A',
                                  'content': 'abcdefghijkl', 'permission_groups': []}])
            index = Path(d) / 'index'
            seen = []

            def reply(path, body):
                seen.append(list(body['input']))
                return 200, {'data': [{'index': i, 'embedding': [float(len(t)), 1.0]}
                                      for i, t in enumerate(body['input'])]}

            with FakeServer(reply) as srv:
                self.mod.main([src, '--index-dir', str(index),
                               '--embed-base-url', srv.base, '--max-chars', '6'])
                seen.clear()
                self.mod.main([src, '--index-dir', str(index),
                               '--embed-base-url', srv.base, '--max-chars', '4'])
            embedded = [t for call in seen for t in call]
            chunks, _, manifest = self._load(index)
            self.assertEqual(manifest['chunk_max_chars'], 4)
            self.assertEqual(sorted(c['content'] for c in chunks), ['abcd', 'efgh', 'ijkl'])
            self.assertEqual(sorted(embedded), ['abcd', 'efgh', 'ijkl'],
                             '분할이 바뀌었는데 예전 본문의 벡터를 재사용했다')

    def test_changing_model_revision_forces_reembedding(self):
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
                self.mod.main([src, '--index-dir', str(index), '--embed-base-url', srv.base,
                               '--embed-model-revision', 'r1'])
                calls.clear()
                self.mod.main([src, '--index-dir', str(index), '--embed-base-url', srv.base,
                               '--embed-model-revision', 'r2'])
            _, _, manifest = self._load(index)
            self.assertEqual(manifest['embed_model_revision'], 'r2')
            self.assertEqual(len(calls), 1, 'revision 이 바뀌었는데 벡터를 재사용했다')

    def test_duplicate_doc_ids_across_sources_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            a = self.jsonl(d, [{'doc_id': 'dup', 'title': 'A', 'content': 'one',
                                'permission_groups': []}], name='a.jsonl')
            b = self.jsonl(d, [{'doc_id': 'dup', 'title': 'B', 'content': 'two',
                                'permission_groups': []}], name='b.jsonl')
            index = Path(d) / 'index'
            with FakeServer(lambda p, body: (200, {'data': [
                    {'index': i, 'embedding': [1.0, 0.0]}
                    for i in range(len(body['input']))]})) as srv:
                with self.assertRaises(SystemExit):
                    self.mod.main([a, b, '--index-dir', str(index),
                                   '--embed-base-url', srv.base])
            self.assertFalse((index / 'current').exists())

    def test_zero_vectors_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            src = self.jsonl(d, [{'doc_id': 'a', 'title': 'A', 'content': 'hello',
                                  'permission_groups': []}])
            index = Path(d) / 'index'
            with FakeServer(lambda p, body: (200, {'data': [
                    {'index': i, 'embedding': [0.0, 0.0]}
                    for i in range(len(body['input']))]})) as srv:
                with self.assertRaises(SystemExit):
                    self.mod.main([src, '--index-dir', str(index),
                                   '--embed-base-url', srv.base])
            self.assertFalse((index / 'current').exists())

    def test_a_second_concurrent_ingest_is_refused_by_the_lock(self):
        with tempfile.TemporaryDirectory() as d:
            src = self.jsonl(d, [{'doc_id': 'a', 'title': 'A', 'content': 'hello',
                                  'permission_groups': []}])
            index = Path(d) / 'index'
            index.mkdir(parents=True)
            (index / '.ingest.lock').write_text('999999\n', encoding='utf-8')
            with self.assertRaises(SystemExit):
                self.mod.main([src, '--index-dir', str(index),
                               '--embed-base-url', 'http://127.0.0.1:1/v1'])

    def test_retrieval_refuses_an_index_built_with_another_model(self):
        from rag import rag_retrieval as rr
        with tempfile.TemporaryDirectory() as d:
            index = Path(d) / 'index'
            (index / 'v1').mkdir(parents=True)
            (index / 'current').write_text('v1', encoding='utf-8')
            (index / 'v1' / 'chunks.jsonl').write_text(
                json.dumps({'doc_id': 'a', 'title': 'A', 'content': 'x',
                            'permission_groups': []}) + '\n', encoding='utf-8')
            (index / 'v1' / 'manifest.json').write_text(
                json.dumps({'embed_model': 'other-model'}), encoding='utf-8')
            import numpy as np
            np.save(index / 'v1' / 'vectors.f16.npy',
                    np.ones((1, 2), dtype=np.float16))
            rr._PINNED.clear()
            cfg = {'base_url': 'http://127.0.0.1:1/v1', 'timeout_sec': 1.0,
                   'max_response_bytes': 1 << 20, 'api_key': 'x',
                   'retrieval': {'enabled': True, 'index_dir': str(index),
                                 'embed_model': 'bge-m3'}}
            with self.assertRaises(ValueError) as ctx:
                rr.retrieve({'rag_query': 'q'}, cfg, time.monotonic() + 5)
            self.assertIn('모델 불일치', str(ctx.exception))
            rr._PINNED.clear()


class SlowHttpErrorBodyRespectsTheBudget(unittest.TestCase):
    """오류 본문만 예산 밖에서 읽으면 느린 4xx/5xx 가 예산을 통째로 우회한다."""

    class _SlowError(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            raw = json.dumps({'error': {'code': 'BOOM', 'detail': 'x' * 400}}).encode()
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            for i in range(0, len(raw), 8):
                try:
                    self.wfile.write(raw[i:i + 8])
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    return
                time.sleep(0.05)

    def test_error_body_read_stops_inside_the_budget(self):
        httpd = HTTPServer(('127.0.0.1', 0), self._SlowError)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = f'http://127.0.0.1:{httpd.server_port}/v1'
        try:
            from rag import vllm_client
            started = time.monotonic()
            out = vllm_client.generate_rag_response(
                's', 'u', {'task': 'new_group_seeds',
                           'config': client_cfg(base, timeout_sec=0.2)})
            elapsed = time.monotonic() - started
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertTrue(out.get('error'))
        self.assertLess(elapsed, 2.0,
                        f'오류 본문을 끝까지 기다렸다 ({elapsed:.2f}s) — 예산을 우회했다')
        self.assertIn('HTTP 500', out['error'], 'HTTP 상태를 잃었다')


class RejectedResponsesLeaveNoLearningState(unittest.TestCase):
    """폐기한 응답이 generator 저장소를 채우면 이후 정상 규칙이 capacity 로 거절된다."""

    def obj(self):
        o = harness({'generators': True, 'evidence': True})
        o._llm_fail = Mock()
        o._llm_archive = Mock()
        o.llm = Mock(enabled=True, schema_bridge=harness().llm.schema_bridge)
        o.config = Mock(rag_module_path='rag.vllm_client')
        return o

    def apply(self, o, payload, task='new_group_seeds', diagnostics=None):
        ctx = {'learning_targets': list(o.learning.targets)[:3]}
        o._llm_apply_result({'task': task, 'raw': json.dumps(payload), 'ctx': ctx,
                             'submitted_at': 1, 'error': None, 'req_id': 1,
                             'llm_seconds': 0.1, 'diagnostics': diagnostics or {}})

    def test_truncated_response_registers_no_generator(self):
        o = self.obj()
        self.apply(o, {'generators': [recipe()]},
                   diagnostics={'finish_reason': 'length'})
        self.assertEqual(len(o.corpus), 0)
        self.assertEqual(len(o.learning.generators), 0,
                         '폐기한 응답이 generator 저장소를 바꿨다')

    def test_wrong_task_response_does_not_bump_target_counters(self):
        o = self.obj()
        for i in range(3):
            add_target(o, entry=100 + i * 10, end=105 + i * 10)
        selected_before = sum(t.get('selected', 0) for t in o.learning.targets.values())
        self.apply(o, {'evaluations': []}, task='new_group_seeds')
        selected_after = sum(t.get('selected', 0) for t in o.learning.targets.values())
        self.assertEqual(selected_after, selected_before,
                         '폐기한 응답이 목표 통계를 올렸다')
        self.assertEqual(len(o.learning.generators), 0)

    def test_a_valid_generator_response_still_registers(self):
        """거부 검사가 정상 경로까지 막지는 않는지."""
        o = self.obj()
        self.apply(o, {'generators': [recipe()]}, diagnostics={'finish_reason': 'stop'})
        self.assertGreater(len(o.corpus), 0, '정상 generator 응답이 막혔다')


class RevisionMismatchIsRefused(unittest.TestCase):
    def index(self, d, manifest):
        index = Path(d) / 'index'
        (index / 'v1').mkdir(parents=True)
        (index / 'current').write_text('v1', encoding='utf-8')
        (index / 'v1' / 'chunks.jsonl').write_text(
            json.dumps({'doc_id': 'a', 'title': 'A', 'content': 'x',
                        'permission_groups': []}) + '\n', encoding='utf-8')
        (index / 'v1' / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
        import numpy as np
        np.save(index / 'v1' / 'vectors.f16.npy', np.ones((1, 2), dtype=np.float16))
        return index

    def retrieve(self, index, want_rev):
        from rag import rag_retrieval as rr
        rr._PINNED.clear()
        cfg = {'base_url': 'http://127.0.0.1:1/v1', 'timeout_sec': 1.0,
               'max_response_bytes': 1 << 20, 'api_key': 'x',
               'retrieval': {'enabled': True, 'index_dir': str(index),
                             'embed_model': 'bge-m3', 'embed_model_revision': want_rev}}
        try:
            return rr.retrieve({'rag_query': 'q'}, cfg, time.monotonic() + 5)
        finally:
            rr._PINNED.clear()

    def test_missing_revision_in_manifest_is_a_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            index = self.index(d, {'embed_model': 'bge-m3'})
            with self.assertRaises(ValueError) as ctx:
                self.retrieve(index, 'r2')
            self.assertIn('revision', str(ctx.exception))

    def test_null_revision_in_manifest_is_a_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            index = self.index(d, {'embed_model': 'bge-m3', 'embed_model_revision': None})
            with self.assertRaises(ValueError):
                self.retrieve(index, 'r2')

    def test_differing_revision_is_a_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            index = self.index(d, {'embed_model': 'bge-m3', 'embed_model_revision': 'r1'})
            with self.assertRaises(ValueError):
                self.retrieve(index, 'r2')

    def test_no_declared_revision_keeps_older_indexes_usable(self):
        """설정이 revision 을 요구하지 않으면 예전 인덱스는 그대로 쓴다."""
        with tempfile.TemporaryDirectory() as d:
            index = self.index(d, {'embed_model': 'bge-m3'})
            with self.assertRaises(Exception) as ctx:
                self.retrieve(index, None)
            self.assertNotIn('revision', str(ctx.exception))   # 임베딩 연결 실패여야 한다


class ErrorBodySurvivesAStalledServer(unittest.TestCase):
    """read1 안에서 소켓 타임아웃이 터져도 받은 본문과 중단 사유를 잃으면 안 된다."""

    PARTIAL = b'{"error":"IMPORTANT_REASON"'

    class _Stall(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', '4000')     # 약속만 하고 안 보낸다
            self.end_headers()
            try:
                self.wfile.write(ErrorBodySurvivesAStalledServer.PARTIAL)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return
            for _ in range(40):                            # 그대로 멈춘다
                if getattr(self.server, 'done', False):
                    return
                time.sleep(0.1)

    def test_partial_body_and_the_stop_reason_are_both_reported(self):
        httpd = HTTPServer(('127.0.0.1', 0), self._Stall)
        httpd.done = False
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = f'http://127.0.0.1:{httpd.server_port}/v1'
        try:
            from rag import vllm_client
            started = time.monotonic()
            out = vllm_client.generate_rag_response(
                's', 'u', {'task': 'new_group_seeds',
                           'config': client_cfg(base, timeout_sec=0.3)})
            elapsed = time.monotonic() - started
        finally:
            httpd.done = True
            httpd.shutdown()
            httpd.server_close()
        err = out.get('error') or ''
        self.assertIn('HTTP 500', err, 'HTTP 상태를 잃었다')
        self.assertIn('IMPORTANT_REASON', err, '받은 오류 본문을 잃었다')
        self.assertIn('예산', err, '왜 잘렸는지가 사라졌다')
        self.assertLess(elapsed, 3.0, f'멈춘 서버를 계속 기다렸다 ({elapsed:.2f}s)')

    def test_socket_is_found_through_the_httperror_wrapper(self):
        """HTTPError 는 실제 HTTPResponse 를 한 겹 감싼다 — 한 단계만 보면 놓친다."""
        from rag import vllm_client
        with FakeServer(lambda p, b: (500, {'error': 'x'})) as srv:
            import urllib.error, urllib.request
            req = urllib.request.Request(srv.base + '/chat/completions', data=b'{}',
                                         method='POST',
                                         headers={'Content-Type': 'application/json'})
            try:
                urllib.request.urlopen(req, timeout=5)
                self.fail('500 이 안 났다')
            except urllib.error.HTTPError as exc:
                self.assertIsNotNone(vllm_client._sock_of(exc),
                                     'HTTPError 에서 소켓을 못 찾아 읽기별 갱신을 건너뛴다')

    def test_read_bounded_returns_partial_and_reason_on_read_failure(self):
        from rag import vllm_client

        class Boom:
            def read1(self, n):
                if not getattr(self, 'hit', False):
                    self.hit = True
                    return b'HEAD'
                raise TimeoutError('timed out')

        body, stopped = vllm_client._read_bounded(
            Boom(), 4096, time.monotonic() + 30, 'u', '오류 본문', partial_ok=True)
        self.assertEqual(body, b'HEAD', '읽기 예외에 이미 모은 조각을 잃었다')
        self.assertIn('수신 실패', stopped)
        with self.assertRaises(Exception):
            vllm_client._read_bounded(Boom(), 4096, time.monotonic() + 30, 'u')


class LegacyCallerCanStillUseTheQueryBlock(unittest.TestCase):
    """meta 없는 호출도 프롬프트의 [RAG-QUERY] 로 질의를 만들 수 있어야 한다."""

    def test_user_prompt_defaults_to_the_user_message(self):
        from rag import vllm_client, rag_retrieval
        seen = {}

        def spy(meta, cfg, deadline):
            seen['meta'] = dict(meta)
            return '', {'enabled': False}

        user = 'body [RAG-QUERY] FWCommit Sanitize [/RAG-QUERY] tail'
        with FakeServer(lambda p, b: ok_completion('{"seeds": []}')) as srv:
            with patch.object(rag_retrieval, 'retrieve', spy):
                with patch.object(vllm_client, '_config',
                                  lambda m: dict(vllm_client.DEFAULTS,
                                                 base_url=srv.base, retries=0,
                                                 timeout_sec=10.0)):
                    vllm_client.generate_rag_response('sys', user)      # meta 없음
        self.assertIn('meta', seen, '검색 함수가 호출되지 않았다')
        self.assertEqual(seen['meta'].get('user_prompt'), user)
        self.assertEqual(
            rag_retrieval.query_from(seen['meta'], seen['meta'].get('user_prompt', ''), 100),
            ('FWCommit Sanitize', 'prompt_block'))


class IngestTakesEndpointsFromTheConfig(unittest.TestCase):
    """색인할 때와 검색할 때의 임베딩 서버·모델이 같아야 한다 — 설정이 단일 출처다."""

    def setUp(self):
        spec = __import__('importlib.util', fromlist=['util']).spec_from_file_location(
            'rag_ingest_cfg', ROOT / 'tools/rag_ingest.py')
        self.mod = __import__('importlib.util', fromlist=['util']).module_from_spec(spec)
        spec.loader.exec_module(self.mod)

    def jsonl(self, d):
        p = Path(d) / 'docs.jsonl'
        p.write_text(json.dumps({'doc_id': 'a', 'title': 'A', 'content': 'hello',
                                 'permission_groups': []}) + '\n', encoding='utf-8')
        return str(p)

    def config(self, d, **retrieval):
        p = Path(d) / 'cfg.json'
        p.write_text(json.dumps({'rag': {'vllm': {'retrieval': retrieval}}}),
                     encoding='utf-8')
        return str(p)

    @staticmethod
    def embed_reply(seen):
        def reply(path, body):
            seen.append((path, body.get('model')))
            return 200, {'data': [{'index': i, 'embedding': [1.0, 0.0]}
                                  for i in range(len(body['input']))]}
        return reply

    def test_endpoint_and_model_come_from_the_config_when_not_given(self):
        with tempfile.TemporaryDirectory() as d:
            seen = []
            with FakeServer(self.embed_reply(seen)) as srv:
                cfg = self.config(d, embed_base_url=srv.base, embed_model='bge-m3-cfg',
                                  embed_model_revision='rev-cfg')
                self.mod.main([self.jsonl(d), '--index-dir', str(Path(d) / 'index'),
                               '--config', cfg])
            self.assertTrue(seen, '설정의 임베딩 서버로 요청이 가지 않았다')
            self.assertEqual(seen[0][1], 'bge-m3-cfg')
            manifest = json.loads((Path(d) / 'index' / (
                Path(d) / 'index' / 'current').read_text().strip()
                / 'manifest.json').read_text())
            self.assertEqual(manifest['embed_model_revision'], 'rev-cfg',
                             'revision 이 설정에서 안 왔다')

    def test_cli_overrides_the_config(self):
        with tempfile.TemporaryDirectory() as d:
            seen = []
            with FakeServer(self.embed_reply(seen)) as srv:
                cfg = self.config(d, embed_base_url='http://127.0.0.1:1/v1',
                                  embed_model='from-config')
                self.mod.main([self.jsonl(d), '--index-dir', str(Path(d) / 'index'),
                               '--config', cfg, '--embed-base-url', srv.base,
                               '--embed-model', 'from-cli'])
            self.assertEqual(seen[0][1], 'from-cli', 'CLI 인자가 설정에 밀렸다')

    def test_unreadable_config_falls_back_without_crashing(self):
        with tempfile.TemporaryDirectory() as d:
            got = self.mod.config_defaults(str(Path(d) / 'missing.json'))
            self.assertEqual(got, dict.fromkeys(self.mod.FALLBACK))

    def test_repo_config_actually_carries_the_two_endpoints(self):
        """8000=생성, 8001=임베딩 이 설정에 살아 있는지."""
        cfg = json.loads((ROOT / 'fuzzer_config.json').read_text(encoding='utf-8'))
        vllm = cfg['rag']['vllm']
        self.assertIn(':8000', vllm['base_url'])
        self.assertEqual(vllm['model'], 'nemotron-3-super')
        self.assertIn(':8001', vllm['retrieval']['embed_base_url'])
        self.assertEqual(vllm['retrieval']['embed_model'], 'bge-m3')
        self.assertNotEqual(vllm['base_url'], vllm['retrieval']['embed_base_url'],
                            '생성·임베딩이 같은 엔드포인트를 가리킨다')
        self.assertEqual(self.mod.config_defaults(str(ROOT / 'fuzzer_config.json'))[
            'embed_base_url'], vllm['retrieval']['embed_base_url'])


class MissingEmbedEndpointIsNotSilent(unittest.TestCase):
    def test_falling_back_to_the_generation_server_warns(self):
        from rag import rag_retrieval as rr
        cfg = {'base_url': 'http://gen-server:8000/v1', 'retrieval': {'enabled': True}}
        with self.assertLogs(level='WARNING') as caught:
            opts = rr._settings(cfg)
        self.assertEqual(opts['embed_base_url'], 'http://gen-server:8000/v1')
        self.assertTrue(any('embed_base_url' in line for line in caught.output),
                        '임베딩이 생성 서버로 가는데 조용했다')

    def test_configured_endpoint_does_not_warn(self):
        from rag import rag_retrieval as rr
        cfg = {'base_url': 'http://gen-server:8000/v1',
               'retrieval': {'enabled': True,
                             'embed_base_url': 'http://embed-server:8001/v1'}}
        logging.disable(logging.NOTSET)
        with patch.object(rr._log, 'warning') as warn:
            opts = rr._settings(cfg)
        self.assertEqual(opts['embed_base_url'], 'http://embed-server:8001/v1')
        warn.assert_not_called()


class DryRunInspectsWithoutAServer(unittest.TestCase):
    """--dry-run 은 임베딩 서버·numpy·설정 없이 돌아야 한다 — 사내 PC 에서 쓰는 점검이다."""

    def setUp(self):
        spec = __import__('importlib.util', fromlist=['util']).spec_from_file_location(
            'rag_ingest_dry', ROOT / 'tools/rag_ingest.py')
        self.mod = __import__('importlib.util', fromlist=['util']).module_from_spec(spec)
        spec.loader.exec_module(self.mod)

    def jsonl(self, d, name, doc_id, content='hello world ' * 100):
        p = Path(d) / name
        p.write_text(json.dumps({'doc_id': doc_id, 'title': 'T', 'content': content,
                                 'permission_groups': ['g']}) + '\n', encoding='utf-8')
        return str(p)

    def run_dry(self, *paths, max_chars=6000):
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = self.mod.main(list(paths) + ['--dry-run', '--max-chars', str(max_chars)])
        return code, buf.getvalue()

    def test_duplicate_doc_ids_across_split_files_are_reported_and_nonzero(self):
        with tempfile.TemporaryDirectory() as d:
            a = self.jsonl(d, 'p001-100.jsonl', 'NVMe_Base', 'x' * 20000)
            b = self.jsonl(d, 'p101-200.jsonl', 'NVMe_Base', 'y' * 20000)
            code, out = self.run_dry(a, b)
        self.assertEqual(code, 1, '중복이 있는데 진행 가능으로 보고했다')
        self.assertIn('doc_id 중복', out)
        self.assertIn('서로 다른 파일', out, '분할 때문인지 구분해 주지 않았다')

    def test_clean_input_reports_zero(self):
        with tempfile.TemporaryDirectory() as d:
            a = self.jsonl(d, 'p001-100.jsonl', 'NVMe_Base_p1')
            b = self.jsonl(d, 'p101-200.jsonl', 'NVMe_Base_p2')
            code, out = self.run_dry(a, b)
        self.assertEqual(code, 0, out)
        self.assertIn('그대로 색인 가능', out)

    def test_dry_run_creates_no_index_and_contacts_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            a = self.jsonl(d, 'doc.jsonl', 'only')
            code, _ = self.run_dry(a)
        self.assertEqual(code, 0)
        self.assertFalse((ROOT / 'rag' / 'index').exists(),
                         '--dry-run 이 인덱스 디렉터리를 만들었다')

    def test_missing_fields_are_counted_not_fatal(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'partial.jsonl'
            p.write_text(json.dumps({'content': 'body text ' * 50}) + '\n'
                         + 'not json at all\n', encoding='utf-8')
            code, out = self.run_dry(str(p))
        self.assertIn('doc_id 없음/빈값', out)
        self.assertIn('JSON 파싱 실패', out)
        self.assertEqual(code, 0, '필드 누락만으로 거부하면 안 된다')

    def test_dry_run_needs_neither_numpy_nor_a_config_file(self):
        """사내 PC 에는 설정도 numpy 도 없을 수 있다 — 점검은 그래도 돌아야 한다."""
        import io, contextlib
        with tempfile.TemporaryDirectory() as d:
            a = self.jsonl(d, 'doc.jsonl', 'only')
            buf = io.StringIO()
            with patch.dict(sys.modules, {'numpy': None}):      # import 시 ImportError
                with contextlib.redirect_stdout(buf):
                    code = self.mod.main([a, '--dry-run',
                                          '--config', str(Path(d) / 'no-such.json')])
        self.assertEqual(code, 0, buf.getvalue())
        self.assertIn('그대로 색인 가능', buf.getvalue())

    def test_a_real_ingest_still_needs_numpy(self):
        """위 시험이 numpy 차단을 실제로 하고 있는지 — 대조군."""
        with tempfile.TemporaryDirectory() as d:
            a = self.jsonl(d, 'doc.jsonl', 'only')
            with patch.dict(sys.modules, {'numpy': None}):
                with self.assertRaises((ImportError, SystemExit)):
                    self.mod.main([a, '--index-dir', str(Path(d) / 'index'),
                                   '--embed-base-url', 'http://127.0.0.1:1/v1'])


class InputsAreResolvedWithoutAShell(unittest.TestCase):
    """Windows 셸은 *.jsonl 을 펴 주지 않는다 — 리터럴 '*' 를 열면 errno 22 다."""

    def setUp(self):
        spec = __import__('importlib.util', fromlist=['util']).spec_from_file_location(
            'rag_ingest_glob', ROOT / 'tools/rag_ingest.py')
        self.mod = __import__('importlib.util', fromlist=['util']).module_from_spec(spec)
        spec.loader.exec_module(self.mod)

    def tree(self, d):
        (Path(d) / 'sub').mkdir()
        for name, doc in (('a.jsonl', 'A'), ('b.jsonl', 'B'), ('sub/c.jsonl', 'C')):
            (Path(d) / name).write_text(
                json.dumps({'doc_id': doc, 'title': doc, 'content': 'text ' * 100,
                            'permission_groups': []}) + '\n', encoding='utf-8')
        (Path(d) / 'notes.txt').write_text('ignore me', encoding='utf-8')

    def test_literal_glob_is_expanded_by_the_tool(self):
        with tempfile.TemporaryDirectory() as d:
            self.tree(d)
            got = self.mod.resolve_inputs([str(Path(d) / '*.jsonl')])
        self.assertEqual([Path(p).name for p in got], ['a.jsonl', 'b.jsonl'])

    def test_directory_is_walked_recursively_for_jsonl_only(self):
        with tempfile.TemporaryDirectory() as d:
            self.tree(d)
            got = self.mod.resolve_inputs([d])
        self.assertEqual(sorted(Path(p).name for p in got),
                         ['a.jsonl', 'b.jsonl', 'c.jsonl'])
        self.assertFalse(any(p.endswith('.txt') for p in got))

    def test_already_expanded_paths_still_work(self):
        with tempfile.TemporaryDirectory() as d:
            self.tree(d)
            paths = [str(Path(d) / 'a.jsonl'), str(Path(d) / 'b.jsonl')]
            self.assertEqual(self.mod.resolve_inputs(paths), paths)

    def test_the_same_file_named_twice_is_used_once(self):
        with tempfile.TemporaryDirectory() as d:
            self.tree(d)
            one = str(Path(d) / 'a.jsonl')
            got = self.mod.resolve_inputs([one, one, str(Path(d) / '*.jsonl')])
        self.assertEqual([Path(p).name for p in got], ['a.jsonl', 'b.jsonl'])

    def test_a_wrong_path_stops_with_a_message_not_errno22(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SystemExit) as ctx:
                self.mod.resolve_inputs([str(Path(d) / 'nope' / '*.jsonl')])
        self.assertIn('찾지 못했습니다', str(ctx.exception))

    def test_empty_directory_is_named_in_the_error(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SystemExit) as ctx:
                self.mod.resolve_inputs([d])
        self.assertIn('.jsonl 이 없습니다', str(ctx.exception))

    def test_dry_run_accepts_a_literal_glob_end_to_end(self):
        """셸이 안 펴 준 인자를 그대로 넘겨도 점검이 돈다(사내 Windows PC 경로)."""
        import io, contextlib
        with tempfile.TemporaryDirectory() as d:
            self.tree(d)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = self.mod.main([str(Path(d) / '*.jsonl'), '--dry-run'])
        self.assertEqual(code, 0, buf.getvalue())
        self.assertIn('입력 2개', buf.getvalue())


class SourceIdentityDistinguishesSplitFiles(unittest.TestCase):
    """PDF 별 폴더에 같은 이름의 분할 파일이 있는 구조 — basename 만 쓰면 합쳐진다."""

    def setUp(self):
        spec = __import__('importlib.util', fromlist=['util']).spec_from_file_location(
            'rag_ingest_src', ROOT / 'tools/rag_ingest.py')
        self.mod = __import__('importlib.util', fromlist=['util']).module_from_spec(spec)
        spec.loader.exec_module(self.mod)

    def per_pdf_tree(self, d, folders=('NVMe_Base', 'PCIe')):
        for folder in folders:
            (Path(d) / folder).mkdir(parents=True, exist_ok=True)
            for i in (1, 2):
                (Path(d) / folder / f'part{i}.jsonl').write_text(
                    json.dumps({'doc_id': f'{folder}_{i}', 'title': folder,
                                'content': f'{folder} body {i} ' * 50,
                                'permission_groups': ['g']}) + '\n', encoding='utf-8')
        return d

    def test_same_filename_in_different_folders_stays_distinct(self):
        with tempfile.TemporaryDirectory() as d:
            self.per_pdf_tree(d)
            inputs = self.mod.resolve_inputs([d])
            ids = {self.mod.source_id(p) for p in inputs}
        self.assertEqual(len(inputs), 4)
        self.assertEqual(len(ids), 4, 'basename 이 같아 소스가 합쳐졌다')
        self.assertIn('NVMe_Base/part1.jsonl', ids)
        self.assertIn('PCIe/part1.jsonl', ids)

    def test_manifest_records_every_input_file(self):
        with tempfile.TemporaryDirectory() as d:
            self.per_pdf_tree(d)
            index = Path(d) / 'index'
            with FakeServer(lambda p, body: (200, {'data': [
                    {'index': i, 'embedding': [float(i + 1), 1.0]}
                    for i in range(len(body['input']))]})) as srv:
                self.mod.main([d, '--index-dir', str(index), '--embed-base-url', srv.base])
            version = (index / 'current').read_text().strip()
            manifest = json.loads((index / version / 'manifest.json').read_text())
        self.assertEqual(len(manifest['sources']), 4,
                         f"manifest 가 입력 4개를 {len(manifest['sources'])}개로 기록했다")

    def test_identity_is_stable_when_the_tree_moves(self):
        """절대 경로를 쓰면 트리를 옮기거나 다른 cwd 에서 돌릴 때 전량 재임베딩이 된다."""
        with tempfile.TemporaryDirectory() as one, tempfile.TemporaryDirectory() as two:
            self.per_pdf_tree(one)
            self.per_pdf_tree(two)
            a = {self.mod.source_id(p) for p in self.mod.resolve_inputs([one])}
            b = {self.mod.source_id(p) for p in self.mod.resolve_inputs([two])}
        self.assertEqual(a, b, '위치가 바뀌면 식별자도 바뀐다 — 재사용이 깨진다')

    def test_a_remaining_collision_is_refused_not_merged(self):
        with tempfile.TemporaryDirectory() as d:
            for side in ('a', 'b'):
                (Path(d) / side / 'split').mkdir(parents=True)
                (Path(d) / side / 'split' / 'p1.jsonl').write_text(
                    json.dumps({'doc_id': f'{side}1', 'title': side,
                                'content': 'body ' * 50,
                                'permission_groups': ['g']}) + '\n', encoding='utf-8')
            index = Path(d) / 'index'
            with FakeServer(lambda p, body: (200, {'data': [
                    {'index': i, 'embedding': [1.0, 0.0]}
                    for i in range(len(body['input']))]})) as srv:
                with self.assertRaises(SystemExit) as ctx:
                    self.mod.main([d, '--index-dir', str(index),
                                   '--embed-base-url', srv.base])
            self.assertIn('소스 식별자', str(ctx.exception))
            self.assertFalse((index / 'current').exists(), '충돌인데 게시했다')

    def test_dry_run_reports_the_collision_before_embedding(self):
        import io, contextlib
        with tempfile.TemporaryDirectory() as d:
            for side in ('a', 'b'):
                (Path(d) / side / 'split').mkdir(parents=True)
                (Path(d) / side / 'split' / 'p1.jsonl').write_text(
                    json.dumps({'doc_id': f'{side}1', 'title': side,
                                'content': 'body ' * 50,
                                'permission_groups': ['g']}) + '\n', encoding='utf-8')
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = self.mod.main([d, '--dry-run'])
        self.assertEqual(code, 1)
        self.assertIn('소스 식별자', buf.getvalue())


if __name__ == '__main__':
    unittest.main()
