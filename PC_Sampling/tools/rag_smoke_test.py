#!/usr/bin/env python3
"""Device-free retrieval / generation smoke test. Never instantiates the fuzzer."""
import argparse
import copy
import importlib.util
import json
import math
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from rag import rag_retrieval, vllm_client

DEFAULT_QUERY = 'NVMe Autonomous Power State Transition APST Set Features FID 0Ch idle time power state'
SYSTEM = ('You assist authorized SSD reliability testing. Return only the requested JSON. '
          'Propose at most two NVMe test seeds; do not claim that any command was executed. '
          'Use reference documents when provided and acknowledge uncertainty in rationale.')


def validate_response(result, task):
    """Reuse the real pure parser/rejection check, without constructing hardware objects."""
    if result.get('error'):
        raise ValueError(result['error'])
    name = '_rag_smoke_fuzzer'
    module = sys.modules.get(name)
    if module is None:
        path = ROOT / 'pc_sampling_fuzzer_v10.3.py'
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        argv = sys.argv
        try:
            sys.argv = [str(path)]
            spec.loader.exec_module(module)
        finally:
            sys.argv = argv
    data = module._llm_extract_json(result.get('raw', ''))
    if not isinstance(data, dict):
        raise ValueError('기존 파서가 JSON 객체를 읽지 못했습니다')
    reason = module._V101Fuzzer._llm_response_rejection(
        None, dict(result, task=task), data)
    if reason:
        raise ValueError(reason)
    return data


def require_retrieval(diag):
    if (not diag.get('enabled') or diag.get('error') or diag.get('skipped')
            or not diag.get('hits') or not diag.get('context_chars')):
        raise ValueError(f'검색 실패/생략/빈 결과: {diag}')
    if any(not math.isfinite(float(h['score'])) for h in diag['hits']):
        raise ValueError('검색 점수가 NaN/Inf 입니다')


def run_stage(stage, config, query):
    cfg = copy.deepcopy(config)
    cfg['rag']['vllm'].setdefault('retrieval', {})['enabled'] = stage != 'generation'
    opts = vllm_client._config({'config': cfg})
    user = (f'[RAG-QUERY]\n{query}\n[/RAG-QUERY]\n'
            'Task: new_group_seeds. Suggest up to two seeds relevant to the query. '
            'Return {"seeds": [{"command": "...", "rationale": "..."}]} '
            'using the supplied schema; an empty seeds array is permitted if uncertain.')
    meta = {'config': cfg, 'task': 'new_group_seeds', 'rag_query': query,
            'user_prompt': user, 'req_id': f'smoke-{stage}'}
    report = {'stage': stage, 'query': query, 'status': 'FAIL'}
    started = time.monotonic()
    try:
        if stage == 'retrieval':
            context, diag = rag_retrieval.retrieve(
                meta, opts, started + float(opts['timeout_sec']))
            report.update(context=context, diagnostics=diag)
            require_retrieval(diag)
        else:
            result = vllm_client.generate_rag_response(SYSTEM, user, meta)
            report['response'] = result
            report['parsed'] = validate_response(result, meta['task'])
            if stage == 'rag':
                require_retrieval(result.get('diagnostics', {}).get('retrieval', {}))
            report['item_counts'] = {k: len(v) for k, v in report['parsed'].items()
                                     if isinstance(v, list)}
        report['status'] = 'PASS'
    except Exception as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'
    report['elapsed_sec'] = round(time.monotonic() - started, 3)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT / 'fuzzer_config.json')
    parser.add_argument('--stage', choices=['all', 'retrieval', 'generation', 'rag'], default='all')
    parser.add_argument('--query', default=DEFAULT_QUERY)
    parser.add_argument('--index-dir', type=Path, help='Existing index root containing current')
    parser.add_argument('--timeout', type=float, help='Budget per stage in seconds')
    parser.add_argument('--output', type=Path, help='New report directory (must not exist)')
    args = parser.parse_args(argv)
    if not args.query.strip() or (args.timeout is not None and
                                 (not math.isfinite(args.timeout) or args.timeout <= 0)):
        parser.error('query must not be empty; timeout must be finite and positive')
    try:
        config = json.loads(args.config.read_text(encoding='utf-8-sig'))
        opts = config['rag']['vllm']
        if not isinstance(opts, dict) or not opts:
            raise ValueError('rag.vllm must be a nonempty object')
        if args.index_dir:
            opts.setdefault('retrieval', {})['index_dir'] = str(args.index_dir.resolve())
        if args.timeout is not None:
            opts['timeout_sec'] = args.timeout
        # Test structured output without silently falling back to free-form generation.
        opts['structured_output'] = True
        opts['freeform_retry'] = False
        effective = vllm_client._config({'config': config})
        retrieval = rag_retrieval._settings(effective)
        out = args.output or ROOT / 'output' / ('rag_smoke_' + datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
        out.mkdir(parents=True, exist_ok=False)
    except Exception as exc:
        print(f'설정/출력 경로 오류: {exc}', file=sys.stderr)
        return 2
    print(f"생성: {effective['base_url']} ({effective['model']})", flush=True)
    print(f"임베딩: {retrieval['embed_base_url']} ({retrieval['embed_model']})", flush=True)
    print(f'보고서: {out.resolve()}', flush=True)
    print('SSD/JTAG 실행 없음. PASS는 연결·파싱·컨테이너 검사이며 의미/채택 검증이 아닙니다.', flush=True)
    report = {'config_path': str(args.config.resolve()),
              'generation_url': effective['base_url'], 'model': effective['model'],
              'retrieval_settings': retrieval, 'stages': []}
    stages = ['retrieval', 'generation', 'rag'] if args.stage == 'all' else [args.stage]
    for stage in stages:
        print(f'[{stage}] 시작', flush=True)
        row = run_stage(stage, config, args.query)
        report['stages'].append(row)
        (out / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        print(f"[{stage}] {row['status']} ({row['elapsed_sec']}s) {row.get('error', '')}", flush=True)
        diag = row.get('diagnostics', row.get('response', {}).get('diagnostics', {}).get('retrieval', {}))
        for hit in diag.get('hits', []):
            print(f"  {hit['score']}: {hit.get('title')} [{hit.get('doc_id')}]", flush=True)
    return int(any(r['status'] != 'PASS' for r in report['stages']))


if __name__ == '__main__':
    raise SystemExit(main())
