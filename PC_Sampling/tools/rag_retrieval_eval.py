#!/usr/bin/env python3
"""기존 스펙 JSONL과 벡터 인덱스를 이용하는 읽기 전용 검색 평가 도구.

사내 Claude Code 인수인계:
- 목적: 건조한 CDW 필드 표를 dense 검색이 놓치는지 재현하고, 질의 개선과
  명령 태그 가산점의 효과를 분리 측정한다. 운영 검색 변경 전 검증 단계다.
- 입력 구분: --source-dir는 스펙별 JSONL 하위 폴더, --index-dir는 current가
  있는 기존 검색 인덱스 루트다. 원본 ID와 분할 후 인덱스 ID는 다를 수 있다.
- 순서: prepare → 본문을 읽어 정답/질의 수동 검토 → evaluate.
  reviewed=true를 일괄 지정하지 말 것. 정규식 후보는 정답이 아니다.
- evaluate만 임베딩 API를 호출한다. 생성 모델/NVMe/퍼저 인스턴스는 호출하지
  않으며, 원본/인덱스/운영 설정을 수정하거나 전체 재임베딩하지 않는다.
- A/B/C/D는 이 파일에서만 시험한다. 운영 rag_retrieval.py 반영과 llm_io
  로그 확장은 별도 작업이다. 실측 개선 없이 운영에 가산점을 넣지 말 것.
- 실행 예시/정답표 형식/한계: ../docs/RAG_RETRIEVAL_EVAL.md.
"""
import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from rag import rag_retrieval, vllm_client

# 시작용 15개 명령이다. 후보가 없는 명령도 숨기지 않는다. 실제 실패 명령과
# 복수 명령 요청을 cases에 추가하고 baseline_query는 운영 질의로 교체한다.
COMMANDS = ['Identify', 'Get Features', 'Set Features', 'Get Log Page',
            'Create I/O Submission Queue', 'Create I/O Completion Queue',
            'Delete I/O Submission Queue', 'Delete I/O Completion Queue',
            'Namespace Management', 'Namespace Attachment', 'Firmware Commit',
            'Firmware Image Download', 'Read', 'Write', 'Dataset Management']
CAPTION = re.compile(r'Figure\s+\d+\s*:\s*([^:\n]{1,140}?)\s*[-–—]\s*Command\s+Dword', re.I)


def canonical(s):
    """GetFeatures / Get Features 등 표기 차이만 제거한다(의미적 별칭 아님)."""
    return re.sub(r'[^a-z0-9]', '', s.lower())


def tags(content):
    # PDF 추출 줄바꿈과 대시 변형을 허용한다. 제목 없는 후속 청크로 태그를
    # 추정 전파하지 않는다. 이 규칙의 누락/오탐은 후보 본문으로 확인해야 한다.
    return sorted(set(m.group(1).strip() for m in CAPTION.finditer(
        re.sub(r'\s+', ' ', content))))


def read_jsonl(path):
    rows = []
    for n, line in enumerate(path.read_text(encoding='utf-8-sig').splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict) or not isinstance(row.get('content'), str):
            raise ValueError(f'{path}:{n}: content string required')
        rows.append(row)
    return rows


def load_index(opts):
    """운영 로더로 동일 행 순서의 청크/벡터를 연다. 문서 벡터는 재계산하지 않는다."""
    import numpy as np
    manifest, chunks, vectors, version = rag_retrieval._load(opts['index_dir'])
    if manifest.get('embed_model') != opts['embed_model']:
        raise ValueError('Index embedding model mismatch')
    if opts.get('embed_model_revision') and manifest.get('embed_model_revision') != opts['embed_model_revision']:
        raise ValueError('Index embedding revision mismatch')
    ids = [r.get('doc_id') for r in chunks]
    if any(not isinstance(x, str) or not x for x in ids) or len(set(ids)) != len(ids):
        raise ValueError('Index doc_ids must be nonempty and unique')
    if vectors.ndim != 2 or not np.isfinite(vectors).all() or (np.linalg.norm(vectors, axis=1) == 0).any():
        raise ValueError('Invalid index vectors')
    return manifest, chunks, vectors, version


def prepare(source, chunks):
    """원본은 근거 탐색용, 정답 후보는 실제 검색 대상 chunks에서만 뽑는다.

    원본과 인덱스가 최신 상태로 일치하는지 자동 보장하지 않는다. 원본에만
    있는 명령은 source_caption_evidence에만 나타날 수 있으므로 확인한다.
    excerpt는 원본 앞부분 미리보기이며 캡션 위치의 정확한 인용은 아니다.
    """
    paths = sorted(source.rglob('*.jsonl')) if source.is_dir() else [source]
    if not paths:
        raise ValueError(f'No JSONLs under {source}')
    evidence = []
    for path in paths:
        for row in read_jsonl(path):
            for command in tags(row['content']):
                evidence.append({'command': command, 'source_file': str(path),
                                 'source_doc_id': row.get('doc_id'),
                                 'excerpt': row['content'][:300]})
    cases = []
    for command in COMMANDS:
        candidates = [{'doc_id': r['doc_id'], 'title': r.get('title'),
                       'covers_commands': tags(r['content']), 'content': r['content']}
                      for r in chunks if canonical(command) in map(canonical, tags(r['content']))]
        cases.append({'command': command, 'reviewed': False, 'split': 'validation',
                      'baseline_query': 'NVMe ' + command.replace(' ', ''),
                      'enhanced_query': '', 'relevant_doc_ids': [],
                      'candidates': candidates})
    return {'instructions': 'Review actual indexed content. Fill relevant_doc_ids and enhanced_query; copy actual production baseline_query; mark reviewed=true. Candidates are NOT ground truth.',
            'source_files': len(paths), 'source_caption_evidence': evidence, 'cases': cases}


def rank_case(scores, chunks, case, bonus, top_k):
    """전체 eligible 청크를 재정렬한다. 태그 미일치 청크도 제외하지 않는다.

    복수 명령 중 하나라도 일치하면 가산점은 한 번만 준다. top_k는 보고서
    표시 개수이고 Hit@5/10 계산 범위를 제한하지 않는다. rr는 최초 정답의
    역순위이며, 여러 정답 전체를 찾았는지 측정하는 recall과 다르다.
    """
    import numpy as np
    wanted = {canonical(x) for x in case.get('commands', [case['command']])}
    tag_scores = np.asarray([float(bool(wanted & {canonical(t) for t in tags(r['content'])})) for r in chunks])
    final = scores + bonus * tag_scores
    order = np.argsort(-final, kind='stable')
    gold = set(case['relevant_doc_ids'])
    positions = [rank for rank, i in enumerate(order, 1) if chunks[int(i)]['doc_id'] in gold]
    rank = min(positions)
    return {'rank': rank, 'hit5': rank <= 5, 'hit10': rank <= 10, 'rr': 1 / rank,
            'top': [{'doc_id': chunks[int(i)]['doc_id'], 'dense_score': float(scores[i]),
                     'tag_score': float(tag_scores[i]), 'final_score': float(final[i])}
                    for i in order[:top_k]]}


def evaluate(cases, chunks, vectors, embed_query, bonus, top_k):
    """A=기존+dense, B=개선+dense, C=기존+태그, D=개선+태그.

    정답 검사를 API 호출 전에 끝낸다. 질의 캐시는 실행 중 메모리에만 있어
    별도 실행에서는 다시 호출된다. development/validation 분리는 사용자가
    정답표에서 지정하며, validation 성적으로 bonus를 반복 튜닝하면 안 된다.
    """
    import numpy as np
    ids = {r['doc_id'] for r in chunks}
    if not cases:
        raise ValueError('Empty evaluation')
    for c in cases:
        if c.get('reviewed') is not True or not c.get('relevant_doc_ids'):
            raise ValueError(f"Unreviewed/missing gold: {c.get('command')}")
        if not set(c['relevant_doc_ids']) <= ids:
            raise ValueError(f"Gold missing from eligible index: {c['command']}")
        if not all(isinstance(c.get(k), str) and c[k].strip() for k in ('baseline_query', 'enhanced_query')):
            raise ValueError('Both queries required')
    results = []
    cache = {}
    for c in cases:
        variants = {}
        for key, label1, label2 in [('baseline_query', 'A', 'C'), ('enhanced_query', 'B', 'D')]:
            q = c[key]
            if q not in cache:
                vec = np.asarray(embed_query(q), dtype=np.float32)
                if vec.shape != (vectors.shape[1],) or not np.isfinite(vec).all() or np.linalg.norm(vec) == 0:
                    raise ValueError('Invalid query embedding')
                # ingest가 L2 정규화한 float16 문서 벡터를 float32로 로드한다.
                # 운영과 동일하게 질의만 정규화하여 기존 점수를 재현한다.
                cache[q] = vectors @ (vec / np.linalg.norm(vec))
            variants[label1] = rank_case(cache[q], chunks, c, 0, top_k)
            variants[label2] = rank_case(cache[q], chunks, c, bonus, top_k)
        results.append({'command': c['command'], 'split': c.get('split', 'validation'),
                        'baseline_query': c['baseline_query'], 'enhanced_query': c['enhanced_query'],
                        'relevant_doc_ids': c['relevant_doc_ids'], 'variants': variants})
    summary = {}
    for split in sorted({r['split'] for r in results}):
        subset = [r for r in results if r['split'] == split]
        summary[split] = {v: {metric: sum(r['variants'][v][metric] for r in subset) / len(subset)
                              for metric in ('hit5', 'hit10', 'rr')} for v in 'ABCD'}
        summary[split]['count'] = len(subset)
        summary[split]['D_vs_A'] = {name: [r['command'] for r in subset if compare(r['variants']['D']['rank'], r['variants']['A']['rank'])]
                                    for name, compare in [('improved', lambda a,b:a<b), ('regressed', lambda a,b:a>b), ('tied', lambda a,b:a==b)]}
    return {'summary': summary, 'results': results, 'unique_queries': len(cache)}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('stage', choices=['prepare', 'evaluate'])
    p.add_argument('--source-dir', type=Path, help='Recursively scan spec JSONL folders (prepare)')
    p.add_argument('--config', type=Path, default=ROOT / 'fuzzer_config.json')
    p.add_argument('--index-dir', type=Path, help='Existing index root containing current')
    p.add_argument('--cases', type=Path)
    p.add_argument('--output', type=Path, required=True, help='New JSON report; never overwrite')
    p.add_argument('--bonus', type=float, default=0.1)
    p.add_argument('--top-k', type=int, default=10)
    a = p.parse_args(argv)
    try:
        import math
        if a.output.exists():
            raise ValueError('Output already exists')
        if not math.isfinite(a.bonus) or a.bonus < 0 or a.top_k < 1:
            raise ValueError('Invalid bonus/top-k')
        cfg = vllm_client._config({'config': json.loads(a.config.read_text(encoding='utf-8-sig'))})
        opts = rag_retrieval._settings(cfg)
        if a.index_dir:
            opts['index_dir'] = str(a.index_dir.resolve())
        manifest, chunks, vectors, version = load_index(opts)
        fingerprint = hashlib.sha256((version / 'chunks.jsonl').read_bytes()).hexdigest()
        if a.stage == 'prepare':
            if not a.source_dir:
                raise ValueError('--source-dir required')
            report = prepare(a.source_dir, chunks)
        else:
            if not a.cases:
                raise ValueError('--cases required')
            draft = json.loads(a.cases.read_text(encoding='utf-8'))
            if draft.get('chunks_sha256') != fingerprint:
                raise ValueError('Cases belong to a different index; prepare/review again')
            # 운영 권한 필터와 같은 모집단에서 순위를 계산한다. 정답이 필터로
            # 제외되면 이를 검색 실패로 집계하지 않고 정답표 오류로 중단한다.
            groups = opts.get('permission_groups')
            if groups:
                keep = [i for i, r in enumerate(chunks) if set(groups) & set(r.get('permission_groups') or [])]
                chunks, vectors = [chunks[i] for i in keep], vectors[keep]
            def embed(q):
                if len(q) > int(opts['query_max_chars']):
                    raise ValueError('Query exceeds query_max_chars; shorten explicitly')
                return rag_retrieval.embed(q, opts, cfg, time.monotonic() + float(cfg['timeout_sec']), shrink=0)
            report = evaluate(draft['cases'], chunks, vectors, embed, a.bonus, a.top_k)
            report['bonus'] = a.bonus
            print(json.dumps(report['summary'], ensure_ascii=False, indent=2))
        report.update(index_version=version.name, chunks_sha256=fingerprint, manifest=manifest,
                      eligible_chunks=len(chunks), permission_groups=opts.get('permission_groups'))
        a.output.parent.mkdir(parents=True, exist_ok=True)
        with a.output.open('x', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f'Saved: {a.output}')
        return 0
    except Exception as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
