#!/usr/bin/env python3
"""■ 배치: **오프라인 퍼징 PC** — 리포 안 `PC_Sampling/rag/` 그대로.

로컬 RAG 검색. `vllm_client.py` 안에서 돌고 **별도 서비스 프로세스를 띄우지 않는다**
— 살았는지 감시해야 할 대상을 다시 만들지 않는 것이 이 설계의 요점이다.

인덱스는 `tools/rag_ingest.py` 가 만든다(구조는 그쪽 docstring 참조).

질의 만들기 (계획 D7 — 사다리)
------------------------------
1. `meta['rag_query']`      — 퍼저가 목표 함수명·명령 이름을 알고 있어 가장 정확
2. 프롬프트의 `[RAG-QUERY] … [/RAG-QUERY]` 블록 — `llm_learning.query_block()` 이
   학습이 켜져 있을 때 붙인다. meta 를 안 넘기는 구버전 호출을 받아 주는 경로다
3. 둘 다 없으면 검색을 **생략**한다(전문을 질의로 쓰지 않는다)
4. 서버가 토큰 초과를 반환하면 제한된 축소 재시도 후 **명시적 실패**

토크나이저는 쓰지 않는다. 길이 제한은 문자 수 기준이며 **정확한 토큰 수를 보장한다고
표현하지 않는다** — 퍼징 PC 에 transformers/sentencepiece 를 다시 들이지 않기 위해서다.
"""
# ── BLAS 스레드 제한 — **numpy import 보다 반드시 먼저** ──────────────────
#   OpenBLAS 워커는 연산이 끝난 뒤에도 다음 작업을 기다리며 sched_yield() 로
#   busy-wait 한다(기본 spin 시간이 길다). 퍼저는 샘플러·LLM 워커·메인 루프가
#   같이 도는 멀티스레드 프로세스라, 코어 수만큼의 스핀 스레드가 CPU 를 태우고
#   다른 스레드를 굶겨 hang 처럼 보인다. 실제로 rag_retrieval 의 top-k 행렬곱에서
#   관측됐다.
#   여기 쓰이는 행렬곱은 (청크수 × 1024) @ (1024,) 하나뿐이고 단일 스레드로 1ms 도
#   안 걸린다 — 스레드를 늘려 얻는 게 없다.
#   setdefault 라 사용자가 명시적으로 지정한 값은 존중한다.
import os as _os_blas
for _v in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS",
           "NUMEXPR_NUM_THREADS", "VECLIB_MAXIMUM_THREADS"):
    _os_blas.environ.setdefault(_v, "1")

import json
import logging
import math
from rag.retrieval_policy import canonical, tags, spec_name, cache_chunk_tags, definition_lookup, enhanced_query, expansion_report, extract_definitions, EXTRACTION_VERSION
import re
import time
from pathlib import Path

_log = logging.getLogger("pcfuzz.rag.rag_retrieval")
_QUERY_BLOCK = re.compile(r"\[RAG-QUERY\](.*?)\[/RAG-QUERY\]", re.S)

# 캠페인은 시작할 때 해석한 인덱스 버전을 끝까지 쓴다.
_PINNED = {}


def _defaults():
    return {"enabled": True, "index_dir": "rag/index", "top_k": 5,
            "embed_base_url": None, "embed_model": "bge-m3",
            "embed_model_revision": None,   # 설정하면 인덱스 manifest 와 대조한다
            "query_max_chars": 8000,      # 토큰 수 보장이 아니다. 보수적 문자 상한
            "context_max_chars": 60000,
            "permission_groups": None, "command_tag_bonus": 0.1}


def _settings(cfg):
    out = _defaults()
    out.update({k: v for k, v in (cfg.get("retrieval") or {}).items() if k in out})
    if not out["embed_base_url"]:
        # 한 서버에 생성·임베딩을 함께 올린 구성이면 맞는 폴백이라 막지는 않는다.
        #   다만 nemotron(8000)·bge-m3(8001) 를 나눠 띄운 구성에서는 임베딩이 생성
        #   서버로 가고, 그래도 점수는 계산되므로 조용히 엉뚱한 문서가 뽑힌다.
        out["embed_base_url"] = cfg["base_url"]
        _log.warning("[LLM/rag] retrieval.embed_base_url 이 없어 **생성 서버**(%s)로 "
                     "임베딩합니다 — 임베딩 서버를 따로 띄웠다면 설정을 확인하세요",
                     out["embed_base_url"])
    out["embed_base_url"] = str(out["embed_base_url"]).rstrip("/")
    return out


def query_from(meta, user, limit):
    """사다리 1→2→3. 못 만들면 (None, 사유)."""
    q = (meta or {}).get("rag_query")
    if isinstance(q, str) and q.strip():
        return q.strip()[:limit], "meta"
    m = _QUERY_BLOCK.search(user or "")
    if m and m.group(1).strip():
        return m.group(1).strip()[:limit], "prompt_block"
    return None, "no_query"


def _load(index_dir):
    """포인터 파일이 가리키는 버전을 연다. 캠페인 중에는 처음 해석한 버전을 유지한다."""
    root = Path(index_dir)
    if not root.is_absolute():
        root = Path(__file__).resolve().parent.parent / root
    key = str(root)
    if key in _PINNED:
        return _PINNED[key]
    pointer = root / "current"
    if not pointer.is_file():
        raise FileNotFoundError(f"인덱스 포인터가 없습니다: {pointer} "
                                f"(tools/rag_ingest.py 로 먼저 만드세요)")
    version = root / pointer.read_text(encoding="utf-8").strip()
    import numpy as np
    manifest = json.loads((version / "manifest.json").read_text(encoding="utf-8"))
    vectors = np.load(version / "vectors.f16.npy")
    chunks = [json.loads(l) for l in (version / "chunks.jsonl").read_text(
        encoding="utf-8").splitlines() if l.strip()]
    if len(chunks) != vectors.shape[0]:
        raise ValueError(f"인덱스 불일치: chunks={len(chunks)} vectors={vectors.shape[0]} "
                         f"({version})")
    _log.warning("[LLM/rag] 인덱스 %s — 청크 %d개, %d차원, 모델 %s",
                 version.name, len(chunks), vectors.shape[1],
                 manifest.get("embed_model"))
    # float16 저장분을 질의마다 float32 로 복사하면 인덱스 크기에 비례해 낭비가 커진다
    #   (10만 청크면 매 질의 400 MB). 한 번만 변환해 캐시한다.
    cache_chunk_tags(chunks)
    manifest["_field_lookups"] = {}
    # v1의 definitions=0 인덱스도 재임베딩 없이 로드 시 1회 복구한다.
    if (manifest.get('metadata_extraction') or {}).get('version') != EXTRACTION_VERSION:
        definitions = list(manifest.get('field_definitions') or [])
        for row in chunks:
            definitions.extend(extract_definitions(row.get('content', ''), row.get('source_file', ''),
                                                  row['doc_id'], row.get('permission_groups') or []))
        manifest['field_definitions'] = definitions
        manifest['_field_definition_source'] = 'load_time_extraction'
    else:
        manifest['_field_definition_source'] = 'manifest'

    matrix32 = vectors.astype(np.float32)
    _PINNED[key] = (manifest, chunks, matrix32, version)
    return _PINNED[key]


def embed(text, opts, cfg, deadline, shrink=2):
    """질의 임베딩. 길이 초과를 서버가 알리면 제한된 횟수만 줄여 재시도한다."""
    from rag.vllm_client import _post, BackendError
    body = text
    for attempt in range(shrink + 1):
        left = deadline - time.monotonic()
        if left <= 0:
            raise BackendError("시간 예산 소진 — 임베딩 요청 중단")
        try:
            data = _post(opts["embed_base_url"] + "/embeddings",
                         {"model": opts["embed_model"], "input": body}, cfg,
                         deadline=deadline)
            return data["data"][0]["embedding"]
        except BackendError as exc:
            over = any(t in str(exc).lower() for t in
                       ("token", "too long", "maximum context", "length"))
            if over and attempt < shrink:
                body = body[: max(200, len(body) // 2)]
                _log.warning("[LLM/rag] 임베딩 길이 초과 — %d자로 줄여 재시도", len(body))
                continue
            raise
    raise RuntimeError("unreachable")


def validate_index_model(manifest, opts, version):
    # 인덱스를 만든 모델과 지금 질의를 임베딩할 모델이 다르면 **벡터 공간이 다르다**.
    #   점수는 여전히 계산되므로 조용히 엉뚱한 문서가 뽑힌다 — 실행 시점에 막는다.
    _built = manifest.get("embed_model")
    if _built and _built != opts["embed_model"]:
        raise ValueError(
            f"인덱스 임베딩 모델 불일치: 인덱스={_built} 설정={opts['embed_model']} "
            f"({version.name}) — 모델 설정과 인덱스를 확인하세요")
    # revision 을 명시했으면 **누락도 불일치**다. 빠진 것을 통과시키면 revision 을
    #   기록하지 않던 구형 인덱스를 새 모델 공간과 섞어 쓰는 것을 막지 못한다.
    _rev, _want_rev = manifest.get("embed_model_revision"), opts.get("embed_model_revision")
    if _want_rev and _rev != _want_rev:
        raise ValueError(
            f"인덱스 임베딩 모델 revision 불일치: 인덱스={_rev or '(기록 없음)'} "
            f"설정={_want_rev} ({version.name}) — manifest와 설정을 확인하세요(생성 날짜와 모델 revision은 다릅니다)")


def retrieve(meta, cfg, deadline):
    """(참고문서 텍스트, 진단) 반환. 실패는 예외로 올린다 — 호출부가 삼킨다."""
    opts = _settings(cfg)
    if not opts["enabled"]:
        return "", {"enabled": False}
    q, source = query_from(meta, (meta or {}).get("user_prompt", ""),
                           int(opts["query_max_chars"]))
    if q is None:
        return "", {"enabled": True, "skipped": "질의 없음 — 전문을 질의로 쓰지 않는다"}

    import numpy as np
    manifest, chunks, vectors, version = _load(opts["index_dir"])
    validate_index_model(manifest, opts, version)
    # 디스크 접근/메타데이터 확장은 LLM 워커에서 수행한다. 메인 퍼저 스레드는
    # 스키마만 전달하며 기존 인덱스(field_definitions 없음)는 원래 질의를 유지한다.
    schemas = (meta or {}).get('rag_query_schemas')
    field_expansion = None
    if schemas is not None and 'field_definitions' in manifest:
        group_key = tuple(sorted(opts['permission_groups'] or []))
        lookups = manifest.setdefault('_field_lookups', {})
        if group_key not in lookups:
            lookups[group_key] = definition_lookup(manifest['field_definitions'], group_key)[0]
        field_expansion = expansion_report((meta or {}).get('rag_query_commands') or [], schemas, lookups[group_key], True)
        expanded = enhanced_query((meta or {}).get('rag_query_commands') or [], schemas, lookups[group_key])
        if expanded:
            q = expanded[:int(opts['query_max_chars'])]
            source = 'index_field_definitions'
    if schemas is not None:
        if field_expansion is None:
            field_expansion = expansion_report((meta or {}).get('rag_query_commands') or [], schemas, {}, False)
        if field_expansion['missing_count']:
            _log.warning('[LLM/rag] 스펙 필드 확장 %d건 / 미확인 %d건 (metadata=%s)',
                         field_expansion['matched_count'], field_expansion['missing_count'],
                         field_expansion['metadata_present'])
    vec = np.asarray(embed(q, opts, cfg, deadline), dtype=np.float32)
    if vec.shape[0] != vectors.shape[1]:
        raise ValueError(f"질의 벡터 차원 불일치: 질의={vec.shape[0]} "
                         f"인덱스={vectors.shape[1]} ({version.name})")
    norm = float(np.linalg.norm(vec)) or 1.0
    # vectors 는 _load 에서 이미 float32 로 변환·캐시된 것이다(질의마다 복사하지 않는다).
    scores = vectors @ (vec / norm)

    groups = opts["permission_groups"]
    # 대상 명령은 구조화된 요청 문맥만 사용한다. 질의 문자열에서 임의 추측하지 않는다.
    commands = (meta or {}).get("rag_query_commands") or []
    if not isinstance(commands, list) or any(not isinstance(c, str) for c in commands):
        raise ValueError("rag_query_commands must be a list of command names")
    bonus = float(opts["command_tag_bonus"])
    if not math.isfinite(bonus) or bonus < 0:
        raise ValueError("command_tag_bonus must be finite and nonnegative")
    wanted = {canonical(spec_name(c)) for c in commands}
    cache_chunk_tags(chunks)  # _load에서 완료; 외부/시험 로더도 최초 1회만 계산
    covers = [row["covers_commands"] for row in chunks]
    matched = np.asarray([bool(wanted & row["_command_keys"]) for row in chunks])
    final_scores = scores + bonus * matched
    order = np.argsort(-final_scores, kind="stable")
    picked, parts = [], []
    for i in order:
        if len(picked) >= int(opts["top_k"]):
            break
        row = chunks[int(i)]
        if groups and not set(row.get("permission_groups") or []) & set(groups):
            continue
        picked.append({"doc_id": row.get("doc_id"), "title": row.get("title"),
                       "score": round(float(final_scores[int(i)]), 4),
                       "dense_score": float(scores[int(i)]),
                       "tag_bonus": bonus if matched[int(i)] else 0.0,
                       "covers_commands": covers[int(i)], "rank": len(picked) + 1})
        parts.append(f"## {row.get('title') or row.get('doc_id')}\n{row.get('content', '')}")

    limit = max(0, int(opts["context_max_chars"]))
    full_context = "\n\n".join(parts)
    text = full_context[:limit]
    offset = 0
    for hit, part in zip(picked, parts):
        hit["injected_chars"] = max(0, min(len(part), len(text) - offset))
        hit["truncated"] = hit["injected_chars"] < len(part)
        offset += len(part) + 2
    return text, {"enabled": True, "query_source": source, "query": q, "query_chars": len(q),
                  "commands": commands, "command_tag_bonus": bonus,
                  "field_expansion": field_expansion,
                  "field_definition_source": manifest.get("_field_definition_source"),
                  "field_definition_count": len(manifest.get("field_definitions") or []),
                  "query_version": (meta or {}).get("rag_query_version"),
                  "metadata_extraction": manifest.get("metadata_extraction"),
                  "context": text, "context_truncated": len(text) < len(full_context),
                  "index_version": version.name, "embed_model": manifest.get("embed_model"),
                  "hits": picked, "context_chars": len(text)}


def preflight(config, enabled, module_path):
    """장치 접근 전 로컬 인덱스를 검증·고정한다. 네트워크 호출 없음.

    --rag는 LLM 기능 토글이다. 로컬 retrieval까지 활성인 vLLM 구성만 검사하며,
    --no-rag/생성 전용/별도 브리지에는 로컬 인덱스를 요구하지 않는다.
    """
    if not enabled or module_path != 'rag.vllm_client':
        return
    from rag.vllm_client import _config
    opts = _settings(_config({'config': config}))
    if not opts['enabled']:
        return
    manifest, _, _, version = _load(opts['index_dir'])
    validate_index_model(manifest, opts, version)
    _log.warning('[LLM/rag] 시작 전 인덱스 검증 통과: %s', version.name)
