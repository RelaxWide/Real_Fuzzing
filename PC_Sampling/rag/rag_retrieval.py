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
import json
import logging
import re
import time
from pathlib import Path

_log = logging.getLogger()
_QUERY_BLOCK = re.compile(r"\[RAG-QUERY\](.*?)\[/RAG-QUERY\]", re.S)

# 캠페인은 시작할 때 해석한 인덱스 버전을 끝까지 쓴다.
_PINNED = {}


def _defaults():
    return {"enabled": True, "index_dir": "rag/index", "top_k": 5,
            "embed_base_url": None, "embed_model": "bge-m3",
            "embed_model_revision": None,   # 설정하면 인덱스 manifest 와 대조한다
            "query_max_chars": 8000,      # 토큰 수 보장이 아니다. 보수적 문자 상한
            "context_max_chars": 60000,
            "permission_groups": None}


def _settings(cfg):
    out = _defaults()
    out.update({k: v for k, v in (cfg.get("retrieval") or {}).items() if k in out})
    if not out["embed_base_url"]:
        out["embed_base_url"] = cfg["base_url"]
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
    _PINNED[key] = (manifest, chunks, vectors, version)
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
    # 인덱스를 만든 모델과 지금 질의를 임베딩할 모델이 다르면 **벡터 공간이 다르다**.
    #   점수는 여전히 계산되므로 조용히 엉뚱한 문서가 뽑힌다 — 실행 시점에 막는다.
    _built = manifest.get("embed_model")
    if _built and _built != opts["embed_model"]:
        raise ValueError(
            f"인덱스 임베딩 모델 불일치: 인덱스={_built} 설정={opts['embed_model']} "
            f"({version.name}) — tools/rag_ingest.py 로 다시 색인하세요")
    # revision 을 명시했으면 **누락도 불일치**다. 빠진 것을 통과시키면 revision 을
    #   기록하지 않던 구형 인덱스를 새 모델 공간과 섞어 쓰는 것을 막지 못한다.
    _rev, _want_rev = manifest.get("embed_model_revision"), opts.get("embed_model_revision")
    if _want_rev and _rev != _want_rev:
        raise ValueError(
            f"인덱스 임베딩 모델 revision 불일치: 인덱스={_rev or '(기록 없음)'} "
            f"설정={_want_rev} ({version.name}) — 다시 색인하세요")
    vec = np.asarray(embed(q, opts, cfg, deadline), dtype=np.float32)
    if vec.shape[0] != vectors.shape[1]:
        raise ValueError(f"질의 벡터 차원 불일치: 질의={vec.shape[0]} "
                         f"인덱스={vectors.shape[1]} ({version.name})")
    norm = float(np.linalg.norm(vec)) or 1.0
    scores = (vectors.astype(np.float32) @ (vec / norm))

    groups = opts["permission_groups"]
    order = np.argsort(-scores)
    picked, parts = [], []
    for i in order:
        if len(picked) >= int(opts["top_k"]):
            break
        row = chunks[int(i)]
        if groups and not set(row.get("permission_groups") or []) & set(groups):
            continue
        picked.append({"doc_id": row.get("doc_id"), "title": row.get("title"),
                       "score": round(float(scores[int(i)]), 4)})
        parts.append(f"## {row.get('title') or row.get('doc_id')}\n{row.get('content', '')}")

    text = "\n\n".join(parts)[: int(opts["context_max_chars"])]
    return text, {"enabled": True, "query_source": source, "query_chars": len(q),
                  "index_version": version.name, "embed_model": manifest.get("embed_model"),
                  "hits": picked, "context_chars": len(text)}
