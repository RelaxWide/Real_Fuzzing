#!/usr/bin/env python3
"""■ 배치: **오프라인 퍼징 PC** — 리포 안 `PC_Sampling/rag/` 그대로 (fuzzer 가 import).
   config `rag.module_path="rag.vllm_client"` 가 이 경로를 가리킨다. 옮기지 말 것.

로컬 vLLM(OpenAI 호환) 백엔드. 사내 2노드 Samba 브리지를 대체한다 —
공유 폴더도, 드롭박스 폴링도, 온라인 PC 의 감시 대상 서비스도 없다.
되돌리려면 config 의 `rag.module_path` 를 `rag.rag_bridge_client` 로 돌리면 된다.

계약 (docs/V10_3_LLM_BACKEND_PLAN.md §P1)
-----------------------------------------
    generate_rag_response(system, user, meta) -> dict
        meta   = {task, req_id, rag_query, config, ...}   # 입력. **수정하지 않는다**
        return = {"raw": "<JSON 문자열>", "diagnostics": {...}}

퍼저 쪽 브리지가 이 dict 와 기존 문자열 반환을 모두 정규화한다. 진단은 **같은 요청의**
아카이브로 들어간다 — 모듈 전역의 '마지막 응답' 같은 통로를 쓰지 않는다(요청이 겹칠 때
엉뚱한 요청에 귀속된다).

의존성
------
표준 라이브러리만 쓴다(`urllib`). 오프라인 리그에 pip 설치 단계를 만들지 않는 것이
OpenAI SDK 대비 이득이다(계획 D2). 토크나이저도 쓰지 않는다 — 길이 제한은 문자 수
기준이며 **정확한 토큰 수를 보장한다고 표현하지 않는다**(계획 D7).
"""
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_log = logging.getLogger()          # 태그를 '[LLM' 로 시작시켜야 llm 전용 로그에 실린다

# ── 설정 ──────────────────────────────────────────────────────────────────
DEFAULTS = {
    "base_url": "http://127.0.0.1:8000/v1",
    "api_key": "not-used",                  # 인증 없음. 서버가 값만 요구한다
    "model": "nemotron-3-super",
    "timeout_sec": 300.0,                   # 요청 전체(임베딩+생성)의 시간 예산
    "connect_timeout_sec": 10.0,
    "max_tokens": 16384,
    "temperature": 0.7,
    "max_response_bytes": 8 * 1024 * 1024,  # 응답 크기 상한(계획 D2)
    "structured_output": True,
    "include_generators_in_schema": True,   # 중첩 anyOf 를 못 다루는 백엔드용 탈출구
    "freeform_retry": False,                # 스키마 거부 시 자유 형식 재시도 — 기본 꺼짐
    "retries": 1,                           # 통신 실패 재시도 횟수(제한적)
    "retrieval": {},                        # P2. rag_retrieval.py 참조
}


def _config(meta):
    """퍼저가 넘긴 실제 설정을 쓴다. 없으면 파일에서 읽되 그건 폴백일 뿐이다.

    백엔드가 기본 fuzzer_config.json 을 독자적으로 읽으면 퍼저의 --config 로 고른
    설정과 어긋난다 — meta 경로가 정본이다.
    """
    cfg = (meta or {}).get("config")
    if isinstance(cfg, dict) and cfg:
        vllm = cfg.get("rag", {}).get("vllm", {}) if "rag" in cfg else cfg
    else:
        vllm = {}
        try:
            path = Path(__file__).resolve().parent.parent / "fuzzer_config.json"
            vllm = json.loads(path.read_text(encoding="utf-8")).get("rag", {}).get("vllm", {})
        except Exception as exc:
            _log.warning("[LLM/vllm] fuzzer_config.json 을 읽지 못했습니다(기본값 사용): %s", exc)
    out = dict(DEFAULTS)
    out.update({k: v for k, v in (vllm or {}).items() if k in DEFAULTS})
    for k in ("base_url", "api_key", "model"):
        env = os.environ.get("RAG_VLLM_" + k.upper())
        if env:
            out[k] = env
    out["base_url"] = str(out["base_url"]).rstrip("/")
    return out


class BackendError(RuntimeError):
    """백엔드 실패. 메시지에 HTTP 상태와 응답 본문 앞부분을 반드시 담는다.

    이번 이관의 발단이 오류 본문을 버려 KeyError 한 단어만 남은 사고였다.
    """


def _post(url, payload, cfg):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {cfg['api_key']}"})
    try:
        with urllib.request.urlopen(req, timeout=cfg["timeout_sec"]) as resp:
            raw = resp.read(int(cfg["max_response_bytes"]) + 1)
    except urllib.error.HTTPError as exc:                  # 4xx/5xx — 본문을 살린다
        detail = ""
        try:
            detail = exc.read(4096).decode("utf-8", "replace")
        except Exception:
            pass
        raise BackendError(f"HTTP {exc.code} {url}: {detail[:1000]}") from None
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise BackendError(f"연결 실패 {url}: {exc}") from None
    if len(raw) > int(cfg["max_response_bytes"]):
        raise BackendError(f"응답이 상한({cfg['max_response_bytes']}B)을 넘었습니다")
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except ValueError as exc:
        raise BackendError(f"JSON 이 아닌 응답: {exc}; {raw[:500]!r}") from None


def _chat(system, user, cfg, schema, deadline):
    payload = {
        "model": cfg["model"],
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "max_tokens": int(cfg["max_tokens"]),
        "temperature": float(cfg["temperature"]),
    }
    if schema is not None:
        payload["response_format"] = {"type": "json_schema", "json_schema": schema}
    left = deadline - time.monotonic()
    if left <= 0:
        raise BackendError("시간 예산 소진 — 생성 요청을 보내지 않았습니다")
    call = dict(cfg, timeout_sec=min(cfg["timeout_sec"], left))
    data = _post(cfg["base_url"] + "/chat/completions", payload, call)
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        raise BackendError(f"choices 없음: {str(data)[:500]}")
    message = choices[0].get("message") or {}
    text = message.get("content")
    if not isinstance(text, str):
        raise BackendError(f"content 가 문자열이 아님: {str(choices[0])[:500]}")
    return text, {
        "finish_reason": choices[0].get("finish_reason"),
        "usage": data.get("usage"),
        "model": data.get("model"),
        # 일부 모델은 사고 과정을 따로 준다. 길이만 남기고 본문은 싣지 않는다.
        "reasoning_chars": len(message.get("reasoning_content") or ""),
        "schema_enforced": schema is not None,
    }


def generate_rag_response(system, user, meta=None):
    """퍼저가 부르는 진입점.

    반환 형태가 호출자에 따라 다르다 — `fuzzer_config.json` 이 v10.2 와 공유되기
    때문이다. meta 를 넘긴 호출자(v10.3)에게는 {"raw", "diagnostics"} 를 주고,
    meta 없이 부른 구버전에는 **기존 계약대로 문자열**을 주고 실패는 raise 한다.
    이렇게 해야 두 버전이 같은 설정으로 이 백엔드를 쓸 수 있다.
    """
    legacy = meta is None
    started = time.monotonic()
    cfg = _config(meta)
    deadline = started + float(cfg["timeout_sec"])
    meta = dict(meta or {})                 # 입력을 수정하지 않는다
    task = meta.get("task")
    diag = {"task": task, "req_id": meta.get("req_id"), "backend": "vllm",
            "base_url": cfg["base_url"], "model": cfg["model"]}

    # ── 검색(P2). 인덱스가 없으면 조용히 건너뛴다 ──
    context, retrieval = "", {"enabled": False}
    try:
        from rag import rag_retrieval
        context, retrieval = rag_retrieval.retrieve(meta, cfg, deadline)
    except ImportError:
        pass
    except Exception as exc:                # 검색 실패가 생성을 막지 않는다
        retrieval = {"enabled": True, "error": f"{type(exc).__name__}: {exc}"}
        _log.warning("[LLM/vllm] 검색 실패 — 문서 없이 생성합니다: %s", exc)
    diag["retrieval"] = retrieval
    if context:
        user = f"{user}\n\n[참고 문서]\n{context}"

    schema = None
    if cfg["structured_output"]:
        try:
            from rag.llm_schema import build_schema
            patterns = ((meta.get("config") or {}).get("io_workload", {}) or {}).get("patterns") or []
            schema = build_schema(task, patterns, bool(cfg["include_generators_in_schema"]))
        except Exception as exc:
            _log.warning("[LLM/vllm] 스키마 생성 실패 — 자유 형식으로 보냅니다: %s", exc)

    attempts = max(1, int(cfg["retries"]) + 1)
    last = None
    for i in range(attempts):
        if time.monotonic() >= deadline:
            last = BackendError("시간 예산 소진")
            break
        try:
            text, info = _chat(system, user, cfg, schema, deadline)
            diag.update(info)
            diag["attempts"] = i + 1
            diag["elapsed_sec"] = round(time.monotonic() - started, 3)
            if info.get("finish_reason") == "length":
                # 잘렸다. 파싱은 실패할 가능성이 높고, 그 판단은 퍼저 파서가 한다.
                _log.warning("[LLM/vllm] 출력 상한에서 잘렸습니다(max_tokens=%s) — "
                             "응답이 불완전할 수 있습니다", cfg["max_tokens"])
            if legacy:
                return text
            return {"raw": text, "diagnostics": diag}
        except BackendError as exc:
            last = exc
            # 스키마 거부로 보이면, 설정으로 켠 경우에만 자유 형식으로 한 번 더.
            if schema is not None and cfg["freeform_retry"] and "HTTP 4" in str(exc):
                _log.warning("[LLM/vllm] 스키마가 거부된 것으로 보입니다 — "
                             "freeform_retry 설정에 따라 자유 형식으로 재시도: %s", exc)
                diag["schema_rejected"] = str(exc)[:500]
                schema = None
                continue
            if i + 1 < attempts:
                _log.warning("[LLM/vllm] 호출 실패(%d/%d) — 재시도: %s", i + 1, attempts, exc)

    diag["attempts"] = attempts
    diag["elapsed_sec"] = round(time.monotonic() - started, 3)
    diag["error"] = str(last) if last else "알 수 없는 실패"
    _log.error("[LLM/vllm] 실패: %s", diag["error"])
    if legacy:
        raise last if last else BackendError(diag["error"])
    return {"raw": "", "diagnostics": diag, "error": diag["error"]}
