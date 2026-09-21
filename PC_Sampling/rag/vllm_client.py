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

_log = logging.getLogger("pcfuzz.rag.vllm_client")          # 태그를 '[LLM' 로 시작시켜야 llm 전용 로그에 실린다

# ── 설정 ──────────────────────────────────────────────────────────────────
DEFAULTS = {
    "base_url": "http://127.0.0.1:8000/v1",
    "api_key": "not-used",                  # 인증 없음. 서버가 값만 요구한다
    "model": "nemotron-3-super",
    # 요청 전체(임베딩+생성+JSON 교정)의 시간 예산. urllib 은 연결 단계만 따로
    #   제한하지 못해 별도 connect timeout 설정을 두지 않는다 — 있으면 지켜지는
    #   것처럼 보이지만 실제로는 아무것도 안 하는 값이 된다.
    "timeout_sec": 300.0,
    "max_tokens": 16384,
    "temperature": 0.7,
    "chat_template_kwargs": None,          # None: 서버 기본값. Nemotron low_effort 등
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
            # utf-8-sig — Windows 편집기의 BOM 을 흡수한다(없어도 그대로 읽힌다).
            vllm = json.loads(path.read_text(encoding="utf-8-sig")).get("rag", {}).get("vllm", {})
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


_READ_CHUNK = 64 * 1024     # 예산을 다시 보기까지 한 번에 읽는 최대 바이트


def _sock_of(resp):
    """응답의 소켓. 읽기마다 타임아웃을 남은 예산으로 갱신하기 위해 필요하다.

    `.fp` 를 따라가며 `.raw._sock` 을 찾는다. 겹 수가 경로마다 다르기 때문이다 —
    정상 응답은 HTTPResponse.fp 가 바로 BufferedReader 이지만, HTTPError 는 실제
    HTTPResponse 를 한 겹 더 감싸서(exc.fp.fp.raw._sock) 한 단계만 보면 놓친다.
    CPython 내부 구조에 기대므로 못 찾으면 None — 그 경우에도 조각마다 하는
    예산 검사는 그대로 동작한다.
    """
    obj = resp
    for _ in range(4):
        sock = getattr(getattr(obj, "raw", None), "_sock", None)
        if sock is not None:
            return sock
        obj = getattr(obj, "fp", None)
        if obj is None:
            break
    return None


def _read_bounded(resp, limit, deadline, url, what="응답", partial_ok=False):
    """예산을 지키며 읽는다. 모든 수신 경로가 **이 함수 하나**를 쓴다.

    `read1` 로 도착한 만큼만 받아 조각마다 예산을 보고, 소켓 타임아웃도 **읽기마다**
    남은 예산으로 줄인다. 연결 전에 한 번만 계산해 두면, 스트림 중간에 서버가 멈췄을
    때 그 한 번의 read 가 예산을 한참 넘겨서야 풀린다.

    `(본문, 중단 사유 또는 None)` 을 돌려준다. **읽기 예외도 안에서 처리한다** —
    소켓 타임아웃이 read1 안에서 터지면 이미 모은 조각까지 함께 잃기 때문이다.

    partial_ok=True 면 예산이 다하거나 수신이 끊겨도 받은 만큼을 돌려준다(HTTP 오류
    본문 — 예산보다 오래 걸려도 **받은 데까지는** 오류 내용을 보고하는 편이 낫다).
    False 면 같은 상황에서 예외를 올린다.
    """
    sock = _sock_of(resp)
    read1 = getattr(resp, "read1", None) or resp.read
    parts, total, stopped = [], 0, None
    while total <= limit:
        if deadline is not None:
            left = deadline - time.monotonic()
            if left <= 0:
                stopped = (f"시간 예산 초과 — {what} 수신을 중단했습니다 "
                           f"({url}, {total}B 수신)")
                break
            if sock is not None:
                try:
                    sock.settimeout(left)
                except OSError:
                    sock = None
        try:
            block = read1(min(_READ_CHUNK, limit + 1 - total))
        except Exception as exc:
            # 읽기 타임아웃을 남은 예산으로 줄여 두었으므로, 예산이 다한 뒤의
            #   타임아웃은 수신 실패가 아니라 예산 초과다.
            if deadline is not None and time.monotonic() >= deadline:
                stopped = (f"시간 예산 초과 — {what} 수신 중 중단 "
                           f"({url}, {total}B 수신)")
            else:
                stopped = f"{what} 수신 실패 ({url}, {total}B 수신): {exc}"
            break
        if not block:
            break
        parts.append(block)
        total += len(block)
    if stopped and not partial_ok:
        raise BackendError(stopped)
    return b"".join(parts), stopped


def _post(url, payload, cfg, deadline=None):
    """POST + JSON 파싱. `deadline` 이 있으면 **수신 중에도** 예산을 본다.

    `urlopen(timeout=)` 은 소켓 연산 하나하나의 상한이라 총 경과 시간을 막지
    못한다. 서버가 조금씩 흘려보내면 recv 마다 타이머가 되감겨 예산을 한참
    넘긴 응답도 성공으로 돌아왔다.

    수신은 성공·오류 경로 모두 `_read_bounded` 하나로 처리한다 — 오류 본문만
    예산 밖에서 읽으면 느린 4xx/5xx 가 예산을 통째로 우회한다.
    """
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {cfg['api_key']}"})
    limit = int(cfg["max_response_bytes"])
    sock_timeout = float(cfg["timeout_sec"])
    if deadline is not None:
        left = deadline - time.monotonic()
        if left <= 0:
            raise BackendError(f"시간 예산 소진 — 요청을 보내지 않았습니다 ({url})")
        sock_timeout = min(sock_timeout, left)
    try:
        with urllib.request.urlopen(req, timeout=sock_timeout) as resp:
            raw, _ = _read_bounded(resp, limit, deadline, url)
    except urllib.error.HTTPError as exc:                  # 4xx/5xx — 본문을 살린다
        # 오류 본문도 같은 예산 아래 읽되, 끊기거나 예산이 다해도 받은 만큼과
        #   중단 사유를 **둘 다** 싣는다 — 오류 내용을 버리지 않는 것이 이번
        #   이관의 발단이었고, 왜 잘렸는지도 같이 알아야 추적이 된다.
        detail, note = "", ""
        try:
            body, stopped = _read_bounded(exc, 4096, deadline, url,
                                          "오류 본문", partial_ok=True)
            detail = body.decode("utf-8", "replace")
            if stopped:
                note = f" [{stopped}]"
        except Exception as read_exc:      # 여기로 오면 안 되지만 상태는 남긴다
            note = f" [오류 본문 수신 실패: {read_exc}]"
        raise BackendError(f"HTTP {exc.code} {url}: {detail[:1000]}{note}") from None
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        # 읽기 타임아웃을 남은 예산으로 줄여 두었으므로, 예산이 다한 뒤의 타임아웃은
        #   '연결 실패'가 아니라 예산 초과다. 원인을 바르게 불러야 추적이 된다.
        if deadline is not None and time.monotonic() >= deadline:
            raise BackendError(f"시간 예산 초과 — {url}: {exc}") from None
        raise BackendError(f"연결 실패 {url}: {exc}") from None
    if len(raw) > limit:
        raise BackendError(f"응답이 상한({limit}B)을 넘었습니다")
    if deadline is not None and time.monotonic() >= deadline:
        # 예산을 넘겨 도착한 결과는 **폐기한다**(계획 P1 의 계약).
        raise BackendError(f"시간 예산 초과 — 도착한 응답을 폐기합니다 ({url})")
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
    template = cfg.get("chat_template_kwargs")
    if template is not None:
        if not isinstance(template, dict):
            raise BackendError("chat_template_kwargs 는 JSON 객체 또는 null 이어야 합니다")
        for key in ("enable_thinking", "low_effort"):
            if key in template and not isinstance(template[key], bool):
                raise BackendError(f"chat_template_kwargs.{key} 는 true/false 이어야 합니다")
        payload["chat_template_kwargs"] = dict(template)
    if schema is not None:
        payload["response_format"] = {"type": "json_schema", "json_schema": schema}
    left = deadline - time.monotonic()
    if left <= 0:
        raise BackendError("시간 예산 소진 — 생성 요청을 보내지 않았습니다")
    data = _post(cfg["base_url"] + "/chat/completions", payload, cfg, deadline=deadline)
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        raise BackendError(f"choices 없음: {str(data)[:500]}")
    message = choices[0].get("message") or {}
    text = message.get("content")
    if not isinstance(text, str):
        raise BackendError(f"content 가 문자열이 아님: {str(choices[0])[:500]}")
    # 서버/파서 버전에 따라 reasoning_content 또는 reasoning 으로 분리된다.
    # 두 키가 함께 있으면 한 필드만 선택해 중복 집계하지 않는다.
    reasoning, reasoning_field = "", None
    for key in ("reasoning_content", "reasoning"):
        value = message.get(key)
        if isinstance(value, str) and value:
            reasoning, reasoning_field = value, key
            break
    return text, {
        "finish_reason": choices[0].get("finish_reason"),
        "usage": data.get("usage"),
        "model": data.get("model"),
        # 일부 모델은 사고 과정을 따로 준다. 길이만 남기고 본문은 싣지 않는다.
        "reasoning_chars": len(reasoning),
        "reasoning_field": reasoning_field,
        "content_chars": len(text),
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
    meta = dict(meta or {})                 # 입력을 수정하지 않는다
    # 예산의 기준 시각. 호출자가 budget_started 를 주면 **최초 호출과 JSON 교정
    #   호출이 하나의 예산을 나눠 쓴다** — 호출마다 새로 주면 json_retries 배만큼
    #   늘어나 요청 하나가 timeout_sec 를 몇 배씩 붙들고 있게 된다.
    _budget_from = meta.get("budget_started")
    if not isinstance(_budget_from, (int, float)) or isinstance(_budget_from, bool):
        _budget_from = started
    deadline = float(_budget_from) + float(cfg["timeout_sec"])
    task = meta.get("task")
    diag = {"task": task, "req_id": meta.get("req_id"), "backend": "vllm",
            "base_url": cfg["base_url"], "model": cfg["model"],
            "requested_chat_template_kwargs": cfg.get("chat_template_kwargs")}

    # 검색 사다리 2단(`[RAG-QUERY]` 블록)은 프롬프트 본문에서 찾는다. meta 를 안
    #   넘기는 구버전 호출은 user_prompt 가 비어 블록이 있어도 못 찾았다. setdefault
    #   라 v10.3 워커가 실어 보낸 **원본** 프롬프트는 교정 호출에서도 덮이지 않는다.
    meta.setdefault("user_prompt", user)

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
