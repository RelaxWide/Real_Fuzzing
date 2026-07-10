#!/usr/bin/env python3
"""오프라인 PC(fuzzer)용 RAG 브리지 클라이언트 — Samba 공유 drop-box 경유로 온라인 LLM 호출.

주의: 이 파일은 LLM 을 직접 부르지 않는 '배달부'다. 실제 LLM 코드(env 설정 + generate_rag
_response)는 온라인 PC 에 두고 srag_llm_service.py 가 부른다(같은 이름과 헷갈리지 말 것).

fuzzer 는 이 파일의 generate_rag_response(user_prompt) 를 백그라운드 워커로 호출한다
(config: module_path="rag.rag_bridge_client", func_name="generate_rag_response",
pass_system_prompt=false). 이 함수는 공유 폴더(_BRIDGE)의 requests/ 에 요청 파일을 쓰고
responses/ 에 응답이 나타날 때까지 폴링(블록)한다. 실제 LLM 은 온라인 PC 의
srag_llm_service.py 가 처리한다. 워커 스레드에서 블록하므로 fuzzing 은 멈추지 않고,
서비스가 죽거나 느리면 timeout → 워커가 잡아 그 라운드만 건너뛴다(graceful).

_BRIDGE: 양쪽 PC 가 같은 물리 폴더를 보는 Samba 공유 위여야 한다. 기본값은 이 파일 옆의
bridge/ (rag/ 가 공유 마운트면 그대로 OK). 마운트 지점이 다르면 RAG_BRIDGE_DIR 환경변수로
지정 — fuzzer 가 sudo 로 돌면 `sudo -E` 로 env 를 넘긴다.
"""
import json
import os
import time
import uuid
from pathlib import Path

_BRIDGE = Path(os.environ.get("RAG_BRIDGE_DIR",
                              Path(__file__).resolve().parent / "bridge"))
_REQ = _BRIDGE / "requests"
_RESP = _BRIDGE / "responses"
_TIMEOUT = float(os.environ.get("RAG_BRIDGE_TIMEOUT", "180"))   # 응답 대기 상한(초)
_POLL = 0.5

_REQ.mkdir(parents=True, exist_ok=True)
_RESP.mkdir(parents=True, exist_ok=True)


def _atomic_write(path: Path, text: str):
    """.tmp 로 쓰고 rename → 읽는 쪽이 부분 파일을 보지 않게. SMB 공유는 write 버퍼가
    서버에 늦게 반영되어 온라인쪽이 '빈 파일'을 먼저 볼 수 있으므로, flush+fsync 로
    내용을 서버에 완전히 밀어넣은 뒤 rename 한다(빈/부분 파일 경합 방지)."""
    tmp = path.parent / (path.name + ".tmp")
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _unlink(path: Path):
    try:
        path.unlink()
    except OSError:
        pass


def generate_rag_response(user_prompt: str) -> str:
    """공유 drop-box 에 요청을 쓰고 응답을 폴링해 텍스트 반환. 워커 스레드에서 블록.
    fuzzer 는 이 함수를 pass_system_prompt=false 로 부르므로 user_prompt 에는 이미
    (system 지시 + task) 가 합쳐져 온다 — 그대로 온라인 LLM 으로 넘긴다."""
    rid = f"{int(time.time() * 1000)}_{os.getpid()}_{uuid.uuid4().hex[:8]}"
    _atomic_write(_REQ / f"req_{rid}.json",
                  json.dumps({"id": rid, "user_prompt": user_prompt}, ensure_ascii=False))
    resp = _RESP / f"resp_{rid}.json"
    deadline = time.monotonic() + _TIMEOUT
    while time.monotonic() < deadline:
        if resp.exists():
            try:
                data = json.loads(resp.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                time.sleep(_POLL)   # 아직 쓰는 중이거나 SMB 동기화 전 → 재시도
                continue
            _unlink(resp)
            if data.get("error"):
                raise RuntimeError(f"RAG service error: {data['error']}")
            return data.get("text", "")
        time.sleep(_POLL)
    _unlink(_REQ / f"req_{rid}.json")   # timeout → 요청 파일 정리
    raise TimeoutError(f"RAG bridge timeout ({_TIMEOUT:.0f}s) — 온라인 srag_llm_service 확인")
