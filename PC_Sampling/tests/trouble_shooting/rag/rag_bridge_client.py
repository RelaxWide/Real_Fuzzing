#!/usr/bin/env python3
"""■ 배치: **오프라인 퍼징 PC** — 리포 안 `PC_Sampling/rag/` 그대로 (fuzzer 가 import).
   config `rag.module_path="rag.rag_bridge_client"` 가 이 경로를 가리킨다. 옮기지 말 것.
   짝이 되는 온라인 쪽 파일 = srag_llm_service.py (그건 LLM PC 에 둔다).

오프라인 PC(fuzzer)용 RAG 브리지 클라이언트 — Samba 공유 drop-box 경유로 온라인 LLM 호출.

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
import logging
import os
import time
import uuid
from pathlib import Path

_BRIDGE = Path(os.environ.get("RAG_BRIDGE_DIR",
                              Path(__file__).resolve().parent / "bridge"))
_REQ = _BRIDGE / "requests"
_RESP = _BRIDGE / "responses"
_TIMEOUT = float(os.environ.get("RAG_BRIDGE_TIMEOUT", "180"))   # 응답 대기 상한(초)
# 이 모듈은 fuzzer 의 워커 스레드 안에서 돈다 → fuzzer 루트 로거를 그대로 쓴다.
# 태그를 '[LLM' 로 시작시켜야 터미널 필터와 llm/ 전용 로그 파일(_LlmOnlyFilter)에 함께 실린다.
_log = logging.getLogger()
_POLL = 0.5

_REQ.mkdir(parents=True, exist_ok=True)
_RESP.mkdir(parents=True, exist_ok=True)


def _chmod_shared(path: Path):
    """공유 drop-box 파일은 **다른 계정**(온라인 PC 의 Samba 계정)이 읽고 지워야 한다.
    퍼저는 sudo 로 돌아 파일이 root 소유로 생기는데, 프로세스 umask 가 빡빡하면 0600 이
    되어 상대가 못 읽는다. 그 경우 서비스는 목록에는 보이지만 read 에 실패해 **조용히
    건너뛴다**(로그도 없음) → 요청이 영원히 처리되지 않는다. 그래서 명시적으로 완화한다.
    """
    try:
        os.chmod(path, 0o666)
    except OSError:
        pass


def _atomic_write(path: Path, text: str):
    """.tmp 로 쓰고 rename → 읽는 쪽이 부분 파일을 보지 않게(같은 폴더 rename = atomic)."""
    tmp = path.parent / (path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)
    _chmod_shared(path)


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
    req = _REQ / f"req_{rid}.json"
    _atomic_write(req, json.dumps({"id": rid, "user_prompt": user_prompt}, ensure_ascii=False))
    # 이 줄이 없으면 "요청을 정말 만들었나 / 어디에 만들었나" 를 확인할 방법이 없다.
    #   서비스가 요청을 못 봤을 때 퍼저·서비스 양쪽 로그가 모두 조용해 진단이 막혔었다.
    try:
        _mode = oct(req.stat().st_mode & 0o777)
        _log.warning(f"[LLM/bridge] 요청 생성: {req}  (프롬프트 {len(user_prompt):,}자, mode={_mode})")
    except OSError as _e:
        _log.warning(f"[LLM/bridge] 요청 생성 직후 stat 실패: {req} — {_e}")
    _t0 = time.monotonic()
    resp = _RESP / f"resp_{rid}.json"
    deadline = _t0 + _TIMEOUT
    while time.monotonic() < deadline:
        if resp.exists():
            try:
                data = json.loads(resp.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                time.sleep(_POLL)   # 아직 쓰는 중이거나 SMB 동기화 전 → 재시도
                continue
            _unlink(resp)
            _log.warning(f"[LLM/bridge] 응답 수신: {rid} ({time.monotonic() - _t0:.1f}s)")
            if data.get("error"):
                raise RuntimeError(f"RAG service error: {data['error']}")
            return data.get("text", "")
        time.sleep(_POLL)
    # 타임아웃 시 요청 파일이 **아직 남아 있는지**가 결정적 단서다:
    #   남아 있음 → 서비스가 그 파일을 한 번도 집어가지 못함(가시성/권한/서비스 정지)
    #   사라짐    → 서비스가 처리는 했는데 응답이 이쪽으로 안 돌아옴(응답 경로 문제)
    _still = req.exists()
    _unlink(req)                       # timeout → 요청 파일 정리
    _log.warning(f"[LLM/bridge] 타임아웃 {_TIMEOUT:.0f}s — 요청파일 잔존={_still} "
                 f"({'서비스가 집어가지 못함' if _still else '서비스가 가져갔으나 응답 미도달'})")
    raise TimeoutError(f"RAG bridge timeout ({_TIMEOUT:.0f}s) — 온라인 srag_llm_service 확인")
