#!/usr/bin/env python3
"""온라인 PC 용 RAG 브리지 서비스 — Samba 공유 drop-box 를 폴링해 실제 LLM 을 처리한다.

오프라인 fuzzer 의 srag_llm_guide.py 가 _BRIDGE/requests/ 에 쓴 요청을 읽어 실제 LLM
함수(generate_rag_response)를 호출하고 _BRIDGE/responses/ 에 답을 쓴다. 온라인 PC 에서
계속 띄워둔다. 요청/응답 파일은 처리 후 삭제(stateless — 서비스 재시작해도 남은 요청부터).

실행:
  RAG_LLM_MODULE=<실제LLM모듈> python3 srag_llm_service.py

환경변수:
  RAG_LLM_MODULE : 실제 LLM 함수가 있는 모듈명(필수). 예: my_internal_llm
                   (그 함수는 generate_rag_response(user_prompt) -> str 형태, system 내장)
  RAG_LLM_FUNC   : 함수명(기본 generate_rag_response)
  RAG_BRIDGE_DIR : 공유 drop-box 경로(기본: 이 파일 옆 bridge/). 오프라인 PC 와 같은 물리 폴더.
"""
import importlib
import json
import os
import sys
import time
from pathlib import Path

_LLM_MODULE = os.environ.get("RAG_LLM_MODULE")
_LLM_FUNC = os.environ.get("RAG_LLM_FUNC", "generate_rag_response")
_BRIDGE = Path(os.environ.get("RAG_BRIDGE_DIR",
                              Path(__file__).resolve().parent / "bridge"))
_REQ = _BRIDGE / "requests"
_RESP = _BRIDGE / "responses"
_POLL = 0.5

if not _LLM_MODULE:
    sys.exit("[RAG service] RAG_LLM_MODULE 환경변수로 실제 LLM 모듈명을 지정하세요 "
             "(예: RAG_LLM_MODULE=my_internal_llm python3 srag_llm_service.py)")

try:
    _llm_call = getattr(importlib.import_module(_LLM_MODULE), _LLM_FUNC)
except Exception as e:
    sys.exit(f"[RAG service] LLM 로드 실패: {_LLM_MODULE}.{_LLM_FUNC} — {e}")

_REQ.mkdir(parents=True, exist_ok=True)
_RESP.mkdir(parents=True, exist_ok=True)


def _atomic_write(path: Path, text: str):
    tmp = path.parent / (path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _unlink(path: Path):
    try:
        path.unlink()
    except OSError:
        pass


def main():
    print(f"[RAG service] watching {_REQ}  (LLM={_LLM_MODULE}.{_LLM_FUNC})", flush=True)
    while True:
        for req in sorted(_REQ.glob("req_*.json")):
            try:
                data = json.loads(req.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                continue   # 아직 쓰는 중 → 다음 라운드 재시도
            rid = data.get("id", "?")
            try:
                out = {"id": rid, "text": _llm_call(data["user_prompt"])}
            except Exception as e:   # LLM 오류는 응답에 실어 오프라인 쪽이 알게
                out = {"id": rid, "text": "", "error": str(e)}
            _atomic_write(_RESP / f"resp_{rid}.json",
                          json.dumps(out, ensure_ascii=False))
            _unlink(req)
            print(f"[RAG service] handled {rid}"
                  f"{' (error)' if out.get('error') else ''}", flush=True)
        time.sleep(_POLL)


if __name__ == "__main__":
    main()
