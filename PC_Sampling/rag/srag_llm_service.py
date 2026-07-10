#!/usr/bin/env python3
"""온라인 PC 용 RAG 브리지 서비스 — Samba 공유 drop-box 를 폴링해 실제 LLM 을 처리한다.

오프라인 fuzzer 의 rag_bridge_client.py 가 _BRIDGE/requests/ 에 쓴 요청을 읽어 실제 LLM
함수(generate_rag_response)를 호출하고 _BRIDGE/responses/ 에 답을 쓴다. 온라인 PC 에서
계속 띄워둔다. 요청/응답 파일은 처리 후 삭제(stateless — 서비스 재시작해도 남은 요청부터).

실행 (인자 불필요 — 같은 폴더에 srag_llm_guide.py 두고):
  python3 srag_llm_service.py

설정은 아래 상수만 필요시 수정(환경변수로도 override 가능).
"""
import importlib
import json
import os
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))   # 같은 폴더의 srag_llm_guide.py 를 import 가능하게

# ═══════════════ 설정 — 필요시 이 값만 수정 (실행 인자 불필요) ═══════════════
LLM_MODULE = "srag_llm_guide"          # 같은 폴더의 srag_llm_guide.py (실제 LLM 함수 보유)
LLM_FUNC   = "generate_rag_response"   # 그 안의 함수명. generate_rag_response(user)->str
BRIDGE_DIR = _HERE / "bridge"          # Samba 공유 drop-box. 오프라인 PC 와 같은 물리 폴더여야 함.
#            ↑ 이 서비스가 공유 폴더에서 돌면 그대로 OK. 마운트 위치가 다르면 실제 경로로:
#              예) BRIDGE_DIR = Path("/mnt/samba_share/bridge")
# ══════════════════════════════════════════════════════════════════════════

# (선택) 환경변수 override — 없으면 위 기본값 사용
LLM_MODULE = os.environ.get("RAG_LLM_MODULE", LLM_MODULE)
LLM_FUNC = os.environ.get("RAG_LLM_FUNC", LLM_FUNC)
BRIDGE_DIR = Path(os.environ.get("RAG_BRIDGE_DIR", BRIDGE_DIR))

_REQ = BRIDGE_DIR / "requests"
_RESP = BRIDGE_DIR / "responses"
_POLL = 0.5

try:
    _llm_call = getattr(importlib.import_module(LLM_MODULE), LLM_FUNC)
except Exception as e:
    sys.exit(f"[RAG service] LLM 로드 실패: {LLM_MODULE}.{LLM_FUNC} — {e}\n"
             f"  → 같은 폴더에 {LLM_MODULE}.py 가 있고 {LLM_FUNC}() 가 정의됐는지 확인하세요.")

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
    print(f"[RAG service] watching {_REQ}  (LLM={LLM_MODULE}.{LLM_FUNC})", flush=True)
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
