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
# 유휴 경고 간격(초). 퍼저는 request_cadence(기본 5000 exec) 마다만 요청하므로 수 분 공백은
# 정상이다 → 기본 15분. 공유가 조용히 끊긴 경우를 잡는 게 목적.
_IDLE_WARN_SEC = float(os.environ.get("RAG_IDLE_WARN_SEC", "900"))

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


def _log(msg: str):
    print(f"[RAG service] {msg}", flush=True)


def main():
    _log(f"watching {_REQ}  (LLM={LLM_MODULE}.{LLM_FUNC})")
    _log(f"유휴 경고 간격 {_IDLE_WARN_SEC:.0f}초 (RAG_IDLE_WARN_SEC 로 조정)")
    last_ok = time.monotonic()     # 마지막으로 요청을 처리한(또는 폴더가 멀쩡했던) 시각
    last_warn = 0.0
    broken = False                 # 감시 폴더 접근 불가 상태인지
    while True:
        now = time.monotonic()

        # ── 감시 폴더 건강 확인 ──────────────────────────────────────────────
        # 중요: Path.glob() 은 폴더가 없어도 예외 없이 **빈 목록**을 돌려준다. 즉 공유가
        #   끊기거나 마운트가 사라져도 서비스는 "요청이 없다" 와 구분하지 못해 조용히 멈춘
        #   것처럼 보인다(실제로 그렇게 놓친 사례가 있었다). 그래서 is_dir() 로 명시 확인한다.
        try:
            alive = _REQ.is_dir()
            reqs = sorted(_REQ.glob("req_*.json")) if alive else []
            err = None
        except OSError as e:        # 끊긴 네트워크 드라이브 등
            alive, reqs, err = False, [], e

        if not alive:
            if not broken or (now - last_warn) >= _IDLE_WARN_SEC:
                _log(f"⚠ 감시 폴더에 접근할 수 없습니다: {_REQ}")
                if err:
                    _log(f"⚠   {err}")
                _log("⚠   공유 연결이 끊겼거나 경로가 사라졌습니다. "
                     "드라이브 매핑/네트워크를 확인하세요.")
                last_warn = now
            broken = True
            time.sleep(_POLL)
            continue
        if broken:
            _log(f"✓ 감시 폴더 접근 복구됨: {_REQ}")
            broken = False
            last_ok = now

        # ── 요청 처리 ────────────────────────────────────────────────────────
        for req in reqs:
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
            _log(f"handled {rid}{' (error)' if out.get('error') else ''}")
            last_ok = time.monotonic()
            last_warn = 0.0

        # ── 유휴 경고 ────────────────────────────────────────────────────────
        # 폴더는 멀쩡한데 오래 요청이 없는 경우. 퍼저가 안 돌거나, 퍼저 쪽 경로가 여기와
        # 다른 폴더를 보고 있을 수 있다(양쪽이 서로 다른 물리 폴더면 둘 다 조용하다).
        now = time.monotonic()
        if (now - last_ok) >= _IDLE_WARN_SEC and (now - last_warn) >= _IDLE_WARN_SEC:
            _log(f"⚠ {int((now - last_ok) / 60)}분간 요청 없음 — watching {_REQ}")
            _log("⚠   퍼저가 안 돌고 있거나, 퍼저 쪽이 다른 폴더를 보고 있을 수 있습니다.")
            last_warn = now

        time.sleep(_POLL)


if __name__ == "__main__":
    main()
