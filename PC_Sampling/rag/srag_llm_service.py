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
import threading
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
    _llm_mod = importlib.import_module(LLM_MODULE)
    _llm_call = getattr(_llm_mod, LLM_FUNC)
except Exception as e:
    sys.exit(f"[RAG service] LLM 로드 실패: {LLM_MODULE}.{LLM_FUNC} — {e}\n"
             f"  → 같은 폴더에 {LLM_MODULE}.py 가 있고 {LLM_FUNC}() 가 정의됐는지 확인하세요.")

# LLM 호출 상한(초). 오프라인 클라이언트 타임아웃(RAG_BRIDGE_TIMEOUT, 기본 180s)보다 짧게
# 잡아야, 매달린 호출을 포기하고 **오류 응답이라도** 제때 돌려줄 수 있다.
_CALL_TIMEOUT = float(os.environ.get("RAG_CALL_TIMEOUT", "150"))

_REQ.mkdir(parents=True, exist_ok=True)
_RESP.mkdir(parents=True, exist_ok=True)


def _reload_llm():
    """LLM 모듈을 다시 import 해 모듈 레벨 세션/클라이언트를 새로 만든다(= 재연결).

    유휴 TCP 연결이 방화벽/NAT 에 조용히 끊기면, 모듈 레벨에 살아 있는 requests.Session
    이나 LLM 클라이언트가 죽은 소켓을 계속 재사용해 응답 없이 매달린다. 모듈을 reload
    하면 그 객체들이 새로 생성돼 연결이 다시 맺힌다 — guide 파일 내용을 몰라도 통한다.
    """
    global _llm_mod, _llm_call
    _llm_mod = importlib.reload(_llm_mod)
    _llm_call = getattr(_llm_mod, LLM_FUNC)


def _call_once(prompt: str, timeout: float) -> str:
    """별도 스레드로 호출해 timeout 안에 안 끝나면 포기.

    파이썬은 스레드를 강제 종료할 수 없어 매달린 스레드는 daemon 으로 남는다(프로세스
    종료 시 정리). 대신 **서비스 루프가 통째로 멈추는 것**을 막는다 — 이게 핵심이다.
    """
    box = {}

    def _run():
        try:
            box['ok'] = _llm_call(prompt)
        except Exception as exc:
            box['err'] = exc

    th = threading.Thread(target=_run, daemon=True)
    th.start()
    th.join(timeout)
    if th.is_alive():
        raise TimeoutError(f"LLM 호출이 {timeout:.0f}초 안에 끝나지 않음(응답 없음)")
    if 'err' in box:
        raise box['err']
    return box.get('ok', '')


def _call_llm_resilient(prompt: str):
    """호출 → 실패 시 모듈 reload(재연결) → 1회 재시도. (text, error) 반환."""
    try:
        return _call_once(prompt, _CALL_TIMEOUT), None
    except Exception as e1:
        _log(f"⚠ LLM 호출 실패: {e1}")
        _log("⚠   연결이 끊긴 것으로 보고 모듈을 다시 로드해 재연결 후 1회 재시도합니다.")
        try:
            _reload_llm()
        except Exception as e_rl:
            _log(f"⚠   모듈 reload 실패(무시하고 재시도): {e_rl}")
        try:
            _text = _call_once(prompt, _CALL_TIMEOUT)
            _log("✓ 재연결 후 성공")
            return _text, None
        except Exception as e2:
            _log(f"⚠ 재시도도 실패: {e2}")
            return "", f"{e2} (재연결 재시도 후에도 실패)"


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
    # 타임스탬프 필수 — 요청 간 공백/처리 지연을 사후에 읽으려면 시각이 있어야 한다.
    print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [RAG service] {msg}", flush=True)


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
            _prompt = data.get("user_prompt") or ""
            # 처리 '시작' 을 먼저 찍는다. 이 서비스는 단일 스레드 동기 루프라 _llm_call 하나가
            #   오래 걸리면 그동안 폴링이 통째로 멈추고, 그 사이 들어온 요청은 오프라인 쪽이
            #   180초 뒤 스스로 지워버려 흔적조차 남지 않는다. 완료 시에만 로그하면 '물려 있는
            #   중' 을 알 방법이 없다.
            _log(f"→ processing {rid} (task 프롬프트 {len(_prompt):,}자)")
            _t0 = time.monotonic()
            _text, _err = _call_llm_resilient(_prompt)
            out = {"id": rid, "text": _text}
            if _err:                 # LLM 오류는 응답에 실어 오프라인 쪽이 알게
                out["error"] = _err
            _el = time.monotonic() - _t0
            _atomic_write(_RESP / f"resp_{rid}.json",
                          json.dumps(out, ensure_ascii=False))
            _unlink(req)
            _log(f"handled {rid} ({_el:.1f}s, 응답 {len(out.get('text') or ''):,}자)"
                 f"{' (error)' if out.get('error') else ''}")
            # 오프라인 클라이언트 타임아웃(RAG_BRIDGE_TIMEOUT, 기본 180s)을 넘겼으면 이미
            #   버려진 응답이다 — 다음 요청들도 줄줄이 타임아웃 날 신호이므로 크게 알린다.
            if _el >= 180:
                _log(f"⚠ 처리에 {_el:.0f}초 소요 — 오프라인 기본 타임아웃(180s) 초과. "
                     f"이 응답은 폐기됐을 가능성이 높습니다.")
                _log("⚠   프롬프트가 커졌거나 LLM 이 느려졌습니다. "
                     "RAG_BRIDGE_TIMEOUT 을 올리거나 원인을 확인하세요.")
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
