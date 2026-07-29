#!/usr/bin/env python3
"""■ 배치: **오프라인 퍼징 PC** — 리포 안 `PC_Sampling/rag/` 그대로.
   rag_bridge_client.py 와 같은 폴더에서 실행한다.

오프라인 PC(fuzzer 쪽)에서 2-PC Samba drop-box 왕복을 단독 점검한다.
하드웨어·fuzzer 불필요. rag_bridge_client 만으로 요청을 쓰고 응답을 받아 JSON 을 확인.

전제:
  - 온라인 PC 에서 srag_llm_service.py 가 떠 있고,
  - 양쪽이 같은 물리 폴더(Samba 공유)의 bridge/ 를 본다.

실행 (rag/ 폴더에서):
    python3 test_bridge.py
  마운트 지점이 다르면:
    RAG_BRIDGE_DIR=/mnt/samba_share/bridge python3 test_bridge.py

확인 내용:
  1) req_*.json 이 공유 requests/ 에 써지고, 온라인 서비스가 처리해 resp_*.json 을 돌려주는가
  2) 반환 문자열에서 fuzzer 와 동일한 brace-scan 으로 JSON 이 뽑히는가
  3) seeds 가 들어있는가

timeout(기본 180s) 안에 응답이 없으면 → 온라인 srag_llm_service 미기동/경로 불일치.
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rag_bridge_client as bc   # noqa: E402  (같은 폴더)

# fuzzer 가 보내는 것과 유사한 프롬프트(system 지시가 접혀 온 형태 — 단일 인자).
PROMPT = (
    "You are an expert NVMe/SSD firmware fuzzing assistant. "
    "Output ONLY a single JSON object, no prose. "
    'Shape: {"seeds":[{"command":<NVMe command name>,"cdw10":<int>,"cdw11":<int>,'
    '"cdw12":<int>,"seed_class":"llm_new_group"}]}. '
    "Each command must be a real NVMe command name and CDW values within spec. "
    "NEVER propose destructive commands (FormatNVM, Sanitize).\n\n"
    "Task: emit 2~3 seeds that exercise Identify (CNS variants) and GetLogPage "
    "(SMART/error/firmware LIDs) with meaningful CDW parameters. JSON only."
)


def _extract_json(text):
    """fuzzer 의 _llm_extract_json 과 동일 — prose 로 감싸도 첫 balanced JSON 추출."""
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        pass
    s, start = text, text.find('{')
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(s)):
            ch = s[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == '\\':
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(s[start:i + 1])
                    except Exception:
                        break
        start = s.find('{', start + 1)
    return None


def main():
    print(f"[test] bridge  = {bc._BRIDGE}")
    print(f"[test] timeout = {bc._TIMEOUT:.0f}s")
    if not bc._BRIDGE.exists():
        print(f"[FAIL] bridge 폴더가 없음: {bc._BRIDGE}\n"
              f"  → Samba 마운트/경로 확인 (RAG_BRIDGE_DIR 로 override 가능).")
        sys.exit(1)
    print("[test] 요청 전송 후 온라인 서비스 응답 대기... "
          "(온라인 srag_llm_service.py 가 떠 있어야 함)")

    t0 = time.monotonic()
    try:
        out = bc.generate_rag_response(PROMPT)
    except TimeoutError as e:
        print(f"[FAIL] {e}\n"
              f"  → 온라인 PC 에서 srag_llm_service.py 실행 중인지, "
              f"BRIDGE_DIR 이 이 폴더와 같은 물리 폴더인지 확인.")
        sys.exit(2)
    except RuntimeError as e:   # 서비스가 LLM 오류를 응답에 실어 보냄
        print(f"[FAIL] 온라인 LLM 오류: {e}\n"
              f"  → 온라인 PC 에서 test_llm.py 로 srag_llm_guide 단독부터 확인.")
        sys.exit(3)
    dt = time.monotonic() - t0
    print(f"[OK] 왕복 응답 수신 ({dt:.1f}s)")

    print("\n=== RAW OUTPUT (앞 1500자) ===")
    print((out or "")[:1500])
    print("\n=== 파싱 ===")
    data = _extract_json(out)
    if not isinstance(data, dict):
        print("[WARN] 왕복은 됐으나 JSON 추출 실패 — LLM 이 JSON 을 안 냄(무해, fuzzer 는 그 라운드 skip).")
        print("  → 온라인에서 test_llm.py 로 프롬프트/지시 튜닝.")
        sys.exit(4)
    seeds = data.get("seeds") or []
    print(f"[OK] JSON 추출됨. seeds={len(seeds)}")
    for s in seeds:
        cdw = {k: v for k, v in s.items() if k.startswith("cdw")}
        print(f"   - {s.get('command')}  {cdw}")
    if seeds:
        print("\n[PASS] 2-PC 왕복 정상 + fuzzer 가 파싱·검증할 형태입니다. "
              "이제 오프라인에서 fuzzer 를 `--rag` 로 실행하면 됩니다 (sudo -E).")
    else:
        print("\n[WARN] 왕복·JSON 은 OK 이나 seeds 가 비었습니다 — 프롬프트/LLM 응답 확인.")


if __name__ == "__main__":
    main()
