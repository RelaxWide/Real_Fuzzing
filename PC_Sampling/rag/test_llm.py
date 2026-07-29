#!/usr/bin/env python3
"""■ 배치: **온라인 LLM PC** — 리포 밖. `srag_llm_guide.py` 와 **같은 폴더**에 두고 실행.
   퍼저에 의존하지 않으므로 온라인 PC 에 리포가 없어도 된다.

온라인 PC 에서 실제 LLM(srag_llm_guide.generate_rag_response)이 fuzzer 가 쓸 만한 JSON
시드를 내는지 단독 점검한다. srag_llm_guide.py 와 같은 폴더에 두고 실행(인자 불필요):

    python3 test_llm.py

확인 내용:
  1) import·호출이 되는가 (env/dotenv 로드, LLM 클라이언트 초기화, 문자열 반환)
  2) 반환에서 fuzzer 와 동일한 방식(brace-scan)으로 JSON 이 뽑히는가
  3) seeds 가 들어있는가 (명령명 + CDW)

fuzzer 미의존(온라인 PC 에 repo 없어도 됨). 모듈/함수는 아래 상수 또는 env 로 바꿀 수 있다.
"""
import importlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))   # 같은 폴더 import
MODULE = os.environ.get("RAG_LLM_MODULE", "srag_llm_guide")
FUNC = os.environ.get("RAG_LLM_FUNC", "generate_rag_response")

# fuzzer 가 보내는 프롬프트와 유사(JSON 계약 + task). 실제로는 system 지시가 접혀 오지만
# 여기선 이 한 덩어리를 그대로 넘겨 LLM 이 JSON 을 내는지만 본다.
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
    s = text
    start = s.find('{')
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
    print(f"[test] 모듈 로드: {MODULE}.{FUNC}")
    try:
        fn = getattr(importlib.import_module(MODULE), FUNC)
    except Exception as e:
        print(f"[FAIL] import 실패: {e}\n"
              f"  → 같은 폴더에 {MODULE}.py 가 있고 {FUNC}() 가 정의됐는지, "
              f"LLM 라이브러리/.env 가 준비됐는지 확인하세요.")
        sys.exit(1)

    print("[test] LLM 호출 중... (수 초)")
    try:
        out = fn(PROMPT)
    except Exception as e:
        print(f"[FAIL] 호출 예외: {e}  (env/인증/네트워크 확인)")
        sys.exit(1)
    if not isinstance(out, str):
        print(f"[WARN] 반환이 문자열이 아님({type(out).__name__}). fuzzer 는 문자열을 기대 "
              f"→ srag_llm_guide 에서 str 로 변환해 반환하세요.")
        out = str(out)

    print("\n=== RAW OUTPUT (앞 1500자) ===")
    print(out[:1500])
    print("\n=== 파싱 ===")
    data = _extract_json(out)
    if not isinstance(data, dict):
        print("[FAIL] JSON 추출 실패 — LLM 이 JSON 을 안 냄(또는 '모르겠다' 류).")
        print("  → 이런 경우 fuzzer 는 그 라운드를 조용히 건너뜁니다(무해). 자주 그러면 "
              "srag_llm_guide 의 system 프롬프트/지시 문구를 'best-effort JSON' 쪽으로 튜닝.")
        sys.exit(2)
    seeds = data.get("seeds") or []
    print(f"[OK] JSON 추출됨. seeds={len(seeds)}")
    for s in seeds:
        cdw = {k: v for k, v in s.items() if k.startswith("cdw")}
        print(f"   - {s.get('command')}  {cdw}")
    if seeds:
        print("\n[PASS] fuzzer 가 파싱·검증할 수 있는 형태입니다. "
              "(실제 스키마 유효성은 fuzzer 가 붙을 때 validate_and_repair 로 최종 판정)")
    else:
        print("\n[WARN] JSON 은 나왔으나 seeds 가 비었습니다 — 프롬프트/LLM 응답 확인.")


if __name__ == "__main__":
    main()
