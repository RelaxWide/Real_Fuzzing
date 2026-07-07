#!/usr/bin/env python3
"""dev 전용 mock LLM callable — 하드웨어·사내 LLM 없이 v9.0 LlmBridge 를 테스트하기 위한 것.

사내 LLM 래퍼의 자리표시자다. 실제 환경에서는 config `rag.module_path`/`func_name` 을
사내 callable(예: `internal_llm.ask`)로 바꾼다. 시그니처는 ChatGPT-API 유사:
    response_text = ask(system_prompt, user_prompt)
반환은 순수 JSON 문자열(가끔 prose 로 감싸 파서 강건성도 시험).

의도적으로 (a) 유효 시드 몇 개 + (b) 위험명령(Sanitize) + (c) 미지 명령을 섞어 반환해,
LlmBridge 의 스키마 검증·위험 필터가 (b)(c)를 걸러내는지 확인한다. LLM 지연 시뮬레이션은
config 로는 못 하니, 필요하면 아래 _SLEEP 를 잠깐 켜서 non-blocking 을 검증한다.
"""
import json
import time

_SLEEP = 0.0   # >0 으로 두면 호출당 그만큼 지연(초) — non-blocking 검증용

# task2: 신규 명령군 시드. 유효 2 + 위험 1(Sanitize) + 미지 1(BogusCmd).
_SEEDS = {
    "seeds": [
        {"command": "GetLogPage", "cdw10": 0x0002_0002, "cdw11": 0, "cdw12": 0,
         "cdw13": 0, "seed_class": "llm_new_group",
         "rationale": "SMART/Health(LID=0x02) 로그 경로 개척"},
        {"command": "Identify", "cdw10": 0x06,
         "seed_class": "llm_new_group",
         "rationale": "Namespace Identification Descriptor(CNS=0x06)"},
        {"command": "Sanitize", "cdw10": 0x02,
         "seed_class": "llm_new_group",
         "rationale": "(의도적 위험 — 필터로 걸러져야 함)"},
        {"command": "BogusCmd", "cdw10": 0,
         "seed_class": "llm_new_group",
         "rationale": "(의도적 미지 명령 — 걸러져야 함)"},
    ]
}

# task3: 멀티-명령 시퀀스. setup->trigger.
_SEQS = {
    "sequences": [
        {"commands": [
            {"command": "SetFeatures", "cdw10": 0x02, "cdw11": 0},
            {"command": "Write", "cdw10": 0, "cdw11": 0, "cdw12": 0},
            {"command": "Flush"},
            {"command": "GetLogPage", "cdw10": 0x0002_0002},
         ],
         "seed_class": "llm_seq",
         "rationale": "APST 설정 후 write/flush → 로그 확인 트리거"},
    ]
}


def _looks_like(user_prompt, *keys):
    u = (user_prompt or "").lower()
    return any(k in u for k in keys)


def ask(system_prompt: str, user_prompt: str) -> str:
    """(system, user) -> JSON 문자열. user_prompt 로 task 를 추정해 canned JSON 반환."""
    if _SLEEP > 0:
        time.sleep(_SLEEP)
    if _looks_like(user_prompt, "sequence", "시퀀스", "setup", "trigger"):
        body = _SEQS
    elif _looks_like(user_prompt, "evaluate", "score", "평가", "keep"):
        # task4: 평가는 seed_id 를 모르는 mock 이라 빈 목록(파이프라인만 확인).
        body = {"evaluations": []}
    else:
        body = _SEEDS
    # 절반은 prose 로 감싸 파서의 brace-scan 강건성도 시험.
    text = json.dumps(body, ensure_ascii=False)
    if len(user_prompt or "") % 2 == 0:
        return f"다음은 요청하신 시드입니다:\n```json\n{text}\n```\n안전에 유의하세요."
    return text
