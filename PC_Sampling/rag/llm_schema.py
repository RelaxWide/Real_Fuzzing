#!/usr/bin/env python3
"""■ 배치: **오프라인 퍼징 PC** — 리포 안 `PC_Sampling/rag/` 그대로. 옮기지 말 것.

LLM 구조화 출력(`response_format: json_schema`)용 **task별 스키마 생성기**.

왜 별도 모듈인가
----------------
스키마는 퍼저 파서가 **실제로 읽는 키**와 일치해야 한다. 표를 보고 손으로 적으면
누락이 생기고, `additionalProperties: false` 로 잠근 스키마에서 누락은 곧 **기능이
조용히 사라지는 것**을 뜻한다. (실제로 계획 초안이 `seeds[].data_len` 을 빠뜨렸는데,
그 값은 `llm_learning.py` 가 `data_len_override` 로 반영하는 살아있는 필드였다.)

그래서 이 모듈을 파서와 분리해 두고, `tests/test_v10_3_backend.py` 가 두 쪽을
대조한다. 파서가 새 키를 읽기 시작하면 시험이 깨진다.

task별 스키마인 이유
--------------------
최상위 키를 전부 optional 로 두면 `{}` 도 스키마상 정상이라, 모델이 빈 객체를 내도
형식 검증을 통과하고 주입할 시드는 0개가 된다. task 마다 필요한 키를 `required` 로
지정해 그 구멍을 막는다.

구조화 출력이 보장하는 것은 **모양이지 의미가 아니다.** `command` 는 enum 으로 못
박지 않는다 — 유효 명령 목록이 제품·설정별로 동적이라 이 모듈이 알 수 없고, 모르는
명령을 버리는 기존 검증(`_llm_make_seed`)이 그대로 남는다.
"""

U32 = {"type": "integer", "minimum": 0, "maximum": 0xFFFFFFFF}
CDWS = ("cdw2", "cdw3", "cdw10", "cdw11", "cdw12", "cdw13", "cdw14", "cdw15")
# data_hex 생성 상한(hex 글자 수 = 2 × 바이트). 모델이 같은 글자를 끝없이 반복하다(예: '0' 15216개)
#   종료 따옴표 없이 max_tokens 에서 잘리는 반복 퇴행을 막는다. 퍼저의 실제 입력 상한
#   (max_input_len)과는 별개 — 그 값은 변이·실행 경로가 쓰는 한도라 낮추면 안 된다.
#   ★ 상한은 **정규식 안에** 둔다. vLLM 의 문법 엔진(xgrammar)은 pattern 이 있으면 maxLength 를
#   무시한다(서버에서 확인: maxLength 4096 인데 15216자가 나옴). 정규식 반복 상한은 강제된다.
#   512자(256B) — 시드 8개 × 512자도 max_tokens 안에 들어가고, APST 표(256B) 같은 구조체도 담긴다.
#   짝수 길이는 문법으로 강제하지 않는다(그룹 반복 정규식은 서버 검증 전) — 퍼저가 홀수면 끝 1글자를 버린다.
DATA_HEX_MAX_CHARS = 512
_DATA_HEX = {"type": "string", "pattern": "^[0-9a-f]{0,%d}$" % DATA_HEX_MAX_CHARS}
# pattern 없는 자유 문자열은 maxLength 가 강제된다 — 같은 반복 퇴행이 다른 필드로 옮겨 가지 않게 상한.
_NAME = {"type": "string", "maxLength": 64}
_TEXT = {"type": "string", "maxLength": 400}

# 퍼저 파서가 읽는 키 — 출처를 주석으로 남긴다(시험이 이 목록과 파서를 대조한다).
_SEED_PROPS = {
    "command":    _NAME,                                 # _llm_make_seed: item.get('command')
    **{k: U32 for k in CDWS},                            # _llm_make_seed: item.get(f'cdw{w}')
    "nsid":       U32,                                   # _llm_make_seed: item.get('nsid')
    "data_hex":   _DATA_HEX,                             # item.get('data_hex')
    "data_len":   {"type": "integer", "minimum": 0},     # llm_learning: item['data_len']
    "seed_class": _NAME,                                 # _llm_apply_result: item.get('seed_class')
    "target_id":  _NAME,                                 # llm_learning: item.get('target_id')
    "rationale":  _TEXT,                                 # 프롬프트가 요청. 파서는 안 읽음
}

_SEQ_PROPS = {
    "commands":        {"type": "array", "minItems": 1,          # sq.get('commands')
                        "items": {"type": "object",
                                  "properties": _SEED_PROPS,
                                  "required": ["command"],
                                  "additionalProperties": False}},
    "setup_id":        _NAME,                                    # llm_learning: sq.get('setup_id')
    "preserve_fields": {"type": "array", "items": _NAME},        # sq.get('preserve_fields')
    "target_id":       _NAME,                                    # sq.get('target_id')
    "seed_class":      _NAME,                                    # 호스트가 'llm_seq' 로 덮어씀
}

_EVAL_PROPS = {
    "seed_id": {"type": "integer"},                      # ev.get('seed_id')
    "score":   {"type": "number"},                       # ev.get('score')
    "keep":    {"type": "boolean"},                      # ev.get('keep')
}

# generators — compile_recipe() 가 받는 유한 DSL.
_PARAM_EXPR = {"anyOf": [
    {"type": "integer"},
    {"type": "object",
     "properties": {"param": {"type": "boolean"}, "add": {"type": "integer"}},
     "required": ["param"], "additionalProperties": False},
]}
_GEN_PROPS = {
    "base": {"type": "object",
             "properties": {"command": _NAME, "nsid": U32,
                            "data_hex": _DATA_HEX,
                            **{k: U32 for k in CDWS}},
             "required": ["command"], "additionalProperties": False},
    "values":  {"type": "array", "minItems": 1, "items": U32},
    "record":  {"type": "array", "maxItems": 32,
                "items": {"type": "object",
                          "properties": {"width": {"type": "integer", "enum": [1, 2, 4, 8]},
                                         "value": _PARAM_EXPR},
                          "required": ["width", "value"], "additionalProperties": False}},
    "repeat":  _PARAM_EXPR,
    "bindings": {"type": "array", "maxItems": 16,
                 "items": {"type": "object",
                           "properties": {"field": {"type": "string", "enum": list(CDWS)},
                                          "lo": {"type": "integer", "minimum": 0, "maximum": 31},
                                          "bits": {"type": "integer", "minimum": 1, "maximum": 32},
                                          "value": _PARAM_EXPR},
                           "required": ["field", "lo", "bits", "value"],
                           "additionalProperties": False}},
    "break_length": {"type": "integer"},
    "target_id":    _NAME,
}

# task → (필수 최상위 키, 선택 최상위 키). '{}' 를 막으려면 required 가 비면 안 된다.
TASK_KEYS = {
    "new_group_seeds": (["seeds"], ["generators"]),
    "sequences":       (["sequences"], []),
    "corpus_eval":     (["evaluations"], []),
    "io_patterns":     (["io_workload"], []),
}


def _workload_props(patterns):
    return {
        "pattern":      {"type": "string", "enum": list(patterns)},   # _llm_make_workload_desc
        "lba_span":     {"type": "integer", "minimum": 1},
        "block_size":   {"type": "integer", "minimum": 1},
        "hot_fraction": {"type": "number"},
        "read_ratio":   {"type": "number"},
        "direction":    _NAME,
    }


def top_level_properties(patterns, include_generators=True):
    """최상위 키 전체의 정의. task 스키마는 여기서 골라 쓴다."""
    props = {
        "seeds": {"type": "array", "items": {
            "type": "object", "properties": _SEED_PROPS,
            "required": ["command"], "additionalProperties": False}},
        "sequences": {"type": "array", "items": {
            "type": "object", "properties": _SEQ_PROPS,
            "required": ["commands"], "additionalProperties": False}},
        "evaluations": {"type": "array", "items": {
            "type": "object", "properties": _EVAL_PROPS,
            "required": ["seed_id"], "additionalProperties": False}},
        "io_workload": {"type": "object", "properties": _workload_props(patterns),
                        "required": ["pattern"], "additionalProperties": False},
    }
    if include_generators:
        props["generators"] = {"type": "array", "maxItems": 2, "items": {
            "type": "object", "properties": _GEN_PROPS,
            "required": ["base", "values"], "additionalProperties": False}}
    return props


def build_schema(task, patterns, include_generators=True):
    """task 용 json_schema 를 만든다. 알 수 없는 task 면 None(=구조화 출력 생략).

    include_generators=False 는 중첩 anyOf 를 못 다루는 guided-decoding 백엔드용
    탈출구다(계획 D3). 스키마에서 빠져도 파서는 계속 generators 를 받는다.
    """
    spec = TASK_KEYS.get(task)
    if spec is None:
        return None
    required, optional = spec
    props = top_level_properties(patterns, include_generators)
    keys = [k for k in (list(required) + list(optional)) if k in props]
    required = [k for k in required if k in props]
    if not required:
        return None
    return {
        "name": f"nvme_fuzz_{task}",
        "strict": False,
        "schema": {"type": "object",
                   "properties": {k: props[k] for k in keys},
                   "required": required,
                   "additionalProperties": False},
    }
