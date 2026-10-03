"""■ 배치: **온라인 LLM PC** — 리포 밖. 이 파일은 그 실물이 아니라 **참고용 사본**이다.

왜 여기 있나
------------
`retrieve_from_rag` 에서 나는 장애를 리포 쪽에서 추적할 방법이 없어서, 2026-09-11
조사 때 구조를 모르는 채로 바깥에서만 소거해야 했다(서비스 3버전 롤백 등). 다음에
같은 일이 없도록 **구조만** 남긴다.

⚠ 이 파일의 성격
  - 사용자가 손으로 옮겨 적은 것이라 **오타가 섞여 있다**(아래 "확인 필요" 참조).
  - 자격증명·엔드포인트·인덱스명은 전부 **가려져 있다**. 실제 값은 온라인 PC 에만 있다.
  - **실행 불가.** 문법 오류가 있고, 그대로 돌릴 목적이 아니다.

⚠ 파일명을 `srag_llm_guide.py` 로 바꾸지 말 것
  서비스(srag_llm_service.py)가 `sys.path.insert(0, _HERE)` 후 `import srag_llm_guide`
  를 한다. 같은 이름이면 온라인 PC 에 복사됐을 때 **진짜 guide 대신 이 스텁**을
  import 한다. 과거에 같은 충돌로 한 번 rename 한 이력이 있다(3e0bc50).

────────────────────────────────────────────────────────────────────────
확인된 결함 (2026-09-11)
────────────────────────────────────────────────────────────────────────
[확정] query_text 가 **프롬프트 전문**이라 임베딩 토큰 상한을 넘는다.
       실측: error_code=QUERY_TOKEN_LIMIT_EXCEEDED, query_tokens=8498,
             max_tokens=8192, embedding_model=bge-m3.
       19,470자(system 1,760 + user 17,710) = 8,498토큰 → 306 초과.
       노트북 테스트가 통과했던 이유 = llm_io.jsonl 에는 user 만 기록돼
       17,710자(≈7,700토큰)였기 때문. system 이 빠져 있었다.
       ※ 8,192 는 **검색 임베딩만**의 한계다. generate_response 는 전문을 받으므로
         검색 쿼리를 줄여도 LLM 이 보는 내용은 줄지 않는다.

[확정] 오류가 통째로 삼켜진다. result['hits'] 가 KeyError 를 내면 str(e) 는 'hits'
       한 단어뿐이라, 응답에 들어 있던 error_code 가 사라진다. 원인 추적이 여기서 막혔다.

[확정] 검색 결과 0건이면 [0] 에서 IndexError. 아직 발현 안 했을 뿐.

[확인 필요] 아래 retrieve_from_rag 에서 만든 변수는 `header`, 넘기는 인자는 `headers`.
       옮겨 적는 과정의 오타일 수 있다. **실물에서 정말 다르면**, 전역 headers 가
       딸려 들어가 인증 헤더가 빠진다. 실물 확인 요.

────────────────────────────────────────────────────────────────────────
"""

import os
from pathlib import Path
from dotenv import set_key
import requests
import json

from openai import OpenAI
import uuid
from dotenv import load_dotenv

ENV_PATH = str(Path("<코드 경로>") / ".env")      # 원문은 `ENV_PATH str(...)` (= 누락, 옮겨적기 오타)

env_vars = {
    "OPENAI_API_KEY": "dummy",
    "credential_key": "<가림>",
    # ... 여러 설정값들
}

system_prompt = """ 어쩌고 """

for key, value in env_vars.items():        # 원문은 `from key, value in ...` (옮겨적기 오타)
    res = set_key(ENV_PATH, key, value)

load_dotenv(ENV_PATH, override=True)

# credential_key 등 환경 변수값들 불러오는 부분
# rag_api_key, rag_credential_key, index_name, search_url, model = ...

client = OpenAI(
    # base_url = ...
    # default_headers = ...
)


def generate_response(user_prompt):
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "system", "content": system_prompt},
                  {"role": "user", "content": user_prompt}],
    )
    return response.choices[0].message.content


def retrieve_from_rag(user_prompt):        # 원문 철자는 `retreive_from_rag`
    header = {                             # ← [확인 필요] 아래 headers= 와 이름 불일치
        "Content-Type": "application/json",
        "api-key": rag_api_key,
        "x-dep-ticket": rag_credential_key,
    }

    fields = {
        "index_name": index_name,
        "permission_groups": ["rag-public"],
        "query_text": user_prompt,         # ← [확정] 프롬프트 전문. bge-m3 8,192토큰 초과 지점
        "num_result_doc": 5,
        "fields_exclude": ["v_merge_title_content"],
    }

    response = requests.request("POST", search_url, data=json.dumps(fields), headers=headers)
    result = response.json()
    # [확정] status_code 확인 없음 → 401/400/500 의 에러 바디가 그대로 result 가 된다.
    # [확정] hits 없으면 KeyError('hits'), 0건이면 IndexError. 둘 다 원인을 지운다.
    return result['hits']['hits'][0]['_source']['merge_title_content']


def generate_rag_response(user_prompt):    # 원문 철자는 `generate_rag_responses`
    rag_context = retrieve_from_rag(user_prompt)
    prompt_with_rag_context = f"{user_prompt}\n[참고 문서]\n{rag_context}"
    return generate_response(prompt_with_rag_context)
