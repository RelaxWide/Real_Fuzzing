# v10.2 RAG 검색 분리 — 추가 패키지 없는 통합형

## 현재 방식

검색 블록 생성은 퍼징 PC의 기존 `llm_learning.py`에, 검색 처리는 온라인 PC의
기존 `srag_llm_guide.py`에 포함한다. `rag_query.py`는 별도로 필요 없다.
**transformers, sentencepiece, BGE-M3 토크나이저 파일과 다운로드가 모두 필요 없다.**
기존 guide의 requests/OpenAI SDK 등 원래 사용하던 의존성은 그대로 필요하다.

- RAG: `[RAG-QUERY]` 블록 안의 짧은 검색 질문만 전달한다.
- LLM: 기존 전체 프롬프트 + 검색 문서를 전달한다. evidence/setup은 자르지 않는다.
- 원본 프롬프트를 요약하는 추가 LLM 호출은 없다.

## 온라인 PC 적용 — 이미 패치했어도 같은 명령

1. 온라인 서비스를 중지한다.
2. 최신 `PC_Sampling/tools/install_rag_query.py` 한 파일만 온라인 PC에 가져온다.
3. 그 파일이 있는 폴더에서 실행한다. 아래 경로를 실제 guide 경로로 바꾼다.

```bash
# 변경 미리보기(파일은 수정하지 않음)
python install_rag_query.py "실제 srag_llm_guide.py 경로"

# 백업 후 적용
python install_rag_query.py "실제 srag_llm_guide.py 경로" --apply
```

4. 서비스를 다시 시작한다.

```bash
python srag_llm_service.py
```

pip 설치나 Hugging Face 접속은 하지 않는다. 기존 `RAG_TOKENIZER_PATH`,
`RAG_QUERY_TOKEN_BUDGET` 환경변수도 새 코드에서는 사용하지 않는다.

설치 도구는 원본 guide, 이전 `rag_query.py` 분리형, 기존 토크나이저 사용 통합형(V1)을
모두 지원한다. V1 블록은 패키지 없는 V2 블록으로 교체한다. 재실행해도 중복 삽입하지 않는다.
guide의 서버/인증/모델 설정과 HTTP 호출을 유지하며 `.bak` 백업을 생성한다.
설치 도구는 적용할 때만 필요하고 서비스 실행에는 필요 없다.

실제 guide는 저장소 밖에 있다. `srag_llm_guide.reference.py`는 구조 참고용이므로
그 파일로 실제 guide를 덮어쓰지 않는다. 실제 온라인 PC에 자동 적용한 것은 아니다.

## 퍼징 PC

최신 v10.2 실행 파일과 `llm_learning.py`를 사용한다. 이미 검색 블록을 생성하는
버전을 배포했다면 이번 변경 때문에 퍼징 PC 파일을 다시 변경할 필요는 없다.
기존 bridge client/schema/config/공유 폴더는 유지한다.

```text
퍼징 PC: PC_Sampling/
  pc_sampling_fuzzer_v10.2.py
  llm_learning.py
  fuzzer_config.json
  rag/rag_bridge_client.py
  rag/rag_schema.py
  rag/bridge/ ...

온라인 PC: 기존 실행 폴더/
  srag_llm_guide.py      # 검색 처리 코드 포함
  srag_llm_service.py
  기존 설정 파일 ...
```

온라인 서비스가 가리키는 bridge는 퍼징 PC의 bridge와 같은 공유 폴더여야 한다.

## 길이 제한과 오류 처리

- 생성 쿼리: task 의미, 관련 명령 최대 3개, 목표 함수 최대 3개. 긴 JSON/hex는 넣지 않는다.
- 온라인 제한: 최대 **1,024자**, 동시에 **UTF-8 2,048바이트** 이내.
  UTF-8 문자의 중간에서 잘렸다면 해당 불완전 문자만 제외한다.
- 이 제한은 문자/바이트 제한이며 **정확한 토큰 수 또는 8,192토큰 이하를 보장한다고
  주장하지 않는다.** 실제 토큰 한도 판정은 검색 서버가 한다.
- 마커 없음/중복/빈 블록/역순/미완성: 짧은 고정 NVMe 기본 질문 사용.
  구버전 호환 때문에 전체 프롬프트를 검색에 보내는 fallback은 제거했다.
  기본 질문은 목표 정보가 부족하므로 정상 마커보다 검색 관련성이 떨어질 수 있다.
- 서버 오류 코드가 `QUERY_TOKEN_LIMIT_EXCEEDED`일 때만 질문을 절반씩 줄여
  최대 3회 추가 검색한다. 최초 포함 총 4회이며, 모든 시도에서 LLM 원본 입력은 보존한다.
- 축소 후에도 실패하면 원래 오류를 반환한다. 검색 성공이나 빈 검색 결과로 가장하지 않는다.
- 정상적인 `hits=[]`는 원본 프롬프트 + `[RAG 문서 없음]`으로 LLM 생성 진행.
- HTTP 오류/본문 오류/잘못된 hits 구조는 원래 원인과 함께 전달한다.
  동일한 토큰 초과 요청을 서비스의 모듈 reload로 반복하지 않는다.
  일반 연결 오류 및 HTTP 429/5xx 재시도는 기존 서비스 정책을 유지한다.

로그 예:

```text
[RAG query] mode=marker chars=97->97 bytes=97 tokenizer=none
[RAG query] server token limit; retry=1/3 chars=1024->512
```

`mode=generic`이 계속 나오면 구버전 퍼저 또는 잘못된 마커인지 확인한다.
LLM 자체의 별도 컨텍스트 한계까지 해결하는 변경은 아니다.

## 설치 구조 검사

도구는 대상 절대 경로, 함수명과 줄 번호, 문장 종류를 먼저 출력한다.
`retrieve_from_rag`/`retreive_from_rag`, `generate_rag_response`/`generate_rag_responses`를
지원한다. JSON 파싱과 첫 문서 반환을 찾아 중간 로그/변수 분리/try-finally를 보존한다.
여러 JSON 응답이나 불명확한 분기는 추측해서 수정하지 않고 변경 전에 오류를 낸다.
기존 `Unexpected retrieval layout` 오류에서는 guide가 수정되지 않았으므로
최신 도구로 같은 명령을 다시 실행한다.

## 검증

74개 회귀 테스트 통과. 패키지가 없는 Python `-I -S` 환경에서 실제 설치 payload의
검색/생성 함수가 동작함을 확인했다. ASCII/한글/이모지 길이 제한, 원본 프롬프트 보존,
서버 토큰 초과 후 축소 성공 및 4회 소진, 다른 오류의 불필요한 축소 재시도 방지,
V1→V2 교체와 재실행을 검증했다. 기존 sampler 및 NVMe 전송 AST 검사도 유지한다.
사내 검색 서버와 실제 SSD 환경은 미검증이다.
