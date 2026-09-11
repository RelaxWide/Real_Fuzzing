# v10.2 검색 쿼리 분리 적용

## 적용 결과와 범위

기존 system/user/evidence/setup 프롬프트 앞에 `[RAG-QUERY]` 블록을 추가한다.
온라인 guide는 이 블록으로 검색하고, 원본 전체 프롬프트와 검색 문서를 LLM에 보낸다.
기존 evidence/setup 정보는 자르지 않는다. 별도 요약 LLM 호출은 추가하지 않는다.

- `llm_learning.py`: 검색 블록 생성 코드 포함. learning 활성 여부와 무관하게 요청에 추가.
- `pc_sampling_fuzzer_v10.2.py`: 요청의 후보 명령을 최대 3개 전달.
- 기존 온라인 `srag_llm_guide.py`: 마커 추출, BGE-M3 토큰 예산, 응답 파싱, LLM 전달을 내부에 포함.
- `rag/srag_llm_service.py`: 토큰 초과/응답 형식 오류 같은 명시적 비재시도 오류는
  같은 요청으로 reload 재시도하지 않고 원래 원인을 반환. 일반 연결 오류 재시도는 유지.
- `tools/install_rag_query.py`: 온라인 코드를 내장한 단일 파일 설치 도구.

**별도 `rag_query.py`는 더 이상 필요하지 않다.** 퍼징 PC는 기존 `llm_learning.py`,
온라인 PC는 기존 guide 안에 각각 필요한 코드가 들어간다.

이 저장소에는 실제 온라인 guide가 없고 구조만 기록한 `srag_llm_guide.reference.py`가 있다.
**참고 사본을 실제 guide 대신 배포하지 않는다.** 실제 온라인 PC에 자동 배포한 것은 아니다.

## 온라인 PC부터 적용

온라인 PC에 `tools/install_rag_query.py` **한 파일만** 가져온다. 아래 명령은
그 파일이 있는 폴더에서 실행한다. `실제_guide_경로`는 서비스가
실제로 import하는 기존 `srag_llm_guide.py`의 경로로 바꾼다.

1. 서비스의 요청 처리가 끝난 뒤 서비스를 중지한다.
2. 서비스를 실행하는 Python 환경에 토크나이저 패키지를 설치한다.

```bash
python -m pip install transformers sentencepiece
```

3. 변경 미리보기:

```bash
python install_rag_query.py "실제_guide_경로"
```

4. 적용:

```bash
python install_rag_query.py "실제_guide_경로" --apply
```

도구는 guide를 시각이 포함된 `.bak`으로 백업하고 검색 처리 코드를 **guide 내부에 삽입**한다.
별도 helper 파일을 읽거나 생성하지 않는다. guide의 서버/인증/모델 설정, HTTP 호출은 유지한다.
함수명 오타 호환: `retrieve_from_rag`/`retreive_from_rag`,
`generate_rag_response`/`generate_rag_responses`를 지원한다.

이전 분리형 패치를 이미 적용했다면 `from rag_query import ...`를 제거하고 내부 코드로
전환한다. 적용 완료 후 그 guide에는 기존 `rag_query.py`가 필요 없으므로, 다른 프로그램에서
사용하지 않는 파일이라면 삭제해도 된다. 설치 도구는 기존 helper 파일을 자동 삭제하지 않는다.
합친 파일에 재실행하면 중복으로 코드를 추가하지 않는다.

원본 guide에는 알려진 `result = response.json()` 및 첫 검색 결과 선택 구조만 수정한다.
실제 파일 구조가 다르면 변경하지 않고 오류를 낸다. 그 경우 파일의 해당 함수에 맞춰
별도 검토해야 하며, 참고 사본으로 덮어쓰지 않는다.

5. 업데이트된 `rag/srag_llm_service.py`도 현재 서비스 파일 위치에 반영한다.
   기존에 직접 조정한 bridge 경로/모듈명 설정은 유지한다. 서비스를 다시 시작한다.

```bash
python srag_llm_service.py
```

토크나이저는 기본 `BAAI/bge-m3`를 최초 1회 내려받아 캐시한다. 모델 가중치는 로드하지 않는다.
Hugging Face 접근이 안 되는 환경이면 서버와 같은 토크나이저 파일을 로컬에 두고
`RAG_TOKENIZER_PATH`를 해당 폴더로 설정한다. 토크나이저 로드 실패를 문자 수 추정으로
무음 우회하지 않는다. 서버가 사용하는 토크나이저 버전/전처리와 일치하는지 확인해야 한다.

## 퍼징 PC 적용

v10.2 실행 파일과 `llm_learning.py`를 업데이트한다. 기존 `rag_bridge_client.py`,
`rag_schema.py`와 공유 bridge 구성은 그대로 유지한다. `rag/rag_query.py`는 필요 없다.
퍼징 PC에는 transformers 설치가 필요 없다. 토크나이저는 온라인 guide에서만 로드한다.
bridge 요청 JSON 및 함수 인자 수는 그대로다. 새 검색 마커는 온라인 guide가 먼저
지원해야 하므로 **guide 먼저, 퍼저 나중** 순서로 배포한다.

## 검색 입력 정책

- task의 의미, 주요 후보 명령 최대 3개, 목표 함수 최대 3개로 결정적으로 구성.
- 목표 함수에 관측된 caller command가 있으면 우선 사용.
- 함수/명령 이름은 항목당 최대 96자로 제한. payload hex나 전체 JSON은 검색에 넣지 않음.
- 온라인 기본 검색 예산: 특수 토큰 포함 **1,024토큰**.
- `RAG_QUERY_TOKEN_BUDGET`으로 16..8,000 범위 설정 가능. 서버 상한 8,192를 가득
  사용하지 않는다. 서버 추가 prefix 등은 별도 고려 대상이며 기본 1,024는 여유를 둔 값이다.
- 마커가 있어도 토큰 예산 적용. 초과 시 검색 입력만 잘라 decode 후 재토큰화로 확인.
- 마커 없음/중복/빈 블록/역순/미완성: 경고 후 전체 입력을 검색 후보로 쓰되 토큰 예산 적용.
  구버전 호환 경로는 앞부분을 자르는 방식이므로 검색 품질까지 보장하지 않는다.

예시 로그:

```text
[RAG query] mode=marker tokens=49->49 budget=1024 truncated=False
```

`mode=legacy`가 계속 나오면 구버전 퍼저 사용 또는 마커 형식 이상을 확인한다.
LLM에 보내는 원본 프롬프트는 그대로이므로 LLM의 별도 컨텍스트 한계까지 해결하는 것은 아니다.

## 응답 처리

- HTTP 오류 또는 JSON의 `error_code`/`error`: 원래 오류로 처리.
  코드, 토큰 수, 한도, 임베딩 모델과 최대 500자의 message를 보존.
- HTTP 200에서도 `QUERY_TOKEN_LIMIT_EXCEEDED`를 확인.
- `hits.hits` 구조 오류/첫 문서 필드 누락: 응답 형식 오류.
- 정상 `hits=[]`: 검색 문서 없이 원본 프롬프트 + `[RAG 문서 없음]`으로 LLM 생성 진행.
- 정상 문서: 기존처럼 첫 문서의 `merge_title_content`를 사용.

토큰 초과와 응답 형식 오류는 같은 요청의 서비스 내부 재시도를 생략한다.
HTTP 429/5xx는 토큰 초과가 아닌 경우 기존 재시도를 허용한다.
퍼저의 캠페인 실패 횟수 설정은 그대로이며, 위 구분은 서비스의 요청 내부 재시도에 해당한다.

## 검증

70개 회귀 테스트 통과. 실제 퍼저 요청 래퍼, 마커 오류와 구버전 입력, HTTP 200 토큰 오류,
빈 결과, 원본 프롬프트 보존, 온라인 guide 패치 후 검색/생성 흐름을 검증했다.
기존 sampler 및 기본 NVMe 전송 함수의 고정 AST 검사도 통과했다.
별도 helper가 없는 폴더에서 설치 도구 단독 실행, 원본 guide 적용, 이전 분리형 guide 전환,
백업 생성 및 재실행 시 중복 삽입 방지도 검증했다.

별도의 임시 환경(transformers 4.46.3)에서 실제 BAAI/bge-m3 토크나이저로 추가 확인:

- 약 39,000토큰 입력을 검색 예산 8,000토큰 이내로 제한(마커/구버전 양쪽).
- 전체 약 30,000토큰 합성 프롬프트에서 마커 검색 질문만 49토큰으로 추출.
- LLM 생성 함수에 원본 전체 프롬프트가 그대로 전달됨을 확인.

이 수치는 합성 입력 검증이다. 사용자가 실패한 실제 8,498토큰 문자열 자체는 없어서
그 동일 문자열을 재현하지는 못했다. 사내 검색 서버/LLM/SSD 실기와 검색 관련성은 미검증이다.

## 최종 배치

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

`install_rag_query.py`는 적용할 때만 필요한 도구다. 서비스 실행 중에는 필요 없다.
Python 패키지 transformers/sentencepiece 및 토크나이저 캐시는 여전히 온라인 PC에 필요하다.
