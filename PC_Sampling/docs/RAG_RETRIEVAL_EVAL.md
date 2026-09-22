# 기존 스펙 JSONL로 검색 품질 비교

`tools/rag_retrieval_eval.py`는 장치를 접근하거나 생성 모델을 호출하지 않는다.
스펙별 하위 폴더의 JSONL을 재귀 탐색하며 기존 검색 인덱스를 재사용한다.
소스 폴더(예: `/home/ssd/pc_sample/rag/jsonl`)와 검색 인덱스는 다르다.
현재 퍼저는 설정의 `rag.vllm.retrieval.index_dir` 아래 `current`가 가리키는
`chunks.jsonl`과 `vectors.f16.npy`를 읽는다. 원본이 추가 분할된 경우 정답 ID는
반드시 **검색 인덱스의 ID**로 지정한다. 원본만 있고 인덱스가 없으면 이 시험을
진행할 수 없다. 자동 재색인은 하지 않는다.

PC_Sampling 디렉터리에서 실행:

```bash
python3 tools/rag_retrieval_eval.py prepare \
  --source-dir /home/ssd/pc_sample/rag/jsonl \
  --output output/rag_eval_cases.json
```

설정의 인덱스 위치가 다르면 `--index-dir /실제/rag/index`를 추가한다.
다른 설정은 `--config /실제/fuzzer_config.json`으로 지정한다.
prepare는 임베딩 API를 호출하지 않는다. 원본 제목 추출 결과와 실제 인덱스의
15개 명령 후보 청크 본문을 출력한다. 후보가 없으면 실제 인덱스 본문에서
해당 명령의 표·절을 검색해 수동으로 정답을 추가한다. 제목 없는 후속 청크의
태그 상속은 아직 하지 않으며, 이 누락도 평가 대상이다.

## 정답표 확인

출력 JSON의 cases 항목을 편집한다:

- `relevant_doc_ids`: 실제 필드 정의를 확인한 정답 청크 ID 목록. 후보를 무조건 정답으로 삼지 않는다.
- `reviewed`: 확인 후 true.
- `baseline_query`: 기본값은 명령 하나의 간이 질의다. 운영 기준 비교에는 실제 질의로 교체한다.
- `enhanced_query`: 예: `NVMe Read Command Dword SLBA NLB LR FUA PRINFO`. 실제 스키마·스펙 필드만 쓴다.
- `split`: 가중치 조정용은 development, 최종 확인용은 validation. 확인용 결과로 반복 튜닝하지 않는다.
- 복수 명령 사례는 `commands: ["Read", "Write"]`를 추가하고 실제 복수 명령 질의를 입력한다.

모든 사례의 검토·질의·정답을 확인해야 평가가 진행된다. 기존 2/10을 재현하려면
당시 동일한 명령·질의·정답표를 사용해야 한다. 15개 기본 후보로 자동 재현되는 수치가 아니다.

```bash
python3 tools/rag_retrieval_eval.py evaluate \
  --cases output/rag_eval_cases.json \
  --bonus 0.1 --top-k 10 \
  --output output/rag_eval_report.json
```

A=기존 질의+임베딩, B=개선 질의+임베딩,
C=기존 질의+태그 가산점, D=개선 질의+태그 가산점.
최종 점수는 원본 유사도 + bonus × 명령 태그 일치 여부.
동일 실행의 동일 질의는 임베딩을 한 번만 요청하며, 각 질의는 전체 eligible 벡터와
비교한다. 운영 permission_groups를 적용한다. 모델/revision과 인덱스 본문 해시를
검사한다. 임베딩 길이 초과 시 질의를 몰래 바꾸지 않고 실패한다.

보고서는 split별 Hit@5/10, MRR(rr), 개선/악화/동률 명령과 명령별 순위·top 결과를 담는다.
Hit는 정답 중 하나 이상이 들어가는 비율이며, 모든 관련 청크의 recall은 아니다.
순위 개선만으로 생성 결과의 정확성 개선까지 입증한 것은 아니다.

파일은 덮어쓰지 않으므로 반복 시험에는 다른 output 이름을 쓴다.
운영 검색에도 D 방식이 연결됐다. `rag.vllm.retrieval.command_tag_bonus` 기본값은
검증에 사용한 0.1이며 0으로 설정하면 태그 가산점만 끌 수 있다. 원본 JSONL과
벡터는 변경하지 않는다. `retrieval.enabled`는 기존 설정을 따르며 인덱스가 없는
환경에서 자동 활성화하지 않는다.

## 운영 질의와 로그 (2026-09-22)

`rag/retrieval_policy.py`가 태그 규칙과 개선 질의 생성 함수를 제공한다.
`_llm_rag_commands()`에서 선택한 동일 명령 집합을 질의와 태그 매칭에 사용한다.
meta.rag_query와 프롬프트 RAG-QUERY 블록도 같은 빌더를 사용한다.
스키마의 word/name을 읽어 `명령 command Command Dword 번호 약칭 전체명 ... field encoding`
형식으로 만든다. 현재 스키마에는 전체명이 없으므로 사용자 평가에서 확인한
OFI/IFC/PRHBT/SCP/SANACT/FID/SEL만 검색용 사전에 확장했고 나머지는 약칭을 유지한다.
실행 스키마와 valid 값은 변경하지 않는다. 선택적인 enum 이름은 붙이지 않는다.
스키마의 모든 정의된 필드를 쓰므로 손으로 작성한 평가 예시와 필드 수/순서는
다를 수 있다. 이 자동 생성 질의의 실서버 성능은 별도로 확인해야 한다.

`rag.log_responses=true`일 때 `llm/llm_io_<timestamp>.jsonl`의 diagnostics에서 확인:

- retrieval.query / commands / query_version / command_tag_bonus
- retrieval.hits: dense_score, tag_bonus, score(최종 점수), rank, covers_commands
- retrieval.hits[].injected_chars / truncated: 선택됐어도 실제로 잘린 청크 구별
- retrieval.context: 길이 제한 후 주입한 본문
- effective_user_prompt / effective_system_prompt: 실제 생성 입력
- correction_attempt 및 correction 하위 진단: 교정 요청 구분

기존 prompt는 RAG 전 원본이다. 기본 설정의 log_responses는 true로 변경했으며
다른 config를 사용하는 환경은 해당 값을 확인한다. 실패/비활성 시에도 진단이
기록된다. 서버 토큰 상한으로 질의 임베딩이 축소되는 기존 재시도는 유지되며,
retrieval.query는 축소 전 질의이므로 축소 경고가 있는 요청은 별도로 확인한다.

## 인덱스 생성 시 자동 메타데이터 추출

새 파일은 추가하지 않는다. `rag_ingest.py`가 원본 레코드를 분할하기 전에
Figure의 명령명·Command Dword 번호와 `전체명 (약칭):` 형태의 필드 행을
추출한다. 줄 시작의 비트 범위, Markdown 표의 `|`도 허용한다.
다른 Figure가 시작되면 이전 명령 문맥을 끝낸다. 임의 설명 문장이나 문맥이
끊긴 레코드 사이의 정의는 추측하지 않는다. 실제 PDF 변환 형식에 따라 누락될
수 있으므로 추출 건수와 원문 근거를 확인해야 한다.

- `chunks.jsonl`: 최종 청크 본문에 근거한 `covers_commands`.
- `manifest.json`: `field_definitions`(명령/Dword/약칭/전체명/원본 파일·문서 ID/
  짧은 근거/권한 그룹), `metadata_extraction`(규칙 버전·정의 수·충돌 키 수·태그 없는 청크 수).
- 동일 명령/Dword/약칭에 전체명이 충돌하면 해당 확장은 제외한다.
- 새 인덱스에서는 추출 정의가 없으면 약칭만 사용한다. 기존 7개 사전은
  field_definitions가 없는 구형 인덱스의 호환 경로에만 남는다.
- `_load()`에서 태그와 정규화된 매칭 키를 한 번 캐싱한다. 구형 인덱스는
  최초 로드 때만 본문을 파싱한다. 필드 조회 사전은 권한 그룹별로 캐싱한다.

실행 스키마의 약칭/Dword를 요청 메타데이터로 넘기고 LLM 워커가 인덱스의
정의를 결합한다. 따라서 메인 스레드에서 인덱스를 읽지 않는다. 프롬프트 블록과
meta의 원래 질의는 이전 형식이며, 실제 임베딩 질의는 `diagnostics.retrieval.query`,
출처는 `query_source=index_field_definitions`로 확인한다. `metadata_extraction`도
진단에 기록된다. 이 검색 질의는 생성 모델의 명령 실행 허용값을 변경하지 않는다.

기존 인덱스를 갱신하려면 **기존과 동일한 입력 파일 전체·모델·revision·분할 설정**으로
rag_ingest.py를 다시 실행한다. 같은 본문의 벡터는 기존 증분 경로로 재사용한다.
입력이 일부만 주어지면 새 인덱스도 그 일부만 포함하므로 원래 입력 전체를 유지한다.
기존 서버 상한 때문에 동적으로 분할됐던 청크는 재사용 키가 다를 수 있어 일부
임베딩 호출이 발생할 수 있다. 실행 로그의 재사용/새 임베딩 개수를 확인한다.
실행 중 퍼저는 기존 버전을 고정하므로 새 메타데이터를 사용하려면 다시 시작한다.

## 시작 전 설정 오류 차단

v10.3 CLI는 LLM이 활성(`--rag` 또는 rag.enabled)이고 로컬 vLLM 검색이 활성일 때,
장치 초기화 전에 인덱스를 로드·고정하고 모델 이름/revision을 검증한다.
명시한 revision이 manifest와 다르거나 manifest에서 누락된 경우 종료 코드 2로
시작을 거부한다. 인덱스 파일 부재/로딩 실패도 같은 방식으로 차단한다.
이 검사는 임베딩 서버를 호출하지 않는다. 실행 중 같은 고정 인덱스를 사용한다.
`--no-rag`, retrieval.enabled=false인 생성 전용 설정, 별도 브리지에는 적용하지 않는다.
일시적인 검색 API 오류의 기존 생성 폴백은 유지한다.
revision은 인덱스 생성 날짜가 아니라 임베딩 모델 식별자이므로, 오류 시 먼저
manifest와 설정을 비교한다. 실제 모델 변경이 없으면 날짜에 맞춰 revision을 바꾸지 않는다.

## v2 추출 및 prompt 기록 수정

`figure-field-definitions-v2`는 Figure 제목이 없는 원본 레코드에서도
`Number of Dwords (NUMD):` 등의 명시적 정의를 수집한다. 같은 약칭의 전체명이
일치하면 공통 조회 사전에 병합하고, 다르면 공통 확장에서 제외한다. 명령/Dword
문맥이 있는 정의는 그 문맥에 한해 우선 사용한다. 위의 v1 제목 필수 제한과
7개 고정 FIELD_NAMES 호환 사전은 더 이상 적용하지 않는다.

구형/v1 인덱스는 `_load()`에서 전체 청크를 한 번 읽어 정의를 보충한다.
디스크 파일을 수정하거나 임베딩 API를 호출하지 않는다. 따라서 코드를 갱신하고
퍼저를 재시작하면 v1의 definitions=0 인덱스도 보충할 수 있다. 생성 파일 자체를
갱신하려면 기존 입력으로 인덱서를 다시 실행한다.

로그 진단:

- `retrieval.field_definition_source`: manifest 또는 load_time_extraction
- `retrieval.field_definition_count`: 실행 시 이용하는 정의 개수
- `retrieval.field_expansion`: 해당 요청에서 실제 확장한 필드와 미확인 필드 목록/개수
- `retrieval.metadata_extraction`: 디스크에 기록된 추출 정보. 로드 시 보충한 경우
  여전히 v1/0건일 수 있으므로 위의 실행 시 정의 개수와 구분한다.

아카이브 최상위 `prompt`는 이제 RAG 후 최종 호출 입력(교정 호출이 있으면 그 입력)을
기록한다. 원래 요청은 `prompt_original`에 남기고, `prompt_source`로 실제 백엔드
진단인지 구형 백엔드의 원본 폴백인지 구분한다. 기존에 기록된 JSONL은 변경하지 않는다.

자동 추출은 명시적인 이름-약칭 정의에 한정된다. 전체 원문의 정의가 항상 이 형태라는
보장은 없으므로 누락 목록으로 추가 형식을 확인한다. 다중 명령의 top-k 배분 정책은
이번 수정에서 변경하지 않았다.

## 필드 정규화·미확인 원인·전체 스키마 감사

진단은 모든 명령에 공통 적용한다. `field_expansion.missing_fields[]`에
`reason`, `normalized_field`, `alias_applied`, 원문 후보(최대 8개)와 전체 후보 수를
기록한다. permission_groups로 제외된 근거는 후보에도 노출하지 않는다.

- definition_missing: 허용된 정의에서 해당 이름을 찾지 못함
- definition_conflict: 같은 문맥 또는 공통 사전에 서로 다른 전체명 후보 존재
- context_mismatch: 동일 명령의 정의가 다른 Dword에 귀속되어 있음
- schema_location_mismatch: 확인된 표준 필드 위치와 실행 스키마 위치가 다름
- 성공은 matched_scoped / matched_global로 구분

추출 v3은 괄호 약칭 없는 `CNS Specific Identifier:`와 `UUID Index:`도 수집한다.
검색 별칭은 명령/Dword별로 한정한다. Identify CNSSI, Identify/GetFeatures/SetFeatures
UIDX와 7개 명령의 SLBA_LO/SLBA_HI를 처리한다. 임의 `_LO/_HI` 제거는 하지 않는다.
원문 정의가 있어야 확장하며, 별칭 자체로 전체명을 꾸며 넣지 않는다.
구형 인덱스는 로드 시 v3 규칙으로 1회 보충하므로 퍼저 재시작으로 적용된다.

명령별 요청에 등장하지 않은 필드까지 점검하려면:

```bash
python3 tools/rag_field_audit.py --config fuzzer_config.json \
  --index-dir rag/index --output output/rag_field_audit.json
```

현행 41개 명령/171개 필드 선언을 AST로 읽는다. 퍼저 인스턴스/장치/API 호출 없이
현재 인덱스와 전체 필드를 대조한다. 이 개수는 스키마가 바뀌면 달라진다.
전체명 매칭 검사이며 모든 NVMe 비트 배치의 적합성을 인증하는 도구는 아니다.

### 검토 중 발견한 별도 스키마 문제

NVMe Base 2.0d Figure 292/293과 현재 Lockdown 실행 스키마의 위치가 다르다:

| 필드 | 현재 | 표준 2.0d |
|---|---|---|
| OFI | CDW10[7:0] | CDW10[15:8] |
| IFC | CDW10[25:24] | CDW10[6:5] |
| PRHBT | CDW10[15] | CDW10[4] |
| SCP | CDW10[19:16] | CDW10[3:0] |
| UUID | CDW10[14:9] | UUID Index, CDW14[6:0] |

출처: https://nvmexpress.org/wp-content/uploads/NVM-Express-Base-Specification-2.0d-2024.01.11-Ratified.pdf

CNSSI는 같은 문서 Identify CDW11의 `CNS Specific Identifier`(괄호 약칭 없음)와
대응한다. UUID와 UUID Index는 일반적인 전역 동의어가 아니므로 일괄 치환하지 않는다.
이번 변경은 검색용 별칭·진단만 적용한다. Lockdown 실행 스키마와 가드는 바꾸지
않았고, UUID 위치 불일치를 진단으로 명시한다. 나머지 비트 불일치는 이 표에
기록했으며 별도 실행 스키마 수정/회귀검증이 필요하다.
