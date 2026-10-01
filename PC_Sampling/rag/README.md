# rag/ — LLM 백엔드 · 로컬 검색 · 스키마 브리지

퍼저(`../pc_sampling_fuzzer_v10.3.py`)가 LLM 에 시드·시퀀스·평가·I/O 워크로드를 요청할 때
쓰는 패키지다. **퍼저 프로세스 안에서 import 되어 돈다** — 별도 서비스를 띄우지 않는다.

작성 기준 2026-09-28. 운용 절차·함정은 [`../docs/RUNBOOK_v10.3.md`](../docs/RUNBOOK_v10.3.md),
설계 근거는 [`../docs/V10_3_LLM_BACKEND_PLAN.md`](../docs/V10_3_LLM_BACKEND_PLAN.md),
구현 현황은 [`../docs/pc_sampling_fuzzer_v10.3.md`](../docs/pc_sampling_fuzzer_v10.3.md).

---

## 1. 구성

```
퍼저 LLM 워커 ──► rag.vllm_client.generate_rag_response(system, user, meta)
                    ├─ rag.rag_retrieval.retrieve()      (retrieval.enabled 일 때)
                    │     ├─ 질의 생성  ← rag.retrieval_policy (명령·CDW 필드 → 검색문)
                    │     ├─ 임베딩     → DGX :8001 bge-m3
                    │     └─ top-k     ← rag/index/<버전>/ (tools/rag_ingest.py 가 만든다)
                    ├─ rag.llm_schema.build_schema(task) (구조화 출력 json_schema)
                    └─ 생성        → DGX :8000 nemotron-3-super
퍼저 메인 스레드 ──► rag.rag_schema.SchemaBridge   (LLM 제안을 발송 기준으로 검증·보정)
```

| 백엔드 | `rag.module_path` | 상태 |
|---|---|---|
| 로컬 vLLM (OpenAI 호환) | `rag.vllm_client` | **현행 기본** |
| 사내 2노드 Samba 브리지 | `rag.rag_bridge_client` | 되돌리기용. `pass_system_prompt=false` 와 함께 쓴다 |

---

## 2. 파일별 설명

### 퍼징 PC 에서 도는 것 (리포 그대로, 옮기지 말 것)

| 파일 | 줄 | 역할 |
|---|---|---|
| `__init__.py` | 14 | **비어 있지 않게 존재해야 한다.** 없으면 `rag` 가 namespace package 가 되어 `sys.path` 뒤쪽의 다른 `rag` 패키지가 이길 수 있고, `No module named 'rag.vllm_client'` 가 원인 모를 채로 난다. 확인: `python3 -c "import rag; print(rag.__file__)"` |
| `vllm_client.py` | 366 | **현행 백엔드.** 표준 라이브러리(`urllib`)만 쓴다. `generate_rag_response(system, user, meta)` 가 검색 → 스키마 → 생성을 한 **시간 예산** 안에서 수행하고 `{"raw", "diagnostics"}` 를 돌려준다. `meta` 없이 부르면(구버전 계약) 문자열을 주고 실패는 raise 한다 |
| `rag_retrieval.py` | 274 | 로컬 검색. 인덱스 로드·고정(캠페인 중 버전 불변), 질의 사다리, 임베딩, numpy top-k, 명령 태그 가산점, 기동 전 인덱스 검증(`preflight`) |
| `retrieval_policy.py` | 210 | 평가 도구와 운영 검색이 **공유하는** 규칙. 명령 → 스펙 이름 정규화, `enhanced_query`(명령·CDW 필드로 검색문 생성), 인덱스의 필드 정의(`Figure N: … Command Dword M` 표) 추출·해석, 청크의 `covers_commands` 태그 |
| `llm_schema.py` | 156 | task별 `json_schema` 생성. 최상위 키를 task 마다 `required` 로 두어 `{}` 응답을 막는다. 스키마가 퍼저 파서가 **실제로 읽는 키**와 어긋나면 `tests/test_v10_3_backend.py` 가 깨진다 |
| `rag_schema.py` | 276 | `SchemaBridge` — LLM 이 낸 시드/시퀀스를 퍼저 발송 기준(`CMD_SCHEMAS`)으로 검증·보정. 퍼저가 `SchemaBridge.from_dict(_llm_schema_dict())` 로 in-process 생성하므로 파일이 필요 없다. `schema_to_prompt` / `is_dangerous` / `validate_and_repair` |
| `rag_bridge_client.py` | 107 | 구 백엔드의 오프라인 쪽 '배달부'. `bridge/requests/` 에 요청을 쓰고 `bridge/responses/` 를 폴링한다. LLM 을 직접 부르지 않는다 |

### 온라인 LLM PC 용 (구 브리지 구성에서만 쓴다)

| 파일 | 역할 |
|---|---|
| `srag_llm_service.py` | 온라인 PC 에서 상주하며 Samba 공유 drop-box 를 폴링해 실제 LLM 함수를 부른다. 온라인 PC 의 `srag_llm_guide.py`(실물, 리포 밖)와 **같은 폴더**에 둔다 |
| `srag_llm_guide.reference.py` | 온라인 PC 실물 guide 의 **참고용 사본**(구조 추적용). 자격증명·엔드포인트 가림, 오타 있음, **실행 불가.** 이름을 `srag_llm_guide.py` 로 바꾸지 말 것 — 서비스가 실물 대신 이 스텁을 import 한다(과거 3e0bc50 에서 한 번 겪음) |

### 생성물 (`.gitignore`)

| 경로 | 내용 |
|---|---|
| `index/` | `tools/rag_ingest.py` 가 만드는 검색 인덱스(내부 스펙 원문 포함) |
| `bridge/requests/`, `bridge/responses/` | 구 브리지의 요청/응답 drop-box |

---

## 3. 호출 계약

```python
generate_rag_response(system, user, meta) -> {"raw": "<JSON 문자열>", "diagnostics": {...}}
```

`meta` 는 퍼저가 요청마다 만든다(`_llm_backend_meta`). 백엔드는 **수정하지 않는다.**

| 키 | 내용 |
|---|---|
| `task` | `new_group_seeds` / `sequences` / `corpus_eval` / `io_patterns` |
| `req_id` | 요청 번호 — 진단은 **그 요청에만** 붙는다 |
| `config` | 퍼저가 **실제로 로딩한** 설정(`--config` 반영). 백엔드가 파일을 따로 읽지 않는다 |
| `product` | 제품 이름 |
| `rag_query` | 검색용 짧은 질의(프롬프트 전문이 아니다) |
| `rag_query_commands` | 이 요청이 실제로 겨냥한 명령 목록(최대 6개) — 태그 가산점과 필드 확장이 같은 목록을 쓴다 |
| `rag_query_schemas` | 위 명령들의 CDW 필드 스키마 — 인덱스의 필드 정의로 질의를 확장할 때 쓴다 |
| `rag_query_version` | 질의 생성 규칙 버전(`command-dword-fields-v2`) |
| `budget_started` | 시간 예산 기준 시각 — 최초 호출과 JSON 교정 호출이 **예산 하나를 나눠 쓴다** |
| `device_epoch` | (v11 진입점만) 예외 이벤트로 장치가 재초기화된 횟수 |

`diagnostics` 에는 `finish_reason`·`usage`·`reasoning_chars`·`elapsed_sec`·`attempts`·
`retrieval`(질의·출처·히트·주입 글자 수·잘림 여부)·`effective_user_prompt`(검색 문서가 붙은
실제 전송본)·`requested_chat_template_kwargs` 가 실린다. `rag.log_responses=true` 면 퍼저가
요청/응답 원본과 함께 `output/<버전>/llm/llm_io.jsonl` 에 남긴다.

### 실패로 세는 것

통신 실패 · **최종** `finish_reason=length`(잘림) · JSON 파싱 실패 · task 형식 오류(요구 컨테이너
없음/타입 틀림)만 실패다. **정상 응답인데 중복이라 채택 0건은 실패가 아니다.** 연속 실패가
`rag.fail_limit`(기본 10)에 닿으면 LLM 경로가 꺼지고 퍼징은 blind/mutation 으로 계속된다.

---

## 4. 검색 흐름

1. **질의 사다리** — `meta.rag_query` → 프롬프트의 `[RAG-QUERY]…[/RAG-QUERY]` 블록 → 둘 다
   없으면 **검색 생략**(전문을 질의로 쓰지 않는다). 길이 상한은 문자 수(`query_max_chars`)이며
   토큰 수 보장이 아니다 — 퍼징 PC 에 토크나이저를 들이지 않는다.
2. **필드 확장** — 인덱스 manifest 에 필드 정의가 있으면 `enhanced_query` 가
   `"<스펙 명령명> command Command Dword 10 11 <약칭> <전체명> … field encoding"` 형태로 질의를
   다시 만든다. 전체명은 **원문 근거가 하나로 정해질 때만** 붙이고 추측하지 않는다.
   못 붙인 필드는 사유(`definition_missing` / `definition_conflict` / `context_mismatch` /
   `schema_location_mismatch`)와 함께 경고 로그로 남는다.
3. **임베딩** — bge-m3(입력 상한 8,192 토큰). 서버가 길이 초과를 알리면 질의를 절반씩
   최대 2번 줄여 재시도한다.
4. **점수** — 코사인 유사도 + `command_tag_bonus`(기본 0.1: 청크의 `covers_commands` 가
   요청 명령과 겹치면 가산). `permission_groups` 로 청크를 거를 수 있다.
5. **주입** — top-k 청크를 `[참고 문서]` 로 user 프롬프트 뒤에 붙인다(`context_max_chars` 상한,
   어느 청크가 얼마나 잘렸는지 진단에 남는다).

검색이 실패해도 생성은 막지 않는다(문서 없이 생성하고 진단에 오류를 남긴다).
단, **기동 전 검증**(`rag_retrieval.preflight`)은 `--rag` + `rag.vllm_client` + `retrieval.enabled`
일 때 장치에 손대기 전에 인덱스를 열어 모델·revision 을 대조하고, 틀리면 퍼저가 시작하지 않는다.
인덱스 **파일이 없거나**(새 PC, 아직 `tools/rag_ingest.py` 안 함) numpy 가 없으면 시작은 하고 그 실행만
검색 없이 생성한다(`[LLM/rag] 검색 인덱스를 쓸 수 없어 이번 실행은 검색 없이 생성합니다` 경고).

**인덱스 버전 고정:** 캠페인은 시작할 때 `current` 가 가리킨 버전을 끝까지 쓴다. 도는 중에
재색인해도 안전하다.

---

## 5. 인덱스 (`index/`)

`tools/rag_ingest.py` 만 만든다(JSONL → 청크 분할 → 임베딩 → 검증 → 게시).

```
rag/index/
├── current                     현재 버전 이름만 담은 포인터(원자적 교체)
└── v<YYYYMMDD_HHMMSS>/
    ├── manifest.json           소스 sha256 · 임베딩 모델 · revision · 차원 · 분할 설정 ·
    │                           field_definitions · metadata_extraction(버전·충돌·태그 없는 청크 수)
    ├── chunks.jsonl            doc_id · title · content · permission_groups · source_file · covers_commands
    └── vectors.f16.npy         float16, L2 정규화
```

- 게시 거부 조건: 소스 식별자 중복, `doc_id` 중복, 본문↔벡터 개수 불일치, 차원 이상,
  NaN/Inf, 영벡터, 더 쪼갤 수 없는 청크. 걸리면 포인터를 바꾸지 않는다.
- 벡터 재사용 키: (소스, `doc_id`, 본문 sha256) + 모델 + revision.
- 이전 버전은 지우지 않는다(실행 중 캠페인이 쓰고 있을 수 있다).
- 필드 정의가 없는 구형 인덱스는 **로드 때 한 번** 본문에서 추출해 쓴다(재임베딩 불필요).
- **색인할 때와 검색할 때의 임베딩 서버·모델·revision 이 같아야 한다.** 다르면 벡터 공간이
  달라 점수는 계산되는데 엉뚱한 문서가 뽑힌다 — 그래서 둘 다 `fuzzer_config.json` 하나에서 읽는다.

---

## 6. 설정 — `fuzzer_config.json` 의 `rag.vllm`

```jsonc
"vllm": {
  "base_url": "http://192.168.10.1:8000/v1",   // 생성 서버(직결 링크 주소)
  "api_key": "not-used",
  "model": "nemotron-3-super",                 // vllm serve --served-model-name 과 글자까지 같게
  "chat_template_kwargs": { "enable_thinking": true, "low_effort": true },  // 불리언만. null=서버 기본
  "timeout_sec": 400.0,                        // 검색+생성+JSON 교정 **전체** 예산
  "max_tokens": 16384,
  "temperature": 0.7,
  "max_response_bytes": 8388608,
  "structured_output": true,                   // json_schema 강제
  "include_generators_in_schema": true,        // 중첩 anyOf 를 못 다루는 백엔드면 false
  "freeform_retry": false,                     // 스키마 거부(HTTP 4xx) 시 자유 형식 재시도
  "retries": 1,                                // 통신 실패 재시도
  "retrieval": {
    "enabled": false,                          // 인덱스를 만든 뒤 true
    "index_dir": "rag/index",
    "top_k": 5,
    "embed_base_url": "http://192.168.10.1:8001/v1",  // 비우면 생성 서버로 임베딩(경고)
    "embed_model": "bge-m3",
    "embed_model_revision": null,              // 채우면 인덱스 manifest 와 대조(누락도 불일치)
    "query_max_chars": 8000,
    "command_tag_bonus": 0.1,
    "context_max_chars": 60000,
    "permission_groups": null
  }
}
```

- 환경변수 `RAG_VLLM_BASE_URL` / `RAG_VLLM_API_KEY` / `RAG_VLLM_MODEL` 이 설정을 덮어쓴다.
- 설정·JSONL 은 UTF-8 BOM 이 있어도 읽는다(`utf-8-sig`).
- LLM 요청 주기·task 비중·상한 등 퍼저 쪽 키(`rag.request_interval_sec`, `task_weights`,
  `max_seeds_per_round`, `schema_max` …)는 런북 §4·§6 참조.

> ⚠ `sudo` 는 `env_reset` 으로 셸의 `no_proxy` 를 버린다. 프록시 환경에서는
> `sudo no_proxy=192.168.10.1 http_proxy= https_proxy= python3 …` 처럼 명령줄에 함께 넘긴다.

> ⚠ numpy 는 전부 함수 안에서 늦게 import 하고, `rag_retrieval.py` 최상단에서 BLAS 스레드를
> 1개로 고정한다(`OPENBLAS_NUM_THREADS` 등). 순서가 바뀌면 OpenBLAS 스핀으로 퍼저가 hang
> 처럼 보인다(런북 §6-4).

---

## 7. 관련 도구 (`../tools/`)

| 도구 | 용도 |
|---|---|
| `rag_ingest.py` | 인덱스 생성. `--dry-run` 으로 서버·numpy 없이 점검(종료코드 0=가능, 1=거부) |
| `rag_smoke_test.py` | 장치 없이 검색·생성 OFF/ON 을 점검하고 단계별 보고서 저장(퍼저를 띄우지 않는다). [`RAG_SMOKE_TEST.md`](../docs/RAG_SMOKE_TEST.md) |
| `rag_field_audit.py` | 퍼저 스키마의 모든 필드가 고정 인덱스에서 어떻게 해석되는지 감사(장치·API 없음) |
| `rag_retrieval_eval.py` | 읽기 전용 검색 평가 — dense 검색이 CDW 필드 표를 놓치는지, 질의 개선과 태그 가산점 효과를 분리 측정. [`RAG_RETRIEVAL_EVAL.md`](../docs/RAG_RETRIEVAL_EVAL.md) |
| `split_pdf.py` | 큰 PDF 를 100쪽 단위로 분할(사내 PDF→JSONL 시스템의 쪽수 제한 대응) |

---

## 8. 테스트

전부 가짜 HTTP 서버·가짜 인덱스로 **DGX 없이** 돈다.

| 파일 | 건수 | 덮는 것 |
|---|---|---|
| `tests/test_v10_3_backend.py` | 104 | 스키마↔파서 대조(AST), 진단 귀속, 시간 예산, 실패 분류, ingest 정합성·재사용·락, 입력 해석, BOM |
| `tests/test_rag_hybrid.py` | 7 | 태그 가산점·명령 없음 폴백·권한 필터·필드 확장 질의·실제 전송 프롬프트 기록 |
| `tests/test_rag_field_resolution.py` | 6 | 필드 전체명 해석·충돌·별칭 |
| `tests/test_rag_metadata.py` | 5 | 필드 정의 추출·충돌·권한, 구형 인덱스 태그 1회 계산, ingest 재사용 |
| `tests/test_rag_preflight.py` | 3 | 기동 전 인덱스 검증(비활성·다른 백엔드는 미검사, revision 불일치 시 CLI 비정상 종료) |
| `tests/test_rag_retrieval_eval.py` | 4 | 평가 도구 |
| `tests/test_rag_smoke.py` | 4 | 스모크 도구 |
| `tests/test_v10_3_blas_threads.py` | 8 | import 순서·BLAS 스레드 고정 |
| `tests/test_llm_thinking.py` | 3 | `chat_template_kwargs` 전달·타입 검증, reasoning 필드 분리 |
| `tests/test_llm_logging.py` | 1 | 백엔드 로그가 텍스트 로그와 LLM 전용 로그 양쪽에 남는지 |

```bash
python3 -m unittest discover -s PC_Sampling/tests -p 'test_rag_*.py'
python3 -m unittest discover -s PC_Sampling/tests -p 'test_v10_3_backend.py'
```

**아직 검증 안 된 것:** 실서버의 구조화 출력(task별 스키마·중첩 `anyOf`·출력 잘림)과 백엔드 장애 시
퍼징 지속은 실기로 통과 기록이 없다(런북 §8·§9).
