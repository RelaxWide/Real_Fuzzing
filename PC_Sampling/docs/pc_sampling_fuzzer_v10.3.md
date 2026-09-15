# pc_sampling_fuzzer v10.3

v10.3 은 v10.2 의 SSD FW 퍼징 기능을 그대로 두고, **LLM 백엔드를 사내 2노드 Samba
브리지에서 로컬 vLLM 으로 옮기는** 버전이다.

계획과 결정 근거는 [V10_3_LLM_BACKEND_PLAN.md](V10_3_LLM_BACKEND_PLAN.md) 를 따른다.

## 진행 상태

| 단계 | 내용 | 상태 |
|---|---|---|
| **P0** | 버전 생성 | **완료** |
| **P1** | vLLM 생성 교체 | **완료** (실기 미검증) |
| **P2** | 로컬 RAG | **구현 완료** — 인덱스 생성 필요 |
| P3 | 전환·측정 | 계측만 완료 |

실기(실제 SSD·JTAG), DGX vLLM 서버, 추출된 JSONL 품질은 아직 검증하지 않았다.

## 지금 상태로 무엇이 되나

`fuzzer_config.json` 의 `rag.module_path` 가 **`rag.vllm_client`** 를 가리킨다.
`rag.vllm.base_url` 의 서버만 뜨면 LLM 경로가 동작한다. 검색은 기본 꺼짐
(`rag.vllm.retrieval.enabled=false`) — P2 인덱스를 만든 뒤 켠다.

되돌리기: `module_path` → `rag.rag_bridge_client`, `pass_system_prompt` → `false`.

## v10.2 대비 변경 (P0)

| 항목 | 내용 |
|---|---|
| `FUZZER_VERSION` | `10.2.0` → `10.3.0` |
| 출력 디렉터리 | `./output/pc_sampling_v10.3.0/` |
| docstring | LLM 항목을 "로컬 vLLM(OpenAI 호환)" 으로, 버전 요약에 v10.3 한 줄 추가 |
| 시험 대상 | `tests/test_v10_2_learning.py` 의 `FUZZER_FILE` 이 v10.3 을 가리킴 |

`llm_learning.py` · `riscv_cov.py` · `nvme_seeds.py` · `fuzzer_config.json` · `rag/` 는
버전 접미사가 없는 공유 자산이라 복사하지 않았다.

## 장치 경로 보호

`tests/fixtures/v10_2_device_ast.json` 의 고정 해시로 다음을 계속 검사한다.

```
RiscvPcsrSampler / JLinkHaltSampler / OpenOCDHaltSampler / OpenOCDPCSampler
_V101Fuzzer._send_nvme_command
```

**시험 대상은 활성 버전을 따라가지만 비교 기준은 검증된 v10.2 fixture 로 고정**한다
(`DEVICE_AST_FILES` 가 v10.2·v10.3 양쪽을 같은 기준선에 대조). 버전업이 기준선을 새로
만들면 의도치 않은 장치 경로 변경까지 승인하게 되므로, fixture 는 **자동 갱신하지 않는다.**
장치 경로를 의도적으로 바꿀 때만 리뷰 후 `hashes`/`source_commit`/`amendments` 를 함께 고친다.

## 실행

기존 v10.2 명령에서 파일명만 바꾸면 된다.

```bash
sudo python3 PC_Sampling/pc_sampling_fuzzer_v10.3.py \
  --product BM9K1 --nvme /dev/nvme0 --namespace 1 --rag
```

## 검증 (P0)

```bash
python3 -m unittest discover -s PC_Sampling/tests -p 'test_*.py'   # 92 tests, OK
python3 PC_Sampling/pc_sampling_fuzzer_v10.3.py --help
```

AST 보호가 실제로 v10.3 을 검사하는지는 **주입 시험으로 확인했다** — `RiscvPcsrSampler`
에 한 줄을 넣으면 `test_device_paths_match_frozen_v102_baseline` 이 실패하고, 되돌리면
통과한다.

실기 동작(실제 SSD·JTAG), DGX vLLM 서버, 추출된 JSONL 품질은 아직 검증하지 않았다.

## P1 — LLM 백엔드

```
generate_rag_response(system, user, meta) -> {"raw": ..., "diagnostics": {...}}
  meta = {task, req_id, rag_query, config(실제 로딩된 것), product}
```

| 파일 | 역할 |
|---|---|
| `rag/vllm_client.py` | urllib 만 쓰는 OpenAI 호환 호출. 시간 예산·응답 크기 상한·HTTP 오류 본문 보존 |
| `rag/llm_schema.py` | task별 `json_schema`. 최상위 키를 task 마다 `required` 로 둬 `{}` 를 막는다 |

**하위호환** — `meta` 없이 부른 v10.2 에는 기존대로 문자열을 주고 실패는 raise 한다.
`fuzzer_config.json` 이 공유되므로 두 버전이 같은 설정으로 이 백엔드를 쓸 수 있다.

**실패 분류** — 통신 실패·잘림(`finish_reason=length`)·파싱 실패만 실패로 센다.
정상 응답인데 중복으로 채택이 0개인 경우는 **실패가 아니다**. v10.2 는 백엔드가 반환만
하면 파싱 성패와 무관하게 연속 실패를 0 으로 되돌려, 무효 응답이 반복돼도 서킷브레이커가
안 걸렸다.

**계측** — 주기 통계에 깔때기가 찍힌다.

```
[LLM/funnel] 요청=12 → 통신ok=12 → JSONok=11 → 항목=64 → 채택=31 (정상0건=2, 연속실패=0/10)
```

## P2 — 로컬 RAG

```bash
# DGX 에 bge-m3 를 두 번째 vLLM 인스턴스로 띄운 뒤
python3 PC_Sampling/tools/rag_ingest.py <JSONL...> \
  --embed-base-url http://192.168.137.238:8001/v1
```

인덱스는 `rag/index/<version>/` 에 만들고 `current` 포인터만 원자적으로 교체한다.
이전 버전은 지우지 않는다 — 실행 중 캠페인이 쓰고 있을 수 있다. `rag/index/` 는
`.gitignore` 다(내부 스펙 원문이 들어갈 수 있다).

만든 뒤 `rag.vllm.retrieval.enabled=true` 로 켠다.

**검색 질의**는 프롬프트 전문이 아니다 — 임베딩 상한(bge-m3 8,192)은 생성 컨텍스트(1M)와
별개 단계의 제약이다. 순서: `meta.rag_query` → 프롬프트의 `[RAG-QUERY]` 블록 → 생략.
토크나이저는 쓰지 않는다(문자 수 기준이며 토큰 수 보장이 아니다).

## 검증 (P1·P2)

```bash
python3 -m unittest discover -s PC_Sampling/tests -p 'test_*.py'   # 115 tests, OK
```

`tests/test_v10_3_backend.py` 23개가 가짜 HTTP 서버로 DGX 없이 돈다. 주요 항목:

- **스키마↔파서 대조**를 AST 로 강제 — 파서가 읽는 키가 스키마에 없으면 실패한다.
  계획 초안이 `data_len` 을 빠뜨렸던 것이 이 시험의 계기이고, 실제로 스키마에서 그
  필드를 빼면 시험이 깨지는 것을 확인했다.
- 기존 문자열 반환과 새 `{raw, diagnostics}` 가 모두 처리되고 진단이 해당 요청에만 붙는지
- HTTP 오류 본문 보존, 스키마 거부 시 자동 폴백 금지, 잘림 보고
- 정상 응답의 채택 0건이 실패로 안 세지는지 / 무효 응답 반복은 서킷브레이커가 걸리는지
- ingest: 임베딩 실패 시 미게시, 포인터 교체, 이전 버전 미삭제, 변경 없는 소스 재사용
- 토크나이저 패키지를 import 하지 않는지(AST)

## 알려진 정리 대상

- `llm_learning.py` 가 스냅샷 파일명을 `learning_v10.2.json` 으로 하드코딩한다. 공유
  모듈이라 v10.3 에서도 그 이름으로 쓴다(출력 디렉터리는 버전별로 갈리므로 충돌은 없다).
  P1 에서 이 모듈을 손댈 때 같이 정리한다.
- 시험 파일명이 `test_v10_2_*` 인 채로 v10.3 을 대상으로 한다. 파일명은 기능 단위라
  버전과 어긋나도 동작에는 문제가 없으나, 정리하려면 상호 import 를 함께 고쳐야 한다.
