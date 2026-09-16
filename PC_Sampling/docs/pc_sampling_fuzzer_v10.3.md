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

**실패 분류** — 실패로 세는 것은 넷이다.

| 실패 | 확인 방법 |
|---|---|
| 통신 실패 | 백엔드 예외. 진단(HTTP 상태·오류 본문)이 **그 요청에** 실려 온다 |
| 잘림 | **최종** `finish_reason=length`. 파싱이 우연히 성공해도 실패다 — 모델이 유효한 JSON 을 낸 뒤 상한에 걸리면 그 안의 목록은 잘린 중간 결과다. 교정 호출이 있었으면 그쪽 값이 최종값(`_llm_final_finish_reason`) |
| 파싱 실패 | `_llm_extract_json` 이 None |
| task 형식 오류 | task 가 요구한 컨테이너가 없거나 타입이 틀림(`_LLM_TASK_CONTAINERS`) |

`_llm_schema_ok` 는 **task 를 보지 않는다** — top-key 가 하나라도 있으면 통과라
`new_group_seeds` 요청에 `{"evaluations": []}` 가 와도, `{"seeds": "bad"}` 가 와도
'정상 응답'이 됐다(후자는 학습 모듈이 빈 배열로 정규화해 조용히 0개 주입이 된다).
구조화 출력이 켜져 있으면 서버가 막아 주지만, `structured_output=false` 나 사내 브리지로
되돌린 상태 — 즉 **뭔가 잘못돼서 폴백한 상황** — 이 정확히 서킷브레이커가 필요한 때다.
검사는 학습 모듈이 정규화하기 **전의 원본**(`raw_original`)으로 한다.
`new_group_seeds` 는 `generators` 만 온 응답도 정상이다(학습 모듈이 seeds 로 컴파일한다).

정상 응답인데 중복으로 채택이 0개인 경우는 **실패가 아니다**. v10.2 는 백엔드가 반환만
하면 파싱 성패와 무관하게 연속 실패를 0 으로 되돌려, 무효 응답이 반복돼도 서킷브레이커가
안 걸렸다.

**진단 귀속** — 진단은 **그 요청에만** 붙는다. 워커의 `_diag` 는 요청마다 초기화하고,
백엔드 실패도 `_LlmBackendFailure` 에 진단을 실어 올린다. 초기화하지 않으면 `_diag` 가
워커 루프를 가로질러 살아서 실패한 요청에 **직전 요청의** `req_id`·`finish_reason` 이
붙는다 — 없는 진단보다 틀린 진단이 해롭다.

**시간 예산** — `timeout_sec` 는 임베딩·생성·JSON 교정을 합한 **요청 하나 전체**의 예산이다.
워커가 `meta.budget_started` 로 기준 시각을 찍어 교정 호출까지 같은 예산을 나눠 쓴다
(호출마다 새 예산을 주면 `json_retries` 배만큼 늘어난다).

`urlopen(timeout=)` 은 소켓 연산별 상한이라 총 경과를 막지 못한다. 그래서 수신은
**성공·오류 경로 모두** `_read_bounded` 하나를 쓴다 — `read1` 로 도착한 만큼씩 받아
조각마다 예산을 보고, 소켓 타임아웃도 **읽기마다** 남은 예산으로 줄인다(연결 전에 한 번만
계산하면 스트림 중간에 서버가 멈췄을 때 그 read 가 예산을 한참 넘겨서야 풀린다). 예산을
넘겨 도착한 결과는 폐기하고, 예산이 다한 뒤의 소켓 타임아웃은 '연결 실패'가 아니라
예산 초과로 보고한다.

느린 **HTTP 오류 본문**도 같은 예산 아래 읽는다. 오류 경로만 예산 밖에 두면 느린
4xx/5xx 가 예산을 통째로 우회한다. 다만 예산이 다하거나 서버가 멈춰도 **HTTP 상태 ·
받은 본문 · 중단 사유 셋 다** 보고한다 — 오류 내용을 버리지 않는 것이 이번 이관의
발단이었고, 왜 잘렸는지도 같이 알아야 추적이 된다.

읽기 예외는 `_read_bounded` **안에서** 처리한다. 밖에서 받으면 read1 안에서 터진
소켓 타임아웃에 이미 모은 조각까지 함께 잃는다. 소켓 탐색(`_sock_of`)은 `.fp` 를
따라가며 `.raw._sock` 을 찾는다 — HTTPError 는 실제 HTTPResponse 를 한 겹 더 감싸서
(`exc.fp.fp.raw._sock`) 한 단계만 보면 오류 경로에서만 읽기별 갱신이 빠진다.

연결 단계만 따로 제한하는 설정은 두지 않는다(urllib 이 지원하지 않아 지켜지는 것처럼
보이기만 한다).

**계측** — 주기 통계에 깔때기가 찍힌다. 채택은 **task 마다 형태가 다르다** — seed·
sequence 만 세면 정상 적용된 corpus_eval·io_patterns 라운드가 전부 '정상0건' 으로
집계돼 P1↔P2 비교 지표가 처음부터 오염된다.

```
[LLM/funnel] 요청=12 → 통신ok=12 → JSONok=11 → 항목=64 → 채택=31(시드 24/시퀀스 5/평가 2/워크로드 0) (정상0건=2, 연속실패=0/10)
```

## P2 — 로컬 RAG

DGX 에 **두 인스턴스**가 뜬다. 생성과 임베딩은 모델도 상한도 다른 별개 단계다.

| 포트 | 모델 | 쓰임 | 설정 키 |
|---|---|---|---|
| 8000 | `nemotron-3-super` | 생성 (컨텍스트 1M) | `rag.vllm.base_url` · `model` |
| 8001 | `bge-m3` | 임베딩 (입력 상한 8,192) | `rag.vllm.retrieval.embed_base_url` · `embed_model` |

```bash
# 0) 먼저 점검 — 임베딩 서버·numpy·설정 없이 돈다. 인덱스를 만들지 않는다
python3 PC_Sampling/tools/rag_ingest.py <JSONL...> --dry-run

# 1) 8001 에 bge-m3 를 띄운 뒤 — 엔드포인트는 설정에서 읽는다
python3 PC_Sampling/tools/rag_ingest.py <JSONL...>
```

`--dry-run` 은 **게시를 막을 것을 임베딩 전에** 찾는다(종료코드 0=진행 가능, 1=거부됨).
레코드 수·content 길이 분포·청크 수·`doc_id` 중복을 보고한다. 본 ingest 와 **같은**
`load_jsonl`/`split_record` 를 쓴다 — 점검을 따로 구현하면 갈라져서, 통과했는데 실제로는
거부되는 일이 생긴다. JSONL 이 다른 망에만 있어 그쪽에서 확인해야 할 때 쓰라고 만든 것이라
설정 파일도 numpy 도 없는 환경에서 돌아간다.

**한 PDF 를 쪽수로 쪼개 만든 JSONL 은 `doc_id` 가 겹치기 쉽다.** 분할 파일마다 같은
`doc_id` 가 붙으면 청크 id 가 파일 간에 충돌해 게시가 거부된다 — `--dry-run` 이 "서로
다른 파일에 같은 doc_id" 로 구분해 알려 준다.

임베딩 서버·모델·revision 은 `fuzzer_config.json` 의 `rag.vllm.retrieval` 에서 읽고,
CLI 인자(`--embed-base-url` 등)가 그것을 덮어쓴다. **인덱스를 만들 때와 검색할 때의
값이 같아야** 하므로 설정을 단일 출처로 둔다 — 두 곳에 두면 IP 가 바뀔 때 어긋나고,
어긋나면 벡터 공간이 달라져 조용히 엉뚱한 문서가 뽑힌다. 실행하면 어느 서버에
무엇으로 색인하는지 한 줄 찍는다(검색이 이상할 때 첫 단서다).

`retrieval.embed_base_url` 이 비면 **생성 서버로** 임베딩하게 된다. 한 서버에 둘 다
올린 구성도 있을 수 있어 막지는 않되, 경고를 띄운다.

인덱스는 `rag/index/<version>/` 에 만들고 `current` 포인터만 원자적으로 교체한다.
이전 버전은 지우지 않는다 — 실행 중 캠페인이 쓰고 있을 수 있다. `rag/index/` 는
`.gitignore` 다(내부 스펙 원문이 들어갈 수 있다).

만든 뒤 `rag.vllm.retrieval.enabled=true` 로 켠다.

**본문과 벡터는 언제나 같이 움직인다.** 임베딩 서버가 청크 길이 초과를 반환하면 그
청크를 **둘로 쪼개 양쪽 다** 임베딩한다. 앞부분만 임베딩하고 원문을 그대로 저장하면
뒷부분의 스펙 내용이 검색에 영영 안 걸리는 인덱스가 정상인 얼굴로 게시된다. 더 쪼갤
수 없으면(`MIN_CHUNK_CHARS` 미만) 게시하지 않고 `--max-chars` 를 줄이라고 알린다.

**벡터 재사용 키는 (소스 파일, doc_id, 본문 sha256)** 이다. 본문이 키에 없으면
`--max-chars` 를 바꿨을 때 같은 doc_id 에 다른 본문이 들어오는데도 — 소스 파일은
안 바뀌었으니 재사용 조건도 통과해 — 예전 본문의 벡터가 붙는다. 임베딩 모델 이름과
`--embed-model-revision` 이 **둘 다** 같을 때만 재사용한다. revision 은 manifest 에
남고, 검색 시 인덱스와 설정이 다르면 실행 시점에 거부한다(모델이 다르면 벡터 공간이
달라 점수는 계산되는데 엉뚱한 문서가 뽑힌다).

**게시 전 검증** — 본문↔벡터 개수, 차원, NaN/Inf, 영벡터, `doc_id` 중복. 하나라도
걸리면 staging 을 버리고 포인터를 바꾸지 않는다. 동시 실행은 `.ingest.lock` 으로 막고
(staging·포인터 임시파일에도 pid 를 붙인다), 중단된 작업이 락을 남겼으면 지우고
다시 실행하라고 알린다.

**검색 질의**는 프롬프트 전문이 아니다 — 임베딩 상한(bge-m3 8,192)은 생성 컨텍스트(1M)와
별개 단계의 제약이다. 순서: `meta.rag_query` → 프롬프트의 `[RAG-QUERY]` 블록 → 생략.
토크나이저는 쓰지 않는다(문자 수 기준이며 토큰 수 보장이 아니다).

2단도 **실제로 동작하는 경로**다. `llm_learning.py` 의 `query_block()`(L50) 이 학습이
켜져 있을 때 프롬프트 앞에 그 블록을 붙인다 — 평소에는 1단 `meta.rag_query` 가 먼저
잡힐 뿐이다. `meta` 를 안 넘기는 구버전 호출은 백엔드가 `user_prompt` 를 user 메시지로
채워(`setdefault`) 2단이 받아 준다. v10.3 워커가 실어 보낸 **원본** 프롬프트는
setdefault 라 교정 호출에서도 덮이지 않는다.

`meta.rag_query` 는 이 요청이 **실제로 겨냥한 명령**(`ctx['rag_query_commands']` — 프롬프트
빌더가 고른 never-sent/low-yield 후보, corpus_eval 이면 표본 명령)을 먼저 쓰고, 없을 때만
task 무관한 목록으로 채운다. `query_block()` 이 쓰는 키와 같다.

## 검증 (P1·P2)

```bash
python3 -m unittest discover -s PC_Sampling/tests -p 'test_*.py'   # 165 tests, OK
```

`tests/test_v10_3_backend.py` 73개가 가짜 HTTP 서버로 DGX 없이 돈다. 주요 항목:

- **스키마↔파서 대조**를 AST 로 강제 — 파서가 읽는 키가 스키마에 없으면 실패한다.
  계획 초안이 `data_len` 을 빠뜨렸던 것이 이 시험의 계기이고, 실제로 스키마에서 그
  필드를 빼면 시험이 깨지는 것을 확인했다.
- 기존 문자열 반환과 새 `{raw, diagnostics}` 가 모두 처리되고 진단이 해당 요청에만 붙는지
- HTTP 오류 본문 보존, 스키마 거부 시 자동 폴백 금지, 잘림 보고
- 정상 응답의 채택 0건이 실패로 안 세지는지 / 무효 응답 반복은 서킷브레이커가 걸리는지
- ingest: 임베딩 실패 시 미게시, 포인터 교체, 이전 버전 미삭제, 변경 없는 소스 재사용
- 토크나이저 패키지를 import 하지 않는지(AST)
- **진단 귀속**: 성공→실패에서 직전 진단을 물려받지 않는지, 첫 요청 실패, 교정 호출 실패
- **시간 예산**: 조금씩 흘려보내는 응답이 폐기되는지, 소진된 예산으로 요청을 안 보내는지
- **실패 판정**: 잘림(최초·교정)·엉뚱한 task·잘못된 타입은 실패, 정상 빈 응답은 성공
- **폐기 응답의 부작용 없음**: 잘림·형식 오류가 generator 저장소·목표 통계를 안 바꾸는지
- **느린 HTTP 오류 본문**도 예산 안에서 멈추는지(HTTP 상태는 유지한 채)
- **revision**: 명시했을 때 manifest 의 누락·null·불일치를 모두 거부하는지
- **멈춘 서버**: 오류 본문 일부만 받고 정지해도 상태·부분 본문·중단 사유가 남는지,
  HTTPError 래퍼 너머에서 소켓을 찾는지
- **구버전 호출**: `meta` 없이 불러도 프롬프트의 `[RAG-QUERY]` 로 질의가 만들어지는지
- **엔드포인트 출처**: ingest 가 설정에서 서버·모델·revision 을 읽는지, CLI 가 그것을
  덮어쓰는지, 설정에 8000(생성)·8001(임베딩)이 서로 다르게 살아 있는지
- **임베딩 폴백**: `embed_base_url` 이 없어 생성 서버로 갈 때 경고가 뜨는지
- **`--dry-run`**: 분할 파일 간 `doc_id` 중복을 종료코드 1 로 알리는지, 인덱스를 안 만드는지,
  numpy·설정 없이 도는지(대조군으로 실제 색인은 numpy 를 요구하는지)
- **깔때기**: 적용된 워크로드가 채택으로 세어지는지(정상0건이 아닌지)
- **인덱스 정합성**: 상한 초과 청크 분할 후 본문 전량 보존·본문↔벡터 일치, 청크 크기·
  revision 변경 시 재임베딩, doc_id 중복·영벡터 거부, 락, 모델 불일치 인덱스 거부

각 시험은 **고친 코드를 되돌리면 실패하는 것**까지 확인했다(17건 주입 시험).

## 알려진 정리 대상

- `llm_learning.py` 가 스냅샷 파일명을 `learning_v10.2.json` 으로 하드코딩한다. 공유
  모듈이라 v10.3 에서도 그 이름으로 쓴다(출력 디렉터리는 버전별로 갈리므로 충돌은 없다).
  P1 에서 이 모듈을 손댈 때 같이 정리한다.
- 시험 파일명이 `test_v10_2_*` 인 채로 v10.3 을 대상으로 한다. 파일명은 기능 단위라
  버전과 어긋나도 동작에는 문제가 없으나, 정리하려면 상호 import 를 함께 고쳐야 한다.
- 수신 중 예산 검사의 초과분은 **한 패킷 도착 시간**까지로 묶인다. 소켓 타임아웃을
  읽기마다 남은 예산으로 줄여 멈춘 연결은 잡지만, 문자 수 상한과 마찬가지로 **정확한
  상한 보장이라고 표현하지 않는다.**
- 오류 본문은 예산이 다하면 **받은 만큼만** 싣는다. 진단 우선이라 의도한 절충이며,
  그 경우 메시지에 `[오류 본문 수신 중 시간 예산 초과 — 일부만]` 이 붙는다.
