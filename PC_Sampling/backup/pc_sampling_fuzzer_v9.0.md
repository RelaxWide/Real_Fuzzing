# PC Sampling SSD Firmware Fuzzer v9.0

OpenOCD PCSR 비침습 샘플링 + `nvme-cli` passthru 기반 Coverage-Guided + State-Aware Fuzzer.

> v9.0 = v8.8 기능 **전체 보존** + **사내 LLM 기반 LLM-guided fuzzing 추가**.
> `--rag` off(기본) 또는 LLM 모듈 import 실패 시 **v8.8 과 byte-동등** — 절대 크래시하지 않는다.
> per-version 파일 규칙: `pc_sampling_fuzzer_v9.0.py` = v8.8.py 복사본에 추가 편집만.
> `fuzzer_config.json`(rag 섹션 추가)·`nvme_seeds.py`·`rag/`(스키마 브리지)는 버전 안 붙는 공유 파일.

---

## v9.0 핵심: LLM-guided fuzzing (in-process 직접 호출)

### 왜
v8.8 은 P9 에서 edge coverage 가 **포화 국면**에 들어섰다. 순수 눈먼 변이(blind mutation)는
아는 hot path 만 반복해, 미접촉 명령군·의미 있는 시퀀스 생성이 취약하다. v9.0 은 **스펙을
아는 사내 LLM 을 "두 번째 시드 공급원"으로 붙여** 성장을 재가속한다.

### 전체 흐름 — 기존 루프는 무변경, LLM 은 사이드채널
```
     ┌───────────── 기존 fuzzing 루프 (그대로) ─────────────┐
     │ [시드 풀]→뽑기(energy)→변이→NVMe 발송→PC 샘플링→(새 coverage면 풀에 추가) │
     └───────▲──────────────────────────────────────────────┘
             │ 시드/시퀀스 주입 (메인 스레드가 주기적으로)
     ┌───────┴──────── v9.0 추가분 (request_cadence exec 마다) ────────┐
     │ ⓐ 스냅샷: 미접촉 함수(_collect_uncov_funcs) + 스키마 요약 + corpus 현황 │
     │ ⓑ 사내 LLM 호출  ← 백그라운드 워커 스레드(수 초, fuzzing 안 멈춤)      │
     │ ⓒ 검증·필터: JSON 파싱 → 스키마 유효? 위험명령 아님? → 통과분만        │
     │ ⓓ 시드 풀·시퀀스 풀 주입 / 에너지 우선순위 조정                        │
     └───────────────────────────────────────────────────────────────┘
```
- **발송/측정/변이 기계는 하나도 안 바뀐다.** LLM 은 corpus 에 좋은 재료를 주기적으로 넣을 뿐.
- **왜 백그라운드 스레드:** LLM 호출이 수 초 → 메인 루프에서 부르면 fuzzing 정지. 워커가
  호출하는 동안 메인 루프는 계속 fuzz 하고, 답이 오면 다음 주기 체크포인트에서 주워간다.
- **왜 검증·필터:** LLM 이 쓰레기/위험 명령(Format·Sanitize=소거) 제안 가능 → 스키마+위험
  리스트로 거른 뒤 주입. 발송 직전 기존 가드가 최종 backstop.
- **왜 off=v8.8 동일:** LLM 끄거나 모듈 import 실패면 사이드채널 전체 skip.

### LLM 3 역할 (task)
1. **신규 명령군 시드**(`new_group_seeds`) — 아직 안 건드린 opcode/명령의 유효 시드 생성 → 시드 풀.
2. **멀티-명령 시퀀스**(`sequences`) — setup→trigger(예: SetFeatures→Write→Flush→GetLogPage) → 시퀀스 풀.
3. **corpus 평가**(`corpus_eval`) — 기존 시드 유용성 점수(`llm_score`) → 에너지 우선순위 반영.

각 task 는 `rag.tasks` 로 개별 on/off. plateau(coverage 정체 `plateau_exec_threshold` 초과) 시
seeds/sequences 우선, 아니면 라운드로빈.

---

## 구조 (신규 심볼)

- **`LlmBridge`** (class, `NVMeFuzzer` 앞) — 사내 LLM callable 을 in-process 로딩(import-guarded)해
  **daemon 워커 스레드 1개·in-flight 1건**으로 호출. `_in_q`(요청)/`_out_q`(결과) 큐. 워커는
  요청 스냅샷만 읽고 결과 텍스트만 큐로 돌려주며, **corpus 등 모든 변이는 메인 스레드가 drain
  시 수행**(기존 sampler↔main 분리와 동일 → lock 불필요). off/로드 실패 시 조용히 비활성(모든
  메서드 no-op).
- **`_llm_schema_dict()`** + **`rag_schema.SchemaBridge.from_dict()`(신규)** — live `CMD_SCHEMAS`/
  `NVME_COMMANDS`/가드 상수로 in-process 검증 dict 구성. 파일 export 없이 **검증 기준을 발송
  기준과 완전 일치**(스키마 drift 제거).
- **`NVMeFuzzer._llm_*`** (전부 메인 스레드):
  - `_llm_build_request(task)` — 스냅샷(`_collect_uncov_funcs`, `schema_to_prompt`, `cmd_stats`,
    corpus 표본) → (system, user) 프롬프트.
  - `_llm_maybe_submit()` — task 선택(plateau/라운드로빈) → 요청 빌드 → `submit`(in-flight 없을 때만).
  - `_llm_drain_and_apply()` / `_llm_apply_result()` — 결과 파싱·검증·주입.
  - `_llm_make_seed()` — LLM 항목 → `validate_and_repair`+`is_dangerous` → `Seed` 또는 None(폐기).
  - `_llm_energy_adjust()` — LLM 출처 시드 부스트(`llm_energy_boost`) / 저평가 비우선화.
- **`_llm_extract_json()`** — LLM 응답에서 첫 balanced JSON 을 brace-depth 스캔으로 추출(prose 로
  감싸도 견딤). 실패 시 None(결과 폐기), **절대 raise 안 함**.
- **`Seed.seed_class`/`Seed.llm_score`**, **`SequenceSeed.seed_class`** 필드 추가(기본 None → 기존 경로 무변경).

### 응답 JSON 계약
```jsonc
{ "seeds":       [ {"command": str, "cdw2/3/10..15": int, "nsid"?: int, "data_hex"?: str, "seed_class"?: str} ],
  "sequences":   [ {"commands": [ {"command": str, "cdwN": int} ... ], "seed_class"?: str} ],
  "evaluations": [ {"seed_id": int, "score": float, "keep": bool} ] }
```
task 별 해당 키만 사용. `command` 는 `CMD_SCHEMAS` 명령명, CDW 는 스키마 valid/vendor 범위 내.

### 3중 안전 방어
1. **`is_dangerous`** — 파괴/잠금 명령(FormatNVM/Sanitize/Security lock/NS Delete) 생성 금지(drop).
2. **`validate_and_repair`** — reserved/invalid ENUM 시드 reject, FLAGS/SLOT clamp.
3. **`_send_nvme_command` 발송 가드** — 스키마 통과분도 BLOCKED_ADMIN/SECP/NS-delete 는 `RC_SKIP`.
   LLM 은 **새 발송 경로를 추가하지 않는다** — 모든 명령이 기존 `_send_nvme_command` 로 흐른다.

---

## 사내 LLM 래퍼 연결

사내 LLM 은 **importable Python callable**(fuzzer 가 in-process 직접 호출). 시그니처 2형태 지원:

| config `pass_system_prompt` | 호출 | 용도 |
|---|---|---|
| `true`(기본) | `func(system, user)` | 개발 mock `ask(system, user)` |
| `false` | `func(system + "\n\n" + user)` **단일 인자** | 사내 `generate_rag_response(user_prompt)` (system_prompt 고정 내장) |

`false` 일 때 브리지의 system 지시(JSON 계약·안전룰)를 user 에 접어 넣어 단일 인자로 호출한다.
사내 함수의 고정 system(`"주어진 참고 문서를 바탕으로 답변해…"`)이 그 앞에 붙는다. **스펙 지식은
LLM 환경에 내장**(RAG 검색은 그쪽) — fuzzer 는 스펙 PDF 임베딩/retrieval 을 하지 않는다.

**실장비 설정 예:**
```json
"rag": {
  "enabled": true,
  "module_path": "<사내 generate_rag_response 모듈>",
  "func_name": "generate_rag_response",
  "pass_system_prompt": false
}
```
CLI override: `--rag / --no-rag / --rag-module <mod> / --rag-func <fn>`.

---

## Config (`fuzzer_config.json` `rag` 섹션, 추가·기본 disabled)
```
enabled(false)  module_path("rag.mock_llm")  func_name("ask")  pass_system_prompt(true)
request_cadence(5000)  plateau_exec_threshold(20000)  max_seeds_per_round(8)  max_seq_per_round(4)
max_uncov_funcs(40)  seed_at_startup(true)  llm_energy_boost(1.5)  reserved_policy("reject")
result_stale_execs(50000)  tasks{new_group_seeds, sequences, corpus_eval}
```
섹션 없어도 `.get` 으로 로드 → 비활성. 모든 신규 호출부는 `if self.llm.enabled:` 가드.

---

## 변경/추가 파일
| 파일 | 내용 |
|------|------|
| `pc_sampling_fuzzer_v9.0.py` | v8.8.py 복사 + `LlmBridge`/`_llm_*`/`Seed.seed_class`/config·CLI |
| `fuzzer_config.json` | `"rag"` 섹션 추가(공유·하위호환) |
| `rag/rag_schema.py` | `SchemaBridge.from_dict` classmethod 추가(파일 없이 in-process 구성) |
| `rag/mock_llm.py` | **신규** dev mock — `ask(system,user)` + `generate_rag_response(user)` |

`rag/export_cmd_schemas.py`(스키마 JSON export)·`rag/split_pdf.py`(스펙 PDF 분할)는 별도 RAG
서비스(drop-box) 경로용 스캐폴딩으로 남아있으나, **v9.0 의 in-process 직접 호출 경로에서는 미사용**.

---

## graceful disable / byte-동등 보장
- `rag.enabled=false` 또는 `--no-rag` → `LlmBridge.__init__` early-return, `start/submit/drain` no-op.
- 모듈 import 실패 / 함수 없음 → `[LLM] 비활성화 …` 경고 후 조용히 v8.8 경로(로그만, 크래시 없음).
- 신규 `Seed.seed_class`/`llm_score` 는 기본 None → `_calculate_energy` 의 `_llm_energy_adjust` 가
  non-llm 시드엔 값 무변경. 즉 **비활성 시 동작·에너지 값 모두 v8.8 과 동일**.

---

## 검증 (mock, 하드웨어·사내 LLM 없이)
- 파이프라인 end-to-end: GetLogPage·Identify **통과**, Sanitize **schema-reject**, BogusCmd
  **unknown drop** → 2 valid / 2 dropped.
- prose 로 감싼 JSON·무효 JSON **강건 파싱**(brace-scan), 절대 raise 안 함.
- seeds+sequences **주입**(seed_class 태그, 에너지 부스트 1.5), corpus 반영.
- **단일 인자 경로**(`generate_rag_response(user)`, `pass_system_prompt=false`) end-to-end 통과.
- **graceful disable**: off / import 실패 / 함수 없음 → 전부 비활성 = v8.8 동등.
- 문법(`py_compile`)·config(`json.load`)·모듈 로드 OK.

**실장비(하드웨어 + 사내 LLM):** config 에 사내 모듈/함수 지정 → `[LLM] 활성` 로그 확인 → 한
라운드가 fuzzing 지속 중 반환하는지, `[LLM] 주입: seeds+N` 로그와 미탐색 명령군의 `cmd_stats`
증가, plateau 트리거 발화 확인. LLM 이 JSON 대신 "모른다"를 자주 내면(RAG 미커버) user prompt
지시 문구 튜닝.

---

## v8.8 이하 (전부 v9.0 에 그대로 유지)
세부는 각 버전 md 참조. 요지: v8.8(주기 차트 os.fork()→subprocess, 호스트 logless 재부팅 제거
+ P9 halt 노이즈/워치독/FWCommit 복구/RDDump PTY 등 세션 수정) / v8.7(PCSR always-on 제거) /
v8.4(IO 워크로드) / v8.1(P9 J-Link halt 샘플러) / v7.x(State-Aware, SequenceSeed, MOpt, CSFuzz).

## 지원 제품
| 제품 | interface | core | coverage 샘플러 | 상태 |
|------|-----------|------|-----------------|------|
| PM9M1 | SWD | R8×3 | OpenOCD PCSR(비침습) | 정상 |
| BM9H1 | JTAG | R8×2 | OpenOCD PCSR(비침습) | 정상 |
| P9 | SWD | R5 단일 | J-Link halt(pylink) | 정상 |

LLM-guided(`--rag`)는 제품 무관 — corpus/시드 레벨 기능이라 샘플러 종류와 독립.

```bash
# 기본(LLM off = v8.8 동등)
sudo python3 pc_sampling_fuzzer_v9.0.py --product P9 --nvme /dev/nvme0n1

# LLM-guided (사내 래퍼 지정)
sudo python3 pc_sampling_fuzzer_v9.0.py --product P9 --nvme /dev/nvme0n1 \
     --rag --rag-module <사내모듈> --rag-func generate_rag_response
# (또는 fuzzer_config.json rag 섹션에 enabled/module_path/func_name/pass_system_prompt 설정)
```
