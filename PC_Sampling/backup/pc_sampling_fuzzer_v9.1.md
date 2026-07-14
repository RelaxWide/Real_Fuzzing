# pc_sampling_fuzzer v9.1

> per-version 파일 규칙: `pc_sampling_fuzzer_v9.1.py` = `v9.0.py` byte-copy 에 아래 편집만.
> 코어 fuzzing 루프·발송 검증(`validate_and_repair`+`is_dangerous`+발송 가드)·샘플러는 무변경.

## 한 줄 요약
v9.0(LLM-guided)의 위에, **디바이스가 실제로 낸 NVMe 완료상태(SC)를 근거로 LLM 조준·스케줄을 교정**하고, 측정 위생(state-cov)과 crash 덤프 안정화(J-Link close)를 보강한 버전.

## 배경 — 왜 v9.1
이번 진단에서 확인된 것:
- 이 펌웨어에서 **다수 opcode 가 `SC=0x01`(Invalid Opcode)=미구현** → opcode 디코드 단계에서 즉시 반송, 포화. 커버리지 성장 여지는 **구현된 소수 명령의 깊은 경로**에만 남음.
- 기존 LLM 되먹임(저수확 단일 목록)이 **"미구현" vs "구현됐으나 필드가 얕음"** 을 뭉뚱그려 → 구현된 좋은 명령(GetLogPage 등)을 "회피"로 오조준.
- 스키마 요약 `[:20]` 캡이 랭킹 바닥 명령(Read/Write 등)의 스키마를 아예 숨겨 → **LLM 명령 고착**.
- 위험 신호는 아니지만, Sanitize In Progress 같은 **전역 백그라운드 상태**가 디바이스 상태를 한꺼번에 스윙 → state-cov 오염.
- P9 timeout 후 J-Link `close()` 의 resume 가 silent 실패 시 R5 가 halt 로 남아 RDDump(NVMe) 무응답.

## 변경 요약

### A. SC-status 되먹임 인프라 (항상 동작)
- `_send_nvme_command`: 완료 시 `self._last_nvme_status` 캡처 — 성공=`0`, device status=full(SCT<<8|SC), errno/미도달=`None`.
- `_account_command`: `cmd_stats[name]` 에 집계 필드 추가 — `reached_fw`(펌웨어 도달 수), `sc_hist`(상태 히스토그램), `invalid_opcode`(SC=0x01 수), `accepted`(성공 시 cdw10 예시 ≤3).
- `_update_unimpl(name)`: **`reached_fw ≥ 5` AND `invalid_opcode/reached_fw ≥ 0.9`** → 확정 미구현(`self._unimpl_cmds`). 이후 비-0x01 상태가 관측되면 해제(상태의존 구현 대비). 상태변화 시 `[LLM/unimpl]` 로그.

### B. LLM 조준 — 프롬프트 (RAG on 일 때)
`_llm_grounding_block` / `_llm_build_request`:
- **#1 명령별 SC digest** — 미구현은 "UNIMPLEMENTED, do NOT propose", 구현-얕음은 "implemented; fix fields to go deeper" 로 **분리**(기존 저수확 단일목록 대체 = 오조준 제거).
- **#2 accept-CDW few-shot** — 디바이스가 실제 accept 한 CDW 예시(유효 envelope).
- **#4 구조적 data_hex 요청**(`_llm_data_directive`) — 구현된 `needs_data` 명령에만 valid 구조 payload 요청(CDW 변이가 못 닿는 data 파싱 경로용). 소비는 기존 data_hex 경로 그대로.
- **#5 시퀀스 재료에서 미구현 opcode 제외**.
- **스키마 `[:20]` 캡 제거 → `[:RAG_SCHEMA_MAX(48)]`** = 구현된 전 명령 스키마 노출(8k 토큰 입력 예산상 ~4k 여유). 랭킹(never-sent/under-explored)은 **우선순위 힌트로만** 유지(가시성/우선순위 분리).
- new_group_seeds 후보에서도 `_unimpl_cmds` 제외.

### C. 스케줄 — 에너지 (항상 동작, 토글 가능)
- **#3 확정 미구현 시드 에너지 바닥**(`_calculate_energy`) — SC=0x01 지배 명령은 opcode 디코드에서 포화라 변이가 무의미 → `RAG_ENERGY_FLOOR(0.05)` 로 눌러 퍼징 예산 회수(0 아님 = 시퀀스 부활 여지). 근거: Entropic(생산성 기반 에너지)/AFLFast COE(포화 컷오프). `unimpl_energy_floor_on=false` 로 A/B 가능.

### D. 측정 위생 — state-cov 전역 이벤트 필터
- 매 100명령 state delta harvest 게이트에 **단일 필터**: 한 delta 에서 동시 변경(비-`:=init`) 필드 수 `> STATE_GLOBAL_EVENT_FIELDS(6)` 이면 **전역 백그라운드 op**(Sanitize/Format In Progress·self-test·controller reset)로 보고 harvest·`update_cov_map` 제외 + baseline 재설정(진입/탈출 delta 둘 다 무시). 명령 종류를 안 봄 — "필드 우르르 변경" 공통 시그니처만 사용.

### E. 안정화 — J-Link close 하드닝
- `JLinkHaltSampler.close()`: R5 resume(`Go`) 후 **`halted()` 재확인 → 여전히 halt 면 최대 3회 재시도(20ms)**, 성공/실패 로그. 기존엔 Go 실패를 silent(`except:pass`)로 삼키고 연결을 닫아 R5 가 halt 로 stranded → RDDump 무응답이 되던 것을 방지 + 자가진단(모드A=resume실패 / resume OK인데 RDDump 실패=모드B=펌웨어 hung).

### F. 리팩토링 / docstring
- `_is_llm_seed(seed)` static 헬퍼 신설 — 여기저기 흩어진 LLM-lineage 판정(`seed_class` 'llm' 접두) **7곳을 단일화**.
- `_sc_name` docstring 추가.

## config 키 (하위호환 — 전부 `.get` 기본값)
| 섹션 | 키 | 기본 | 의미 |
|---|---|---|---|
| rag | `unimpl_min_exec` | 5 | 미구현 확정 최소 FW 도달 수 |
| rag | `unimpl_ratio` | 0.9 | invalid_opcode/reached_fw 임계 |
| rag | `unimpl_energy_floor` | 0.05 | 확정 미구현 시드 에너지 바닥 |
| rag | `unimpl_energy_floor_on` | true | #3 토글 |
| rag | `schema_max` | 48 | 스키마 노출 안전상한(정상 미적용) |
| strategy | `state_global_event_fields` | 6 | 전역 이벤트 판정 동시-변경 필드 임계 |

## 관측 (로그 — 전부 `[LLM`/`[J-Link`/`[State-Cov` 접두)
- `[LLM/unimpl] <cmd> 확정 미구현 (Invalid Opcode N/M)` / `... 판정 해제` — 미구현 판정 (터미널 노랑, calibration 초반에 관측).
- `[LLM/v9.1] 확정 미구현=[...] | accept예시 보유 명령=N | 구현됐으나 필드거부 관측=M` — 되먹임 성숙도.
- `[LLM/stats] ★LLM이 뚫은 새 커버리지(누적)=...★` — new_cov.
- `[J-Link] close: R5 resume 확인` / `... resume 실패 — ...` — close 하드닝 자가진단.
- `[State-Cov] 전역 이벤트 감지 — N 필드 동시 변경 → state-cov 제외 + 재baseline`.
- **프롬프트 검증:** `rag.log_responses=true` → `output/pc_sampling_v9.1.0/llm/llm_io_*.jsonl` 의 `prompt` 필드(보낸 것) + `response`(받은 것).

## 알려진 한계 / 다음 작업
- **new_cov 는 하한(lower bound)**: P9 는 halt 샘플링(DBGPCSR 미구현)이라 **fast-path under-sampling** + "global-first 발견" 기준 → LLM 실제 도달을 과소평가. → 보조 지표 후보: **SC-depth 진전**(0x01→0x02→성공)으로 샘플러가 못 잡는 도달 깊이 측정.
- **P9 hung 펌웨어 덤프**: RDDump(NVMe)는 살아있는 펌웨어가 필요 → hung/halt 상태 덤프 불가. 근본 해법은 **in-process pylink `memory_read` 기반 JTAG 덤프**(미구현). close 하드닝 로그가 모드 A/B 를 가려줌.
- **SANACT 가드**: `opcode_override` 가 Sanitize(0x84) 를 파괴적 SANACT(2/3/4)로 트리거 가능(`--no-erase` 없을 때). 데이터 파괴 방지용 send-time SANACT 가드는 **별개 안전 이슈로 보류**(원하면 추가).
- accept-CDW few-shot 은 현재 relevance 정렬 없이 앞 10개 노출(캡에 걸릴 때만 영향) — reached_fw 정렬 개선 여지.

## 실행
```bash
sudo -E python3 pc_sampling_fuzzer_v9.1.py --product P9 --nvme /dev/nvme0n1 ... --rag
```
v9.0 실행 인자 그대로. `--rag` off 또는 LLM 모듈 import 실패 시 사이드채널 비활성(A/C/D/E/F 인프라는 저비용으로 계속 — 발송/커버리지엔 무해).

## 파일
- `pc_sampling_fuzzer_v9.1.py` — v9.0 byte-copy + 위 A~F.
- `fuzzer_config.json` — rag/strategy 튜닝키 추가(공유 파일, 하위호환).
