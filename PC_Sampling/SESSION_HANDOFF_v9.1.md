# SESSION HANDOFF — v9.1 (SC-status 되먹임 + LLM 조준 + 측정/안정화 세션)

> 이 파일이 현재 핸드오프다. 구 `SESSION_HANDOFF_v8.8.md`/`v9.0.md` 는 `backup/` 으로 이동.
> v9.1 = v9.0(LLM-guided) 위에 **디바이스 실제 완료상태(NVMe SC)를 근거로 LLM 조준·스케줄 교정**
> + 측정 위생(state-cov) + crash 덤프 안정화(J-Link close).

---

## 0. 현재 상태 한 줄
- **최신 = `pc_sampling_fuzzer_v9.1.py`** (`FUZZER_VERSION="9.1.0"`). 상세: `pc_sampling_fuzzer_v9.1.md`.
- `--rag` off(기본) 시 코어 fuzzing/발송 무변경. SC 집계·에너지 floor·state-cov 필터·close 하드닝은 **RAG 무관하게 저비용 동작**(발송/커버리지엔 무해).
- 구버전(`v8.0`~`v9.0` .py/.md) = `backup/`. git 이력에도 전부 보존.

---

## 1. v9.1 변경 (이번 세션) — 상세는 `pc_sampling_fuzzer_v9.1.md`
핵심 진단: 이 펌웨어는 **다수 opcode 가 `SC=0x01`(Invalid Opcode)=미구현** → opcode 디코드에서 포화. 커버리지 여지는 **구현된 소수 명령의 깊은 경로**.

- **(A) SC 되먹임 인프라:** `_send_nvme_command` 가 `_last_nvme_status` 캡처, `_account_command` 가 `cmd_stats` 에 `reached_fw/sc_hist/invalid_opcode/accepted` 집계, `_update_unimpl`(도달≥5 & invalid_opcode≥90%)로 `_unimpl_cmds` 확정.
- **(B) LLM 조준(프롬프트):** #1 명령별 SC digest(미구현 "제안금지" / 구현 "필드교정" 분리) · #2 accept-CDW few-shot · #4 구조적 data_hex(구현 needs_data 만) · #5 시퀀스 재료 미구현 제외 · **스키마 `[:20]` 캡 제거**(→ 구현 전 명령 노출, 명령 고착 해소).
- **(C) 에너지:** 확정 미구현 시드 바닥(`RAG_ENERGY_FLOOR`) — Entropic/AFLFast COE 근거.
- **(D) state-cov 전역 이벤트 필터:** 한 delta 동시변경 필드 > `STATE_GLOBAL_EVENT_FIELDS(6)` → Sanitize/Format In Progress 등 전역 op 로 보고 harvest 제외+재baseline.
- **(E) J-Link close 하드닝:** R5 resume 검증·재시도·로깅 — silent Go 실패로 R5 halt 잔류 → RDDump 무응답 방지 + 자가진단.
- **(F) 리팩토링:** `_is_llm_seed` 헬퍼로 LLM-lineage 판정 7곳 단일화, `_sc_name` docstring.
- **config(하위호환):** `rag.{unimpl_min_exec,unimpl_ratio,unimpl_energy_floor,unimpl_energy_floor_on,schema_max}`, `strategy.state_global_event_fields`.

---

## 2. 이번 세션 진단 — 다음 세션이 알아야 할 것 (중요)
- **`rc=22` = `SC=0x01` Invalid Opcode = 미구현.** 커널 반송이 아니라 펌웨어 도달 후 opcode 디코드 거부. `rc=121`=LBA Out of Range 등(nvme-cli 가 SC→errno 매핑). "device 지원"은 OACS 광고값이 아니라 **실측 SC 가 ground truth**.
- **`new_cov` 는 하한(lower bound):** P9 는 halt 샘플링(DBGPCSR 미구현)이라 **fast-path(invalid opcode reject 등) under-sample** + "global-first 발견" 기준 → LLM 실제 도달을 과소평가. 측정 자체는 정확(귀속 게이팅/이중계산 없음 확인). 보조 지표 후보 = **SC-depth 진전**(0x01→0x02→성공).
- **P9 hung 펌웨어 덤프 불가(현):** RDDump = NVMe 경로라 **살아있는 펌웨어가 응답해야** 함 → hung/halt 상태는 못 뜸(J-Link halt + RDDump = 재현 확인됨). 근본해법 = **in-process pylink `memory_read`(JTAG) 덤프**(미구현). `[J-Link] close:` 로그가 모드A(resume실패)/B(펌웨어hung) 구분.
- **Sanitize 사고:** `opcode_override` 가 Sanitize(0x84)를 파괴적 SANACT(2/3/4)로 트리거 가능(`--no-erase` 없을 때) → 실제 소거 + Sanitize In Progress 로 상태 오염. state-cov 필터(D)로 오염은 차단했으나, **데이터 파괴 방지용 SANACT send-time 가드는 별개 안전이슈로 보류**(원하면 추가).

---

## 3. v9.0 배선 — 유지 (2-PC Samba drop-box)
### 구조
- **온라인 PC (Windows)**: 사내 LLM. `srag_llm_service.py` + `srag_llm_guide.py`(사용자 실제 LLM, `generate_rag_response(user_prompt)->str`).
- **오프라인 PC (Linux, fuzzer)**: `pc_sampling_fuzzer_v9.1.py` + `rag/rag_bridge_client.py`(drop-box 클라이언트, LLM 코드 없음).
- **연결**: Samba 공유 `rag/bridge/`(requests/·responses/). 워커 스레드가 요청 write→온라인 폴링·LLM·응답 write→읽어 반환. fuzzing 안 멈춤, timeout=graceful skip. **bridge 파일은 소비 후 삭제(정상)**.

### rag/ 파일
| 파일 | PC | 역할 |
|---|---|---|
| `rag_bridge_client.py` | 오프라인 | fuzzer import(`module_path=rag.rag_bridge_client`), drop-box 클라이언트 |
| `srag_llm_service.py` | 온라인 | 공유폴더 폴링→실제 LLM 호출 |
| `srag_llm_guide.py` | 온라인 | 사용자 실제 LLM(repo 아님) |
| `rag_schema.py` | 오프라인 | 산출물 in-process 검증(`SchemaBridge.from_dict`) |
| `mock_llm.py`/`test_llm.py`/`test_bridge.py` | dev/온라인 | 배선·단독·왕복 점검 |

### 설정 (오프라인 `fuzzer_config.json` rag)
`enabled:true, module_path:"rag.rag_bridge_client", func_name:"generate_rag_response", pass_system_prompt:false`(사내 함수 단일인자 → fuzzer system 을 user 에 접어 보냄). **입력 최대 8k 토큰**(현재 프롬프트 ~4k, 여유). CLI `--rag/--no-rag`, `sudo -E` 실행(env 전달).

### 안전 (3중, 무변경)
`is_dangerous`(Format/Sanitize/lock/NS-delete drop) → `validate_and_repair`(reserved reject) → `_send_nvme_command` 발송 가드(`RC_SKIP`). LLM 은 새 발송 경로 없음.

### 검증 상태
mock end-to-end + 온라인 `test_llm.py` [PASS] + 2-PC `test_bridge.py` 왕복 [PASS] 확인됨. (온라인 Windows 는 `python3`=Store 스텁 → 반드시 `python`.) 실장비 `--rag` 실행은 하드웨어 필요.

### 실행 절차
1. 온라인: `python srag_llm_service.py`(watching 대기). 2. 오프라인 config `--rag`. 3. `sudo -E python3 pc_sampling_fuzzer_v9.1.py --product P9 --nvme /dev/nvme0n1 ... --rag`. 4. 확인: 워커 기동, `RAG_REQUEST_CADENCE`마다 요청, 응답 시드 `seed_class='llm_*'` corpus 진입, `[LLM/unimpl]`·`[LLM/v9.1]` 로그. 프롬프트 검증은 `rag.log_responses=true` → `output/pc_sampling_v9.1.0/llm/llm_io_*.jsonl` 의 `prompt` 필드.

---

## 4. 호스트 OS freeze — halt-vs-controller 타이밍 레이스 (조사 종료)
- **✅ 확정**: `--no-jlink` 60만 execs 무이상 → J-Link halt 없으면 안정, 있으면 1만~45만서 터짐 = **freeze 원인 = halt 샘플링(halt-vs-컨트롤러 타이밍 레이스). 조사 종료.**
- 성격: 특정 명령이 방아쇠 아님(로그 끊김 지점 제각각). go_settle 로 튜닝 불가(분산 큼, n=1~2). 근본원인 캡처(kdump/ramoops)는 logless 로 전부 무증거 → 포기 합리적.
- **결정**: default `go_settle_ms=5`, corpus 체크포인트+재부팅 자동재시작으로 freeze 를 "리부팅 1회 비용"으로 흡수. J-Link 캠페인 = 희소 샘플링(go_settle↑ → halt 수↓ → 레이스↓) + 복원력. RAG 실검증은 J-Link 필요(커버리지 피드백)라 이 복원력 위에서.
- ⚠️ **주의**: State-cov 가 재시작 시 0 으로 보이는 건 `state_cov_map` 이 resume 미복원이라서(PC 커버리지는 복원). 중간 리셋 버그 아님.

---

## 5. 남은 로드맵 / 다음 작업
- **SC-depth 보조 지표**(new_cov 하한 보완) — 샘플러가 못 잡는 도달 깊이 측정.
- **in-process pylink `memory_read` 덤프**(P9 hung 상태 JTAG 덤프) — RDDump 한계 해결.
- accept-CDW few-shot relevance 정렬, SANACT 가드(안전), 문서 헤더 "v9.0"→"v9.1" 정합성.
- edge coverage 포화 → state/시퀀스 기반 심화.

## 6. 로그 위치
`output/pc_sampling_v9.1.0/` (fuzzer log, llm/, state_corpus/, graphs/, crashes/). 배너에 `Sampling: ... go_settle=Nms` 실제값.
