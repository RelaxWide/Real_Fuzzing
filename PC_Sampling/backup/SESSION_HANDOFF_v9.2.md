# SESSION HANDOFF — v9.2 (SC-depth 신호 + LLM data/피드백 강화 세션)

> 이 파일이 현재 핸드오프다. 구 `SESSION_HANDOFF_v8.8/v9.0/v9.1.md` 는 `backup/`.
> v9.2 = v9.1(SC 되먹임) 위에 SC-depth 커버리지 보완 + LLM 구조적 data + 닫힌 피드백 + P9 모니터링 수정.

---

## 0. 현재 상태 한 줄
- **최신 = `pc_sampling_fuzzer_v9.2.py`** (`FUZZER_VERSION="9.2.0"`). 상세: `pc_sampling_fuzzer_v9.2.md`.
- `--rag` off 시 코어 fuzzing/발송 무변경. SC 집계·에너지·state-cov 필터·close/모니터링 수정은 RAG 무관 저비용 동작.
- 구버전(v8.0~v9.1 .py/.md) = `backup/`. git 이력 보존.

---

## 1. v9.2 변경 (이번 세션) — 상세 `pc_sampling_fuzzer_v9.2.md`
- **PC 모니터링 재연결 수정:** RDDump 경로가 `sampler.close()`(pylink 종료) 후 재연결 안 해 timeout 후 PC 모니터링이 "프로세스 없음" 반복하던 것 → 모니터링 진입 시 lazy `_reconnect()`.
- **Tier1 SC-depth 신호:** 디바이스 SC 를 "펌웨어 처리 깊이"(0=Invalid Opcode … 3=성공) 서수로(`_sc_depth`), 명령별 `best_depth` 추적. LLM 이 깊이 전진 시 `depth_adv` 지표(+`[LLM/depth]`) **및 `is_interesting` 보상(corpus 진입)** → halt 샘플러가 못 보는 도달을 포착·탐색 유도.
- **Tier2 구조적 data:** `_DATA_LAYOUTS` 로 Copy/Reservation*/SecuritySend/Directive/SetFeatures 등 **스펙 레이아웃**을 프롬프트에 제시 → LLM 이 유효 `data_hex` 로 **data 파싱 코드** 도달(LLM 유일가치).
- **Tier3 닫힌 피드백:** SC digest 에 best_depth·"성공까지 거리" 명시 + LLM 자신이 진전시킨 명령(`_llm_depth_cmds`) 되먹임("keep pushing").

---

## 2. 핵심 진단 (승계 — 다음 세션 필수)
- **`rc=22` = `SC=0x01` Invalid Opcode = 미구현.** 커널 반송 아님, 펌웨어 opcode 디코드 거부. OACS 광고값이 아니라 **실측 SC 가 ground truth**.
- **`new_cov` 는 하한:** P9 halt 샘플링(DBGPCSR 미구현)이 fast-path under-sample + global-first. → **v9.2 SC-depth 가 이 blindness 를 보완**(디바이스가 항상 주는 도달 깊이).
- **P9 hung 펌웨어 덤프 불가(현):** RDDump=NVMe 라 살아있는 펌웨어 필요. hung/halt 상태는 못 뜸(재현 확인). 근본해법 = **in-process pylink `memory_read`(JTAG) 덤프**(미구현). `[J-Link] close:` 로그가 모드A(resume실패)/B(펌웨어hung) 구분.
- **Sanitize 사고:** `opcode_override` 가 Sanitize(0x84)를 파괴적 SANACT(2/3/4)로 트리거 가능(`--no-erase` 없을 때). state-cov 오염은 필터로 차단했으나 **데이터 파괴 방지 SANACT 가드는 보류**(안전).

---

## 3. v9.0 배선 — 유지 (2-PC Samba drop-box)
- **온라인 PC(Windows)**: `srag_llm_service.py` + `srag_llm_guide.py`(사용자 실제 LLM). **`python`으로 실행**(python3=Store 스텁).
- **오프라인 PC(Linux)**: `pc_sampling_fuzzer_v9.2.py` + `rag/rag_bridge_client.py`(drop-box, LLM 코드 없음).
- **연결**: Samba `rag/bridge/`. 워커 스레드가 요청 write→온라인 폴링·LLM·응답 write→읽어 반환. bridge 파일은 소비 후 삭제(정상). **입력 최대 8k 토큰**(현재 ~4k 여유).
- **설정**: `enabled:true, module_path:"rag.rag_bridge_client", func_name:"generate_rag_response", pass_system_prompt:false`. `sudo -E` 실행.
- **안전 3중(무변경)**: `is_dangerous` → `validate_and_repair` → `_send_nvme_command` 가드.
- **검증**: mock/`test_llm.py`/`test_bridge.py` [PASS]. 실장비 `--rag` 는 하드웨어 필요.
- **프롬프트 검증**: `rag.log_responses=true` → `output/pc_sampling_v9.2.0/llm/llm_io_*.jsonl` 의 `prompt`/`response`.

---

## 4. 호스트 OS freeze — halt-vs-controller 레이스 (조사 종료)
- **✅ 확정**: `--no-jlink` 60만 execs 무이상 → freeze 원인 = halt 샘플링(halt-vs-컨트롤러 타이밍 레이스). 근본원인 캡처(kdump/ramoops) 전부 무증거 → 포기 합리적.
- **결정**: default `go_settle_ms=5`, corpus 체크포인트+재부팅 자동재시작으로 흡수. J-Link 캠페인 = 희소 샘플링 + 복원력.
- ⚠️ State-cov 가 재시작 시 0 으로 보이는 건 `state_cov_map` resume 미복원(PC 커버리지는 복원). 중간 리셋 버그 아님.

---

## 5. 남은 로드맵 / 다음 작업
- **in-process pylink `memory_read` 덤프**(P9 hung JTAG 덤프) — RDDump 한계 해결. ← 다음 큰 항목.
- **SANACT send-time 가드**(데이터 파괴 방지, 안전).
- `state_cov_map` resume 영속화, accept-CDW relevance 정렬(소소).
- (상위 컨셉) LLM 을 "커버리지 시드원"→"버그 가설 생성기"로 — edge 포화 심화 시.
- edge coverage 포화 → state/시퀀스 심화.

## 6. 로그 위치
`output/pc_sampling_v9.2.0/` (fuzzer log, llm/, state_corpus/, graphs/, crashes/). 배너 `Sampling: ... go_settle=Nms`.
