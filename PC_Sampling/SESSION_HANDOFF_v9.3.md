# SESSION HANDOFF — v9.3 (LLM-구동 I/O 워크로드 + FFM 파생 필드 세션)

> 이 파일이 현재 핸드오프다. 구 `SESSION_HANDOFF_v8.8/v9.0/v9.1/v9.2.md` 는 `backup/`.
> v9.3 = v9.2(SC-depth·구조적 data·닫힌 피드백) 위에 **LLM-구동 I/O 워크로드**(io_patterns task + descriptor 증폭 버스트 + FFM 파생 telemetry 필드 + 되먹임).

---

## 0. 현재 상태 한 줄
- **최신 = `pc_sampling_fuzzer_v9.3.py`** (`FUZZER_VERSION="9.3.0"`). 상세: `pc_sampling_fuzzer_v9.3.md`, 설계: `v9.3_IO_workload_design.md`.
- **io_patterns 는 config ON (`rag.tasks.io_patterns:true`), plateau-gated.** (한때 `[LLM/exec]` 하드 제로로 io_patterns 를 의심해 OFF A/B 를 걸었으나, **실제 원인 = 온라인 RAG 서비스 python 이 꺼져 있어** LLM 응답 자체가 안 온 것(환경). v9.3 코드 무관 확인 → 재ON.)
  - **동작 조건**: 온라인 PC 의 RAG 서비스 실행 + `rag.enabled:true`(또는 `--rag`) + `io_workload.enabled:true` + `rag.tasks.io_patterns:true`. 모두 충족 시, **edge-cov plateau(RAG_PLATEAU_EXECS=2만 execs 무성장) 때만** io_patterns 제출 → 즉시 안 떠도 정상(활발히 뚫는 중엔 seed/sequence 집중).
- `--rag` off 또는 `rag.tasks.io_patterns` off → v9.2와 동등(버스트 미발생, 기존 round-robin 워크로드 무변경). FFM 필드는 순수 추가(입력 없으면 degrade).
- 구버전(v8.0~v9.2 .py/.md) = `backup/`. git 이력 보존.

---

## 1. v9.3 변경 (이번 세션) — 상세 `pc_sampling_fuzzer_v9.3.md`
- **FFM 파생 필드**(`source:'derived'`): `capture()` 가 raw 읽은 뒤 `_derive_frag_pressure` 로 FTL 조각화/GC 압력 지수(0..100) 계산·주입. %-타입 압력 필드 정규화 가중평균, **존재 항 재정규화**(제품 무관). delta/state_cov/LLM 되먹임 전부 기존 파이프라인 자동.
- **io_patterns task**: LLM에 텔레메트리 `{값+desc}` 주고 워크로드 descriptor 받음. `_llm_make_workload_desc` 검증 → `_pending_workload`. **⚠️ plateau-gated**: edge-cov 정체 시에만 돌파 로테이션 합류(비-plateau=v9.2 스케줄 동일). 초기 v9.3 이 io_patterns 를 공유 회전(weight=2)에 상시 넣어 LLM breakthrough 가 급감한 회귀를 이 게이팅으로 수정(단일 워커 슬롯 → 상시 포함은 seed/sequence 를 뺏음).
- **descriptor 증폭 버스트**(`_run_llm_workload_burst`): `_gen_workload_block(desc=)` 로 패턴/파라미터 오버라이드, block 반복하며 FFM **상승 후 정체(patience) 시 조기 종료**(안 오르면 천장까지). 매 명령 PC샘플 → edge-cov 자동. 되먹임(`_llm_workload_feedback`)으로 다음 라운드 개선.
- config: `ffm_frag` 필드(r8/p9), `rag.tasks/task_weights.io_patterns`, `io_workload.burst_*`.
- **미구현(다음)**: 워크로드 corpus(효과적 descriptor 저장·replay/mutate). 현재 버스트 1회성.

---

## 2. 핵심 진단 (승계 — 다음 세션 필수)
- **`rc=22` = `SC=0x01` Invalid Opcode = 미구현.** 커널 반송 아님, 펌웨어 opcode 디코드 거부. OACS 광고값 아니라 **실측 SC 가 ground truth**.
- **`new_cov` 는 하한:** P9 halt 샘플링(DBGPCSR 미구현)이 fast-path under-sample + global-first. v9.2 SC-depth·v9.3 FFM/edge-cov(워크로드)로 보완.
- **P9 hung 펌웨어 덤프 불가(현):** RDDump=NVMe 라 살아있는 펌웨어 필요. 근본해법 = in-process pylink `memory_read`(JTAG) 덤프(미구현).
- **Sanitize/파괴 명령**: `opcode_override` 가 Sanitize(0x84) 파괴적 SANACT 트리거 가능. state-cov 오염은 필터 차단, SANACT send-time 가드는 보류.
- **보안 잠금 방지**(v9.2): SecuritySend(0x81) SECP allowlist, Lockdown(0x24) blocked. SecuritySend/FWDownload 는 LLM data 생성 제외.

---

## 3. v9.0 배선 — 유지 (2-PC Samba drop-box)
- **온라인 PC(Windows)**: `srag_llm_service.py`+`srag_llm_guide.py`(사용자 LLM). **`python`으로 실행**.
- **오프라인 PC(Linux)**: `pc_sampling_fuzzer_v9.3.py` + `rag/rag_bridge_client.py`(drop-box). Samba `rag/bridge/`, 워커 스레드 폴링. 입력 최대 8k 토큰.
- 설정: `enabled:true, module_path:"rag.rag_bridge_client", func_name:"generate_rag_response"`. `sudo -E` 실행.
- 안전 3중(무변경): `is_dangerous`→`validate_and_repair`→`_send_nvme_command` 가드. io_patterns descriptor 도 `_llm_make_workload_desc` + 발송 시 `_wl_clamp`/가드.
- 프롬프트 검증: `rag.log_responses=true` → `output/pc_sampling_v9.3.0/llm/llm_io_*.jsonl`.

---

## 4. 호스트 OS freeze — halt-vs-controller 레이스 (조사 진행)
- **✅ 확정(기존)**: `--no-jlink` 60만 execs 무이상 → freeze 원인 = halt 샘플링(halt-vs-컨트롤러 타이밍 레이스). 별개로 주기 차트 `os.fork()` = logless **재부팅**(검증됨).
- **이번 세션 진단 방향**: slub_debug 정상 적용됐는데도 slub 라인 0 + 실시간 dmesg 무증거 + pstore 빔 → **하드 행이라 printk 자체가 생성 안 됨**(슬랩 손상 아님 신호, halt 하드행 가설 강화).
  - **다음 조치**: grub `GRUB_CMDLINE_LINUX` 에 `nmi_watchdog=1 hardlockup_panic=1 softlockup_panic=1` (slub_debug 넣은 그 줄) → `update-grub`(또는 grub2-mkconfig) → 재부팅 → `/proc/cmdline` 확인. 하드 행이 **NMI 백트레이스 뱉게** 강제. 실시간 dmesg에 뜸(netconsole 불필요 — 전송 아니라 출력 생성이 문제).
  - 그래도 무(無)면 = NMI도 서비스 못 하는 **커널 하위 하드웨어 행** 확정 → 소프트 트레이스 불가, 복원력 완화책(go_settle_ms, corpus 체크포인트+재부팅 자동재시작)으로 종결. `journalctl -k | grep -i mce` 확인.
- ⚠️ 재부팅 시 State-cov 0 표시 = `state_cov_map` resume 미복원(PC 커버리지는 복원). 버그 아님.

---

## 5. 남은 로드맵 / 다음 작업
- **워크로드 corpus**(v9.3 ④): 효과적 descriptor 저장 + replay(재증폭)/mutate + FFM-EMA. ← v9.3 직속 후속.
- **in-process pylink `memory_read` 덤프**(P9 hung JTAG 덤프).
- **SANACT send-time 가드**(데이터 파괴 방지).
- `state_cov_map` resume 영속화.
- freeze: nmi_watchdog/lockup detector 재현 대기(§4).
- 단일 LLM 시드 적체 진단(v9.2 미해결): `[LLM/stats]` 단일 N[fav M] 실측 보고 대기.

## 6. 로그 위치
`output/pc_sampling_v9.3.0/` (fuzzer log, llm/, state_corpus/, graphs/, crashes/). `[IO-WL/burst]`·`[LLM] 워크로드 descriptor` 로 워크로드 동작 확인.
