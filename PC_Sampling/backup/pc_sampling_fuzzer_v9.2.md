# pc_sampling_fuzzer v9.2

> per-version 규칙: `v9.2.py` = `v9.1.py` byte-copy + 아래 편집만. v9.1 이전 상세는 `backup/`의 각 md.

## 한 줄 요약
v9.1(SC 되먹임) 위에 — **SC-depth(펌웨어 처리 깊이)를 커버리지 보완 신호로** 도입(Tier1), **LLM 구조적 data payload 강화**(Tier2), **닫힌 피드백 루프**(Tier3), + P9 timeout 후 **PC 모니터링 재연결 수정**.

## 배경
- `new_cov` 는 하한(halt 샘플링 fast-path under-sampling). LLM 이 더 깊이 도달해도 PC 커버리지가 못 보면 기여가 0으로 보임 → 측정·선택 둘 다 blindness.
- P9 timeout 후 RDDump 는 되는데(디바이스 생존 시) 이후 **PC 모니터링 실패** — RDDump 경로가 pylink 를 close 하고 재연결 안 함.

## 변경

### 0. PC 모니터링 재연결 (버그 수정)
RDDump 경로(`enable_debug_tool_dump`)가 컨트롤러 응답 복구를 위해 `sampler.close()`(pylink 종료, `jlink=None`)를 부른 뒤 재연결하지 않아, 모니터링 루프의 `read_stuck_pcs` 가 `_openocd_alive()=False` 로 "프로세스 없음"만 반복했다. → 모니터링 진입 시 세션이 닫혀 있으면 **lazy `_reconnect()`**(self-healing) 로 복구.

### Tier 1 — SC-depth 신호 (측정 + 보상)
디바이스가 돌려주는 SC 는 펌웨어가 명령을 **어디까지 처리했나**의 표식(opcode 디코드→필드검증→핸들러→실동작). `_sc_depth(full)` 로 서수 0~3 매핑:
`0`=Invalid Opcode(0x01) · `1`=제네릭 필드/컨텍스트 반송 · `2`=명령특정 검증/핸들러 도달 · `3`=성공.
- `cmd_stats[name]['best_depth']` 로 명령별 최대 깊이 추적.
- **지표:** LLM 계보 시드가 어떤 명령의 best_depth 를 전진시키면 `_llm_stats['depth_adv']++` (+`[LLM/depth]` 로그). halt 샘플러가 못 보는 도달을 결정적으로 포착.
- **보상:** depth 전진 실행은 PC 커버리지 0 이어도 `is_interesting=True` → **corpus 진입**으로 프론티어(구현-얕음)를 실제로 파고듦. depth 전진은 명령당 ≤3회라 corpus 폭증 없음.

### Tier 2 — LLM 구조적 data payload 강화
`_DATA_LAYOUTS` 로 구조적 data 명령(Copy/Reservation*/SecuritySend/DirectiveSend/SetFeatures/NamespaceManagement/FWDownload/IOMgmtSend/DatasetManagement)의 **스펙 레이아웃**을 명령별로 프롬프트에 제시. LLM 이 유효 `data_hex` 를 만들어 **data 파싱 코드**(CDW 변이·값-사전으로는 못 뚫는)에 도달. `_llm_data_directive` 가 구현된 needs_data 명령에만 레이아웃 첨부.

### Tier 3 — 닫힌 피드백 루프
- SC digest(#1)에 **best_depth·"성공까지 남은 거리"** 명시 → LLM 이 어느 명령을 얼마나 밀면 되는지 판단(repair).
- **자기 제안 되먹임:** `_llm_depth_cmds`(LLM 계보가 진전시킨 명령) → "Your proposals already advanced these — keep pushing" 라인. KernelGPT식 iterative repair.

### 보안 잠금 방지 강화 (v9.2 후속)
- **SecuritySend(0x81) SECP = ALLOWLIST**(`ALLOWED_SECURITY_SEND_SECP`, 기본 `0x00` info만) — denylist 로는 0xEE(IEEE1667)·vendor(0xF0~) 잠금 벡터를 놓칠 수 있어 허용 목록 외 전부 차단. opcode_override 도 `actual_opcode` 로 잡힘. config `strategy.allowed_security_send_secp` 로 안전 SECP 추가 가능.
- **Lockdown(0x24) 차단** — 관리 인터페이스 잠금 명령을 `blocked_admin_opcodes` 에 추가.
- **SecuritySend → `_DATA_LLM_EXCLUDE`** — FWDownload(실 fw_bin)와 함께 LLM data 생성 대상에서 제외.

## 관측 로그 (신규)
- `[LLM/depth] <cmd> SC-depth 전진 →N (<status>) | 누적=M` — LLM 이 깊이 전진시킴.
- `[LLM/stats] ... ★SC-depth 전진(누적)=M★ ...` — new_cov 옆 보완 지표.
- `[MONITOR] pylink 재연결 완료 (RDDump 후 세션 복구)` — 모니터링 수정 동작.

## config
신규 키 없음(Tier 1-3 은 무설정). v9.1 키(`rag.unimpl_*/schema_max`, `strategy.state_global_event_fields`) 그대로.

## 검증 포인트
- `[LLM/depth]`·`[LLM/stats] SC-depth 전진` 이 오르는지 → LLM 기여가 PC 커버리지 밖에서도 보임.
- SC digest 에 "reached depth N/3 — K step(s) from success" 표기.
- timeout 후 `[MONITOR] pylink 재연결 완료` → PC 모니터링 정상.
- data_hex 가 응답에 포함되고 해당 명령 best_depth 가 오르는지(구조적 payload 효과).

## 파일
- `pc_sampling_fuzzer_v9.2.py` — v9.1 byte-copy + 위.
- `fuzzer_config.json` — 무변경(v9.1 키 유지).
