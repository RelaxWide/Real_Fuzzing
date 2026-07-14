# pc_sampling_fuzzer v9.3

> per-version 규칙: `v9.3.py` = `v9.2.py` byte-copy + 아래 편집만. v9.2 이전 상세는 `backup/`·각 md.

## 한 줄 요약
v9.2(SC-depth·구조적 data·피드백) 위에 — **LLM-구동 I/O 워크로드**를 추가. LLM이 admin gap이 아니라 **텔레메트리(값+desc)를 보고 워크로드 descriptor를 내면**, fuzzer가 **수천 Read/Write로 증폭 실행**해 FTL 내부 상태(GC/wear/fragmentation)를 밀고, **FFM(파생 telemetry 필드)** 으로 효과를 재서 LLM에 되먹인다.

## 배경
- SSD는 Read/Write가 主 — 그 누적 I/O가 FTL 깊은 로직을 threshold로 민다(사용자 논문 SDF-Fuzz 논지). 그런데 v9.2 LLM은 coverage-gap 프레이밍 때문에 Read/Write를 안 만들고 admin으로만 몰림.
- I/O는 수천 명령이 있어야 상태를 민다 → LLM에 JSON 6개 명령 받는 건 무의미. **descriptor(레시피)를 받아 fuzzer가 증폭**하는 구조.

## 변경 (설계 상세 = `v9.3_IO_workload_design.md`)

### 1. FFM = 파생 telemetry 필드 (`source:'derived'`)
- `NVMeStateMonitor.capture()` 가 raw 필드(smart/vendor/security)를 읽은 뒤 `_derive_frag_pressure` 로 **FFM(FTL 조각화/GC 압력 지수 0..100)** 계산해 `result`에 주입.
- 공식 = %-타입 압력 필드(`sec_free_blocks_pct` 핵심 + PE skew + slc/sys/percent usage)의 **정규화 가중평균, 존재 항 가중치로 재정규화**. → 없는 필드(예: p9 df_*)는 자동 제외+재정규화 = **제품 무관, config 표 관리 0**.
- FFM이 관측 필드가 되므로 `delta`/`state_cov_map`/버킷/LLM `{값,desc}` 되먹임을 **기존 파이프라인이 자동 처리**. 별도 추적 코드 없음.
- 활성 카운터(patrol/reclaim/refresh/wear_count)는 FFM에 안 섞고 **각자 EVENT 필드**로 유지(무한 카운터 스케일 함정 회피).

### 2. io_patterns LLM task + descriptor
- 4번째 task `io_patterns`. **edge-cov 정체(plateau)일 때만** 돌파 로테이션(seq/ngs/io_patterns)에 합류 — 활발히 뚫는 동안엔 후보에서 제외해 **LLM 을 seed/sequence 에 100% 집중(=v9.2 스케줄 동일)**. LLM 워커 슬롯이 1개뿐이라 상시 넣으면 seed/sequence 를 뺏어 breakthrough 급감(초기 v9.3 회귀 → 이 게이팅으로 수정). `_pending_workload` 있으면 새 요청 안 함(중복 적체 방지).
- `_llm_build_request('io_patterns')`: **텔레메트리 `{name=value [desc]}` 스냅샷**(FFM 포함) + 패턴 enum + descriptor 스키마 요청. LLM은 값+설명으로 판단(제품 바뀌어도 적용).
- LLM 출력 = 단일 `io_workload` descriptor `{pattern, lba_span, block_size, hot_fraction, read_ratio, direction}`. `_llm_make_workload_desc` 검증(pattern∈enum, 범위체크; LBA/NLB 실상한은 발송 시 `_wl_clamp`).

### 3. descriptor 증폭 버스트 + FFM 조기 종료
- `_gen_workload_block(pattern, lim, desc=None)`: desc가 lba_span(working-set)/block_size(NLB)/hot_fraction/read_ratio 를 **오버라이드**(전부 device bound clamp). `desc=None`=기존 동작(byte-동등).
- `_run_llm_workload_burst(desc)`: block 반복(천장 `burst_blocks_max`), `burst_snap_blocks`마다 FFM 관측 → **상승 후 정체(patience_k)면 조기 종료**(평형 도달, 마모 절약). **FFM이 한 번도 안 오르면 천장까지**(느린/무효 구분불가 → 최대 기회). wall-time 안전캡. 매 명령 PC샘플 → **edge-cov 자동 크레딧**.
- **되먹임**: 직전 버스트 (pattern, FFM 델타)를 `_llm_workload_feedback` 가 다음 io_patterns 프롬프트에 삽입("moved FFM Δ… → push further / try different").

## 관측 로그 (신규)
- `[LLM] 워크로드 descriptor 수신: pattern=… span=… bs=… hot=… rd=…`
- `[IO-WL/burst] pattern=… blocks=N rc0=M FFM a→b (Δd) stop=saturated|ceiling|walltime|timeout …`
- state 스냅샷에 `ffm_frag` 필드가 다른 state_fields 와 함께 찍힘(init_value 등록/버킷).

## config (`fuzzer_config.json`)
- `state_fields.r8`/`.p9`: `ffm_frag`(source=derived, fn=frag_pressure, inputs=항별 field+weight).
- `rag.tasks.io_patterns:true`, `rag.task_weights.io_patterns:2`.
- `io_workload`: `burst_blocks_max:50`, `burst_snap_blocks:5`, `burst_patience_k:3`, `ffm_field:"ffm_frag"`, `burst_walltime_cap_sec:120`.

## 검증 포인트
- state 스냅샷에 `ffm_frag` 가 나오고 워크로드 버스트 전후로 값이 움직이는지.
- `[IO-WL/burst]` 의 stop 사유 분포(saturated=평형 도달 정상, ceiling=느린/강한 워크로드).
- io_patterns 되먹임 이후 LLM descriptor 가 FFM 을 더 미는 방향으로 바뀌는지.
- `--rag` off / io_patterns off → 기존 round-robin 워크로드 경로와 동일(버스트 미발생).

## 미구현 (다음)
- **워크로드 corpus**: 효과적 descriptor(FFM 델타 큰 것) 저장 → replay(재증폭)/mutate. 현재 버스트는 1회성.

## 파일
- `pc_sampling_fuzzer_v9.3.py` — v9.2 byte-copy + 위.
- `fuzzer_config.json` — ffm_frag 필드 + io_patterns task + 버스트 파라미터.
- `v9.3_IO_workload_design.md` — 설계·정정(DRP 미채택, FFM=측정자) 상세.
