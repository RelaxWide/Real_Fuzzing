# docs/ — 문서 색인

현행 퍼저는 `../pc_sampling_fuzzer_v11.5.py` 다. 버전별 문서는 **그 버전에서 바뀐 것만** 적는다.
엔진 전체 설명은 v10.3 문서와 런북이 여전히 기준이다(v11 은 그 위에 얹힌 변경).
종료된 조사 기록은 [`archive/`](archive/) 로 옮겼다.

작성 2026-10-30. 각 문서의 상태(구현/실기 검증 여부)는 문서 머리말이 정본이다.

## 처음 읽는 순서

1. [`pc_sampling_fuzzer_v10.3.md`](pc_sampling_fuzzer_v10.3.md) — 엔진 구성과 LLM 백엔드 현황 (v11 도 같은 엔진)
2. [`V11_2.md`](V11_2.md) → [`V11_3_BACKGROUND_SAMPLING_PLAN.md`](V11_3_BACKGROUND_SAMPLING_PLAN.md) → [`V11_4_RESPONSE_COVERAGE.md`](V11_4_RESPONSE_COVERAGE.md) → [`V11_5_PRODUCT_VARIANTS.md`](V11_5_PRODUCT_VARIANTS.md) · [`V11_5_DEVICE_INFO_QTMGR.md`](V11_5_DEVICE_INFO_QTMGR.md) — 최신 변경을 시간순으로
3. 운용: [`RUNBOOK_v10.3.md`](RUNBOOK_v10.3.md) — LLM/RAG 운용, 트러블슈팅, crash 덤프 수집

## v11 계열 (현행)

| 문서 | 내용 |
|---|---|
| [`V11_EXCEPTION_INJECTION_PLAN.md`](V11_EXCEPTION_INJECTION_PLAN.md) | 예외 주입(NSSR·POR 등)·사전시험·타이밍·불량 보존 |
| [`V11_1_VISUALIZATION.md`](V11_1_VISUALIZATION.md) | 실행 기록(`run_record`)·`compare_runs`·CSFuzz p 수정 |
| [`V11_2.md`](V11_2.md) | PM preflight 멈춤 방지, BM9K1 PM 중 디버그 세션 분리, PS 기반 timeout 배율 |
| [`V11_3_BACKGROUND_SAMPLING_PLAN.md`](V11_3_BACKGROUND_SAMPLING_PLAN.md) | BM9K1 상시 백그라운드 샘플링 설계·구현 기록(§10), 포화 휴식, J-Link 재사용 |
| [`V11_4_RESPONSE_COVERAGE.md`](V11_4_RESPONSE_COVERAGE.md) | 응답 시그니처 커버리지(`--no-jlink` 피드백) |
| [`V11_5_PRODUCT_VARIANTS.md`](V11_5_PRODUCT_VARIANTS.md) | `BM9K1_LENOVO` / `BM9K1_HP`, `family` 설정 |
| [`V11_5_DEVICE_INFO_QTMGR.md`](V11_5_DEVICE_INFO_QTMGR.md) | `[Device Info]` 항목, `[QTMGR]` 보고, 로그 파일 형식 |

## LLM · RAG

| 문서 | 내용 |
|---|---|
| [`pc_sampling_fuzzer_v10.3.md`](pc_sampling_fuzzer_v10.3.md) | 로컬 vLLM 백엔드·RAG 구현 현황 |
| [`pc_sampling_fuzzer_v10.2.md`](pc_sampling_fuzzer_v10.2.md) | 실행 근거 기반 LLM 탐색 설정·사용법 |
| [`V10_2_LLM_IMPLEMENTATION.md`](V10_2_LLM_IMPLEMENTATION.md) | v10.2 학습 확장(setup 보존·generator·task 배분) 구현 |
| [`V10_3_LLM_BACKEND_PLAN.md`](V10_3_LLM_BACKEND_PLAN.md) | 백엔드 이관 계획과 결정 근거 |
| [`LLM_IMPROVEMENT_PROJECT.md`](LLM_IMPROVEMENT_PROJECT.md) | LLM 개선 조사·설계(2026-09-09) |
| [`RAG_RETRIEVAL_EVAL.md`](RAG_RETRIEVAL_EVAL.md) · [`RAG_SMOKE_TEST.md`](RAG_SMOKE_TEST.md) | 검색 평가 도구, 스모크 시험 |

패키지 구조와 호출 계약(vLLM 직접 호출·사내 SRAG 브리지)은 [`../rag/README.md`](../rag/README.md).

## BM9K1 (RISC-V)

| 문서 | 내용 |
|---|---|
| [`V10_BM9K1_PLAN.md`](V10_BM9K1_PLAN.md) | BM9K1 커버리지 전체 설계 |
| [`BM9K1_ASSETS.md`](BM9K1_ASSETS.md) | 커버리지 자산(`basic_blocks`·`functions`·`callgraph`·`symbols`) 규격 |
| [`SESSION_HANDOFF_v10.0_overlay.md`](SESSION_HANDOFF_v10.0_overlay.md) | 코드 오버레이 커버리지·실기 확인 항목 |
| [`HANDOFF_BM9K1_LINK_DEVICELOST_20261002.md`](HANDOFF_BM9K1_LINK_DEVICELOST_20261002.md) | SJTAG·PCSR 링크 불안정 / 장치 소실 인계 |
| [`HANDOFF_BM9K1_SJTAG_KERNEL_DEBUGPOWER_20261007.md`](HANDOFF_BM9K1_SJTAG_KERNEL_DEBUGPOWER_20261007.md) | 위 문서의 후속 — 디버그 전원 드롭·커널 의존성 |

디버그 연결 도구는 [`../risc-v/README.md`](../risc-v/README.md).

## 설계만 있는 것 (미구현)

| 문서 | 상태 |
|---|---|
| [`V10_1_SPEC_OUTCOME_DENOMINATOR.md`](V10_1_SPEC_OUTCOME_DENOMINATOR.md) | NVMe spec outcome 분모 설계. 퍼저에 `spec_outcome` 구현 없음 |

## 연구·논문

| 문서 | 내용 |
|---|---|
| [`paper.md`](paper.md) | 논문 포지셔닝·기여·평가 정리 |
| [`LLM_strategies_and_paper_positioning.md`](LLM_strategies_and_paper_positioning.md) | LLM 전략과 연구 novelty (v9.2 기준) |

## archive/ — 종료된 조사·옛 버전 노트

| 문서 | 내용 |
|---|---|
| [`archive/PM9M1_HP_FREEZE_V102.md`](archive/PM9M1_HP_FREEZE_V102.md) | PM9M1_HP v10.2 OS freeze 조사 (2026-09-15) |
| [`archive/HANDOFF_PM9M1_HP_KERNEL_FAULT_20260917.md`](archive/HANDOFF_PM9M1_HP_KERNEL_FAULT_20260917.md) | 위 건의 커널 fault 후속 인계 (2026-09-17) |
| [`archive/HANDOFF_osfreeze_investigation.md`](archive/HANDOFF_osfreeze_investigation.md) | P7/Cortex-R5 halt 시기 OS freeze 조사 (2026-07) |
| [`archive/pc_sampling_fuzzer_v9.8.md`](archive/pc_sampling_fuzzer_v9.8.md) | v9.8 실행 노트 |

## 다른 폴더의 README

[`../products/README.md`](../products/README.md) 제품별 자산 · [`../dump/README.md`](../dump/README.md) 덤프 도구 ·
[`../rag/README.md`](../rag/README.md) LLM/RAG · [`../risc-v/README.md`](../risc-v/README.md) BM9K1 디버그 ·
[`../tests/trouble_shooting/README.md`](../tests/trouble_shooting/README.md) 9/29 정상 시점 코드 재현
