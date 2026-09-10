# v10.1 상태 및 JLink 끊김 조사 — 2026-09-10

## 확인 범위

- 기준 커밋: `38ea6ca`. 조사 시작 시 작업 트리는 clean.
- 실기와 실행 로그는 사용자 환경에만 있다. 대상 제품, 실행 옵션, 실패 단계는 미확인.
- 이번 변경은 코드에서 확인한 BM9K1 샘플러 결함의 수정이다. 실제 끊김 원인 확정이나 실기 해결 검증은 아직 아니다.

## 프로젝트 구성

- `pc_sampling_fuzzer_v10.1.py`: NVMe 명령 생성·실행, PC/state 커버리지, corpus, LLM 연동, PM/POR, 장애 증거 수집과 리포트가 모인 주 실행 파일.
- `fuzzer_config.json`: 제품별 sampler 및 실행·관측 정책. 최신 커밋은 FFM을 WAF 기반 매핑 조각화 중심으로 변경하고 WAF/SLC-fold 관측을 추가했다.
- BM9K1: `RiscvPcsrSampler` → `riscv_cov.PcsrSession` → `risc-v/sfe76_link.py`, cJTAG/SBA 비침습 샘플링. 코어별·오버레이별 커버리지 지원.
- P9: `JLinkHaltSampler`, pylink로 halt/read/resume. PM9M1/BM9H1 등은 OpenOCD 경유 경로도 존재한다. 제품에 따라 조사 대상이 달라진다.
- `docs/SESSION_HANDOFF_v10.0_overlay.md`: 오버레이 구현과 실기 검증 항목. JTAG 연결 상태의 POR 부팅 문제를 하드웨어 제약으로 기록하고 있다. 현재 장비에도 동일한지는 확인이 필요하다.
- `docs/V10_1_SPEC_OUTCOME_DENOMINATOR.md`, `spec/nvme_outcome_denominator_v10.1.json`: 명령-응답 관측 분모 설계/카탈로그. 주 실행 파일에서는 `spec_outcome`/`denominator` 명칭의 연결 코드를 찾지 못했다. 문서 존재만으로 기능 완료로 판단하지 않는다.

## 이번 수정

1. 전체 읽기가 실패한 버스트를 오버레이 폐기보다 먼저 transport 장애로 보고한다. 기존에는 bank 판별 실패로 `continue`하여 장애 판정을 건너뛸 수 있었다. 빈 버스트(pin 실패)는 기존 8회 한도를 유지한다.
2. 새 window에서 `_invalid_streak`와 `_all_invalid_since`를 함께 초기화한다. 오래된 시간을 새 window의 연속 무효 시간으로 계산하지 않는다.
3. 정지 요청 또는 transport 오류가 있으면 `_maybe_recover()`에서 새 복구를 시작하지 않는다. 메인 루프의 복구 경로로 넘긴다.

## 남은 위험과 실기 확인

### 추가 단서: 재연결의 `세션 OK` 직후 전 코어 PC 미관측

사용자가 전달한 증상이며 실제 로그 원문은 아직 미확인이다. 기존 `세션 OK`는
`PcsrSession.open()` 뒤, 코어 pin/PC/ELF 검증 **전**에 찍혔다. 따라서 PC 관측 복구를
보장하지 않는다. 준비 완료 로그와 PC 검증 완료 로그를 분리했다.

추가로 `connect()`가 검증 중 `self._weights`를 직접 줄이므로 전 코어 검증이 한 번
실패하면 빈 계획이 다음 시도에도 남는 결함을 확인했다. 이제 후보 계획을 별도로
검증하고 사용 가능한 코어가 있을 때만 반영한다. 사용 가능한 코어가 없으면 세션을
닫으며, PC가 0개인 경우 전송 실패인지 valid PC 부재인지 별도 로그를 남긴다.
최초 전 코어 PC 소실 원인은 아직 미확정이지만, 그 뒤 정상 회복을 막는 결함은 수정했다.
첫 시도 전 코어 실패 → 두 번째 정상 관측 시 연결 성공 회귀 테스트를 추가했다.

- 공용 `stop_sampling()`은 2초+1초 join 뒤에도 스레드가 살아 있으면 진행한다. JLink 백엔드의 `_close_telnet()`은 no-op이므로 DLL 호출이나 이미 시작한 인증을 중단하지 못한다. 이번 정지 가드는 이미 진행 중인 호출을 취소하지 않는다.
- `_stop_worker()`도 살아 있는 스레드 참조를 지울 수 있다. 세션별 lock은 개별 접근을 직렬화하지만 sampler의 세션 교체와 window 수명 전체를 보호하지 않는다. 장시간 호출이 실제 발생한다면 작업자 종료 확인과 복구 소유권 정리가 추가로 필요하다.
- P9 `connect()`에는 로컬 `jl`을 연 뒤 실패했을 때 명시적으로 닫지 않는 경로가 있다. P9가 대상이면 이 경로와 DLL 오류를 우선 조사해야 한다.
- 실기에서는 실행 명령, 제품, 최초 실패 전후 로그를 함께 확보한다. 특히 `[cJTAG/SBA]`, `[pcsr]`, `[Sampler]`, `[J-Link DLL]`, FWCommit/PM 직후 여부, 수동 재연결 결과를 확인한다.
- BM9K1 연결만 분리해서 확인할 때는 퍼저 종료 후 실제 `PC_Sampling` 디렉토리에서 `sudo python3 tools/check_bm9k1_connect.py --root "$PWD"`를 실행할 수 있다. 이 도구는 연결/인증/SBA 접근을 수행한다. 실행 중 퍼저와 동시에 프로브를 점유하지 않는다.

## 로컬 검증

`python3 -m unittest discover -s PC_Sampling/tests -v`

AST로 실제 sampler 메서드를 읽어 하드웨어 초기화 없이 실행한다. 전송 실패+오버레이, 빈 버스트 재시도 한도, 정상 invalid PC, window 타이머 초기화, 정지/오류 시 복구 억제를 검증한다. 실제 USB/DLL 동작과 장시간 스레드 경합을 재현하는 테스트는 아니다.
