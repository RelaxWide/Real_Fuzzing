# LLM 개선 프로젝트 — 최신 연구 기반 방법론 확장

- 작성일: 2026-09-09
- 기준: LLM 경로 수정 커밋 `837e103`, Extended SMART 관측이 추가된 v10.1 및 `36006ef`
- 상태: 이 문서는 조사·설계 기록이다. 후속 v10.2 구현과 로컬 검증 범위는
  [V10_2_LLM_IMPLEMENTATION.md](V10_2_LLM_IMPLEMENTATION.md)를 참조한다. 실기 성능 개선은 미검증이다.
- 대상: 소유하거나 시험 권한이 있는 SSD의 펌웨어 안정성·신뢰성 검증

## 1. 목적과 핵심 방향

현재 구조에서 가장 유망한 개선은 LLM이 만든 시드를 더 많이 투입하는 것이 아니라,
**상태 설정을 보존하면서 특정 목표를 반복 탐색하고, 실제 실행 결과로 생성 전략을 개선하는 것**이다.

2026-09-09까지 공개된 연구 중 2025~2026년 학회 논문을 중심으로 조사했다.
아래 SSD 적용안은 논문의 기법을 현재 환경에 맞게 바꾼 제안이며, 논문에서 보고한 성능 향상이
SSD에서도 검증된 것은 아니다. 소스 코드 계측, 정확한 실행 커버리지, 대상 초기화를 전제하는
연구의 조건을 PC 샘플링과 실물 SSD 환경에 그대로 적용하지 않는다.

| 우선순위 | 적용 방향 | 현재 코드에서 더해지는 것 | 주요 근거 |
|---|---|---|---|
| 1 | 상태 설정을 보존하는 목표 지향 시퀀스 | 성공한 setup 유지, trigger 중심 변이 | SYSYPHUZZ, NDSS 2026 |
| 2 | 목표별 근거 묶음 | 함수 목록 → 명령·조건·관측·제약의 연결 | PromeFuzz, CCS 2025 |
| 3 | 재사용 가능한 입력 생성 규칙 | 개별 CDW·hex → 파라미터화된 생성기 | G²Fuzz·ELFuzz, USENIX Security 2025 |
| 4 | 실측 성과에 따른 작업 배분 | 고정 task 비율 → 상황별 효율 학습 | ReFuzz, NDSS 2026 |
| 공통 기반 | 측정 잡음과 실제 개선 구분 | 샘플링 조건을 포함한 비교 실험 | The Unbearable Randomness of Fuzzing, EuroS&P 2026 |

연구상 기대 효과의 우선순위와 구현 순서는 다르다. 구현은 필요한 데이터 기반을 먼저 만드는
**목표별 근거 묶음 → setup 보존형 시퀀스 → 제한된 생성 규칙 → 성과 기반 task 배분** 순서를 권한다.

## 2. 현재 기반과 범위

현재 코드에는 시퀀스, 공유 LBA/NLB 문맥, 명령별 커버리지, proposal 계보,
실제 발송 조건을 맞춘 대조 예시, repair/reject 피드백, coverage gap 순환이 있다.
v10.1에는 BM9K1 Extended SMART 관측이 추가됐다.

주요 연결 지점은 `../pc_sampling_fuzzer_v10.1.py`의 다음 함수다.

| 함수 | 확장 역할 |
|---|---|
| `_llm_build_request()` | 목표별 근거와 제한된 생성 과제 전달 |
| `_llm_gap_sort()` / `_llm_gap_mark()` | 목표 노출과 실제 탐색 이력의 구분 |
| `_apply_seq_ctx()` | 기존 공유 문맥을 바탕으로 시퀀스 의존관계 보존 확장 |
| `_llm_make_workload_desc()` | 선언적 생성 규칙의 기존 소규모 사례 |
| `_llm_maybe_submit()` | task 선택 정책 확장 |
| `_update_llm_boost()` | 기존 LLM/mutation 성과 비교와 새 정책의 관계 정리 |
| `_llm_telemetry_block()` | 상태 문맥과 이상 징후의 역할 구분 |

기존 [방법론 로드맵](ROADMAP_v9.6plus_methodology.md)에도 generator, scheduler, state graph 등의
유사 아이디어가 있다. 이 문서는 최신 연구 근거와 단계별 도입 범위를 보완한다.
기존 [논문 포지셔닝](paper.md)과 [LLM 전략 정리](LLM_strategies_and_paper_positioning.md)는
과거 버전 기준이므로 현재 구현 상태의 증거로 그대로 사용하지 않는다.

## 3. 상태 설정을 보존하는 목표 지향 시퀀스

### 연구 근거

SYSYPHUZZ는 이미 도달했지만 충분히 탐색하지 못한 코드 영역을 대상으로 필요한 선행 syscall
문맥을 유지하고, 관련 호출을 집중적으로 변이한다. 미도달 코드만 추구하는 것과 다른 접근이다.
원래 대상은 Linux 커널이며, syscall과 BB의 관계 및 실행 빈도 피드백을 사용한다.

출처: [SYSYPHUZZ: the Pressure of More Coverage — NDSS 2026](https://www.ndss-symposium.org/wp-content/uploads/2026-s921-paper.pdf)

### SSD 적용안

1. 관측 성과가 있었던 시퀀스에서 `setup`과 `trigger`를 구분한다.
2. setup의 성공 여부와 필요한 공유 값을 기록한다.
3. 일정한 탐색 예산에서는 setup을 유지하고 trigger의 필드·payload만 변이한다.
4. setup 자체를 바꾸는 탐색은 별도 비중으로 유지한다.

LLM에 매번 새로운 긴 체인을 요구하기보다 다음처럼 구체적인 과제를 제공한다.

> 이 선행 시퀀스 뒤에서 목표 함수가 관측됐다. 선행 조건은 유지하고, 마지막 명령의 어떤
> 필드 관계를 바꾸면 다른 동작을 탐색할 수 있을지 제안하라.

### 적용상의 제약

- 실제 BB 실행 빈도를 PC 샘플 수로 대체하지 않는다. 오래 머무는 루프와 샘플 예산이 큰
  코어는 더 많이 관측될 수 있다.
- 초기에는 비슷한 샘플링 조건에서 목표 함수가 관측된 **명령 윈도우 비율**을 사용한다.
  이것도 실행 빈도의 대용 지표이지 실제 실행 횟수는 아니다.
- BM9K1은 POR 제약이 있으므로 같은 setup을 재실행했다고 같은 내부 상태가 됐다고
  가정하지 않는다. setup 완료 조건과 관측 가능한 상태를 함께 확인한다.
- LLM이 제안한 의존관계와 실측으로 확인된 의존관계를 구분한다.

## 4. 목표별 근거 묶음

### 연구 근거

PromeFuzz는 코드 메타데이터, 문서의 제약, 실제 API 사용 관계를 구조화하고 생성 대상에
필요한 정보만 제공한다. 정보량 자체보다 서로 연결된 제약과 사용 관계가 중요하다.
원래 대상은 C/C++ 라이브러리의 fuzzing harness 생성이다.

출처: [PromeFuzz: A Knowledge-Driven Approach to Fuzzing Harness Generation with Large Language Models — CCS 2025](https://pvz122.github.io/pdf/25-promefuzz.pdf)

### SSD 적용안

현재 gap 순환은 프롬프트에 노출된 횟수로 후보를 돌린다. 다음 단계에서는 목표별로 아래
정보를 연결한다.

| 정보 | 내용 |
|---|---|
| 목표 | 코어·bank를 포함한 함수 식별자 |
| 접근 근거 | 특정 명령에서 직접 호출자가 관측된 관계 |
| 입력 조건 | 실제 queue/opcode/selector와 payload 구조 |
| 최근 시도 | 실행한 파라미터군과 실행 횟수 |
| 관측 결과 | 응답 분포, 목표 관측 여부, 관련 상태 변화 |
| 다음 가설 | 유지할 조건과 변경할 조건 |

**프롬프트 노출 횟수, LLM이 실제로 선택한 횟수, 장치에서 실행된 횟수는 별개로 기록한다.**
후보로 보여줬지만 LLM이 선택하지 않은 목표를 반복 실패한 목표로 취급하지 않는다.

새 정적분석 시스템 없이 기존 `cmd_cov_keys`, proposal 계보, 실행 기록과 repair/reject
피드백으로 시작할 수 있다. 이후 목표에 필요한 NVMe 규격 절과 제품 capability를 붙인다.
지원 능력은 근거로 제공하되, 미지원 응답을 검사하는 테스트까지 자동 제거하는 규칙과는
구분한다. 기존 발송 guard는 유지한다.

## 5. 재사용 가능한 입력 생성 규칙

### 연구 근거

G²Fuzz는 LLM이 비텍스트 바이너리를 직접 생성하는 비용과 한계를 줄이기 위해 입력 생성기를
합성하고, 그 결과를 기존 퍼저로 세밀하게 변이한다. ELFuzz는 생성기 자체를 커버리지
피드백으로 진화시키며, 같은 커버리지 개수라도 서로 다른 코드를 탐색하는 생성기를 구분한다.

출처:

- [G²Fuzz: Low-Cost and Comprehensive Non-textual Input Fuzzing with LLM-Synthesized Input Generators — USENIX Security 2025](https://www.usenix.org/system/files/usenixsecurity25-zhang-kunpeng.pdf)
- [ELFuzz: Efficient Input Generation via LLM-driven Synthesis Over Fuzzer Space — USENIX Security 2025](https://www.usenix.org/system/files/usenixsecurity25-chen-chuyang.pdf)

### SSD 적용안

현재 `io_workload` descriptor는 이 방향의 작은 구현이다. 이를 구조화된 명령 payload에도
확장한다. LLM은 다음을 제안하고, 실제 바이트 인코딩과 길이 계산은 호스트 코드가 수행한다.

- 사용할 descriptor 구조와 반복 개수 범위
- count·length·CDW 사이에서 유지할 관계
- 시험할 경계값 집합
- 한 번에 의도적으로 어긋나게 할 관계

첫 구현은 임의 Python 실행보다 **지원 연산이 제한된 JSON 생성 규칙**으로 충분하다.
생성 결과는 기존 검증·발송 경로를 통과한다. LLM 한 번의 응답으로 여러 변형을 만들고,
기존 변이 엔진이 그 주변을 탐색한다. 평가 단위에 `generator_id`를 추가한다.

### 평가와 보존

생성기 A가 먼저 실행돼 신규 BB credit을 가져갔다는 이유로 B를 무가치하게 판단하지 않는다.
신규 발견 수와 함께 관측 코드 집합의 상보성을 본다. PC 샘플링에서는 한 번의 미관측으로
집합 포함 관계를 확정하지 않는다. 반복 관측은 보존 우선순위의 신뢰도를 높이는 데 사용하고,
희귀한 단발 관측을 자동 폐기하는 규칙으로 사용하지 않는다.

## 6. 실측 성과에 따른 task 배분

### 연구 근거

ReFuzz는 이전 프로세서에서 효과가 있었던 테스트를 재사용하면서 현재 coverage 문맥에 따라
테스트 선택을 contextual bandit으로 조정한다. 원래 대상은 프로세서 테스트이며,
LLM task 스케줄링은 이 프로젝트에서의 응용 제안이다.

출처: [ReFuzz: Reusing Tests for Processor Fuzzing with Contextual Bandits — NDSS 2026](https://www.ndss-symposium.org/wp-content/uploads/2026-f118-paper.pdf)

### SSD 적용안

현재는 가중 RR와 plateau 우선순위로 task를 선택하고, LLM boost는 LLM 계보와 mutation
계보의 성과를 비교한다. 다음 단계에서는 현재 상태에서 신규 시드, 기존 시퀀스 개선,
I/O workload 변경 중 어디에 다음 LLM 호출을 쓸지 결정한다.

처음부터 복잡한 모델을 도입하지 않는다. task별 최근 성과와 비용을 집계하고 최소 탐색
비중을 유지하면서 배분을 조절하는 작은 정책부터 기존 RR와 비교한다.

선행 조건:

1. 응답 수신만으로 보상을 확정하지 않는다. 시드가 실행되고 평가 예산을 소비한 뒤 귀속한다.
2. 샘플링 실패와 탐색 실패를 구분한다. 관측 불능을 신규 커버리지 0으로 학습시키지 않는다.
3. `corpus_eval`은 입력 생성 task와 같은 직접 보상으로 비교하지 않는다. 간접 효과이므로
   별도 on/off 실험으로 평가한다.
4. 생성기·시퀀스 계보별 성과 기록을 먼저 갖춘다. 실행 수, 장치 시간, LLM 비용을 분리한다.

## 7. 상태 피드백과 불량 판정의 분리

### 연구 근거

BSFuzzer는 규격의 필드 제약과 메시지 의존관계를 추출해 테스트를 만들고 응답을 검증한다.
실제 BLE 장치 대상이라는 점은 유관하지만, 논문이 보고한 상태 수준 응답 검증 정확도는
약 74%다. LLM의 해석을 곧바로 불량 확정으로 사용하기에는 한계가 있다.

출처: [BSFuzzer: Context-Aware Semantic Fuzzing for BLE Logic Flaw Detection — NDSS 2026](https://www.ndss-symposium.org/wp-content/uploads/2026-f94-paper.pdf)

### SSD 적용안

v10.1 Extended SMART 관측은 다음 역할을 구분해 사용한다.

| 관측 역할 | 사용처 |
|---|---|
| 내부 작업 상태 | 시퀀스·workload 선택의 문맥 |
| 새 동작을 시사하는 변화 | 탐색 후보 보존의 근거 |
| timeout·오류·매체 이상 관련 변화 | 별도 이상 징후 기록과 재확인 |

상태 변화만으로 버그를 선언하지 않는다. 오류 카운터 증가 자체를 계속 추구하는 보상으로
삼지도 않는다. LLM에는 규격 근거가 있는 검사 후보를 제안하게 하고, 검토·확정된 조건의
판정은 호스트 코드로 수행한다. 자기유발 오류, 정상 관리 동작, 카운터 중복을 구분한다.

## 8. 측정과 비교 실험

EuroS&P 2026의 *The Unbearable Randomness of Fuzzing*은 PRNG seed를 고정해도 대상,
환경, 퍼저 내부의 시간 의존성 때문에 결과가 달라지며, 반복 횟수는 관측 분산과 검정력에
따라 결정해야 한다고 분석한다.

출처: [The Unbearable Randomness of Fuzzing — EuroS&P 2026](https://www.eurecom.fr/en/publication/8694)

이 프로젝트에서는 적응형 코어 샘플 예산 변경 자체가 관측 커버리지에 영향을 준다.
초기 비교에서는 샘플링 정책을 고정하고, 이후 적응형 샘플링과의 상호작용을 별도 평가한다.
제품·FW·정적 자산·시작 corpus·장치 초기 상태와 샘플링 조건을 기록한다.

비교 지표:

- 동일 시간 예산에서 코어·bank별 관측 BB/함수 성장
- setup 성공 후 trigger까지 도달한 비율
- LLM 호출·토큰당 실제 실행된 고유 입력과 탐색 성과
- 신규 상태 전이와 재현 가능한 불량
- 샘플 무효율, 오버레이 drop, 장치 초기 상태 차이
- 생성 규칙별 관측 코드 집합의 상보성과 유지 비용

단일 최고 결과 대신 반복 실행의 분포를 비교한다. 한 번의 긴 캠페인을 여러 구간으로
나눴다고 독립 반복 실험으로 간주하지 않는다. 같은 SSD의 후속 실험은 마모·FTL 상태가
남을 수 있으므로 초기 조건과 실행 순서의 영향을 기록한다.

## 9. 단계별 구현·검증 순서

| 단계 | 범위 | 확인할 결과 |
|---|---|---|
| 0 | 현재 버전 기준선과 계측 조건 기록 | 측정 변동과 시작 상태를 설명할 수 있음 |
| 1 | 목표별 근거 묶음 | 노출·제안·실행이 구분되고 목표별 결과를 역추적할 수 있음 |
| 2 | setup 보존형 시퀀스 탐색 | 기존 방식 대비 trigger 도달과 목표 탐색이 개선되는지 확인 |
| 3 | 제한된 생성 규칙 | 호출당 입력 다양성·실행 성과가 개선되는지 확인 |
| 4 | 성과 기반 task 배분 | 동일 비용에서 기존 RR보다 나은지 확인 |

기능을 한꺼번에 켜지 않고 각 단계의 효과를 분리 검증한다. 완전한 상태기계, 임의 코드
생성기 진화, 복잡한 학습 모델은 초기 범위에 포함하지 않는다. 이 문서는 구현 승인이나
실기 실행 지시를 대신하지 않으며, 현재는 후속 개선 작업을 위한 조사·설계 기록이다.
