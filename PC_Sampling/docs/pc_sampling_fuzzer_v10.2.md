# pc_sampling_fuzzer v10.2

v10.2.0은 v10.1의 SSD FW 퍼징 기능을 기반으로, **LLM 제안을 실제 실행 결과와 연결해
다음 탐색에 반영하는 버전**이다. 목표별 근거 추적, setup 보존형 시퀀스, JSON 입력 생성 규칙,
실측 성과 기반 LLM 작업 배분을 추가했다.

구현 기준 커밋: `13204e6`. 상세 설계와 검증 항목은
[V10_2_LLM_IMPLEMENTATION.md](V10_2_LLM_IMPLEMENTATION.md)를 참조한다.

## v10.1 대비 변경 사항

| 항목 | v10.2 동작 |
|---|---|
| 목표 관리 | 함수를 core/bank/entry로 식별하고 프롬프트 노출·LLM 선택·채택·실행·관측을 구분 |
| 실행 피드백 | 명령 필드, 실제 발송 문맥, 완료 상태, 최근 상태 snapshot을 목표·proposal과 연결 |
| 시퀀스 탐색 | 기본 80%는 setup을 유지하고 마지막 trigger만 변이, 나머지는 기존 전체 변이 |
| 입력 생성 | LLM의 JSON 규칙 하나에서 여러 payload/CDW 조합을 생성하고 기존 변이 엔진으로 탐색 |
| 작업 선택 | 평가를 마친 proposal의 성과와 비용으로 신규 시드·시퀀스·workload 작업 비중 조절 |
| 관측 신뢰성 | 샘플링 실패와 CQE 미확인을 신규 커버리지 0점 표본으로 학습하지 않음 |
| 결과 저장 | 기준선·목표·proposal·generator·작업별 통계를 `llm/learning_v10.2.json`에 저장 |

기존 NVMe 발송 함수와 제품별 샘플러 구현을 유지한다. v10.1의 JLink 복구 수정과 LLM 서비스
연속 실패 10회 설정도 이어받는다. v10.1 실행 파일은 별도로 유지한다.

## 실행 방법

기존 v10.1 실행 명령에서 파일명을 `pc_sampling_fuzzer_v10.2.py`로 바꾸면 된다.
제품, 장치, namespace, PM, POR 등 기존 시험 조건을 그대로 사용한다.

다음은 저장소 루트에서 실행하는 BM9K1 예시다. 장치 번호와 나머지 옵션은 기존 시험 명령을 따른다.

```bash
sudo python3 PC_Sampling/pc_sampling_fuzzer_v10.2.py \
  --product BM9K1 \
  --nvme /dev/nvme0 \
  --namespace 1 \
  --rag
```

기존 `--config`, `--no-rag`, `--no-jlink` 등 CLI 옵션도 사용할 수 있다.
전체 옵션은 다음 명령으로 확인한다.

```bash
python3 PC_Sampling/pc_sampling_fuzzer_v10.2.py --help
```

배포할 때는 실행 파일 외에 같은 디렉터리의 `llm_learning.py`와 갱신된 `fuzzer_config.json`도
함께 반영한다. 기존 `rag/`, 제품 자산, NVMe 명령 스키마 등은 기존 프로젝트 구성을 사용한다.
Windows RAG bridge의 호출 API는 동일하며, 생성 규칙은 퍼징 PC에서 처리한다.

## 기본 설정

`fuzzer_config.json`의 기존 `rag` 객체 안에 다음 `learning` 설정이 있다.
아래 내용은 해당 부분의 발췌이며 전체 설정 파일을 대체하는 내용이 아니다.

```json
{
  "learning": {
    "enabled": true,
    "evidence": true,
    "preserve_setup": true,
    "generators": true,
    "adaptive_tasks": true,
    "setup_preserve_ratio": 0.8,
    "evaluation_commands": 8,
    "exploration_every": 4,
    "max_variants": 16,
    "random_seed": 102
  }
}
```

| 설정 | 의미 |
|---|---|
| `enabled` | LLM 학습 확장 전체 활성화 |
| `evidence` | 목표별 실행 근거를 LLM 프롬프트에 제공 |
| `preserve_setup` | corpus 시퀀스에 setup 보존형 탐색 적용 |
| `generators` | LLM 응답의 JSON 생성 규칙 처리 |
| `adaptive_tasks` | 실측 성과 기반 LLM 작업 선택 |
| `setup_preserve_ratio` | setup 보존 방식으로 시퀀스를 실행할 확률 |
| `evaluation_commands` | proposal 평가에 필요한 유효 관측 명령 수 |
| `exploration_every` | 최소 탐색 슬롯의 요청 주기. 기본값은 4회마다 한 슬롯 |
| `max_variants` | 생성 규칙 하나의 최대 파라미터 값 개수 |
| `random_seed` | 학습 모듈 전용 RNG seed. 전체 SSD 실험의 결정론을 보장하지는 않음 |

생성 규칙은 응답당 최대 2개를 처리하며, 전개된 시드는 일반 시드와
`rag.max_seeds_per_round` 예산을 공유한다. 현재 기본값은 라운드당 8개다.

`learning.enabled=false`로 확장을 끌 수 있다. `--no-rag`는 LLM 서비스 사용을 끄는 옵션이며
`learning.enabled`와는 별개다. 학습 기록까지 끄려면 `learning.enabled=false`를 사용한다.

## setup 보존 방식

시퀀스의 마지막 명령을 trigger, 앞의 명령들을 setup으로 취급한다.

1. setup 보존 실행에서는 setup 입력을 복사해 재실행한다.
2. 각 setup 명령의 CQE 성공과 `rc=0`을 확인한다.
3. setup이 실패하거나 완료를 확인할 수 없으면 후속 trigger를 취소한다.
4. setup이 성공하면 마지막 trigger를 변이해 실행한다.
5. 성공한 보호 실행의 setup을 이후 LLM 요청에 재사용 후보로 제공한다.

이 실행 도중에는 별도 I/O workload와 PM rotation을 끼워 넣지 않는다.
Write→Read/Compare/Write의 알려진 공유 관계와 LLM이 명시한 `preserve_fields`를 사용해
trigger에서 유지해야 하는 값을 보존한다. 전체 변이 방식에서는 실패 이후의 반응도 탐색할 수 있다.

setup이 성공했다고 SSD의 내부 FTL 상태까지 이전 실행과 같다고 판단하지 않는다.
동적으로 반환된 NSID를 읽어 다음 명령으로 전달하는 일반적인 의존관계 엔진은 포함하지 않는다.

## 정상·비정상 입력 테스트

JSON 생성 규칙은 descriptor 개수, payload 길이, CDW 필드 사이의 관계를 유지하거나
지정한 관계를 의도적으로 바꾸는 데 사용한다. 생성 결과는 기존 스키마 검증과 발송 경로를 거친다.

예를 들어 `break_length: -1`은 host `data_len`을 payload 길이보다 1바이트 작게 지정하고,
양수는 더 크게 지정한다. 기존의 비정상 data_len 변이를 제거하거나 페이지 수 기준으로
자동 차단하는 필터는 추가하지 않았다. 길이만 다른 입력이 중복으로 제거되지 않도록 수정했다.

이 기능은 PRP 리스트 직접 편집 기능이 아니다. PRP/SGL 구성은 기존 커널 passthru 경로를 따른다.
IOMMU 설정이나 커널 변경은 이 버전의 설치 조건이 아니다.

## 결과 확인

실행 output 디렉터리 아래 `llm/learning_v10.2.json`을 확인한다.
주기 통계, LLM 요청·응답 처리, 종료 시 기록되며 매 명령마다 파일을 쓰지는 않는다.

| 필드 | 확인할 내용 |
|---|---|
| `baseline` | kernel, config, 초기 corpus hash, ELF hash, 시작 시 상태 snapshot |
| `targets` | 목표별 offered/selected/accepted/executed/observed/unobservable 및 최근 시도 |
| `proposals` | 제안별 평가 실행 수, 신규 관측 성과, 비용, 입력 signature |
| `generators` | 생성 규칙, 관측 코드 집합, 신규 발견 수 |
| `tasks` | 작업별 요청 수, 완료된 평가, 요청/응답 문자 수, 서비스 소요 시간 |
| `counts` | setup 취소, trigger 도달, 관측 불능, 저장 상한에 따른 eviction 등 |
| `errors` | 최근 생성 규칙·응답 처리 진단 |

`submission=completion`은 NVMe 완료 상태 확인, `guard_skip`은 발송 전 guard 차단,
`unknown`은 완료 여부 미확인이다. **unknown을 FW 미제출로 단정하지 않는다.**
PC 미관측도 코드 미실행의 증거로 사용하지 않는다.

현재 bridge는 토큰 사용량을 반환하지 않으므로 `usage_tokens`는 `null`이다.
장치 시간 필드는 발송 경로의 호스트 측 경과 시간이며 SSD 자체 처리시간만을 의미하지 않는다.

이 파일은 유한한 최근 기록이다. 기본적으로 target 512개, proposal 2048개, generator 128개,
generator별 코드 키 4096개, 최근 명령 256개까지 보존한다. 전체 명령 이력과 불량 재현 자료는
기존 ledger, history, replay 산출물도 함께 확인한다.

## 비교 실험

기능별 효과를 보려면 `enabled=true`를 유지하면서 `evidence`, `preserve_setup`, `generators`,
`adaptive_tasks`를 모두 끈 실행을 기준으로 삼고, 위 순서대로 기능을 추가한다.
이는 v10.2 내부 기능 비교이며 v10.1과 완전히 동일한 실행 궤적을 보장하는 모드는 아니다.

```bash
python3 PC_Sampling/tools/compare_llm_learning.py \
  run_a/llm/learning_v10.2.json \
  run_b/llm/learning_v10.2.json
```

제품/FW, 시작 corpus, 시간 예산, 샘플링 조건을 맞춘 독립 실행들을 비교한다.
한 번의 실행에서 신규 코드 수가 더 많았다는 이유만으로 개선을 확정하지 않는다.

## 검증 상태

구현 시 로컬에서 다음 검증을 완료했다.

- 전체 37개 테스트 통과: 기존 sampler 회귀 6개, v10.2 시험 31개.
- Python 문법 검사와 CLI `--help` 확인.
- 기존 sampler 구현 및 NVMe 발송 함수의 AST 동일성 검사.
- 실제 v10.2 응답 적용, 명령 회계, calibration 경로를 모의 입력으로 검증.

```bash
python3 -m unittest discover -s PC_Sampling/tests -p 'test_*.py' -v
python3 -m py_compile PC_Sampling/pc_sampling_fuzzer_v10.2.py PC_Sampling/llm_learning.py
```

실제 SSD/JLink의 장시간 동작, 탐색 효율 및 불량 재현율 향상은 아직 실측하지 않았다.
별도 계획인 Spec outcome 분모/compiler/observe/guide 구현도 이번 버전에 포함하지 않는다.

## 관련 문서

- [LLM 개선 프로젝트 설계](LLM_IMPROVEMENT_PROJECT.md)
- [v10.2 상세 구현·리뷰 기록](V10_2_LLM_IMPLEMENTATION.md)
- [v10.1 JLink 상태 및 복구 조사](STATUS_v10_1_JLINK.md)
- [Spec outcome 별도 계획](V10_1_SPEC_OUTCOME_DENOMINATOR.md)
