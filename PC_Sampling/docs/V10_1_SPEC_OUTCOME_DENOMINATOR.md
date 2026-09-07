# v10.1 전 제품 NVMe Spec Outcome Coverage 분모 및 구현 계획

## 1. 목표와 적용 범위

NVMe 명령의 실제 실행 결과를 `(queue, opcode, subcategory, SCT, SC)` 단위로 관측하고,
제품에 적용 가능한 고정 분모 중 몇 개를 달성했는지 측정한다.

이 기능은 특정 제품의 JTAG 구성이나 펌웨어 주소에 종속된 기능이 아니다.
`fuzzer_config.json`의 `PRODUCT_PROFILES`에 등록된 BM9K1, PM9M1 계열, BM9H1, P7, P9 및
향후 추가 제품을 모두 대상으로 한다. 제품별 차이는 다음 두 계층으로 제한한다.

- 코드 커버리지 계층: 제품별 PCSR/halt 및 SWD/JTAG/cJTAG sampler
- Spec outcome 계층: 제품별 NVMe capability profile과 고정 denominator snapshot

Spec outcome tracker는 sampler를 참조하지 않는 host-side 공통 모듈로 구현한다. 한 제품에서
추가한 명령-응답 집계 로직이 다른 제품의 sampler 구현을 변경하게 해서는 안 된다.

이 지표는 다음을 주장하지 않는다.

- NVMe 적합성 또는 응답 정합성
- 펌웨어 코드 커버리지 100%
- vendor-specific 상태의 완전성
- 특정 입력에서 특정 응답이 나와야 한다는 판정

공식 명칭은 **제품 적용 가능 NVMe 명령-응답 조합 관측 커버리지**로 한다.

마스터 분모는 `spec/nvme_outcome_denominator_v10.1.json`에 둔다. 현재 catalog는 NVMe Base
2.3과 NVM Command Set 1.2 및 현재 퍼저의 명령 집합을 기준으로 한다.

## 2. 분모 모델과 확정 규칙

마스터 catalog는 표준 전체 후보이므로 그 자체가 숫자 분모는 아니다. 캠페인 전에 다음 순서로
각 제품의 적용 가능한 분모를 확정한다.

1. `--product`에 대응하는 product profile에서 controller type, transport, 활성 I/O Command
   Set 및 capability를 읽는다.
2. 이번 캠페인에서 실제 활성화한 명령과 safety profile을 적용한다.
3. 필수 명령과 필수 CNS/LID/FID를 포함한다.
4. Identify OACS/ONCS와 Commands Supported and Effects의 CSUPP로 선택 명령을 판정한다.
5. Supported Log Pages와 Feature Identifiers Supported and Effects 자료로 LID/FID를 판정한다.
6. `include_when` 조건이 제품과 subcategory에 적용될 때만 조건부 outcome을 포함한다.
7. 판정할 수 없는 capability는 추측하지 않고 `unresolved`로 분모 밖에 둔다.
8. 결과와 catalog/profile hash를 `denominator_snapshot.json`으로 저장하고 실행 중 변경하지 않는다.

지원 명령은 해당 명령의 `outcomes` 또는 `supported_outcomes`를 사용한다. 미지원 명령도 실제
퍼징 범위에 포함했다면 그 명령의 target은 `SCT=0, SC=0x01 Invalid Command Opcode`다. 지원
명령의 미지원 CNS/LID/FID에는 명령별 `unsupported_outcomes`를 적용한다.

집계 key는 다음과 같다.

```text
(queue, actual opcode, canonical subcategory, SCT, SC)
```

SCT/SC만 정규화한다. DNR, M, CRD는 별도 진단 통계이며 분모를 늘리지 않는다. CQE가 없는
host errno, timeout, subprocess 오류 및 guard에 의해 제출되지 않은 명령도 target outcome으로
세지 않는다.

`TelemetryHostInitiated`는 실제 wire 명령이 `Get Log Page / LID=0x07`이므로 별도 분모를
만들지 않는다. opcode override나 admin/I/O swap도 seed 이름이 아닌 실제 wire command로
canonicalize한다.

기본 제외 범위는 다음과 같다.

- 통제된 media/data fault가 필요한 SCT 2
- ANA 또는 multipath 장비가 필요한 SCT 3
- 제품 response specification이 없는 vendor-specific 상태
- Abort/SQ delete/power-loss notification처럼 별도 동시성이나 장비가 필요한 완료 상태
- 해당 specification revision의 표끼리 값이 충돌하는 상태

이 항목은 영구 제외가 아니다. `media-fault`, `multipath`, `power-loss` 같은 별도 campaign
profile에서 독립 분모로 활성화할 수 있다.

NVMe Base 2.3에서 확인된 충돌은 다음과 같으며 기본 targets에 포함하지 않는다.

- Manufacturing Default Personality Required
  - Figure 103: SCT 1 / SC `0x3D`
  - Figure 187: SCT 1 / SC `0x1F`
- I/O Command Set Combination Rejected
  - Figure 103: SCT 1 / SC `0x2B`
  - Figure 485: SCT 1 / SC `0x15`

관측 커버리지는 `covered target pairs / applicable target pairs`로 계산한다. 명령별 및
subcategory별 값도 함께 제공한다. targets 밖에서 새로 관측한 조합은 별도 누적하되 실행 중
분모에 자동 추가하지 않는다.

## 3. 최종 실행 모델

```text
spec master catalog
        +
product capability profile
        +
campaign command/safety profile
        ↓  offline compile
denominator_snapshot.json (immutable)
        ↓  runtime load only
기존 명령 실행 → 기존 CQE status 파싱 → passive set lookup
        ↓
covered / uncovered / unexpected / unresolved / generator_gap
```

제품별 snapshot은 독립된 분모다. 전 제품 결과를 하나의 covered set으로 합치지 않는다.
통합 현황은 제품별 `covered/total`, 백분율, unresolved 및 generator gap을 나란히 표시한다.

## 4. 동작 모드

CLI는 다음 세 모드를 제공한다.

```text
--spec-outcome-mode off
--spec-outcome-mode observe
--spec-outcome-mode guide
```

### off

기능을 생성·측정·출력하지 않는다. 기존 동작과 완전히 동일한 하위 호환 모드다.

### observe

고정 snapshot을 읽고 기존 명령 결과만 수동 관측한다. 다음 항목을 변경하지 않는다.

- 명령 생성 및 실행 순서
- RNG 소비 순서
- seed 선택 확률과 energy
- corpus 보존 조건
- LLM 요청, prompt 및 reward
- sampling window와 timeout

초기 전 제품 rollout과 정량 평가의 기본 모드다.

### guide

observe가 충분히 검증된 뒤 활성화한다. 신규 target 달성을 corpus/LLM/energy의 보조 목표로
사용한다. 이 모드는 의도적으로 실행 궤적을 바꾸므로 observe 결과와 섞어 비교하지 않는다.

## 5. 데이터 계약

### 5.1 Master catalog

`spec/nvme_outcome_denominator_v10.1.json`은 표준에서 도출한 후보와 적용 조건을 보관한다.
실행 중 직접 해석하지 않는다.

추가할 기계 판독 필드는 다음과 같다.

```json
{
  "selector_extract": {
    "word": 10,
    "mask": 255,
    "shift": 0,
    "format": "LID=0x{value:02X}"
  },
  "applicability": {
    "all": ["command.GetLogPage.supported", "lid.0x07.supported"]
  }
}
```

현재 설명 문자열인 `include_when`은 compiler가 평가할 수 있는 predicate ID로 변경한다.
자유 문자열은 설명 용도로만 남긴다.

### 5.2 Product capability profile

제품별 파일은 `products/<product>/outcome_profile.json`에 둔다. 이 파일은 주소, serial number,
서명값 같은 정보를 포함하지 않고 표준 capability와 명시적 override만 가진다.

```json
{
  "schema_version": 1,
  "product": "PRODUCT_NAME",
  "transport": "pcie",
  "controller_type": "io",
  "io_command_sets": ["nvm"],
  "capability_source": "validated_capture",
  "supported_commands": ["Identify", "Read", "Write"],
  "supported_selectors": {
    "CNS": [0, 1, 2, 3, 5, 6, 7, 8],
    "LID": [0, 1, 2, 3, 5, 18],
    "FID": [1, 2, 4, 5, 7, 8, 9, 10, 11]
  },
  "explicit_exclusions": []
}
```

표준 정보만으로 확정할 수 없는 값은 지원 또는 미지원으로 추측하지 않고 `unresolved`에 둔다.

### 5.3 Denominator snapshot

runtime이 읽는 유일한 분모 파일이다. 모든 조건은 미리 해석되어 있어야 한다.

```json
{
  "schema_version": 1,
  "product": "PRODUCT_NAME",
  "catalog_sha256": "...",
  "profile_sha256": "...",
  "created_at": "...",
  "targets": [
    {
      "queue": "io",
      "opcode": 2,
      "command": "Read",
      "subcategory": "none",
      "sct": 0,
      "sc": 128,
      "name": "LBA Out of Range"
    }
  ],
  "unresolved": [],
  "excluded": [],
  "generator_gaps": []
}
```

snapshot은 캠페인 도중 변경하지 않는다. resume은 지원하지 않으며 새 실행의 `covered`는 항상
빈 집합에서 시작한다. snapshot 자체는 결과 재현과 감사 목적으로 출력 디렉터리에 복사한다.

### 5.4 Runtime observation

`_send_nvme_command()`가 기존 결과를 이용해 다음 임시 문맥을 만든다.

```python
NvmeObservation(
    queue=actual_queue,
    opcode=actual_opcode,
    cdw10=seed.cdw10,
    cdw11=seed.cdw11,
    cdw12=seed.cdw12,
    cdw13=seed.cdw13,
    full_status=full_status,
    submitted=True,
    source=source,
)
```

원본 seed 이름이 아니라 `opcode_override`, `force_admin` 및 guard 적용 후 실제 wire 명령을
사용한다. DNR/M/CRD는 제거하고 `SCT=(status>>8)&7`, `SC=status&0xff`만 target key로 쓴다.

## 6. 공식 집계 범위

계측 gate는 preflight, device 초기화, prefill 및 startup calibration이 끝나고 main fuzz loop가
시작되는 지점에서 연다. gate 이전 응답은 capability나 진단 자료일 뿐 공식 분자가 아니다.

source별 결과는 다음과 같이 분리한다.

- `fuzz`: mutation, random, deterministic, LLM seed 및 명시적 sequence
- `state_replay`: state corpus replay
- `workload`: 보장된 Read/Write workload 주입
- `maintenance`: recovery, reattach, write-protect 복구 및 기타 관리 명령

공식 기본 분자는 `fuzz`다. `state_replay`와 `workload`를 포함한 전체 관측값도 별도로 제공하되,
보장 workload가 성공 조합을 대신 달성한 것처럼 보이지 않도록 합산 결과를 명확히 구분한다.
`maintenance`는 공식 분자에서 항상 제외한다.

관측 결과 분류는 다음과 같다.

- `covered`: 고정 targets에 있고 이번 실행에서 한 번 이상 관측
- `uncovered`: targets에 있으나 미관측
- `unexpected`: 유효 CQE지만 targets 밖의 `(SCT, SC)`
- `host_failure`: timeout, errno, subprocess 오류 또는 CQE 없는 결과
- `unresolved`: capability 미확정으로 숫자 분모에서 제외
- `generator_gap`: 분모에는 있지만 현재 generator가 만들 수 없는 subcategory

## 7. 상세 구현 Phase

### Phase 0 — 의미와 schema 동결

목적은 구현 중 분모 의미가 바뀌지 않게 하는 것이다.

작업:

1. coverage key와 `covered/unexpected/host_failure` 의미를 확정한다.
2. 공식 source 범위와 계측 gate를 확정한다.
3. unsupported command 및 unsupported selector의 분모 규칙을 확정한다.
4. media/path/vendor/외부 fault profile의 기본 제외 규칙을 확정한다.
5. master catalog의 `include_when`을 machine-readable predicate로 변환한다.
6. catalog와 snapshot용 JSON Schema를 작성한다.

완료 조건:

- 동일 입력 catalog/profile로 byte-equivalent target 목록이 생성된다.
- target key에 seed family 이름이나 sampler 정보가 들어가지 않는다.
- 스펙 충돌 항목이 기본 targets에 들어가지 않는다.

### Phase 1 — Catalog validator와 offline compiler

목적은 runtime device 접근 없이 제품별 분모를 생성하는 것이다.

추가 모듈/도구:

```text
spec_outcome_catalog.py
tools/build_outcome_snapshot.py
tools/check_outcome_profile.py
```

작업:

1. master catalog의 opcode/queue/SCT/SC 범위 및 중복을 검사한다.
2. CNS/LID/FID의 0x00~0xFF 분류 누락과 겹침을 검사한다.
3. `PRODUCT_PROFILES`의 모든 제품에 profile 존재 여부를 검사한다.
4. product capability와 campaign의 활성 명령/안전 설정을 교집합한다.
5. 조건부 outcome을 해석하고 targets를 평면화한다.
6. unresolved, exclusion 및 generator gap을 targets와 분리한다.
7. catalog/profile hash가 포함된 immutable snapshot을 생성한다.

비영향 조건:

- compiler의 기본 동작은 파일 입력만 사용한다.
- 장치에서 자료를 수집하는 옵션은 별도 프로세스의 명시적 `--collect`로만 제공한다.
- 퍼저가 snapshot이 없다고 runtime auto-probe해서는 안 된다.

완료 조건:

- 등록된 모든 제품 profile을 일괄 검사하는 명령이 성공한다.
- 같은 profile의 반복 compile 결과 targets가 동일하다.
- snapshot 없이 `observe/guide`를 요청하면 명확히 실패하고 `off`로 조용히 폴백하지 않는다.

### Phase 2 — Passive runtime observer

목적은 기존 퍼징 궤적을 변경하지 않고 결과를 측정하는 것이다.

추가 모듈:

```text
spec_outcome_coverage.py
```

핵심 상태:

```python
targets: frozenset[OutcomeKey]
covered_by_scope: dict[str, set[OutcomeKey]]
unexpected: Counter[OutcomeKey]
host_failures: Counter[str]
first_hit: dict[OutcomeKey, HitMetadata]
```

퍼저 연결 지점:

1. 초기화 시 snapshot을 한 번 읽고 `frozenset`으로 만든다.
2. `_send_nvme_command()`에서 실제 queue/opcode/CDW/status 문맥을 저장한다.
3. `_stop_sampling_checked()`가 끝난 뒤 `_account_command()`에서 observation을 소비한다.
4. `RC_SKIP`, CQE 없는 errno, timeout 및 subprocess 오류는 target 대조에서 제외한다.
5. observation을 소비한 뒤 즉시 초기화하여 stale status 재사용을 막는다.
6. 계측 gate 이전 및 maintenance source는 공식 covered에 넣지 않는다.

observe 모드에서는 `is_interesting`, corpus, energy, LLM 통계를 변경하지 않는다.

완료 조건:

- device-facing 추가 NVMe/JTAG 명령 수가 0이다.
- 명령 한 번당 추가 동작은 메모리 decode/set lookup으로 제한된다.
- sampling thread가 종료되기 전에 tracker가 호출되는 경로가 없다.
- opcode override와 admin/I/O swap이 실제 wire command로 귀속된다.
- Telemetry seed가 `GetLogPage/LID=0x07`로 canonicalize된다.

### Phase 3 — 리포트와 영속화

목적은 실행 중 진행률과 종료 후 미달성 목표를 사람이 읽을 수 있게 하는 것이다.

출력물:

```text
denominator_snapshot.json
spec_outcome_coverage.json
spec_outcome_coverage.csv
spec_outcome_events.jsonl
report.html
coverage_growth.jsonl
```

100회 통계에 다음 필드를 추가한다.

```text
[SPEC-COV] fuzz 73/186 (39.25%) | all 81/186 (43.55%) |
           unexpected=4 unresolved=2 generator_gap=0
```

`coverage_growth.jsonl`에는 `spec_covered`, `spec_total`, `spec_pct`, `spec_unexpected`를
추가한다. 명령마다 파일을 쓰지 않고 기존 주기 flush에 합친다. `spec_outcome_events.jsonl`은
target의 최초 hit와 unexpected 최초 관측만 기록한다.

`report.html`은 다음 계층으로 표시한다.

```text
product
└── command
    └── CNS/LID/FID/other subcategory
        └── SCT/SC: covered | uncovered | excluded | unresolved
```

완료 조건:

- JSON/CSV/HTML의 covered/total 값이 동일하다.
- 종료·Ctrl+C·timeout 정리 중에도 마지막 메모리 상태가 best-effort로 저장된다.
- 제품별 결과에 다른 제품의 target이 섞이지 않는다.

### Phase 4 — Generator reachability 정합화

목적은 분모에는 있으나 현재 퍼저가 생성할 수 없는 목표를 제거하는 것이 아니라 generator를
스펙에 맞게 고치는 것이다.

우선 수정 항목:

1. `GetLBAStatus.ATYPE`을 `0x02`, `0x10`, `0x11`로 수정한다.
2. `IOMgmtReceive/Send`의 CDW10 `MO/MOS`, CDW11 `NUMD` 배치를 수정한다.
3. CNS/LID/FID whitelist의 표준 누락과 reserved/vendor 겹침을 수정한다.
4. selector decoder와 generator가 동일 field descriptor를 공유하게 한다.
5. snapshot의 모든 활성 subcategory에 적어도 하나의 생성 경로가 있는지 검사한다.
6. 상태 이름 표를 SC 단독이 아닌 `(SCT, SC)` 키로 바꾸고, 현재 `Data Transfer Error`의
   잘못된 `SC=0x05` 표기를 Base 2.3의 `SC=0x04`로 수정한다.

완료 조건:

- 활성 targets에 대한 `generator_gap=0`이다.
- reserved/vendor 값은 campaign profile에서 허용한 경우만 생성된다.
- 각 selector 경계값의 wire CDW가 기대값과 일치한다.

### Phase 5 — 전 제품 observe rollout

목적은 모든 등록 제품에서 동일한 tracker를 검증하는 것이다.

작업:

1. 각 제품의 capability 자료를 별도 수집하고 profile을 작성한다.
2. 제품 담당자가 snapshot의 supported/unresolved/excluded를 검토한다.
3. 각 sampler 유형에서 짧은 observe smoke campaign을 수행한다.
4. `off`와 `observe`의 동일 RNG 실행 command history를 비교한다.
5. exec/s, timeout 수, sampler 실패율 및 corpus 변화를 비교한다.
6. 전 제품 결과를 제품별 표로 합치는 summary 도구를 추가한다.

완료 조건:

- `PRODUCT_PROFILES`에 등록된 모든 제품이 snapshot validation을 통과한다.
- deterministic mock 실행에서 off/observe command history hash가 동일하다.
- observe가 corpus 크기, seed 선택 및 LLM 요청 수를 바꾸지 않는다.
- 장치별 차이는 product profile과 snapshot에만 존재한다.

### Phase 6 — Guide 및 LLM 연동

목적은 검증된 분모를 실제 탐색 목표로 활용하는 것이다.

작업:

1. `spec_new_target`을 별도 interesting 원인으로 추가한다.
2. 신규 target을 만든 seed를 유한한 spec corpus로 보존한다.
3. 명령/서브카테고리별 미달성 target을 LLM context에 제공한다.
4. LLM과 mutation의 `new target / executed command` 기여율을 각각 측정한다.
5. 이미 달성한 조합보다 미달성 조합의 생성 확률을 제한적으로 높인다.
6. 기존 BB coverage, state coverage 및 SC-depth와 reward 충돌을 제한한다.

안전장치:

- guide는 명시적 옵션에서만 활성화한다.
- 분모는 guide 실행 중에도 변경하지 않는다.
- unexpected 상태 발견은 자동으로 target에 편입하지 않는다.
- spec corpus 상한은 활성 target 수를 넘지 않도록 한다.

완료 조건:

- observe와 guide 결과가 모드 태그로 명확히 구분된다.
- LLM/mutation별 신규 target 기여가 report에 표시된다.
- guide가 timeout/crash 판정 및 안전 guard를 우회하지 않는다.

### Phase 7 — 운영 고정과 회귀 방지

목적은 스펙·제품·퍼저 버전 변경에도 수치 의미를 유지하는 것이다.

작업:

1. catalog/profile/snapshot schema version 호환 정책을 정한다.
2. 스펙 revision 변경은 catalog 새 버전으로만 반영한다.
3. 제품 FW capability 변경 시 새 profile/snapshot을 발행한다.
4. CI에서 전 제품 profile validation과 denominator diff를 실행한다.
5. 분모 변경 PR에는 추가·삭제 target 및 사유 요약을 자동 생성한다.

완료 조건:

- snapshot hash가 다른 실행을 동일 캠페인 결과로 합치지 않는다.
- 분모 변경 이력이 diff로 추적된다.
- 신규 제품은 core tracker 수정 없이 profile/catalog adapter 추가만으로 등록된다.

## 8. 필수 시험

### 단위 시험

- SCT/SC에서 DNR/M/CRD를 제거해 같은 key가 되는지 확인
- queue가 다른 동일 opcode가 서로 섞이지 않는지 확인
- CNS/LID/FID 및 기타 selector bit 추출 확인
- supported, unsupported, unexpected, host failure 분류 확인
- 같은 target 반복 관측 시 분자가 한 번만 증가하는지 확인
- snapshot target 중복, 범위 오류 및 hash mismatch 거부 확인

### 통합 시험

- `rc=0`을 `(SCT=0, SC=0)`으로 기록
- nvme-cli status 문자열에서 SCT/SC 보존
- status 없는 errno와 `RC_SKIP` 미계상
- opcode override 및 force-admin 실제 명령 귀속
- Telemetry alias 중복 방지
- calibration과 maintenance 응답 공식 분자 제외
- state replay/workload를 별도 scope로 집계

### 비영향 회귀 시험

- 같은 seed/RNG로 `off`와 `observe`의 command history hash 비교
- 두 모드의 corpus 추가/삭제 순서 비교
- LLM 요청 횟수와 제안 적용 순서 비교
- sampler start/stop 호출 횟수 비교
- 추가 subprocess 및 장치 접근이 0인지 mock으로 확인
- per-command 동기 파일 쓰기가 없는지 확인

## 9. 구현 순서 결정

Phase 0~3을 먼저 완료해 passive 지표의 신뢰성을 확보한다. Phase 4에서 generator gap을 0으로
만든 뒤 모든 제품에 Phase 5 observe를 적용한다. 수치와 비영향성이 확인되기 전에는 Phase 6
guide 또는 LLM reward를 활성화하지 않는다.

첫 운영 버전은 `off`를 기본으로 두고 snapshot이 준비된 제품에서만 `observe`를 명시적으로
활성화한다. 모든 등록 제품의 profile 검증이 끝난 이후에도 snapshot 누락 시 runtime auto-probe는
하지 않으며, 명확한 설정 오류로 종료하는 원칙을 유지한다.
