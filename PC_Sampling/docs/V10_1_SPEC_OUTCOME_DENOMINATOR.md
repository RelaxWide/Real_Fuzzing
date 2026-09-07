# v10.1 NVMe 명령-응답 조합 분모

## 목적

`spec/nvme_outcome_denominator_v10.1.json`은 NVMe Base 2.3과 NVM Command Set 1.2를
기준으로, 현재 퍼저가 모델링하는 명령의 `(명령/서브카테고리, SCT, SC)` 관측 목표를
정의한다.

이 지표는 입력과 응답의 정합성을 판정하지 않는다. 따라서 명칭은 **NVMe 적합성
커버리지**가 아니라 **제품 적용 가능 NVMe 명령-응답 조합 관측 커버리지**로 한다.

## 분모 확정 절차

마스터 JSON은 표준 전체 후보이므로 그 자체로 숫자 분모가 아니다. 캠페인 시작 시 다음
순서로 제품 분모를 고정한다.

1. Controller type은 I/O controller, transport는 PCIe, command set은 NVM으로 고정한다.
2. 필수 명령 및 필수 CNS/LID/FID를 포함한다.
3. Identify의 OACS/ONCS와 Commands Supported and Effects의 CSUPP로 선택 명령을 판정한다.
4. Supported Log Pages와 Feature Identifiers Supported and Effects가 있으면 LID/FID 지원을 판정한다.
5. capability를 판정할 수 없는 선택 항목은 추측하지 않고 `unresolved`로 보고한다.
6. 파괴적·환경 의존 프로파일을 사용하지 않으면 해당 항목을 제외 사유와 함께 보고한다.
7. 결과와 마스터 JSON 해시를 `denominator_snapshot.json`으로 저장하고 캠페인 중 변경하지 않는다.

`include_when`이 붙은 결과는 조건이 제품 capability 및 해당 서브카테고리에 적용될 때만
포함한다. 이를 평가하지 못한 조건부 결과도 `unresolved`이며 임의로 분모에 넣지 않는다.

지원 명령은 해당 명령의 `outcomes` 또는 `supported_outcomes`를 사용한다. 미지원 명령을
실제로 퍼징 범위에 둘 경우 그 명령의 목표는 `SCT=0, SC=0x01` 하나다. LID/FID/CNS가
지원되지 않는 경우에는 명령별 `unsupported_outcomes`를 사용한다.

## 집계 키

```text
(queue, actual opcode, canonical subcategory, SCT, SC)
```

SCT와 SC만 정규화해 사용한다. DNR, M, CRD는 별도 진단 통계이며 분모를 늘리지 않는다.
nvme-cli가 CQE 상태를 출력하지 않은 host errno, timeout, subprocess 오류는 명령-응답
조합으로 세지 않는다.

`TelemetryHostInitiated`는 실제 wire 명령이 `Get Log Page / LID=0x07`이므로 별도 분모를
만들지 않는다. 같은 원칙으로 향후 seed family 이름과 wire 명령이 다르면 wire 기준으로
canonicalize한다.

## 보고할 지표

```text
전체 관측 커버리지      = covered target pairs / applicable target pairs
명령별 커버리지         = command covered / command applicable
서브카테고리별 커버리지 = subcategory covered / subcategory applicable
목표 외 신규 조합       = 별도 누적, 분모에 자동 추가하지 않음
미해결 capability        = 분모 밖에서 개수와 항목을 명시
```

목표 외 조합은 다음 캠페인 전에 스펙 또는 제품 문서로 검토한다. 정상 목표로 확인된 경우에만
마스터 JSON 버전을 올려 추가한다. 실행 중 발견값으로 분모를 움직이지 않는다.

## 기본 제외 범위

- 통제된 media/data fault가 필요한 SCT 2
- ANA·multipath 장비가 필요한 SCT 3
- 제품 response spec이 없는 vendor-specific 상태
- Abort/SQ delete/power-loss notification처럼 별도 동시성·장비가 필요한 완료 상태
- 현재 NVMe 2.3 문서 내 표끼리 값이 충돌하는 상태

이 항목들은 영구 제외가 아니다. `media-fault`, `multipath`, `power-loss` 같은 별도 캠페인
프로파일을 만들 때 독립 분모로 활성화한다.

## 확인된 NVMe 2.3 표 충돌

- Manufacturing Default Personality Required:
  - Figure 103: SCT 1 / SC `0x3D`
  - Figure 187: SCT 1 / SC `0x1F`
- I/O Command Set Combination Rejected:
  - Figure 103: SCT 1 / SC `0x2B`
  - Figure 485: SCT 1 / SC `0x15`

두 항목은 `spec_disputed_outcomes`에 기록하되 기본 분모에는 넣지 않는다. NVMe errata나
제품의 실제 응답 규격으로 우선값이 확인된 뒤 활성화한다.

## 현재 v10.0 생성기와의 차이

이 파일은 v10.1의 목표 분모이며, 현재 v10.0 생성 가능값을 그대로 옮긴 목록이 아니다.
분모를 실제로 연결하기 전에 최소한 다음 스키마 차이를 함께 고쳐야 한다.

- `GetLBAStatus.ATYPE`: v10.0의 `[0, 1, 2]`가 아니라 NVM 1.2의
  `[0x02, 0x10, 0x11]`을 사용한다.
- `IOMgmtReceive`/`IOMgmtSend`: Base 2.3의 CDW10에 `MO/MOS`, CDW11에 `NUMD`가
  위치한다. v10.0은 두 dword를 반대로 모델링한다.
- CNS/LID/FID: v10.0 whitelist에는 표준 항목 누락과 예약 범위 겹침이 있으므로,
  확정 snapshot의 서브카테고리를 생성기가 실제로 만들 수 있는지 자동 검사한다.

분모에 있으나 생성 불가능한 목표는 단순 미커버가 아니라 `generator_gap`으로 보고해야 한다.
그 상태에서 100%를 목표로 표시하면 안 된다.
