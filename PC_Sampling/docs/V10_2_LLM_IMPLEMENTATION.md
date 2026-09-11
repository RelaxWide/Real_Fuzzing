# v10.2 실행 근거 기반 LLM 탐색

실행·설정 안내: [pc_sampling_fuzzer v10.2](pc_sampling_fuzzer_v10.2.md).

기준: `pc_sampling_fuzzer_v10.1.py`를 복사한 `pc_sampling_fuzzer_v10.2.py` (10.2.0).
설계 근거: [LLM_IMPROVEMENT_PROJECT.md](LLM_IMPROVEMENT_PROJECT.md).
상태: 코드 구현 및 하드웨어 없는 단위·통합 검증 완료. 실제 SSD/JLink에서의 장시간 성능과
불량 재현율 개선은 아직 측정하지 않았다.

## 실행

기존 실행 명령의 파일명만 `pc_sampling_fuzzer_v10.2.py`로 바꾸고 기존 제품·장치·PM 등의
옵션을 유지한다. LLM을 사용하던 실행에는 기존처럼 `--rag`를 사용한다.

```bash
python3 PC_Sampling/pc_sampling_fuzzer_v10.2.py --help
```

`llm_learning.py`도 실행 파일과 같은 디렉터리에 배포해야 한다. 기존 Windows RAG bridge의
호출 API는 변경하지 않았다. JSON 생성 규칙은 퍼징 호스트에서 해석한다.

설정은 기존 `fuzzer_config.json`의 `rag.learning`에 추가했다. v10.1은 이 키를 읽지 않는다.
v10.1 실행 파일, 드라이버, IOMMU/커널 설정은 이 작업에서 변경하지 않았다.

## 구현 내용

| 단계 | 구현 |
|---|---|
| 기준선 | 퍼징 시작 시 config, kernel, 초기 corpus hash, ELF hash(지원 시), sampler, 최근 state snapshot 기록 |
| 목표별 근거 | core/bank/entry 기반 target ID, 노출·선택·채택·완료 확인 실행·목표 관측·관측 불능을 분리 |
| setup 보존 | corpus 시퀀스의 마지막 명령을 trigger로 정의. 보호 실행에서는 setup을 복사하고 trigger만 변이 |
| 입력 생성 규칙 | 유한 JSON 규칙을 little-endian payload 및 CDW 변형으로 전개. 기존 스키마 및 발송 guard를 거침 |
| 작업 배분 | 유효 관측 실행 예산을 소비한 proposal의 신규 관측 성과와 장치/LLM 시간을 반영. 최소 탐색 유지 |
| 결과 보존 | 기본 60초 간격으로 `llm/learning_v10.2.json` 전체 저장. 종료 시 강제 저장. 임시 파일 후 교체 방식 |

목표 후보는 코어별로 번갈아 선택한다. 본체 callgraph에 근거가 있는 경우 직접 호출자가
관측된 명령도 연결한다. 오버레이 bank의 호출 관계를 본체 주소로 추정하지 않는다.
프롬프트에는 요청 당시 target ID와 setup 복사본을 넣고 응답에도 해당 요청의 context를
사용한다. 다른 요청의 목표나 알 수 없는 setup ID를 임의로 연결하지 않는다.

### setup과 의존관계

- 기본 80%는 setup 보존, 나머지는 기존 전체 변이 방식이다. 별도 RNG를 사용한다.
- 보호 실행에서는 setup의 각 명령에 CQE 성공과 rc=0을 요구한다. 실패·guard skip·완료 미확인 시
  pending trigger를 취소한다. 탐색 실행에서는 실패 뒤 동작을 계속 관측할 수 있다.
- 보호 실행의 멤버 사이에는 별도 I/O workload와 PM rotation을 주입하지 않는다.
- 알려진 Write→Read/Compare/Write 관계는 LBA/NLB 및 필요한 data/NSID를 보존한다.
- 그 밖의 의존관계는 응답의 `preserve_fields`로 trigger의 원래 필드를 유지하도록 지정한다.
  지원 필드: cdw2/3/10..15, data, nsid_override, data_len_override.
- 실제로 성공한 보호 실행의 setup만 재사용 후보로 기록한다. 같은 setup의 성공은 같은 FTL
  내부 상태의 증거가 아니다. 최근 상태 snapshot은 관측 문맥이며 현재 명령 직후 상태라는 보장도 없다.
- 임의 위치 trigger, 동적으로 생성된 NSID 등 결과 필드에서 다음 입력을 계산하는 일반적인
  의존관계 엔진은 초기 범위에 포함하지 않는다.

LLM은 `{"setup_id":"s...","commands":[최종_trigger]}`로 요청에 포함된 setup을 재사용하거나,
기존처럼 전체 `commands` 시퀀스를 반환할 수 있다. 부분적으로 탈락한 시퀀스는 채택하지 않는다.

### 생성 규칙 예시

DSM descriptor 개수와 NR을 함께 바꾸는 예시다. 값과 지원 명령은 기존 제품/발송 정책을 따른다.

```json
{
  "generators": [{
    "base": {"command": "DatasetManagement", "cdw11": 4},
    "values": [1, 2, 16],
    "record": [
      {"width": 4, "value": 0},
      {"width": 4, "value": 1},
      {"width": 8, "value": 0}
    ],
    "repeat": {"param": true},
    "bindings": [{
      "field": "cdw10", "lo": 0, "bits": 8,
      "value": {"param": true, "add": -1}
    }]
  }]
}
```

- 파라미터 하나의 유한 값 목록, 고정 폭 정수 record, 반복, CDW bitfield 관계만 지원한다.
- `break_length: -1`은 payload보다 host data_len을 1바이트 작게 만드는 명시적 변이다.
  양수도 허용한다. 페이지 수 비교로 안전/불량 입력을 판정하거나 작게 지정한 값을 자동 제거하지 않는다.
- PRP 리스트 자체를 직접 편집하는 기능은 아니다. PRP/SGL은 기존 커널 passthru 경로가 구성한다.
- 크기 초과, 비정수, 겹치는 bitfield, 잘못된 연산은 전개 전에 거부한다. 정수 overflow를 묵시적으로
  wrap하지 않는다. 임의 Python 실행은 없다.
- 규칙 하나에 기본 최대 16개 값, 응답마다 최대 2개 규칙. 생성 입력은 기존 `rag.max_seeds_per_round`
  예산을 공유한다. 예산 때문에 미채택된 수를 별도로 기록한다.
- 기존 seed 중복 판정에 NSID/queue/opcode/data_len override를 포함해 길이만 다른 실험이 사라지지 않게 했다.
- generator ID는 규칙 내용의 hash다. 신규 발견 수와 관측 코드 집합을 별도로 보존한다. 뒤에 실행된
  규칙의 신규 발견 수가 0이라는 이유로 규칙을 폐기하지 않는다.

### 보상·오류 의미

`submission=completion`은 NVMe 완료 상태가 확인된 실행이다. `unknown`은 CQE를 확인하지 못한
실행이며 **FW에 제출되지 않았다는 뜻이 아니다**. `guard_skip`은 기존 발송 guard가 차단한 입력이다.

샘플링 실패/복구가 발생한 window, 유효 코드 관측이 없는 window, CQE 미확인 실행은 새 task
scheduler의 0점 표본으로 사용하지 않는다. 목표 코어/bank가 관측되지 않은 경우도 목표 미도달
결론과 구분한다. 기존 LLM 대 mutation energy boost의 관측 분모도 유효 window에 맞췄다.
calibration도 실행별로 기록하여 원본 시드가 먼저 얻은 성과를 놓치지 않는다.

기본적으로 proposal당 유효 명령 8회 이후 한 번 보상한다. 시퀀스는 trigger 경계까지 기다린다.
보상은 `log(1+신규 관측 코드 수)/(평가 장치 시간+분담 LLM 응답 시간)`이다. 최근 32개의 완료된
평가를 이용한다. `corpus_eval`은 직접 커버리지 보상으로 비교하지 않고 최소 탐색 슬롯에서 평가한다.
여기서 장치 시간은 NVMe 발송 경로의 호스트 측 wall time이며 SSD 자체 처리시간만을 뜻하지 않는다.
LLM task 선택과 corpus의 LLM/mutation energy boost는 서로 다른 선택 단계다.

현재 bridge는 토큰 사용량을 반환하지 않으므로 `usage_tokens=null`이다. 요청/응답 문자 수와
서비스 소요 시간은 별도 기록하며 토큰 수로 표시하지 않는다. input_signature는 요청 입력 및
발송 문맥의 해시이며, 실제 PRP 주소를 포함하는 완전한 SQE 해시가 아니다.

## 비교 설정

`rag.learning`에서 다음 플래그를 독립적으로 바꿀 수 있다.

| 설정 | 의미 |
|---|---|
| enabled=false | 전체 확장을 비활성화 |
| evidence=false | 목표별 근거 프롬프트를 끔 |
| preserve_setup=false | 기존 시퀀스 변이 방식 |
| generators=false | JSON 생성 규칙 비활성화 |
| adaptive_tasks=false | 기존 가중 RR/plateau 작업 선택 |

기능 효과 비교에는 enabled=true 상태에서 나머지 네 기능을 모두 끈 arm을 시작점으로 쓰고,
evidence → preserve_setup → generators → adaptive_tasks 순서로 추가한다. 이 비교의 기준은
v10.2의 공통 회계 수정이 적용된 기준선이다. v10.1 전체와 byte 단위 동일 동작을 주장하지 않는다.

제품/FW, 시작 corpus, 실행 시간, 샘플링 조건을 맞추고 초기 비교에서는 adaptive 코어 가중치를
고정한다. SSD 상태·마모·실행 순서 영향이 있으므로 독립 실행들의 분포를 비교한다.

```bash
python3 PC_Sampling/tools/compare_llm_learning.py \
  run_a/llm/learning_v10.2.json run_b/llm/learning_v10.2.json
```

snapshot에는 유한한 최근 기록과 보존 상한이 있다. 기본 target 512개, proposal 2048개,
generator 128개, generator별 코드 키 4096개, 최근 명령 256개다. proposal별 입력 signature는
64개까지 기록한다. 잘림/eviction 카운터를 확인해야 하며, 이 자료를 전체 캠페인의 완전한
명령 이력으로 사용하지 않는다. 전체 실행/불량 재현 자료는 기존 ledger·명령 history와 함께 본다.

## 검증과 리뷰

2026-09-11 보완 기준 로컬 결과: 전체 50개 시험 통과(기존 sampler 회귀 6개 + v10.2 시험 44개).
Python 문법 검사, CLI `--help`, 고정 기준 sampler/발송 함수 AST 검사도 통과했다.

```bash
python3 -m unittest discover -s PC_Sampling/tests -p 'test_*.py' -v
python3 -m py_compile PC_Sampling/pc_sampling_fuzzer_v10.2.py PC_Sampling/llm_learning.py
```

리뷰에서 수정한 항목:

1. Critical issues: setup 실패 후 trigger 진행, setup 중 workload/PM 개입, 요청 context 혼동,
   sampler 복구 성공을 이전 window 관측 성공으로 취급하는 경로를 차단/분리했다.
2. Potential bugs: 길이만 다른 시드 dedup, calibration 성과 누락, 파생 시드 proposal 유실,
   오버레이 bank 혼동, 작은 저장 상한에서 응답 등록 중 예외를 수정했다.
3. Reliability improvements: 유한 JSON DSL, 단계별 설정, 지연 보상, 최소 탐색, 유한 기록 저장,
   원본 LLM 응답 아카이브 보존, 종료·예외 시 snapshot 저장을 추가했다.
4. Suggested tests: 로컬 시험은 실제 v10.2 스키마/응답 처리/회계/calibration을 모의 장치로
   확인한다. 실제 장비에서는 setup 실패, JLink 관측 불능, 정상/비정상 data_len과 장시간
   반복 캠페인의 성과·오버헤드를 확인해야 한다. 실기 테스트를 수행했다고 주장하지 않는다.

별도 문서의 Spec outcome 분모/compiler/observe/guide 전체 구현은 이번 버전에 포함하지 않았다.


## 2026-09-11 리뷰 반영

1. Critical issues: 이번 리뷰 범위에서 별도 치명 결함은 보고되지 않았다.
2. Potential bugs: 학습 모듈 누락은 배포 경로를 포함한 `[FATAL]`로 안내한다. 설정의 타입·범위
   오류는 키와 값을 명시하고 리소스 초기화 전에 종료한다. 미지 키는 경고 후 무시해 공유 config의
   후속 버전 키를 허용한다. sampler 시작 호출을 감싸 window마다 발송 기록을 초기화하고,
   stop/회계에서 한 번 소비해 이전 proposal에 sampling_failure·비용이 중복 귀속되지 않게 했다.
   이 변경은 sampler 구현 자체를 수정하지 않는다. 기존에도 sampling_failure를 0점 보상으로
   쓰지는 않았으며, 이번 수정은 실패 기록과 비용의 귀속 문제를 해결한다.
3. Reliability improvements: `rag.learning.snapshot_min_interval_sec` 기본값은 60초다. 간격
   안에서는 `snapshot()`의 coverage 정렬과 JSON 직렬화도 실행하지 않는다. 저장 실패에도 간격을
   적용하며 종료 시에는 강제 저장한다. AST 기준은 `tests/fixtures/v10_2_device_ast.json`에 동결했다.
   기준 커밋은 `13204e6`이며 해당 커밋의 원본 AST와도 대조했다. v10.2 장치 경로를 의도적으로
   수정하는 경우에만 리뷰 후 fixture의 hash와 source_commit을 함께 갱신한다. 테스트 실패 시
   자동 갱신하지 않는다. 정규화는 위치 정보를 제외하고 빈 type_params를 무시하여 Python
   3.8/3.12의 AST 형식 차이를 흡수한다.
4. Suggested tests: `test_v10_2_hardening.py`에 배포 누락/설정 오류 subprocess 시험,
   미지 키 경고, 발송 없는 window, 반복 stop, 정상 발송 시간의 회계 전달, 발송 중 예외,
   저장 간격/실패 재시도/종료 강제 저장, coverage 상한 round-trip 시험을 추가했다.

저장 부하 측정: generator 128개 × 각 4096개의 정수 키(`(i << 48) + j`)를 채운 합성
snapshot은 **13,965,383 bytes(약 13.3 MiB), 저장 0.287초**였다. 로컬 파일시스템에서의 단일
측정이며 SSD 테스트 리그의 디스크 처리량을 보장하는 수치는 아니다. generator coverage 상한만
채웠으므로 모든 메타데이터까지 포함한 최대 파일 크기라는 뜻도 아니다. 회귀 시험은 실행 시간의
절대 임계값 대신 전체 키 복원 및 간격 안에서의 직렬화 생략을 검사한다.
