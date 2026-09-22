# pc_sampling_fuzzer v10.2

> **이 문서는 이력이다.** 운용은 v10.3(`RUNBOOK_v10.3.md`)만 쓴다. 여기 적힌 2-PC Samba
> drop-box RAG 경로(`tools/install_rag_query.py`, `RAG_QUERY_DEPLOYMENT.md`, 온라인
> `srag_llm_guide.py` 패치)는 v10.3 의 로컬 vLLM 전환으로 **저장소에서 제거됐다**.
> 필요하면 히스토리에서 복구한다: `git log --diff-filter=D -- PC_Sampling/tools/install_rag_query.py`

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
함께 반영한다. 모듈 누락 시 배포 위치를 포함한 `[FATAL]` 안내로 종료한다. 기존 `rag/`, 제품 자산, NVMe 명령 스키마 등은 기존 프로젝트 구성을 사용한다.
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
    "random_seed": 102,
    "snapshot_min_interval_sec": 60
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
| `snapshot_min_interval_sec` | 전체 snapshot 저장 시도 간 최소 간격(초). 기본 60, 0이면 제한 없음 |

미지의 `rag.learning` 키는 이름을 경고하고 무시한다. 공유 config에 후속 버전의 키가 추가돼도
v10.2의 알려진 옵션은 계속 사용할 수 있다. 알려진 옵션의 잘못된 타입·범위는 해당 키와 값을
포함한 `[FATAL]` 안내로 종료하며, 기본 퍼저의 리소스 초기화 전에 검사한다.

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
주기 통계와 LLM 요청·응답 처리 시 저장을 요청하되 기본 60초 간격으로 제한한다.
간격 안에서는 전체 coverage 정렬·직렬화도 생략한다. 종료·예외 정리 시에는 간격과 무관하게
전체 결과를 저장한다. 저장 실패도 같은 간격으로 재시도하여 반복 I/O를 방지한다.

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

- 2026-09-11 보완 기준 전체 50개 테스트 통과: 기존 sampler 회귀 6개, v10.2 시험 44개.
- Python 문법 검사와 CLI `--help` 확인.
- sampler 구현 및 NVMe 발송 함수의 AST를 초기 구현 커밋 `13204e6`의 고정 해시와 비교.
  v10.1 파일을 비교 기준으로 읽지 않으므로 v10.1 후속 수정과 독립적이다.
- 실제 v10.2 응답 적용, 명령 회계, calibration 경로를 모의 입력으로 검증.

```bash
python3 -m unittest discover -s PC_Sampling/tests -p 'test_*.py' -v
python3 -m py_compile PC_Sampling/pc_sampling_fuzzer_v10.2.py PC_Sampling/llm_learning.py
```

추가 회귀 시험은 모듈 누락 안내, 미지 설정 키 호환, 발송 없는 window의 실패 귀속,
반복 stop의 중복 기록 방지, 정상 발송 시간 보존, 저장 주기 및 종료 시 강제 저장을 포함한다.

실제 SSD/JLink의 장시간 동작, 탐색 효율 및 불량 재현율 향상은 아직 실측하지 않았다.
별도 계획인 Spec outcome 분모/compiler/observe/guide 구현도 이번 버전에 포함하지 않는다.

## 관련 문서

- [LLM 개선 프로젝트 설계](LLM_IMPROVEMENT_PROJECT.md)
- [v10.2 상세 구현·리뷰 기록](V10_2_LLM_IMPLEMENTATION.md)
- v10.1 JLink 상태 및 복구 조사 — 문서 제거됨(`git log -- PC_Sampling/docs/STATUS_v10_1_JLINK.md`)
- [Spec outcome 별도 계획](V10_1_SPEC_OUTCOME_DENOMINATOR.md)

## Timeout 이후 진단 종료와 메모리 기록

PC 모니터링은 30초 간격으로 **총 20회** 관측 후 종료한다(Ctrl+C 조기 종료 가능).
JLink/UFAS 출력은 출력 폴더의 별도 로그 파일로 직접 기록하고,
RDDump의 줄바꿈 없는 출력도 8 KiB 단위로 분할해 무제한 RAM 누적을 방지한다.
`process_memory.jsonl`에는 timeout/덤프/차트/모니터링 단계별 PID와 RSS를 기록한다.
검증 및 보고된 OOM/Identify timeout의 판정 한계를 적은 `V10_2_TIMEOUT_MEMORY_REVIEW.md`는
조사 종료로 제거됐다(`git log -- PC_Sampling/docs/V10_2_TIMEOUT_MEMORY_REVIEW.md`).

## Coverage growth 차트 누락 수정

RISC-V(BM9K1)는 `CoverageModel`에 정적 커버리지를 보관하고 기존 ARM용
`_sa_loaded`는 False로 둔다. 그런데 정적 차트 함수가 이 플래그만 확인하고
즉시 반환해서 `graphs/coverage_growth.png`와 코어별 firmware map을 건너뛰었다.
이제 통계와 동일한 `_cov_totals()`로 판단한다. 성장률과 범례의 BB/함수 분모도
전체 코어 기준으로 맞췄다. 기존 ARM 경로 역시 같은 집계 함수를 사용한다.

성장 곡선에는 통계 이력이 최소 2개 필요하며, 부족하거나 정적 분모가 없으면
주 로그의 `[StatGraph]`에 생략 사유를 기록한다. 생성 시점은 기존과 동일하게
차트 갱신 주기(기본 5,000 실행) 및 정상적인 종료 정리 단계다.
OOM/SIGKILL로 강제 종료되면 종료 정리가 실행되지 않을 수 있다.

`coverage_growth_axes.png`, `coverage_growth_normalized.png`,
`coverage_growth_by_source.png`는 별도 오프라인 도구의 산출물이다.
이미 저장된 데이터는 다음 명령으로 그릴 수 있다(SSD 접근 없음).

```bash
python3 PC_Sampling/tools/coverage_growth_plot.py /path/to/output_dir
```

검증: 총 58개 회귀 테스트 통과. RISC-V/ARM 양쪽에서 실제 PNG 생성,
전체 코어 분모의 범례, figure 해제, 이력 부족 안내를 확인했다. 실기는 미검증이다.

## RAG 검색 입력 분리

v10.2 요청에 짧은 `[RAG-QUERY]` 블록을 추가했다. 기존 evidence/setup은 유지하며,
온라인 guide에서 검색 입력만 최대 1,024자·UTF-8 2,048바이트로 제한한다.
로컬 토크나이저 없이 서버의 토큰 초과 응답에만 축소 재검색(최대 3회 추가)을 적용한다.
**온라인 guide도 먼저 업데이트해야 한다.** 퍼저만 업데이트하면 기존 guide는 여전히
전체 프롬프트를 검색에 보낸다. 기존 온라인 설정을 보존하는 설치 도구와 순서는 `RAG_QUERY_DEPLOYMENT.md`에 있었으나,
v10.3 로컬 vLLM 전환으로 이 경로 전체가 제거됐다(§ 문서 머리말 참조).

### RAG 배포 파일 통합

검색 블록 생성은 `llm_learning.py`에, 온라인 검색 처리는 기존 `srag_llm_guide.py`에
합친다. **별도 `rag_query.py` 배포는 필요 없다.** 온라인 적용 도구
`install_rag_query.py`도 단독 파일로 실행되며 이전 분리형 guide를 통합형으로 전환한다.
구체적인 명령과 최종 배치는 `RAG_QUERY_DEPLOYMENT.md`를 따랐다 — 둘 다 제거됨.

### 토크나이저 의존성 제거

transformers/sentencepiece 및 토크나이저 다운로드가 필요 없는 V2 통합형으로 변경했다.
이미 패치한 온라인 guide에도 최신 `install_rag_query.py --apply`를 다시 실행해야 한다.
기존 토크나이저 코드 블록을 교체하며 추가 파일이나 pip 설치는 필요 없다.

### FW Commit 후 재연결 로그 (2026-09-14)

FW Commit 성공 후 예약된 디버그 재연결은 터미널에 성공/실패와 소요 시간을
한 줄로 출력한다. 인증·DM 활성화·PC 검증·재시도 상세와 예외 traceback은
기존 `fuzzer_*.log`에 남긴다. 하위 Python 코드의 stdout/stderr도 이 구간에서
`[FWCommit/detail]`로 기록하며, 출력 전체를 메모리에 모으지 않는다.
다른 스레드의 출력과 FW Commit 이외의 장애 복구 출력은 기존대로 유지한다.
장치 명령, 인증 판단, 재연결 횟수는 바꾸지 않는다.
배포 시 `pc_sampling_fuzzer_v10.2.py`만 교체하면 되며, 실행 중인 프로세스에는
적용되지 않는다. 모의 성공/실패/예외 및 다른 스레드 출력으로 검증했으며
BM9K1 실기 검증은 별도로 필요하다.

### BM9K1 종료 후 PC 모니터링 재인증 제거 (2026-09-14)

종료 후 20회 PC 모니터링에서 P9의 `sampler.jlink` 존재 여부를 BM9K1에도
적용해 매회 재연결하던 오류를 수정했다. BM9K1은 `session.lk/dap`이 있는
기존 세션에서 Core0 PCSR을 회당 한 번 읽는다. 세션이 닫혔거나 관측이
실패하면 PC 읽기 불가로 표시하며 인증·세션 재연결·복구를 수행하지 않는다.
30초 간격과 최대 20회 제한은 유지한다. 덤프가 세션을 닫았다면 모니터링이
이를 다시 열지 않으므로 PC를 얻을 수 없다. 모의 세션에서 20회 읽기와
세션 없음·무효 PC·전송 예외를 검증했으며 실기 검증은 별도로 필요하다.
배포 파일은 `pc_sampling_fuzzer_v10.2.py` 하나다.

### PM9M1_HP 초기 PC universe 응답 오염 방어 (2026-09-15)

기존 OpenOCD PCSR 파서는 응답 전체의 `0x...` 토큰을 수집했다. 따라서
진단 메시지의 ID 값 하나와 정상 PC 세 개가 함께 수신되면 네 코어로
파싱되어 관측이 실패할 수 있었다. 이 파서·초기화·diagnose 메서드는
v9.8과 동일했으며, 보고된 추가 `0x6xxxxxxx` 값의 실제 출처는 원문 로그
확인이 필요하다. BM9K1 대응으로 코어 수가 바뀌었다고 확정하지 않는다.

OpenOCD의 read_all_pcs Tcl 응답을 `PCFUZZ_PCSR:r번호:값들:END` 형태로
구분하고, 현재 요청 번호의 완전한 응답 한 개만 파싱한다. 응답 밖의
진단 메시지는 파일 로그에 보존하되 PC로 세지 않는다. 응답 내부의
코어 수 불일치·오류·무효 PC는 계속 거부하며, 이전 요청 번호의 응답도
인정하지 않는다. PCSR 주소·읽기 횟수·전원 설정·Thumb 마스킹은 유지한다.

추가 ID/명령 echo/이전 응답/중복 프레임/분할 소켓 수신/무효 PC/제품별
코어 수와 SWD·JTAG 명령 생성을 모의 검증했다. 실제 OpenOCD/SSD에서는
미검증이다. 이번 변경에 한해 OpenOCDPCSampler AST 기준을 명시적으로
갱신했으며, 다른 샘플러와 NVMe 전송 경로의 기준은 그대로다.
배포는 `pc_sampling_fuzzer_v10.2.py`만 교체하고 다음 실행부터 적용한다.


### OS freeze 진행 기록 (2026-09-15)

선택적 `PCFUZZ_FREEZE_TRACE=47471`과 별도 PuTTY 창의 `--freeze-watch`를 추가했다.
기본 비활성, 추가 배포 파일/패키지 없음. 마지막 명령과 sampler/통계 fsync/
learning/차트 단계 및 독립 프로세스 상태를 Windows PuTTY 로그에 남긴다.
사용법·기존 버전 비교·증거의 한계는 [PM9M1_HP_FREEZE_V102.md](PM9M1_HP_FREEZE_V102.md) 참조.

### PCSR 프레임 앞 NUL 처리 (2026-09-15)

사용자 원문 `read_all_pcs r1\r\n\x00PCFUZZ_PCSR:r1:0x1adb9 0x17a5 0x89cd:END`
으로 프레임 0개 실패를 재현했다. `strip()`이 NUL을 제거하지 않는 것이 원인이다.
응답 줄 경계의 공백/CR/LF/NUL만 제거하도록 수정했다. PC 값 내부의 NUL,
텍스트 접두사, 이전 요청 번호, 4개 PC 값은 계속 거부한다. 기존 Thumb 마스킹
결과는 `(0x1adb8, 0x17a4, 0x89cc)`다. 원문 및 분할 CR/NUL 수신 테스트는
수정 전 실패·수정 후 통과했다. 원래의 추가 `0x6xxxxxxx` 값 출처는 이 로그로
확정하지 않는다. 실기 미검증. v10.2 본체 파일만 교체하면 된다.
