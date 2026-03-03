# PC Sampling 기반 SSD 펌웨어 Coverage-Guided Fuzzer — 기술 보고서

**버전**: v4.6
**최종 수정**: 2026-03-03
**파일**: `pc_sampling_fuzzer_v4.6.py`

---

## 목차

1. [프로젝트 개요](#1-프로젝트-개요)
2. [버전 이력](#2-버전-이력)
3. [시스템 아키텍처](#3-시스템-아키텍처)
4. [모듈별 상세 분석](#4-모듈별-상세-분석)
   - 4.1 [J-Link PC 샘플러 (JLinkPCSampler)](#41-j-link-pc-샘플러)
   - 4.2 [NVMe 명령어 체계](#42-nvme-명령어-체계)
   - 4.3 [시드 관리 및 초기 시드 생성](#43-시드-관리-및-초기-시드-생성)
   - 4.4 [AFL++ 기반 Mutation 엔진](#44-afl-기반-mutation-엔진)
   - 4.5 [Power Schedule (에너지 기반 시드 선택)](#45-power-schedule)
   - 4.6 [커버리지 피드백 메커니즘](#46-커버리지-피드백-메커니즘)
   - 4.7 [NVMe 명령 전송 (subprocess)](#47-nvme-명령-전송)
   - 4.8 [시각화 및 출력](#48-시각화-및-출력)
5. [AFL++ 대비 비교 분석](#5-afl-대비-비교-분석)
6. [성능 분석](#6-성능-분석)
7. [v4.3 버그 수정 및 개선사항](#7-v43-버그-수정-및-개선사항)
8. [v4.4 개선사항](#8-v44-개선사항)
9. [v4.5 개선사항](#9-v45-개선사항)
10. [v4.6 개선사항 및 정리](#10-v46-개선사항)
11. [알려진 제한사항 및 향후 과제](#11-알려진-제한사항-및-향후-과제)
12. [관련 연구 및 도입 가능 기술](#12-관련-연구-및-도입-가능-기술)
13. [실행 방법 및 CLI 옵션](#13-실행-방법-및-cli-옵션)
14. [출력 디렉토리 구조](#14-출력-디렉토리-구조)

---

## 1. 프로젝트 개요

### 1.1 목적

SSD 펌웨어의 NVMe 명령 처리 코드에 대해 **coverage-guided fuzzing**을 수행하여, 잠재적인 버그/취약점/비정상 동작을 발견한다.

### 1.2 핵심 차별점

일반적인 소프트웨어 퍼저(AFL++, libFuzzer 등)는 타겟 바이너리를 instrumentation하여 커버리지를 수집하지만, SSD 펌웨어는 독립 하드웨어에서 실행되므로 이 방식을 적용할 수 없다. 본 퍼저는 이를 해결하기 위해:

| 구성요소 | 일반 퍼저 (AFL++) | 본 퍼저 (PC Sampling) |
|---|---|---|
| 커버리지 수집 | 컴파일 시 instrumentation | J-Link JTAG Halt-Sample-Resume |
| 입력 전달 | stdin / 파일 / 공유 메모리 | NVMe passthru (nvme-cli subprocess) |
| 타겟 환경 | 동일 호스트 프로세스 | 별도 하드웨어 (SSD 컨트롤러) |
| Primary signal | `(prev_loc >> 1) XOR cur_loc` → bitmap | Unique PC 주소 → set (결정론적) |
| Edge 추적 | CFG branch (결정론적) | `(prev_pc, cur_pc)` 튜플 (진단용, 타이밍 의존) |

### 1.3 하드웨어 구성

```
┌──────────────┐     JTAG/SWD      ┌──────────────────┐
│  Host PC     │◄──────────────────►│  J-Link V9       │
│  (Python)    │                    │  Debug Probe     │
│              │     NVMe/PCIe      │                  │
│  nvme-cli    │◄──────────────────►│  SSD Controller  │
│              │                    │  (Cortex-R8)     │
└──────────────┘                    └──────────────────┘
```

- **Host PC**: 퍼저 실행, J-Link 연결, NVMe 명령 전송
- **J-Link V9**: JTAG을 통해 SSD 컨트롤러의 PC(Program Counter) 읽기
- **SSD Controller**: Cortex-R8 기반, 펌웨어 주소 공간 `0x00000000` ~ `0x00147FFF`

---

## 2. 버전 이력

### v4.0 — Edge 커버리지 + Power Schedule 도입

| 항목 | 내용 |
|---|---|
| **Edge 커버리지** | 기존 단일 PC 수집에서 `(prev_pc, cur_pc)` 튜플 기반 edge 커버리지로 전환. 단순히 "어떤 주소를 방문했는가"가 아닌 "어떤 경로로 이동했는가"를 추적 |
| **Seed dataclass** | 퍼징 입력을 `Seed` 데이터클래스로 구조화. `data`, `cmd`, `exec_count`, `energy`, `found_at`, `new_edges` 등의 메타데이터 포함 |
| **Power Schedule** | AFLfast "explore" 방식의 에너지 기반 시드 선택. 적게 실행된 시드에 높은 에너지를 부여하여 탐색 다양성 확보 |

### v4.1 — NVMe 스펙 시드 + AFL++ Mutation + CDW 지원

| 항목 | 내용 |
|---|---|
| **CDW2~CDW15 필드** | Seed에 NVMe Command Dword 필드를 추가하여 명령어의 세부 파라미터까지 mutation 대상에 포함 |
| **NVMe 스펙 기반 초기 시드** | 각 Opcode별로 NVMe 스펙에 따른 정상 명령어를 초기 시드로 자동 생성. Identify(CNS 0~3), GetLogPage(LID 1~6), GetFeatures(FID 1~11), Read/Write(다양한 LBA/NLB) 등 |
| **AFL++ havoc/splice** | 16종의 havoc mutation + splice + CDW mutation 구현. `INTERESTING_8/16/32`, `ARITH_MAX=35` 등 AFL++ 상수 그대로 사용 |
| **명령어별 추적** | `cmd_edges`, `cmd_pcs`, `cmd_traces` 딕셔너리로 명령어별 edge/PC/trace를 독립 추적. CFG 그래프 생성 기능 추가 |

### v4.2 — Subprocess 연동 + 글로벌 포화 + Idle PC 감지

| 항목 | 내용 |
|---|---|
| **subprocess + 샘플링 연동** | nvme-cli를 subprocess로 실행하면서 동시에 J-Link 샘플링. 명령 전송 전에 샘플링을 시작하고("덫 놓기"), 명령 완료 후 중단 |
| **글로벌 기준 포화 판정** | 이전까지는 현재 실행 내에서의 새로움만 판단했으나, v4.2에서 글로벌 edge set 대비 새 edge 여부로 포화를 판정. 이미 알려진 경로를 반복 샘플링하는 낭비 방지 |
| **idle PC 감지** | `diagnose()` 단계에서 가장 빈도 높은 PC를 idle PC로 지정. 샘플링 중 연속 N회 idle PC에 머물면 조기 중단 |
| **확장 mutation** | opcode mutation(10%), nsid mutation(10%), Admin↔IO 교차(5%), data_len 불일치(8%), GetLogPage NUMDL 과대 요청(15%) |

### v4.3 — 버그 수정 + 설정 분리 + 성능 개선 + 안정성 강화

| 항목 | 분류 | 내용 |
|---|---|---|
| **로그 메시지 불일치** | BugFix | `"ioctl direct (no subprocess)"` → `"subprocess (nvme-cli passthru)"`. 실제 구현은 subprocess 방식인데 로그만 ioctl이라고 표시되던 문제 |
| **글로벌 포화 임계값** | BugFix | 하드코딩된 `20`을 `global_saturation_limit` 설정값으로 분리. `--global-saturation-limit` CLI 옵션 추가 |
| **prev_pc 캐리오버 제거** | BugFix | 이전 v4.2에서는 `self.prev_pc`를 실행 간 유지하여 서로 다른 NVMe 명령어 간의 가짜 edge가 생성될 수 있었음. v4.3에서 매 실행마다 sentinel(0xFFFFFFFF)으로 리셋 |
| **post_cmd_delay_ms 구현** | BugFix | 설정에만 존재하고 실제로는 사용되지 않던 `post_cmd_delay_ms`를 `_send_nvme_command()` 내에서 명령 완료 후 sleep으로 구현 |
| **EXCLUDED_OPCODES CLI 버그** | BugFix | CLI 파싱에서 `excluded_opcodes = []`로 초기화하여 스크립트 상단 `EXCLUDED_OPCODES` 상수가 무시되던 버그 수정. 이제 상수를 기본값으로 가져오고 CLI 추가분을 병합 |
| **cmd_traces deque 교체** | Perf | `list.pop(0)` (O(n)) → `collections.deque(maxlen=200)` (O(1)) |
| **interval 체크포인트 frozenset** | Perf | `sample_count in (10, 25, 50, 100, 200, 500)` 튜플 → 클래스 변수 `_INTERVAL_CHECKPOINTS = frozenset(...)` |
| **랜덤 생성 비율 설정 분리** | Clarity | 하드코딩된 `0.8` (80% corpus, 20% random) → `random_gen_ratio` 설정값 + `--random-gen-ratio` CLI 옵션 |
| **Mutation 통계 추적** | Feature | Summary에서 실제 전송된 opcode 분포, mutation 종류별 횟수/비율, passthru 타입(admin/io) 분포, 입력 소스(corpus vs random) 비율을 출력 |
| **Timeout crash 불량 보존** | Feature | timeout 시 J-Link로 stuck PC를 20회 샘플링하여 crash 메타데이터에 기록. 빈도 분석으로 hang/loop/recovery 판별. **CPU를 resume 상태로 유지**하여 불량 현상 보존. reconnect/rescan/드라이버 재로드 없이 퍼징 중단 |
| **D state 블로킹 방지** | BugFix | subprocess kill 후 `communicate()`에 5초 타임아웃 추가. 커널 NVMe 에러 복구(command abort → controller reset → PCIe FLR) 중 nvme-cli가 D state에 빠져 무한 블로킹되는 문제 해결 |
| **제외 Opcode 설정** | Feature | `EXCLUDED_OPCODES` 상수 + `--exclude-opcodes "0xC1,0xC0"` CLI 옵션. 디바이스 탈락을 유발하는 opcode를 mutation 대상에서 제외 |
| **확장 Mutation 확률 설정** | Feature | 하드코딩된 확장 mutation 확률을 설정값으로 분리. `--opcode-mut-prob 0`으로 opcode mutation 비활성화 가능 |
| **AFL++ Corpus Culling** | Feature | 1000회마다 실행. 각 edge에 대해 data가 가장 작은 seed를 favored로 마킹하고, favored 아니면서 충분히 실행된(5회+) seed를 제거. Seed에 `covered_edges` set과 `is_favored` 플래그 추가 |
| **NVMe 디바이스 사전 검증** | Feature | 퍼징 시작 전 `/dev/nvme0` 존재 여부 + 읽기/쓰기 권한 확인. 없으면 즉시 에러 출력 후 종료 (J-Link 연결 전에 실패) |
| **J-Link Heartbeat** | Feature | 1000회마다 `_read_pc()` 시도. 실패 시 JTAG 연결 끊김으로 판단하고 퍼징 중단 |
| **실제 Opcode 기준 추적** | Feature | opcode_override 사용 시 `Identify_Controller_op0xD1`처럼 실제 전송 opcode로 분류. 히트맵/bar chart/per-command stats/rc_stats 모두 적용. 기존에는 base 명령어에 mutation된 opcode의 커버리지가 오염되어 누적됨 |
| **SMART Health 로그** | Feature | `nvme smart-log` 결과를 INFO 레벨로 기록. 퍼징 시작 전(baseline) + 10,000회마다(모니터링) + 퍼징 종료 후(최종 상태) |
| **Corpus/Graphs 초기화** | Feature | 매 실행 시작 시 이전 실행의 `corpus/`, `graphs/` 폴더를 삭제 후 재생성. 이전 데이터와 혼합 방지 |
| **`--seed-dir` CLI 옵션 추가** | BugFix | 백엔드 로직(`_load_seeds()`)은 있었으나 CLI parser에 옵션이 없어 사용 불가였음. `--seed-dir` 옵션 추가로 이전 corpus를 시드로 재활용 가능 |
| **Dead code 제거** | Cleanup | v4.3에서 timeout 시 복구하지 않는 정책으로 변경됨에 따라, 더 이상 호출되지 않는 `_resume()`, `reconnect()` 메서드 삭제 |

### v4.4 — Tracking Label 개선 + dmesg 캡처 + Heatmap 크기 제한

| 항목 | 분류 | 내용 |
|---|---|---|
| **Tracking Label NVMe 스펙 매핑** | Feature | opcode_override 시 NVMe 스펙에 일치하는 명령어가 있으면 해당 이름 사용 (예: opcode 0x0A → `GetFeatures`), 없으면 `unknown_op0x{XX}` 형태. 기존의 `{원래명령어}_op0x{XX}` 방식은 opcode가 변형된 시점에서 원래 명령어와 관계없으므로 제거 |
| **Return code distribution 개선** | Feature | Tracking Label 변경이 자동 반영되어, Per-command stats와 Return code distribution에서도 NVMe 스펙 기준 명령어명 또는 `unknown_op0x{XX}`로 표시 |
| **Heatmap 명령어 수 제한** | BugFix | opcode mutation으로 고유 추적 키가 수백 개 이상 생성되면 heatmap 이미지가 `81045px` 등 초대형이 되어 `Image size too large` 에러 발생. 상위 40개(edge 수 기준)만 표시하도록 제한 |
| **Heatmap DPI 동적 조정** | BugFix | matplotlib 최대 픽셀 제한(65536) 초과 방지. figure 크기에 따라 DPI를 동적으로 낮춤 (최소 50 DPI) |
| **Timeout dmesg 캡처** | Feature | timeout 발생 시 `dmesg` 마지막 80줄을 캡처하여 crash 메타데이터(JSON)와 별도 텍스트 파일(`.dmesg.txt`)로 저장. 커널 NVMe 드라이버의 동작(command abort, controller reset, PCIe FLR 등)을 사후 분석 가능. 로그에는 NVMe 관련 라인만 요약 출력 |
| **Opcode 역방향 매핑 테이블** | Internal | `_OPCODE_TO_NAME: dict[tuple[int, str], str]` — `(opcode, "admin"\|"io")` → 명령어 이름. Admin/IO 동일 opcode(예: 0x02 = GetLogPage/Read)를 구분 |

### v4.5 — Hit Count Bucketing + Calibration + Deterministic Stage + MOpt

| 항목 | 분류 | 내용 |
|---|---|---|
| **Hit count bucketing** | Feature | edge별 누적 실행 횟수를 AFL++ 스타일 로그 버킷(1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+)으로 변환. 진단용으로 추적되며 corpus 판단에는 미사용 |
| **Calibration** | Feature | 초기 시드를 N회(기본 3) 반복 실행하여 PC 주소 안정성 측정. 과반수(>50%) 이상 run에서 등장한 PC를 `stable_pcs`로 분류. global_coverage에 관측된 전체 PC 합집합 반영. edge 통계는 진단용으로 별도 추적 |
| **Calibration DLL stderr 억제** | BugFix | calibration의 tight halt/read/go 루프에서 J-Link DLL이 `"Cannot read register (R15) while CPU is running"` 경고를 stderr에 직접 출력하는 문제. `os.dup2(devnull, 2)` / `os.dup2(saved, 2)` 로 fd 수준에서 억제, `finally`에서 반드시 복원 |
| **Calibration 결과 요약 테이블** | Feature | calibration 완료 후 시드별 Stability / StablePCs / AllPCs를 표 형식으로 출력하고, Seeds 수 · Global PCs · Avg stability 요약 표시 |
| **Calibration 이중 start_sampling 버그** | BugFix | `_calibrate_seed()`가 명시적 `start_sampling()`을 호출하지만 `_send_nvme_command()` 내부에서도 호출하여 run당 두 개의 sampling thread가 동시 실행되던 문제. 수정: `_calibrate_seed()` 내부의 명시적 `start_sampling()` 호출 제거 |
| **Deterministic stage** | Feature | 새 시드의 CDW10~CDW15 필드에 대해 체계적 mutation(walking bitflip 32개, arithmetic ±1~10, interesting_32/8 대입) 수행. 제너레이터 기반 + deque로 havoc보다 우선 소비 |
| **MOpt mutation scheduling** | Feature | Pilot/Core 2단계 모드. Pilot(기본 5000회): 16개 mutation operator 균등 사용하며 성공률 측정. Core(기본 50000회): 성공률 기반 가중치로 효과적인 operator에 집중 |
| **Edge count 저장/로드** | Feature | `coverage_edge_counts.txt` 파일로 edge별 누적 hit count 저장/로드 |
| **Summary 통계 확장** | Feature | MOpt 모드, operator별 finds/uses/성공률 출력 |
| **CLI 옵션 추가** | Feature | `--calibration-runs`, `--no-deterministic`, `--det-arith-max`, `--no-mopt`, `--mopt-pilot-period`, `--mopt-core-period` |

### v4.5 이후 수정 — PC 기반 coverage signal 전환 + 버그 수정

| 항목 | 분류 | 내용 |
|---|---|---|
| **Primary signal 전환** | Redesign | `is_interesting` 기준을 `(prev_pc, cur_pc)` edge에서 **unique PC 주소**로 변경. edge는 타이밍에 따라 달라지는 비결정적 쌍이지만 PC 주소는 코드 실행 시 항상 생성되어 결정론적. corpus 크기가 펌웨어 코드 크기에 자연스럽게 수렴 |
| **Seed 필드 변경** | Redesign | `new_edges→new_pcs`, `covered_edges→covered_pcs`, `stable_edges→stable_pcs` |
| **corpus culling PC 기반 전환** | Redesign | `edge→best_seed` 매핑 → `pc→best_seed` 매핑. 각 PC 주소에 대해 data가 가장 작은 seed를 favored로 선정 |
| **Calibration PC 기반 전환** | Redesign | edge 안정성 측정 → PC 주소 안정성 측정. `stable_pcs`, `covered_pcs` 저장, global_coverage에 합집합 반영 |
| **Edge Confirmation** | Feature | 진단용 edge 추적에 confirmation 도입. `EDGE_CONFIRM_THRESHOLD`(기본 2)회 이상 관측된 edge만 `global_edges`로 승격. corpus 판단에는 미사용 |
| **bucket_changes 오탐 수정** | BugFix | 미확정(pending) edge의 hit count 변화가 `is_interesting`을 오탐시키던 문제 수정 |
| **covered_pcs 노이즈 수정** | BugFix | corpus 추가 시 `current_edges`(noise edge 포함)를 저장하여 culling의 favored 판정을 오염시키던 문제. `covered_pcs = current_trace`(결정론적 PC 집합)로 교체 |
| **corpus culling exec_count 임계값** | BugFix | unfavored seed 제거 조건 `exec_count >= 5` → `exec_count >= 2`로 강화 |
| **corpus 하드 상한** | Feature | `max_corpus_hard_limit` 설정값(기본 0=비활성). 양수로 설정 시 culling 후에도 초과하면 exec_count 높은 비선호 seed부터 강제 제거 |
| **포화 체크 PC 기반 전환** | BugFix | `_sampling_worker`의 글로벌 포화 판단 신호를 `global_edges_ref`(edge) → `global_coverage_ref`(PC 주소)로 변경. 기존 문제: calibration이 `global_edges`를 모든 초기 시드 edge로 채워두므로 이후 퍼징 실행에서 거의 모든 edge가 "이미 알려진 것"으로 판정 → 연속 20샘플 후 즉시 종료(`last_run=2-3`) |
| **`stop_sampling()` 반환값 수정** | BugFix | `len(current_edges)` → `len(current_trace)` 반환. primary signal이 PC 주소로 전환된 이후에도 `last_run` 로그가 edge 수를 표시하여 오해를 유발 |
| **로그 `pcs_this_run` 추가** | Feature | per-exec 로그에 `pcs_this_run`(이번 실행 unique PC 수) 추가, `edges=`를 `edges_diag=current/global`로 변경하여 진단용임을 명시 |

### v4.6 — io-passthru 장치 수정 + Passthru Timeout 분리 + Crash 시 SSD 상태 장기 보존 + Edge 추적 코드 제거

| 항목 | 분류 | 내용 |
|---|---|---|
| **io-passthru → namespace block device** | BugFix | io-passthru 명령을 `/dev/nvme0`(char device) 대신 `/dev/nvme0n1`(namespace block device)로 전송. `/dev/nvme0`로 `io-passthru`를 전송하면 커널이 `NVME_IOCTL_IO_CMD` deprecated 경고를 dmesg에 출력. admin-passthru는 `/dev/nvme0` 유지 |
| **Passthru timeout 분리** | Feature | 기존에는 subprocess 감지 timeout(nvme_timeouts)이 nvme-cli `--timeout` 인자로 그대로 전달되어, timeout 발생 시 커널이 NVMe 명령을 포기하고 controller reset → PCIe FLR을 수행. v4.6에서 두 timeout을 분리: (1) `nvme_timeouts` — subprocess `communicate(timeout=...)` 감지 창 (퍼저 crash 인식), (2) `NVME_PASSTHRU_TIMEOUT_MS=2_592_000_000`(30일) — nvme-cli `--timeout` (커널 reset 방지). crash 발생 시 SSD 펌웨어 상태를 그대로 보존하여 JTAG 분석 가능 |
| **Crash 시 nvme-cli 프로세스 보존** | Feature | crash 감지 후 `process.kill()`을 호출하지 않음. nvme-cli fd가 열린 채로 유지되므로 커널이 NVMe 명령을 포기하지 않아 controller reset이 발생하지 않음. `start_new_session=True`(setsid)로 퍼저 종료 후에도 nvme-cli가 init에 입양되어 생존. crash nvme-cli PID를 로그 및 `crashes/crash_nvme_pid.txt`에 기록 |
| **`nvme_passthru_timeout_ms` FuzzConfig 필드** | Feature | `FuzzConfig.nvme_passthru_timeout_ms` 필드 추가. CLI `--passthru-timeout`으로 오버라이드 가능 |
| **시작 로그 업데이트** | Feature | 시작 시 두 timeout을 명확히 구분하여 출력: `"Timeouts    : subprocess=..."`, `"Passthru TO : ...ms (...일, crash 시 SSD 상태 장기 보존)"` |
| **Edge 추적 코드 제거** | Perf | `current_edges`, `global_edges`, `global_edge_pending`, `global_edge_counts`, `global_edge_buckets`, `current_edge_counts`, `_last_bucket_changes`, `EDGE_CONFIRM_THRESHOLD`, `cmd_edges` 및 관련 루프 전부 제거. 샘플링 루프 내 hot path에서 매 샘플마다 실행되던 edge tuple 생성·set 추가·dict 갱신 연산 제거. `evaluate_coverage()`의 edge confirmation O(n) 루프 및 hit count bucketing O(m) 루프 제거. CFG 그래프 시각화는 `cmd_traces`(ordered PC sequence)에서 인접 쌍으로 edge를 직접 도출. 전체 183줄 감소(3291→3108) |

---

## 3. 시스템 아키텍처

### 3.1 전체 흐름도

```
                         ┌─────────────────────────────┐
                         │       메인 퍼징 루프         │
                         │  (NVMeFuzzer.run)            │
                         └─────────┬───────────────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
             ┌────────────┐ ┌──────────┐  ┌────────────┐
             │  시드 선택  │ │ Mutation │  │ 커버리지   │
             │ (에너지    │ │ (AFL++   │  │ 평가       │
             │  기반)     │ │  havoc)  │  │ (PC set)   │
             └─────┬──────┘ └────┬─────┘  └─────┬──────┘
                   │             │              │
                   └──────┬──────┘              │
                          ▼                     │
                   ┌────────────┐               │
                   │ NVMe 전송  │               │
                   │ (subprocess│               │
                   │  nvme-cli) │               │
                   └──────┬─────┘               │
                          │  동시 실행           │
                          ▼                     │
                   ┌────────────┐               │
                   │ PC 샘플링  │───────────────┘
                   │ (J-Link    │  current_trace
                   │  halt/go)  │  → global_coverage
                   └────────────┘
```

### 3.2 한 번의 실행(Execution) 상세

```
 1. _select_seed()       → 에너지 기반 가중치 랜덤으로 시드 선택
 2. _mutate()            → havoc + splice + CDW + 확장 mutation 적용
 3. start_sampling()     → J-Link 샘플링 스레드 시작 (백그라운드)
 4. subprocess.Popen()   → nvme-cli passthru 명령 전송
                           (admin → /dev/nvme0, io → /dev/nvme0n{ns})
 5. communicate()        → 명령 완료 대기 (timeout=nvme_timeouts[group])
 6. post_cmd_delay       → 추가 샘플링 대기
 7. stop_sampling()      → 샘플링 스레드 종료
 8. evaluate_coverage()  → current_trace(PC 집합)와 global_coverage 비교 → new_pcs 계산
                           (edge 추적은 진단용으로 별도 수행)
 9. tracking_label()     → (v4.3) 실제 opcode 기준 추적 키 결정
10. if interesting:      → corpus에 새 시드 추가 (covered_pcs = current_trace)
11. [매 100회]           → 상태 출력 + 로그 flush
12. [매 1,000회]         → corpus culling + J-Link heartbeat
13. [매 10,000회]        → SMART health 로그 기록
```

### 3.3 스레드 모델

```
Main Thread                    Sampling Thread (daemon)
    │                              │
    ├─ start_sampling() ──────────►│ _sampling_worker()
    │                              │   halt → read PC → go
    ├─ Popen(nvme-cli)             │   halt → read PC → go
    │                              │   halt → read PC → go
    ├─ communicate() (blocking)    │   ...
    │                              │   (포화 감지 시 자동 종료)
    ├─ post_cmd_delay              │
    │                              │
    ├─ stop_sampling() ───────────►│ stop_event.set()
    │   join(timeout=2.0)          │ return
    │                              │
    ├─ evaluate_coverage()
    │
```

- **Thread Safety**: 샘플링 스레드에서 `global_coverage_ref = self.global_coverage`로 참조를 캐싱하여 attribute lookup 제거. CPython GIL 하에서 `set.__contains__`는 원자적이므로 실질적 동시성 문제 없음.

---

## 4. 모듈별 상세 분석

### 4.1 J-Link PC 샘플러

**클래스**: `JLinkPCSampler`

#### 4.1.1 연결 및 초기화

```python
connect() → JLink.open() → set_tif(JTAG) → connect(Cortex-R8, 12000kHz)
```

- `_find_pc_register_index()`: Cortex-R8에서 R15(PC)의 레지스터 인덱스가 반드시 15가 아닐 수 있으므로, `register_list()`를 탐색하여 동적으로 결정
- DLL 함수 참조 캐싱: `self.jlink._dll.JLINKARM_Halt`, `JLINKARM_ReadReg`, `JLINKARM_Go`를 인스턴스 변수로 캐싱하여 매 호출 시 attribute lookup 제거

#### 4.1.2 PC 읽기 (Halt-Sample-Resume)

```python
_read_pc():
    halt()          # CPU 정지
    pc = read_reg() # PC 레지스터 읽기
    go()            # CPU 재개 (finally 블록)
    return pc
```

- 1회 샘플에 halt + read + go 3번의 J-Link DLL 호출
- 실패 시 `None` 반환, `go()`는 항상 `finally`에서 실행하여 CPU 정지 상태 방지

#### 4.1.3 진단 (diagnose)

- 시작 전 PC를 20회 읽어서 J-Link 연결 상태 확인
- 30% 이상 동일 PC가 나오면 해당 PC를 **idle PC**로 지정
- idle PC: SSD 펌웨어의 idle loop 주소. 이 주소에서만 반복적으로 샘플링되면 의미 있는 코드 실행이 아닌 것으로 판단

#### 4.1.4 포화(Saturation) 판정 (v4.3 개선)

두 가지 독립 조건 (OR):

| 조건 | 임계값 | 설명 |
|---|---|---|
| **글로벌 포화** | `global_saturation_limit` (기본 20) | 연속 N회 새로운 global PC가 없음 |
| **idle 포화** | `saturation_limit` (기본 10) | 연속 N회 idle PC에 머물러 있음 |

v4.5 이후 수정에서 포화 신호를 `global_edges_ref`(edge) → `global_coverage_ref`(PC 주소)로 변경하여 primary coverage signal과 일치시킴.

#### 4.1.5 prev_pc 리셋 정책 (v4.3 변경)

| 버전 | 동작 | 문제 |
|---|---|---|
| v4.2 | `self.prev_pc`를 실행 간 유지 | 실행 A의 마지막 PC → 실행 B의 첫 PC가 가짜 edge로 기록됨 |
| v4.3 | 매 `_sampling_worker()` 시작 시 `prev_pc = 0xFFFFFFFF` (sentinel) | 실행 간 독립. AFL++와 동일하게 각 실행이 독립적 edge set 생성 |

---

### 4.2 NVMe 명령어 체계

#### 4.2.1 명령어 분류

**기본 명령어 (비파괴, 안전)**:

| 이름 | Opcode | 타입 | 설명 |
|---|---|---|---|
| Identify | 0x06 | Admin | 장치/NS 정보 조회 |
| GetLogPage | 0x02 | Admin | 로그 페이지 조회 |
| GetFeatures | 0x0A | Admin | 기능 조회 |
| Read | 0x02 | I/O | 데이터 읽기 |
| Write | 0x01 | I/O | 데이터 쓰기 |

**확장 명령어 (파괴적, 옵트인)**:

| 이름 | Opcode | 타입 | 타임아웃 그룹 | 설명 |
|---|---|---|---|---|
| SetFeatures | 0x09 | Admin | command | 기능 설정 |
| FWDownload | 0x11 | Admin | command | 펌웨어 이미지 다운로드 |
| FWCommit | 0x10 | Admin | fw_commit (120s) | 펌웨어 슬롯 활성화 |
| FormatNVM | 0x80 | Admin | format (600s) | NVM 포맷 |
| Sanitize | 0x84 | Admin | sanitize (600s) | 보안 삭제 |
| TelemetryHostInitiated | 0x02 | Admin | telemetry (30s) | 텔레메트리 로그 |
| Flush | 0x00 | I/O | flush (30s) | 캐시 플러시 |
| DatasetManagement | 0x09 | I/O | dsm (30s) | TRIM/Deallocate |

#### 4.2.2 타임아웃 체계 (v4.6 변경)

v4.6부터 **두 가지 독립적인 timeout**을 사용한다:

**① subprocess 감지 timeout (`nvme_timeouts`)** — 퍼저의 crash 인식 창:

```
command:    8,000ms   (일반)
flush:      30,000ms
dsm:        30,000ms
telemetry:  30,000ms
fw_commit:  120,000ms
format:     600,000ms
sanitize:   600,000ms
```

`communicate(timeout=...)` 인자로 사용. 이 시간을 초과하면 퍼저가 crash로 판단하고 처리한다.

**② nvme-cli passthru timeout (`NVME_PASSTHRU_TIMEOUT_MS`)** — 커널 reset 방지:

```
기본값: 2,592,000,000ms (30일, u32 최대 ~49.7일)
```

nvme-cli `--timeout` 인자로 사용. 커널이 NVMe 명령을 포기하는 시점을 결정한다. 이 값을 충분히 크게 설정하면, 퍼저의 subprocess timeout이 먼저 발동하므로 커널이 controller reset → PCIe FLR을 수행하지 않아 SSD 펌웨어 상태가 보존된다.

**동작 흐름 (crash 시)**:

```
t=0ms   : NVMe 명령 전송 (nvme-cli PID=1234, --timeout=2592000000)
          start_new_session=True → 새 세션(setsid), 부모 종료 후에도 생존
t=8s    : subprocess communicate(timeout=8) 만료 → 퍼저가 crash 인식
t=8s    : process.kill() 없음 → fd 유지
          stdout/stderr 파이프 부모 쪽만 닫음
          _crash_nvme_pid = 1234 저장
t=8s~   : J-Link로 stuck PC 20회 샘플링 → crash 저장 → 퍼징 중단
t=10s   : 퍼저(Python) 종료
          → nvme-cli PID=1234는 init에 입양(orphan), D-state로 생존
          → fd(/dev/nvme0n1) 유지 → 커널 reset 없음
이후 30일: SSD 펌웨어 상태 그대로 보존
분석 완료: kill 1234  (또는 cat crashes/crash_nvme_pid.txt | xargs kill)
```

**동작 흐름 (정상 실행 시)**:

```
t=0ms  : NVMe 명령 전송
t=~5ms : SSD가 응답 → nvme-cli 정상 종료
         subprocess timeout 발동 없음 → 성능 영향 없음
```

---

### 4.3 시드 관리 및 초기 시드 생성

#### 4.3.1 Seed 데이터 구조

```python
@dataclass
class Seed:
    data: bytes              # NVMe 데이터 페이로드
    cmd: NVMeCommand         # 연결된 NVMe 명령어
    cdw2~cdw15: int          # NVMe CDW 필드 (8개)
    opcode_override: int     # opcode mutation
    nsid_override: int       # namespace ID mutation
    force_admin: bool        # Admin↔IO 교차
    data_len_override: int   # data_len 불일치
    exec_count: int          # 선택 횟수
    found_at: int            # 발견 시점
    new_pcs: int             # 발견한 새 unique PC 주소 수 (primary coverage signal)
    energy: float            # 계산된 에너지
    covered_pcs: set         # 이 시드 실행 시 방문된 PC 주소 집합 (culling용)
    is_favored: bool         # corpus culling에서 선정된 favored seed
    is_calibrated: bool      # calibration 완료 여부
    stability: float         # 0.0~1.0, PC 주소 안정성 비율
    stable_pcs: set          # calibration에서 과반수 실행에 등장한 PC 주소
```

#### 4.3.2 초기 시드 생성 (`_generate_default_seeds`)

NVMe 스펙에 따른 **정상 명령어 파라미터**를 초기 시드로 생성:

| 명령어 | 시드 수 | 예시 |
|---|---|---|
| **Read** | **15** | NLB 1/8/32/128/256/max(0xFFFF), LBA 0~10000, FUA, 64비트 LBA 경계 2개 |
| **Write** | **16** | NLB 1/8/32/128/256 (data 일치), LBA 0~10000, FUA, 64비트 LBA 경계 2개, 패턴 0x00/0xAA/0xFF/순차 |
| Identify | 4 | CNS=0x00(NS), 0x01(Controller), 0x02(Active NS), 0x03(NS Descriptor) |
| GetLogPage | 2 | Error Info(LID=1), SMART(LID=2) |
| GetFeatures | 3 | FID=0x06(Write Cache), 0x07(Queues), 0x0B(Async Events) |
| SetFeatures | 1 | Number of Queues |
| FWDownload | 1 | offset=0, 1KB |
| FWCommit | 2 | CA=1 Slot 0/1 |
| FormatNVM | 1 | LBAF 0 |
| Sanitize | 1 | Block Erase |
| Telemetry | 1 | Host-Initiated |
| Flush | 1 | (파라미터 없음) |
| DSM | 1 | TRIM LBA 0, 8 blocks |

**Read/Write 시드 설계 원칙**:
- NLB는 스펙 최대값(CDW12[15:0]=0xFFFF, 65536 blocks=32MB)까지 사용. Read는 `data_len=(NLB+1)×512`로 자동 계산, Write는 NLB×512B와 data를 일치시킴 (스펙 준수).
- 64비트 SLBA(CDW10=SLBA[31:0], CDW11=SLBA[63:32])를 활용한 LBA 경계 시드 포함. 실 디바이스 용량을 넘는 LBA는 Out-of-Range 에러 처리 코드 경로를 탐색.
- `MAX_INPUT_LEN` 4096 → 131072(128KB)로 증가하여 Write 대용량 시드가 mutation 이후에도 유효한 크기를 유지.

---

### 4.4 AFL++ 기반 Mutation 엔진

#### 4.4.1 Havoc Mutation (`_mutate_bytes`)

16종의 바이트 레벨 mutation을 `2^(1~7)` 회 스택 적용:

| # | Mutation | 설명 | AFL++ 대응 |
|---|---|---|---|
| 0 | bitflip 1/1 | 랜덤 위치 1비트 반전 | `FLIP_BIT` |
| 1 | interesting 8-bit | 경계값 삽입 (-128, -1, 0, 1, 127 등) | `interesting_8` |
| 2 | interesting 16-bit | LE/BE 경계값 삽입 | `interesting_16` |
| 3 | interesting 32-bit | LE/BE 경계값 삽입 | `interesting_32` |
| 4 | arith 8-bit | ±1~35 가감 | `ARITH_8` |
| 5 | arith 16-bit | LE/BE ±1~35 가감 | `ARITH_16` |
| 6 | arith 32-bit | LE/BE ±1~35 가감 | `ARITH_32` |
| 7 | random byte | 랜덤 바이트 설정 | `RANDOM_BYTE` |
| 8 | byte swap | 2바이트 위치 교환 | (AFL++ 유사) |
| 9 | delete bytes | 1~len/4 바이트 삭제 | `DELETE_BYTES` |
| 10 | insert bytes | clone 또는 random 삽입 | `INSERT_BYTES` |
| 11 | overwrite bytes | clone 또는 random 덮어쓰기 | `OVERWRITE_BYTES` |
| 12 | crossover/splice | 다른 corpus 엔트리와 교차 | `SPLICE` |
| 13 | shuffle | 랜덤 범위 셔플 | (독자) |
| 14 | block set | 고정값 블록 설정 | (독자) |
| 15 | ASCII integer | 숫자 문자열 삽입 | `MOpt` |

#### 4.4.2 CDW Mutation (`_mutate_cdw`)

32비트 CDW 필드 전용 6종 mutation:

| # | Mutation | 설명 |
|---|---|---|
| 0 | bitflip 1~4 bits | 1~4개 비트 반전 |
| 1 | arith add/sub | ±1~35 가감 |
| 2 | interesting 32-bit | 경계값 설정 |
| 3 | random 32-bit | 완전 랜덤 |
| 4 | byte-level | 32비트 중 1바이트만 랜덤 |
| 5 | endian swap | 16-bit 또는 32-bit 엔디안 교환 |

30% 확률로 1~3개 CDW 필드에 적용.

#### 4.4.3 확장 Mutation (NVMe 특화)

| Mutation | 기본 확률 | CLI 옵션 | 목적 |
|---|---|---|---|
| opcode override | 10% | `--opcode-mut-prob` | vendor-specific(0xC0~0xFF), 완전 랜덤, bitflip, 다른 명령어 opcode. `EXCLUDED_OPCODES`에 지정된 opcode는 자동 제외 |
| nsid override | 10% | `--nsid-mut-prob` | nsid=0, 0xFFFFFFFF(broadcast), 존재하지 않는 NS |
| Admin↔IO 교차 | 5% | `--admin-swap-prob` | 잘못된 큐로 전송하여 디스패치 혼란 유도 |
| data_len 불일치 | 8% | `--datalen-mut-prob` | CDW와 data_len이 다른 값을 가지도록 하여 DMA 엔진 혼란 |
| GetLogPage NUMDL 과대 | 15% | (고정) | 스펙 초과 크기 로그 요청. GetLogPage 명령어에만 적용되므로 별도 설정 불필요 |

---

### 4.5 Power Schedule

#### 4.5.1 AFLfast "explore" 스케줄

```python
_calculate_energy(seed):
    if exec_count == 0:
        return MAX_ENERGY (16.0)    # 새 시드는 최대 에너지

    ratio = total_executions / seed.exec_count
    if ratio <= 1:
        return 1.0

    power = floor(log2(ratio))
    return min(MAX_ENERGY, 2^power)
```

**원리**: 적게 실행된 시드일수록 높은 에너지 → 높은 선택 확률. 많이 실행된 시드는 이미 충분히 탐색된 것으로 간주.

---

### 4.6 커버리지 피드백 메커니즘

#### 4.6.1 Primary Signal: Unique PC 주소

```python
evaluate_coverage():
    initial_pcs = len(global_coverage)
    global_coverage.update(current_trace)
    new_pcs = len(global_coverage) - initial_pcs
    is_interesting = (new_pcs > 0)   # 새 PC 주소 발견 시만 interesting
```

PC 주소는 **결정론적**: 코드 경로 A가 실행되면 해당 주소들이 반드시 `current_trace`에 생성된다.

#### 4.6.2 Edge (CFG 시각화용)

`(prev_pc, cur_pc)` edge는 타이밍에 따라 달라지는 **비결정적** 쌍이므로 corpus 추가 기준으로 사용하지 않는다. v4.6에서 edge 실시간 추적(hot path의 set.add + dict 갱신)을 제거했다.

CFG 그래프 생성 시에만 `cmd_traces`에서 인접 PC 쌍으로 edge를 도출한다:

```python
for trace in cmd_traces[cmd_name]:
    for i in range(len(trace) - 1):
        edge_counts[(trace[i], trace[i+1])] += 1
```

#### 4.6.3 커버리지 저장소

| 저장소 | 타입 | 역할 |
|---|---|---|
| `global_coverage` | `Set[int]` | **Primary** — 전체 세션 누적 unique PC 주소 |
| `current_trace` | `Set[int]` | **Primary** — 현재 실행의 PC 주소 |
| `cmd_pcs` | `Dict[str, Set[int]]` | 명령어별 누적 unique PC (시각화용) |
| `cmd_traces` | `Dict[str, deque]` | 명령어별 최근 200개 ordered PC sequence (CFG 그래프용) |

v4.6에서 `global_edges`, `current_edges`, `global_edge_pending`, `global_edge_counts`, `global_edge_buckets` 등 edge 추적 저장소를 모두 제거했다. CFG 그래프의 edge는 `cmd_traces`의 인접 PC 쌍 `(trace[i], trace[i+1])`에서 직접 도출한다.

---

### 4.7 NVMe 명령 전송

#### 4.7.1 전송 방식 (v4.6 변경)

```python
_send_nvme_command(data, seed):
    # v4.6: IO 명령은 namespace block device 사용 (deprecated ioctl 방지)
    if passthru_type == "io-passthru":
        target_device = f"{config.nvme_device}n{config.nvme_namespace}"  # /dev/nvme0n1
    else:
        target_device = config.nvme_device                                 # /dev/nvme0

    # subprocess 감지 timeout (퍼저 crash 인식 창)
    timeout_ms = config.nvme_timeouts.get(cmd.timeout_group, ...)
    # nvme-cli --timeout (커널 reset 방지용, v4.6: 분리)
    passthru_timeout_ms = config.nvme_passthru_timeout_ms  # 기본 2,592,000,000ms (30일)

    nvme_cmd = ['nvme', 'admin-passthru'|'io-passthru', target_device,
                '--opcode=...', ...,
                f'--timeout={passthru_timeout_ms}',  # 커널 포기 시점 (30일)
                '--data-len=...', '--input-file=...' | '-r']

    sampler.start_sampling()
    # v4.6: start_new_session=True — 부모 종료 후에도 생존 (setsid)
    process = Popen(nvme_cmd, start_new_session=True, ...)
    try:
        stdout, stderr = process.communicate(timeout=timeout_ms / 1000)  # 8초
    except subprocess.TimeoutExpired:
        # v4.6: process.kill() 없음 — fd 유지 → 커널 reset 없음
        process.stdout.close(); process.stderr.close()
        self._crash_nvme_pid = process.pid  # crash 핸들러에서 로그/파일 저장
        return RC_TIMEOUT
    if post_cmd_delay > 0:
        sleep(post_cmd_delay)
    return process.returncode
```

#### 4.7.2 io-passthru 장치 선택 근거 (v4.6)

Linux 커널 5.18+에서 `NVME_IOCTL_IO_CMD` ioctl은 deprecated 처리되었다. 이 ioctl은 character device(`/dev/nvme0`)로 I/O 명령을 보낼 때 사용되며, 커널은 dmesg에 다음 경고를 출력한다:

```
nvme0: ioctl NVME_IOCTL_IO_CMD is deprecated and will be removed. Please update nvme-cli
```

`nvme io-passthru`를 namespace block device(`/dev/nvme0n1`)로 전송하면 `NVME_IOCTL_SUBMIT_IO` 경로를 사용하므로 이 경고가 발생하지 않는다. admin-passthru는 여전히 `/dev/nvme0`(char device)를 사용한다.

#### 4.7.3 반환값 분류

| 값 | 의미 | 처리 |
|---|---|---|
| `>= 0` | nvme-cli returncode (0=성공) | 정상 처리, rc 통계 기록 |
| `RC_TIMEOUT (-1001)` | NVMe 타임아웃 | stuck PC 20회 샘플링 → crash 저장 → 펌웨어 resume 유지 → 퍼징 중단 (복구 동작 없음) |
| `RC_ERROR (-1002)` | subprocess 내부 에러 | 스킵 |

---

### 4.8 시각화 및 출력

#### 4.8.1 CFG 그래프 (DOT + PNG)

- 명령어별 `(prev_pc, cur_pc)` edge를 **Graphviz DOT** 파일로 생성
- 노드 색상: entry(green), exit(red), 일반(blue)
- Edge 굵기: 빈도에 비례
- edge > 500개면 `sfdp` 레이아웃 사용 (대규모 그래프용)

#### 4.8.2 1D Address Coverage Heatmap

- 펌웨어 주소 공간을 bin으로 나누어 각 bin의 PC 히트 수를 히트맵으로 표시
- 전체(ALL) + 명령어별 행으로 구성
- 상위 40개(edge 수 기준) 명령어만 표시 (v4.4: 크기 제한)

#### 4.8.3 2D Edge Heatmap

- prev_pc × cur_pc 인접 행렬을 2D 히트맵으로 표시
- log 스케일, inferno 컬러맵

#### 4.8.4 명령어 비교 막대 차트

- 명령어별 edge 수, PC 수, 실행 횟수를 가로 막대 차트로 비교

---

## 5. AFL++ 대비 비교 분석

### 5.1 구현된 기능

| AFL++ 기능 | 구현 상태 | 구현 방식 |
|---|---|---|
| Havoc stage | 구현 완료 | 16종 mutation, 2^(1~7) 스택 |
| Splice stage | 구현 완료 | 15% 확률, 랜덤 분할점 합성 |
| Interesting values | 구현 완료 | 8/16/32-bit, AFL++ 동일 상수 |
| Arithmetic mutation | 구현 완료 | 8/16/32-bit, LE/BE, ARITH_MAX=35 |
| Power Schedule (explore) | 부분 구현 | 에너지만 사용, perf_score 미포함 |
| Edge coverage | v4.6에서 실시간 추적 제거 | CFG 시각화 시 cmd_traces에서 on-demand 도출 |
| PC address coverage | 구현 완료 (독자적) | unique PC 주소 기반 primary signal |
| Hit count bucketing | v4.6에서 제거 | PC 샘플링 hit count는 루프 횟수가 아닌 샘플링 빈도를 반영하여 의미 약함 |
| Calibration | v4.5 구현 | 시드별 N회 반복 실행으로 PC 주소 안정성 측정 |
| Deterministic stage | v4.5 구현 | CDW 필드 대상 walking bitflip + arithmetic + interesting |
| MOpt | v4.5 구현 | Pilot/Core 2단계 mutation operator scheduling |
| Corpus management | 구현 완료 | interesting → corpus 추가 + AFL++ 방식 culling (1000회마다) |
| Crash detection | 구현 완료 | timeout → crash 저장 |
| Resume (coverage reload) | 구현 완료 | coverage.txt + coverage_edges.txt + edge_counts 로드 |

### 5.2 독자적 기능 (AFL++에 없는)

| 기능 | 설명 |
|---|---|
| NVMe CDW mutation | 32-bit CDW 필드 전용 mutation (6종) |
| opcode override | vendor-specific 범위 탐색, opcode bitflip. 제외 opcode 목록 지원 |
| nsid override | 잘못된 namespace로 에러 핸들링 코드 탐색 |
| Admin↔IO 교차 | 잘못된 큐로 전송하여 디스패치 혼란 유도 |
| data_len 불일치 | CDW와 데이터 크기 불일치로 DMA 엔진 테스트 |
| GetLogPage NUMDL 과대 | 스펙 초과 크기 로그 요청 |
| idle PC 감지 | 의미 없는 idle loop 샘플링 자동 중단 |
| 명령어별 CFG 시각화 | 각 NVMe 명령어가 실행하는 펌웨어 코드 경로 시각화 |
| 실제 opcode 기준 추적 | opcode_override 사용 시 별도 키로 커버리지 분리 (오염 방지) |
| SMART Health 모니터링 | 퍼징 전/중/후 SSD 건강 상태 기록 |
| Timeout 불량 보존 | timeout 시 복구 없이 펌웨어 resume 상태 유지 (디버깅용) |
| 커널 reset 방지 (v4.6) | nvme-cli --timeout을 1시간으로 분리하여 crash 시 SSD 상태 보존 |

---

## 6. 성능 분석

### 6.1 실행 속도 병목

```
1회 실행 = J-Link 샘플링 + subprocess(nvme-cli) + 커버리지 평가

                  ┌────────────────────────────┐
시간 분배 (추정): │ subprocess fork/exec: ~60%  │ ← 최대 병목
                  │ J-Link halt/read/go: ~30%   │
                  │ Python 로직: ~10%            │
                  └────────────────────────────┘
```

**v4.6 성능 영향**: `--passthru-timeout`(1시간)을 nvme-cli에 전달하는 것은 **정상 실행에 영향 없음**. SSD가 정상 응답하는 경우(수 ms) subprocess timeout은 발동하지 않으므로 throughput은 v4.5와 동일하다. Crash 이벤트(드물게 발생)에서만 동작이 다르다.

---

## 7. v4.3 버그 수정 및 개선사항

*v4.3 상세 내용은 [버전 이력](#v43--버그-수정--설정-분리--성능-개선--안정성-강화) 참조*

---

## 8. v4.4 개선사항

*v4.4 상세 내용은 [버전 이력](#v44--tracking-label-개선--dmesg-캡처--heatmap-크기-제한) 참조*

---

## 9. v4.5 개선사항

### 9.1 [Feature] Hit Count Bucketing

edge별 누적 실행 횟수를 AFL++ 스타일 로그 버킷(1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+)으로 변환. 진단용으로 추적되며 corpus 판단에는 미사용.

### 9.2 [Feature] Calibration (시드 안정성 측정)

초기 시드를 N회(기본 3) 반복 실행하여 PC 주소 안정성 측정. 과반수(>50%) 이상 run에서 등장한 PC를 `stable_pcs`로 분류.

```
[Calibration] Results:
────────────────────────────────────────────────────────────────
   # Command              Stability  StablePCs   AllPCs
────────────────────────────────────────────────────────────────
   1 Identify              100.0%          42          42
   2 GetLogPage             83.3%          35          42
  ...
────────────────────────────────────────────────────────────────
  Seeds: 26  |  Global PCs: 847  |  Avg stability: 94.2%
────────────────────────────────────────────────────────────────
```

### 9.3 [Feature] Deterministic Stage

새 시드의 CDW10~CDW15 필드에 대해 체계적 mutation(walking bitflip 32개, arithmetic ±1~10, interesting_32/8 대입) 수행. 제너레이터 기반 + deque로 havoc보다 우선 소비.

### 9.4 [Feature] MOpt (Mutation Operator Scheduling)

Pilot/Core 2단계 모드. Pilot(기본 5000회): 16개 mutation operator 균등 사용하며 성공률 측정. Core(기본 50000회): 성공률 기반 가중치로 효과적인 operator에 집중.

---

## 10. v4.6 개선사항

### 10.1 [BugFix] io-passthru → Namespace Block Device

**문제**: nvme-cli `io-passthru` 명령을 character device(`/dev/nvme0`)로 전송하면 Linux 커널이 `NVME_IOCTL_IO_CMD` deprecated 경고를 dmesg에 출력한다.

```
nvme0: ioctl NVME_IOCTL_IO_CMD is deprecated and will be removed. Please update nvme-cli
```

이 경고는 각 io-passthru 실행마다 발생하여 dmesg를 오염시키고, crash 분석 시 실제 에러 메시지를 가릴 수 있다.

**원인**: `/dev/nvme0`는 NVMe character device로, I/O 명령을 위한 올바른 장치가 아니다. I/O 명령은 namespace block device(`/dev/nvme0n1`)로 전송해야 한다. admin 명령(Identify, GetLogPage 등)은 namespace 개념이 없으므로 character device(`/dev/nvme0`)로 전송한다.

**수정**:

```python
# v4.6: 명령 타입에 따라 장치 선택
if passthru_type == "io-passthru":
    target_device = f"{self.config.nvme_device}n{self.config.nvme_namespace}"
    # 예: /dev/nvme0n1 (namespace block device)
else:  # admin-passthru
    target_device = self.config.nvme_device
    # 예: /dev/nvme0 (character device)
```

**영향**: dmesg 경고 제거, crash 분석 시 실제 에러 메시지 가독성 향상.

### 10.2 [Feature] Passthru Timeout 분리 + Crash 시 nvme-cli 프로세스 보존

**배경**: v4.5까지는 nvme-cli `--timeout` 인자에 퍼저의 subprocess 감지 timeout(예: 8000ms)을 그대로 사용했다. NVMe 명령이 timeout되면:

```
t=8s : subprocess communicate() 만료 → process.kill() → nvme-cli 종료
     → fd(/dev/nvme0) 닫힘
     → 커널: orphaned in-flight 명령 정리 (abort → reset)
     → dmesg: "nvme0: I/O 23 QID 0 timeout, reset controller"
     → SSD 펌웨어 상태 리셋 (crash 분석 불가)
```

**근본 원인**: `process.kill()`로 fd가 닫히면 커널이 cleanup 경로로 진입한다. `--timeout` 값은 fd가 열려있는 동안의 능동적 타임아웃에만 적용되며, fd close 이벤트에는 무관하다.

**v4.6 해결책**: 두 가지 변경을 조합한다.

```python
# 1. subprocess를 새 세션으로 분리 (부모 종료 후에도 생존)
process = subprocess.Popen(
    nvme_cmd,
    start_new_session=True,   # setsid() — SIGHUP 차단
    ...
)

# 2. TimeoutExpired 시 process.kill() 제거
except subprocess.TimeoutExpired:
    # kill 없음 → fd 유지 → 커널 cleanup 경로 진입 안함
    process.stdout.close()   # 파이프 부모 쪽만 닫음
    process.stderr.close()
    self._crash_nvme_pid = process.pid
    return RC_TIMEOUT

# 3. passthru timeout은 30일 (u32 최대 ~49.7일 이내)
NVME_PASSTHRU_TIMEOUT_MS = 2_592_000_000  # 30일
```

**동작 원리**:
- **정상 실행**: SSD가 수 ms 내 응답 → `communicate()` 정상 리턴 → kill 없음. 성능 영향 없음.
- **Crash 발생**: 8초 후 `communicate()` TimeoutExpired → kill 없이 파이프만 닫음 → nvme-cli 생존 (D-state) → fd 유지 → 커널 reset 없음 → SSD 상태 보존.
- **퍼저 종료 후**: `start_new_session=True` 덕분에 SIGHUP 차단 → nvme-cli가 init에 입양 → D-state로 계속 생존.
- **SSD 보존 기간**: nvme-cli `--timeout=30일` 만료 시까지 (또는 수동 kill 전까지).

**출력 파일 추가**:
- `crashes/crash_nvme_pid.txt`: 보존된 nvme-cli PID

**새 CLI 옵션**:

```
--passthru-timeout MS   nvme-cli에 전달할 --timeout 값
                        (기본: 2592000000ms = 30일)
```

**시작 로그 (v4.6)**:

```
[WARNING] Timeouts    : subprocess=command:8000,flush:30000,...
[WARNING] Passthru TO : 2592000000ms (30.0일, nvme-cli --timeout, crash 시 SSD 상태 장기 보존)
```

**crash 발생 시 로그**:

```
[ERROR]   [SSD 상태 보존] nvme-cli PID=1234 가 살아있습니다 (fd 유지 → 커널 reset 없음).
[ERROR]   SSD 상태는 nvme-cli --timeout(30일) 만료까지 보존됩니다.
[ERROR]   분석 완료 후 종료: kill 1234
[ERROR]   PID 파일: .../crashes/crash_nvme_pid.txt
```

### 10.3 [BugFix] Timeout Crash 후 커널 Controller Reset 차단

**문제 현상**: timeout crash 감지 후 "퍼징을 중단합니다. SSD와 NVMe 장치 상태를 그대로 유지합니다." 로그 출력 후 약 1분 뒤 커널이 SSD를 reset하여 crash 상태가 소멸.

**근본 원인**: `nvme-cli --timeout=2592000000`(30일)은 passthru 명령 자체의 per-command timeout만 설정한다. Linux 커널 NVMe 드라이버는 내부 admin 명령(Async Event Request, Keep-Alive 등)에 `ADMIN_TIMEOUT = 60초`를 독립적으로 사용한다. 펌웨어 크래시 시:

```
t=0s  : 펌웨어 크래시 (NVMe 완료 큐 응답 중단)
t≈60s : 커널 NVMe 드라이버 내부 admin 명령 타임아웃 (ADMIN_TIMEOUT=60s)
t≈60s : nvme_timeout() 발동 → nvme_reset_ctrl() 호출 → SSD 상태 소멸
```

passthru 명령에 30일 timeout을 설정해도 드라이버 내부 타이머(`ADMIN_TIMEOUT`)는 별개이므로 영향을 받지 않는다.

**해결**: timeout 감지 직후 `/sys/bus/pci/drivers/nvme/unbind`로 NVMe PCIe 드라이버를 제거한다. 드라이버가 사라지면 `ADMIN_TIMEOUT` 타이머도 함께 사라져 controller reset이 발생하지 않는다.

```
t=0s  : 펌웨어 크래시
t≈12s : 퍼저 subprocess timeout 감지
t≈14s : stuck PC 읽기 완료 (J-Link, 20회 샘플)
t≈14s : [신규] echo '<BDF>' > /sys/bus/pci/drivers/nvme/unbind
       → 커널 NVMe 드라이버 제거 → ADMIN_TIMEOUT 타이머 소멸
       → SSD 펌웨어 상태 무기한 보존
```

**사이드 이펙트**:
- `/dev/nvme*` 장치 파일이 사라짐 (드라이버 없으므로 정상)
- nvme-cli 프로세스가 D-state에서 깨어나 ENODEV로 종료됨 (정상)
- SSD 펌웨어는 JTAG(J-Link)로 여전히 접근 가능
- 분석 완료 후 rebind: `echo '<BDF>' > /sys/bus/pci/drivers/nvme/bind`

**신규 메서드**:
- `_get_nvme_pci_bdf()`: 시작 시 `/sys/class/nvme/<dev>`에서 PCI BDF 검색
- `_unbind_nvme_driver()`: BDF를 `/sys/bus/pci/drivers/nvme/unbind`에 기록

---

### 10.4 [Refactor] 코드 정리 (v4.6 후속)

hot-path 비활성화 코드 제거 및 코드 품질 개선.

**주요 변경 항목**:

| 항목 | 내용 |
|---|---|
| `Counter` 모듈 레벨 import | 3개 로컬 import → 상단 1개로 통합 |
| `self.prev_pc` 제거 | `JLinkPCSampler`의 dead field 제거 (로컬 `prev_pc` 변수는 유지) |
| defaultdict 중복 init 제거 | `cmd_stats` / `cmd_pcs` / `cmd_traces` 초기 키 설정 루프 제거 |
| `_compute_edges_from_traces()` 추출 | traces → edge 집합 변환 로직을 `@staticmethod`로 통합 (3개 호출 지점) |
| CLI help 수정 | `--passthru-timeout` help 문자열 "1시간" → "30일" 수정 |
| `cmd_traces` 저장 조건 단순화 | 이중 조건 → `raw_in_range` 단일 조건으로 단순화 |
| 불필요한 changelog 제거 | 모듈 docstring에서 v4.1~v4.4 상세 항목 제거 (v4 기반 요약으로 대체) |
| stale 주석 제거 | "이전 v4.2에서는..." 등 역사적 설명 주석 제거 |
| heatmap 라벨 업데이트 | `prev_pc → cur_pc` → `src_pc → dst_pc` (primary signal 변경 반영) |
| feature 출력 정리 | 기동 시 feature 목록에서 제거된 `prev_pc reset` 항목 삭제 |
| 기본 실행 시간 | `TOTAL_RUNTIME_SEC` 3600(1시간) → 604800(1주일) |
| 전체 명령어 기본 활성화 | `FuzzConfig.all_commands` 및 `--all-commands` 기본값 `False` → `True` |
| 초기 시드 분포 조정 | Read/Write 각 10개로 증가, GetFeatures 10→3, GetLogPage 5→2, Sanitize 3→1. AFLfast 에너지 공식 유지하면서 초기 corpus 비중으로 커맨드 선택 빈도를 간접 조정 |

---

## 11. 알려진 제한사항 및 향후 과제

### 11.1 구조적 한계

| 한계 | 설명 | 심각도 | 비고 |
|---|---|---|---|
| **PC 샘플링 해상도** | halt-sample-resume 방식은 모든 명령어를 캡처하지 못함. 짧은 함수는 놓칠 수 있음 | 중간 | - |
| ~~**Hit count 미지원**~~ | ~~동일 edge의 실행 횟수 변화를 감지 못함~~ | ~~높음~~ | **v4.5에서 해결** (hit count bucketing) |
| **subprocess 오버헤드** | 매 실행마다 fork+exec. exec/s 제한의 주 원인 | 중간 | 검토 완료: timeout 시 프로세스 kill이 필요하므로 subprocess 방식 유지 |
| **단일 코어 샘플링** | SSD가 멀티코어(예: Cortex-R8 듀얼)면 한 코어만 샘플링 | 높음 | 하드웨어 제약: J-Link 1개, JTAG/SWD 포트 1개로 불가 |
| ~~**비결정적 커버리지**~~ | ~~샘플링 타이밍에 따라 동일 입력도 다른 edge를 생성할 수 있음~~ | ~~중간~~ | **v4.5에서 완화** (calibration으로 안정성 측정 및 필터링) |

### 11.2 향후 개선 과제

| 과제 | 우선순위 | 설명 | 상태 |
|---|---|---|---|
| ~~Hit count bucketing~~ | ~~높음~~ | ~~edge별 hit count를 bucket화하여 "새로움" 기준 확장~~ | **v4.5 구현 완료** |
| ~~Calibration~~ | ~~중간~~ | ~~시드별 edge 안정성 측정, 불안정한 edge 필터링~~ | **v4.5 구현 완료** |
| ~~Deterministic stage~~ | ~~중간~~ | ~~초기 탐색에서 체계적 경계값 발견~~ | **v4.5 구현 완료** |
| ~~MOpt (mutator scheduling)~~ | ~~중간~~ | ~~mutation 연산자별 효과 추적 및 가중치 조정~~ | **v4.5 구현 완료** |
| ~~io-passthru device 수정~~ | ~~낮음~~ | ~~deprecated NVME_IOCTL_IO_CMD 경고 제거~~ | **v4.6 구현 완료** |
| ~~Passthru timeout 분리~~ | ~~중간~~ | ~~crash 시 SSD 상태 보존을 위한 timeout 구조 개선~~ | **v4.6 구현 완료** |
| ~~커널 reset 차단 (unbind)~~ | ~~높음~~ | ~~timeout crash 후 ADMIN_TIMEOUT(60s)에 의한 커널 reset 차단 — PCIe NVMe 드라이버 즉시 unbind~~ | **v4.6 버그픽스 완료** |
| ~~Edge 추적 코드 제거~~ | ~~높음~~ | ~~hot path에서 불필요한 edge 연산 제거 (183줄, 샘플당 set.add + dict 갱신)~~ | **v4.6 구현 완료** |
| ~~코드 품질 정리~~ | ~~낮음~~ | ~~dead code, 중복 init, 로컬 import, stale 주석 제거~~ | **v4.6 구현 완료** |
| Entropic scheduling | 중간 | 정보 이론 기반 시드 스케줄링 (corpus 성숙 후 AFLFast 대체) | 미구현 |
| NVMe 구조 인식 mutation | 중간 | Peach Pit 방식 CDW 필드별 의미론적 mutation | 미구현 |
| Directed fuzzing | 높음 | Ghidra CFG 기반 거리맵으로 특정 코드 영역 집중 탐색 | 미구현 |
| 크래시 서명 자동 분류 | 중간 | crash_pc + fault 레지스터 + NVMe status code 기반 서명 | 미구현 |

---

## 12. 관련 연구 및 도입 가능 기술

### 12.1 본 프로젝트의 학술적 위치

본 퍼저는 학술 문헌에서 독자적 위치를 차지한다:

1. **GDBFuzz, µAFL과 같은 Hardware-in-the-loop** 방식이지만, MCU(Cortex-M)가 아닌 스토리지 컨트롤러(Cortex-R8)를 대상으로 하며, HW breakpoint(GDBFuzz)나 ETM trace(µAFL) 대신 통계적 PC 샘플링을 사용
2. **State Data-Aware SSD Fuzzer와 같은 도메인 특화** 퍼저이지만, 에뮬레이션(FEMU)이 아닌 실 하드웨어에서 동작하여 진정한 펌웨어 커버리지를 수집
3. **kAFL, PTfuzz와 같은 하드웨어 트레이스 기반** 접근이지만, Intel PT가 없는 ARM JTAG 환경에 적응
4. **SPDK NVMe fuzzer와 같은 NVMe 인식** 퍼저이지만, 블랙박스 명령 랜덤화가 아닌 펌웨어 측 커버리지 피드백을 활용

### 12.2 Hardware-in-the-Loop 펌웨어 퍼징

| 이름 | 저자 / 연도 | 학회 | 접근 방식 | 본 프로젝트와의 관계 |
|------|------------|------|-----------|---------------------|
| **GDBFuzz** | Eisele et al. / 2023 | ISSTA 2023 | GDB 하드웨어 breakpoint로 uninstrumented 펌웨어의 basic-block 커버리지 수집 | 가장 유사한 선행 연구. halt-breakpoint-resume 루프가 우리의 halt-sample-resume과 구조적으로 동일 |
| **µAFL** | Li et al. / 2022 | ICSE 2022 | ARM ETM 하드웨어 트레이싱으로 MCU 펌웨어의 완전한 분기 트레이스 수집. 10 zero-day | ETM은 완전한 트레이스를 제공하지만 CoreSight 인프라 필요. Cortex-R8 SSD에 ETM 핀 미노출 가능 |

### 12.3 NVMe / 스토리지 퍼징

| 이름 | 저자 / 연도 | 설명 | 본 프로젝트와의 관계 |
|------|------------|------|---------------------|
| **State Data-Aware SSD Fuzzer** | Yoon, Lee / 2025 | FEMU(NVMe SSD 에뮬레이터)에서 AFL++로 FTL/GC 상태 인식 퍼징 | 가장 직접적으로 비교 가능한 SSD 퍼징 연구. 에뮬레이션 기반 vs 실 하드웨어 |
| **SPDK NVMe Fuzzer** | Intel / 2023 | SPDK 내장 NVMe 퍼저. LibFuzzer 통합, NVMe-oF 및 물리 드라이브 대상 | NVMe 명령 랜덤화 참조 구현 |
| **pydiskcmd** | jackeichen | Python으로 NVMe raw 명령 전송 (ioctl 직접 호출) | nvme-cli subprocess 대체 후보 → fork/exec 오버헤드 제거 |

---

## 13. 실행 방법 및 CLI 옵션

### 13.1 기본 실행 (안전 명령어만)

```bash
sudo python3 pc_sampling_fuzzer_v4.6.py
```

### 13.2 특정 명령어 지정

```bash
sudo python3 pc_sampling_fuzzer_v4.6.py --commands Read Write GetFeatures
```

### 13.3 전체 명령어 (파괴적 포함)

```bash
sudo python3 pc_sampling_fuzzer_v4.6.py --all-commands
```

### 13.4 전체 CLI 옵션

| 옵션 | 기본값 | 설명 |
|---|---|---|
| `--device` | Cortex-R8 | J-Link 타겟 디바이스 |
| `--nvme` | /dev/nvme0 | NVMe 장치 경로 |
| `--namespace` | 1 | NVMe 네임스페이스 ID |
| `--commands` | (기본 5개) | 활성화할 명령어 이름 |
| `--all-commands` | False | 파괴적 명령어 포함 전체 활성화 |
| `--speed` | 12000 | JTAG 속도 (kHz) |
| `--runtime` | 3600 | 총 퍼징 시간 (초) |
| `--output` | ./output/pc_sampling_v4.6/ | 출력 디렉토리 |
| `--samples` | 500 | 실행당 최대 샘플 수 |
| `--interval` | 0 | 샘플 간격 (us) |
| `--post-cmd-delay` | 0 | 명령 완료 후 추가 샘플링 (ms) |
| `--addr-start` | 0x00000000 | 펌웨어 .text 시작 주소 |
| `--addr-end` | 0x00147FFF | 펌웨어 .text 종료 주소 |
| `--resume-coverage` | None | 이전 coverage.txt 경로 |
| `--saturation-limit` | 10 | idle PC 연속 감지 임계값 |
| `--global-saturation-limit` | 20 | 글로벌 PC 포화 임계값 |
| `--max-energy` | 16.0 | Power Schedule 최대 에너지 |
| `--random-gen-ratio` | 0.2 | 완전 랜덤 입력 비율 |
| `--exclude-opcodes` | (없음) | 제외할 opcode 목록 (e.g., `"0xC1,0xC0"`) |
| `--opcode-mut-prob` | 0.10 | opcode mutation 확률 (0=비활성화) |
| `--nsid-mut-prob` | 0.10 | NSID mutation 확률 (0=비활성화) |
| `--admin-swap-prob` | 0.05 | Admin↔IO 교차 확률 (0=비활성화) |
| `--datalen-mut-prob` | 0.08 | data_len 불일치 확률 (0=비활성화) |
| `--seed-dir` | None | 시드 디렉토리 경로 (이전 corpus를 시드로 재활용) |
| `--timeout GROUP MS` | (그룹별 기본값) | subprocess 감지 타임아웃 그룹별 오버라이드 |
| **`--passthru-timeout`** | **2592000000** | **nvme-cli --timeout 값 (ms, 기본 30일). crash 시 nvme-cli 프로세스 보존 → SSD 상태 장기 유지. v4.6 신규** |
| `--calibration-runs` | 3 | 초기 시드당 calibration 실행 횟수 (0=비활성화) |
| `--no-deterministic` | False | Deterministic stage 비활성화 |
| `--det-arith-max` | 10 | Deterministic arithmetic 최대 delta |
| `--no-mopt` | False | MOpt mutation scheduling 비활성화 |
| `--mopt-pilot-period` | 5000 | MOpt pilot 단계 실행 횟수 |
| `--mopt-core-period` | 50000 | MOpt core 단계 실행 횟수 |

---

## 14. 출력 디렉토리 구조

```
output/pc_sampling_v4.6/
├── fuzzer_YYYYMMDD_HHMMSS.log    # 실행 로그
├── coverage.txt                   # 글로벌 PC 커버리지 (hex, 줄당 1개)
├── .nvme_input.bin                # NVMe 입력 데이터 (재사용, 임시)
├── corpus/                        # interesting 입력 저장
│   ├── input_Read_0x2_a1b2c3d4e5f6
│   ├── input_Read_0x2_a1b2c3d4e5f6.json   # CDW 메타데이터
│   └── ...
├── crashes/                       # timeout/crash 입력 저장
│   ├── crash_Identify_0x6_...
│   ├── crash_Identify_0x6_....json       # crash 메타데이터 + 이유
│   ├── crash_Identify_0x6_....dmesg.txt  # 커널 로그 스냅샷
│   ├── crash_nvme_pid.txt                # v4.6: 보존된 nvme-cli PID (kill로 수동 종료)
│   └── ...
└── graphs/                        # 시각화 출력
    ├── summary.json               # 명령어별 edge/PC 수 요약
    ├── Read_edges.json            # 명령어별 edge/PC/trace 데이터
    ├── Read_cfg.dot               # CFG 그래프 (DOT)
    ├── Read_cfg.png               # CFG 그래프 (PNG, graphviz 필요)
    ├── ...
    ├── command_comparison.png     # 명령어별 비교 차트
    ├── coverage_heatmap_1d.png    # 1D 주소 커버리지 히트맵
    └── edge_heatmap_2d.png        # 2D edge 히트맵
```

---

## 부록: 의존성

| 패키지 | 용도 | 필수 |
|---|---|---|
| `pylink` (pylink-square) | J-Link 제어 | 필수 |
| `nvme-cli` (시스템) | NVMe passthru 명령 전송 | 필수 |
| `matplotlib` | 히트맵, 비교 차트 | 선택 |
| `numpy` | 히트맵 행렬 계산 | 선택 |
| `graphviz` (시스템) | CFG PNG 렌더링 | 선택 |

```bash
pip install pylink-square matplotlib numpy
sudo apt install nvme-cli graphviz
```

## 부록: GitHub

소스 코드: https://github.com/RelaxWide/Real_Fuzzing/tree/main/PC_Sampling
