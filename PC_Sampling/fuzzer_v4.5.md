# PC Sampling 기반 SSD 펌웨어 Coverage-Guided Fuzzer — 기술 보고서

**버전**: v4.5
**최종 수정**: 2026-02-11
**파일**: `pc_sampling_fuzzer_v4.5.py`

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
10. [알려진 제한사항 및 향후 과제](#10-알려진-제한사항-및-향후-과제)
11. [관련 연구 및 도입 가능 기술](#11-관련-연구-및-도입-가능-기술)
12. [실행 방법 및 CLI 옵션](#12-실행-방법-및-cli-옵션)
13. [출력 디렉토리 구조](#13-출력-디렉토리-구조)

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
| Edge 정의 | `(prev_loc >> 1) XOR cur_loc` → bitmap | `(prev_pc, cur_pc)` 정확한 튜플 → set |

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
| **Hit count bucketing** | Feature | edge별 누적 실행 횟수를 AFL++ 스타일 로그 버킷(1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+)으로 변환. 버킷 변화 시 interesting으로 판단하여 루프 반복 횟수 변화를 감지 |
| **Calibration** | Feature | 초기 시드를 N회(기본 3) 반복 실행하여 edge 안정성 측정. 과반수(>50%) 이상 run에서 등장한 edge를 `stable_edges`(시드 품질 메타데이터)로 분류. **global_edges에는 합집합(all_seen) 반영** — PC Sampling의 확률론적 특성상 실제 실행된 코드도 매 run마다 캡처되지 않으므로 교집합/100% 재현 기준 대신 합집합 사용. `stability` 수치는 Power Schedule 등 시드 품질 지표로만 활용 |
| **Calibration DLL stderr 억제** | BugFix | Calibration 구간의 tight halt/read/go 루프에서 J-Link DLL이 `"Cannot read register (R15) while CPU is running"` / `"CPU is not halted"` 경고를 stderr에 직접 출력하는 문제. `JLINKARM_Halt()`는 비동기(fire-and-forget)라 CPU 정지 확인 없이 바로 반환하며, 일반 퍼징에서는 NVMe 명령 처리 시간이 완충 역할을 하지만 calibration의 빡빡한 루프에서는 타이밍 위반이 빈번히 발생. Python `except Exception`으로는 DLL 수준의 stderr를 막을 수 없으므로, calibration 블록 전체를 `os.dup2(devnull, 2)` / `os.dup2(saved, 2)` 로 fd 수준에서 억제하고 `finally`에서 반드시 복원 |
| **Calibration 결과 요약 테이블** | Feature | calibration 완료 후 시드별 Stability / StableEdges / AllEdges 를 표 형식으로 출력하고, 전체 Seeds 수 · Global stable edges · Avg stability 요약을 표시한 뒤 퍼징을 시작. 기존에는 각 시드가 log.info 한 줄씩 출력되어 전체 결과를 한눈에 파악하기 어려웠음 |
| **Calibration 이중 start_sampling 버그** | BugFix | `_calibrate_seed()`가 매 run마다 `start_sampling()`을 명시적으로 호출하지만, `_send_nvme_command()` 내부에서도 `start_sampling()`을 호출하여 run당 두 개의 sampling thread가 동시에 실행됨. Thread 2가 `current_edges = set()`으로 리셋하면 Thread 1은 구 set에 add하여 데이터 유실. 또한 `stop_sampling()`은 Thread 2만 join하고 Thread 1은 zombie로 남아 다음 run의 `current_edges`에 이전 run의 edge를 혼입시킴. 그 결과 매 run의 edge 집합이 비결정적으로 달라져 `stable = {}` → **StableEdges 전부 0**. 수정: `_calibrate_seed()` 내부의 명시적 `start_sampling()` 호출 제거 |
| **Deterministic stage** | Feature | 새 시드의 CDW10~CDW15 필드에 대해 체계적 mutation(walking bitflip 32개, arithmetic ±1~10, interesting_32/8 대입) 수행. 제너레이터 기반 + deque로 havoc보다 우선 소비. 값이 0인 CDW 필드는 건너뜀 |
| **MOpt mutation scheduling** | Feature | Pilot/Core 2단계 모드. Pilot(기본 5000회): 16개 mutation operator 균등 사용하며 성공률 측정. Core(기본 50000회): 성공률 기반 가중치로 효과적인 operator에 집중. 주기적으로 모드 전환 |
| **Edge count 저장/로드** | Feature | `coverage_edge_counts.txt` 파일로 edge별 누적 hit count 저장/로드. resume 시 버킷 상태 완전 복원 |
| **Summary 통계 확장** | Feature | Summary에 hit count 추적 edge 수, MOpt 모드, operator별 finds/uses/성공률 출력 |
| **CLI 옵션 추가** | Feature | `--calibration-runs`, `--no-deterministic`, `--det-arith-max`, `--no-mopt`, `--mopt-pilot-period`, `--mopt-core-period` |

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
             │  기반)     │ │  havoc)  │  │ (edge set) │
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
                   │ (J-Link    │  current_edges
                   │  halt/go)  │  → global_edges
                   └────────────┘
```

### 3.2 한 번의 실행(Execution) 상세

```
 1. _select_seed()       → 에너지 기반 가중치 랜덤으로 시드 선택
 2. _mutate()            → havoc + splice + CDW + 확장 mutation 적용
 3. start_sampling()     → J-Link 샘플링 스레드 시작 (백그라운드)
 4. subprocess.Popen()   → nvme-cli passthru 명령 전송
 5. communicate()        → 명령 완료 대기
 6. post_cmd_delay       → 추가 샘플링 대기
 7. stop_sampling()      → 샘플링 스레드 종료
 8. evaluate_coverage()  → current_edges와 global_edges 비교
 9. tracking_label()     → (v4.3) 실제 opcode 기준 추적 키 결정
10. if interesting:      → corpus에 새 시드 추가 (covered_edges 포함)
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

- **Thread Safety**: 샘플링 스레드에서 `global_edges_ref = self.global_edges`로 참조를 캐싱하여 attribute lookup 제거. CPython GIL 하에서 `set.__contains__`는 원자적이므로 실질적 동시성 문제 없음. 다만, 메인 스레드가 `global_edges.update()`하는 시점과 샘플링 스레드가 읽는 시점이 겹칠 수 있어 이론적으로는 stale read 가능 (퍼징 결과에 영향 미미).

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
| **글로벌 포화** | `global_saturation_limit` (기본 20) | 연속 N회 새로운 global edge가 없음 |
| **idle 포화** | `saturation_limit` (기본 10) | 연속 N회 idle PC에 머물러 있음 |

v4.2에서는 글로벌 포화 임계값이 `20`으로 하드코딩되어 있었으나, v4.3에서 `global_saturation_limit` 설정값으로 분리.

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

#### 4.2.2 타임아웃 그룹

명령어별 타임아웃을 그룹으로 관리하여, 같은 성격의 명령어에 동일한 타임아웃 적용:

```
command:    8,000ms   (일반)
flush:      30,000ms
dsm:        30,000ms
telemetry:  30,000ms
fw_commit:  120,000ms
format:     600,000ms
sanitize:   600,000ms
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
    new_edges: int           # 발견한 새 edge 수
    energy: float            # 계산된 에너지
    covered_edges: set       # v4.3: 이 시드 실행 시 발견된 edge set (culling용)
    is_favored: bool         # v4.3: corpus culling에서 선정된 favored seed
```

#### 4.3.2 초기 시드 생성 (`_generate_default_seeds`)

NVMe 스펙에 따른 **정상 명령어 파라미터**를 초기 시드로 생성:

| 명령어 | 시드 수 | 예시 |
|---|---|---|
| Identify | 4 | CNS=0x00(NS), 0x01(Controller), 0x02(Active NS), 0x03(NS Descriptor) |
| GetLogPage | 5 | Error Info(LID=1), SMART(LID=2), FW Slot(LID=3), Cmd Effects(LID=5), Self-test(LID=6) |
| GetFeatures | 10 | FID=0x01~0x0B (Arbitration ~ Async Event Config) |
| Read | 4 | LBA 0/1/1000, NLB 1/8 |
| Write | 3 | LBA 0/1000, 패턴 0x00/0xAA |
| SetFeatures | 1 | Number of Queues |
| FWDownload | 1 | offset=0, 1KB |
| FWCommit | 2 | CA=1 Slot 0/1 |
| FormatNVM | 1 | LBAF 0 |
| Sanitize | 3 | Block Erase, Overwrite, Crypto Erase |
| Telemetry | 1 | Host-Initiated |
| Flush | 1 | (파라미터 없음) |
| DSM | 1 | TRIM LBA 0, 8 blocks |

**정상 시드의 중요성**: 퍼저가 완전 랜덤 입력으로 시작하면 대부분 SSD에서 즉시 에러로 거부되어 의미 있는 코드 경로를 탐색할 수 없음. NVMe 스펙 기반 정상 시드로 시작하면 실제 명령 처리 코드까지 도달한 뒤, mutation을 통해 경계값/에러 핸들링 코드를 탐색.

#### 4.3.3 시드 로딩 순서

```
1. 사용자 시드 디렉토리 (--seed-dir) 로드 (있는 경우)
2. NVMe 스펙 기반 기본 시드 항상 추가
```

**주의사항**: 사용자 시드의 JSON 메타데이터에 `command` 키가 없으면, 해당 시드가 모든 활성 명령어에 대해 중복 추가됨. 이는 의도적 설계(모든 명령어로 시도)이거나 잠재적 이슈일 수 있음.

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

#### 4.4.3 Splice (`_splice`)

15% 확률로 havoc 전에 적용:
1. 현재 시드(A)와 다른 corpus 시드(B) 선택
2. 랜덤 분할점에서 A[:split] + B[split:] 또는 반대로 합성
3. 합성된 결과에 havoc mutation 추가 적용

#### 4.4.4 확장 Mutation (NVMe 특화)

v4.3에서 모든 확률이 설정값으로 분리되어 CLI에서 개별 비활성화 가능 (`--opcode-mut-prob 0` 등).

| Mutation | 기본 확률 | CLI 옵션 | 목적 |
|---|---|---|---|
| opcode override | 10% | `--opcode-mut-prob` | vendor-specific(0xC0~0xFF), 완전 랜덤, bitflip, 다른 명령어 opcode. `EXCLUDED_OPCODES`에 지정된 opcode는 자동 제외 |
| nsid override | 10% | `--nsid-mut-prob` | nsid=0, 0xFFFFFFFF(broadcast), 존재하지 않는 NS |
| Admin↔IO 교차 | 5% | `--admin-swap-prob` | 잘못된 큐로 전송하여 디스패치 혼란 유도 |
| data_len 불일치 | 8% | `--datalen-mut-prob` | CDW와 data_len이 다른 값을 가지도록 하여 DMA 엔진 혼란 |
| GetLogPage NUMDL 과대 | 15% | (고정) | 스펙 초과 크기 로그 요청. GetLogPage 명령어에만 적용되므로 별도 설정 불필요 |

**일반 명령어만으로 퍼징** (확장 mutation 전부 비활성화):
```bash
python3 pc_sampling_fuzzer_v4.5.py \
  --opcode-mut-prob 0 --nsid-mut-prob 0 \
  --admin-swap-prob 0 --datalen-mut-prob 0
```

#### 4.4.5 Mutation 적용 순서

```
_mutate(seed):
    1. [15%] splice → 두 시드 합성
    2. _mutate_bytes() → havoc (2^1 ~ 2^7 스택)
    3. [30%] CDW mutation → 1~3개 CDW 필드 변형
    4. [configurable] opcode override (excluded 필터링 포함)
    5. [configurable] nsid override
    6. [configurable] Admin↔IO 교차
    7. [configurable] data_len 불일치
    8. [15%] GetLogPage NUMDL 과대 (해당 명령어인 경우)
```

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

#### 4.5.2 가중치 랜덤 선택

```python
_select_seed():
    for seed in corpus:
        seed.energy = _calculate_energy(seed)

    total = sum(energies)
    r = uniform(0, total)
    cumulative scan → 선택
```

#### 4.5.3 AFL++ 실제 구현과의 차이

| AFL++ | 본 퍼저 |
|---|---|
| `perf_score` (실행시간, 파일크기, 경로깊이 등) × power factor | 순수 에너지만 사용 |
| 여러 스케줄 (FAST, COE, LIN, QUAD, MMOPT, RARE, SEEK, EXPLORE) | explore만 구현 |
| bitmap density 기반 가중치 | edge set 크기 미고려 |

---

### 4.6 커버리지 피드백 메커니즘

#### 4.6.1 Edge 정의

```
edge = (prev_pc, cur_pc)
```

- PC 샘플링에서 연속으로 읽힌 두 PC 값의 쌍
- 정확한 주소 튜플이므로 해시 충돌 없음 (AFL++와 달리)

#### 4.6.2 커버리지 저장소

| 저장소 | 타입 | 용도 |
|---|---|---|
| `global_edges` | `Set[Tuple[int,int]]` | 전체 세션 누적 edge |
| `current_edges` | `Set[Tuple[int,int]]` | 현재 실행의 edge |
| `global_coverage` | `Set[int]` | 전체 세션 누적 PC (비교용) |
| `current_trace` | `Set[int]` | 현재 실행의 PC |

#### 4.6.3 "Interesting" 판정

```python
evaluate_coverage():
    new_edges = len(global_edges ∪ current_edges) - len(global_edges)
    is_interesting = (new_edges > 0)
```

- **한 개라도 새로운 edge가 발견되면 interesting** → corpus에 추가
- Hit count 변화는 고려하지 않음 (AFL++와의 주요 차이)

#### 4.6.4 AFL++와의 커버리지 모델 비교

| 관점 | AFL++ | 본 퍼저 |
|---|---|---|
| Edge 표현 | `(prev_loc >> 1) ^ cur_loc` → bitmap index | `(prev_pc, cur_pc)` → set element |
| 저장소 | 64KB bitmap (고정 크기) | Python set (가변 크기) |
| 해시 충돌 | 있음 (bitmap 크기 제한) | 없음 (정확한 주소 쌍) |
| Hit count | 8-bit counter → bucket (1,2,3,4-7,...) | 없음 (존재 여부만) |
| "새로움" 기준 | 새 edge OR hit count bucket 변화 | 새 edge만 |
| 메모리 사용 | 고정 64KB | edge 수에 비례 (수만~수십만 edge 시 수 MB) |

---

### 4.7 NVMe 명령 전송

#### 4.7.1 전송 방식

```python
_send_nvme_command(data, seed):
    nvme_cmd = ['nvme', 'admin-passthru'|'io-passthru', '/dev/nvme0',
                '--opcode=...', '--namespace-id=...', '--cdw2=...', ..., '--cdw15=...',
                '--timeout=...', '--data-len=...', '--input-file=...' | '-r']

    sampler.start_sampling()        # 샘플링 먼저 시작
    process = Popen(nvme_cmd)
    stdout, stderr = process.communicate(timeout=...)
    if post_cmd_delay > 0:          # v4.3: 추가 샘플링 대기
        sleep(post_cmd_delay)
    return process.returncode
```

#### 4.7.2 data_len 결정 로직

```
if data_len_override:      → override 값 사용 (2MB 상한)
elif needs_data and data:  → len(data)
elif IO cmd (Read/Write):  → (NLB + 1) × 512
elif GetLogPage:           → (NUMDL + 1) × 4
elif Identify/GetFeatures: → 4096 (고정)
else:                      → 0
```

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
- v4.3: opcode_override 사용 시 `Identify_Controller_op0xD1`처럼 실제 opcode별로 별도 행 생성

#### 4.8.3 2D Edge Heatmap

- prev_pc × cur_pc 인접 행렬을 2D 히트맵으로 표시
- log 스케일, inferno 컬러맵
- 대각선 참조선 (순차 실행 영역)
- v4.3: 실제 opcode 기준으로 분류 (mutation된 opcode의 edge가 원래 명령어에 오염되지 않음)

#### 4.8.4 명령어 비교 막대 차트

- 명령어별 edge 수, PC 수, 실행 횟수를 가로 막대 차트로 비교
- v4.3: 실제 opcode 기준 분류 반영 (e.g., `GetFeatures` vs `GetFeatures_op0xD1`)

#### 4.8.5 SMART Health 로그 (v4.3 추가)

- `nvme smart-log` 실행 결과를 INFO 레벨로 로그 기록
- 기록 시점: 퍼징 시작 전(baseline) / 10,000회마다 / 퍼징 종료 후
- SSD 온도, 가용 예비 공간, 미디어 에러 수 등 건강 상태 모니터링
- 디바이스 탈락(timeout) 후에는 실패하고 warning만 출력

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
| Edge coverage | 구현 완료 (변형) | 정확한 (prev,cur) 튜플 (bitmap 아님) |
| **Hit count bucketing** | **v4.5 구현** | AFL++ 동일 8단계 로그 버킷. bucket 변화 시 interesting |
| **Calibration** | **v4.5 구현** | 시드별 N회 반복 실행으로 edge 안정성 측정 |
| **Deterministic stage** | **v4.5 구현** | CDW 필드 대상 walking bitflip + arithmetic + interesting |
| **MOpt** | **v4.5 구현** | Pilot/Core 2단계 mutation operator scheduling |
| Corpus management | 구현 완료 | interesting → corpus 추가 + AFL++ 방식 culling (1000회마다) |
| Crash detection | 구현 완료 | timeout → crash 저장 |
| Resume (coverage reload) | 구현 완료 | coverage.txt + coverage_edges.txt + edge_counts 로드 |

### 5.2 미구현 기능

| AFL++ 기능 | 영향 | 비고 |
|---|---|---|
| **Trimming** | 낮음 | NVMe CDW는 고정 크기 32비트 필드이므로 불필요. 검토 완료 |
| **Fork server** | 해당 없음 | NVMe 하드웨어 퍼징이므로 fork server 개념 자체가 적용 불가 |
| **Cmplog/Redqueen** | 낮음 | 매직 바이트 자동 탐색. NVMe 명령 구조는 이미 스펙 기반 시드로 커버 |
| **Dictionary** | 낮음 | NVMe 스펙 기반 시드가 사실상 dictionary 역할 |

> **v4.3에서 추가 구현된 AFL++ 기능**: corpus culling (favored seed 선정 + 비기여 seed 제거)
> **v4.5에서 추가 구현된 AFL++ 기능**: hit count bucketing, calibration, deterministic stage, MOpt

### 5.3 독자적 기능 (AFL++에 없는)

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
| NVMe 디바이스 사전 검증 | 시작 전 장치 존재 + 권한 확인 |
| J-Link Heartbeat | 1000회마다 JTAG 연결 상태 확인 |
| Timeout 불량 보존 | timeout 시 복구 없이 펌웨어 resume 상태 유지 (디버깅용) |

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

#### subprocess 오버헤드

매 실행마다:
1. `fork()` — 프로세스 복제
2. `exec()` — nvme 바이너리 로드
3. 커널 NVMe ioctl 실행
4. stdout/stderr 파이프 수집
5. `waitpid()` — 프로세스 종료 대기

AFL++의 fork server는 `exec()`를 1회만 수행하고 이후 `fork()`만 반복하여 이 비용을 최소화하지만, 본 퍼저에서는 외부 도구(nvme-cli)를 사용하므로 이 최적화가 불가능함.

### 6.2 메모리 사용

| 데이터 | 예상 크기 | 비고 |
|---|---|---|
| `global_edges` (set) | ~1MB (10만 edge 기준) | Python tuple의 set, 각 entry ~120 bytes |
| `global_coverage` (set) | ~0.5MB (5만 PC 기준) | Python int의 set |
| `corpus` (list of Seed) | ~수 MB | data + CDW + 메타데이터 |
| `cmd_traces` (deque) | ~수 MB | 명령어당 최대 200개 trace |

### 6.3 v4.3 성능 개선

| 변경 | 이전 | 이후 | 효과 |
|---|---|---|---|
| `cmd_traces` | `list`, `pop(0)` O(n) | `deque(maxlen=200)` O(1) | trace 200개 기준 ~200x 빠른 제거 |
| interval 체크 | `in (tuple)` O(n) | `in frozenset` O(1) | 미미하지만 매 샘플마다 호출 |

---

## 7. v4.3 버그 수정 및 개선사항

### 7.1 [BugFix] 로그 메시지 불일치

**문제**: 라인 1802 (v4.2)에서 `"NVMe I/O : ioctl direct (no subprocess)"`라고 로그를 출력하지만, 실제 구현은 `subprocess.Popen`으로 `nvme-cli`를 호출하는 방식.

**수정**: `"NVMe I/O : subprocess (nvme-cli passthru)"`로 변경.

**영향**: 로그를 보는 사용자가 실제 동작 방식을 오해할 수 있었음.

### 7.2 [BugFix] 글로벌 포화 임계값 하드코딩

**문제**: `_sampling_worker()` 내에서 `since_last_global_new >= 20`으로 하드코딩. 이미 `saturation_limit` 설정이 있지만 이는 idle PC용이고, 글로벌 포화 임계값은 별도 설정 없이 20으로 고정.

**수정**:
- `GLOBAL_SATURATION_LIMIT = 20` 상수 추가
- `FuzzConfig.global_saturation_limit` 필드 추가
- `--global-saturation-limit` CLI 옵션 추가
- `_sampling_worker()`에서 `self.config.global_saturation_limit` 참조

### 7.3 [BugFix] prev_pc 실행 간 캐리오버

**문제**: v4.2에서 `self.prev_pc = prev_pc`로 실행 간 prev_pc를 유지. 실행 A의 마지막 PC가 `0x1000`이고 실행 B의 첫 PC가 `0x5000`이면, `(0x1000, 0x5000)`이 edge로 기록됨. 이는 실제 펌웨어의 제어 흐름이 아닌 가짜 edge.

**수정**: `_sampling_worker()` 시작 시 `prev_pc = 0xFFFFFFFF` (sentinel)으로 초기화. `self.prev_pc`에 저장하지 않음.

**영향**: 가짜 edge가 corpus 오염을 일으킬 수 있었음 (false positive interesting 판정).

### 7.4 [BugFix] post_cmd_delay_ms 미사용

**문제**: `FuzzConfig.post_cmd_delay_ms` 설정과 `--post-cmd-delay` CLI 옵션이 있지만, 실제 코드에서 이 값을 사용하는 곳이 없음.

**수정**: `_send_nvme_command()`에서 `process.communicate()` 완료 후, `post_cmd_delay_ms > 0`이면 `time.sleep()` 추가. 이 시간 동안 샘플링 스레드가 계속 동작하여 SSD 내부 후처리 코드를 캡처.

### 7.5 [Perf] cmd_traces deque 교체

**문제**: `self.cmd_traces[cmd_name]`이 `List`이고, 200개 초과 시 `traces.pop(0)` 호출. 리스트 앞에서 제거는 O(n).

**수정**: `deque(maxlen=200)`으로 교체. 자동으로 오래된 항목이 제거되고, popleft는 O(1).

### 7.6 [Perf] interval 체크포인트 frozenset

**문제**: `sample_count in (10, 25, 50, 100, 200, 500)` — tuple의 `in` 검색은 O(n).

**수정**: 클래스 변수 `_INTERVAL_CHECKPOINTS = frozenset({10, 25, 50, 100, 200, 500})`. frozenset의 `in` 검색은 O(1).

### 7.7 [Clarity] 랜덤 생성 비율 설정 분리

**문제**: `random.random() < 0.8`로 하드코딩된 80% corpus / 20% random 비율.

**수정**: `RANDOM_GEN_RATIO = 0.2` 상수 + `FuzzConfig.random_gen_ratio` 필드 + `--random-gen-ratio` CLI 옵션. 메인 루프에서 `random.random() >= self.config.random_gen_ratio` 조건으로 변경.

### 7.8 [BugFix] EXCLUDED_OPCODES CLI 파싱 버그

**문제**: CLI 파싱에서 `excluded_opcodes = []`로 초기화하여, 스크립트 상단에 `EXCLUDED_OPCODES = [0xC1, 0xC0]`을 설정해도 CLI 옵션을 안 넘기면 빈 리스트로 덮어씀.

**수정**: `excluded_opcodes = list(EXCLUDED_OPCODES)`로 상수를 기본값으로 가져오고, CLI `--exclude-opcodes`로 추가 지정 시 병합.

### 7.9 [Feature] 제외 Opcode 설정

**배경**: opcode mutation으로 vendor-specific opcode(예: 0xC1, 0xC0)를 보내면 SSD가 응답 불능 상태에 빠져 커널이 controller reset → 장치 해제를 수행함.

**구현**:
- `EXCLUDED_OPCODES: List[int] = []` 스크립트 상단 상수
- `FuzzConfig.excluded_opcodes` 필드
- `--exclude-opcodes "0xC1,0xC0"` CLI 옵션
- opcode mutation 발생 시 제외 대상이면 override 취소 (원래 opcode 사용)

### 7.10 [Feature] 확장 Mutation 확률 설정

**문제**: 확장 mutation 확률(10%, 10%, 5%, 8%)이 코드에 하드코딩되어, 특정 mutation만 끄려면 코드 수정이 필요했음.

**수정**: `OPCODE_MUT_PROB`, `NSID_MUT_PROB`, `ADMIN_SWAP_PROB`, `DATALEN_MUT_PROB` 상수 + FuzzConfig 필드 + CLI 옵션 (`--opcode-mut-prob` 등). 0으로 설정하면 해당 mutation 비활성화.

### 7.11 [Feature] AFL++ Corpus Culling

**구현**: `_cull_corpus()` 메서드, 1000회마다 실행. corpus 10개 이하이면 skip.
1. 각 edge에 대해 data가 가장 작은 seed를 `favored`로 마킹
2. favored 아니고 + 5회 이상 실행되고 + 기본 시드가 아닌 seed 제거
3. Seed에 `covered_edges` set 저장 (corpus 추가 시 `current_edges` 스냅샷)

### 7.12 [Feature] NVMe 디바이스 사전 검증

**구현**: `run()` 시작 시 `/dev/nvme0` 존재 여부 + `os.access(R_OK | W_OK)` 확인. 실패 시 J-Link 연결 전에 즉시 종료.

### 7.13 [Feature] J-Link Heartbeat

**구현**: 1000회마다 `_read_pc()` 시도. None 반환 시 JTAG 연결 끊김으로 판단하고 퍼징 중단.

### 7.14 [Feature] 실제 Opcode 기준 추적

**문제**: opcode_override로 0xD1을 보내도 커버리지가 원래 명령어(e.g., `Identify_Controller`)에 누적됨. 히트맵/통계가 오염.

**수정**: `_tracking_label(cmd, seed)` 메서드 도입. opcode_override 있으면 `Identify_Controller_op0xD1`처럼 별도 키 생성. `cmd_edges`, `cmd_pcs`, `cmd_traces`, `cmd_stats`, `rc_stats` 모두 실제 opcode 기준으로 분류. defaultdict 사용으로 새 키 자동 생성.

### 7.15 [Feature] SMART Health 로그

**구현**: `_log_smart()` 메서드. `nvme smart-log /dev/nvme0`을 subprocess로 실행하고 결과를 INFO 레벨로 기록.
- 퍼징 시작 전: baseline 상태
- 10,000회마다: 퍼징 중 SSD 상태 변화 모니터링
- 퍼징 종료 후: 최종 상태
- 디바이스 탈락 시 실패하고 warning만 출력

### 7.16 [Feature] Corpus/Graphs 폴더 초기화

**구현**: `run()` 시작 시 `shutil.rmtree()`로 `output/corpus/`, `output/graphs/` 삭제 후 재생성. 이전 실행 데이터와 혼합 방지.

---

## 8. v4.4 개선사항

### 8.1 [Feature] Tracking Label NVMe 스펙 매핑

**문제**: v4.3에서 opcode_override 사용 시 `Identify_Controller_op0xD1`처럼 **원래 명령어명을 접두사로 붙였으나**, opcode가 변형된 시점에서 해당 명령어와는 무관하다. 예를 들어 Identify(0x06) 시드에서 opcode가 0x0A로 변형되면 실제로는 GetFeatures 명령어인데 `Identify_op0x0A`로 표시됨.

**수정**:
- `_OPCODE_TO_NAME` 역방향 매핑 테이블 도입: `(opcode, "admin"|"io")` → 명령어 이름
- Admin/IO 타입을 고려하여 동일 opcode를 구분 (예: 0x02 → Admin=`GetLogPage`, IO=`Read`)
- `_tracking_label()` 로직 변경:

```python
# v4.3: 항상 원래 명령어명 + opcode 접미사
return f"{cmd.name}_op0x{seed.opcode_override:02X}"
# 예: Identify_op0x0A, Identify_op0xD1

# v4.5: NVMe 스펙 매핑 우선, 없으면 unknown
spec_name = _OPCODE_TO_NAME.get((opcode, actual_type))
if spec_name is not None:
    return spec_name          # 예: GetFeatures (0x0A가 스펙에 있으므로)
return f"unknown_op0x{opcode:02X}"  # 예: unknown_op0xD1 (스펙에 없음)
```

**동작 예시**:

| 원래 명령어 | opcode_override | force_admin | v4.3 결과 | v4.5 결과 |
|---|---|---|---|---|
| Identify | 없음 | 없음 | `Identify` | `Identify` |
| Identify | 0x0A | 없음 | `Identify_op0x0A` | `GetFeatures` |
| Identify | 0xD1 | 없음 | `Identify_op0xD1` | `unknown_op0xD1` |
| Identify | 0x02 | 없음 (Admin) | `Identify_op0x02` | `GetLogPage` |
| Read | 0x02 | 없음 (IO) | `Read_op0x02` | `Read` |
| Read | 0x06 | True (→Admin) | `Read_op0x06` | `Identify` |
| Read | 0x84 | True (→Admin) | `Read_op0x84` | `Sanitize` |
| Read | 0xC5 | 없음 (IO) | `Read_op0xC5` | `unknown_op0xC5` |

**영향**: Per-command stats, Return code distribution, 히트맵, CFG 그래프 모두 자동 반영.

### 8.2 [BugFix] Heatmap 이미지 크기 초과

**문제**: opcode mutation으로 고유 추적 키(active_cmds)가 수백 개 이상 생성되면, 1D 히트맵의 행 수가 그에 비례하여 증가. `figsize=(18, 1.2 * n_rows + 1.5)`에서 `n_rows=500`이면 높이 601.5인치 → 150 DPI에서 90,225 픽셀 → matplotlib의 `Image size of 2700x81045 pixels is too large` 에러 발생.

**수정** (2단계 방어):

1. **명령어 수 상한 (MAX_HEATMAP_CMDS = 40)**: active_cmds가 40개를 초과하면 edge 수 기준 상위 40개만 히트맵에 표시. 나머지는 로그에서만 확인 가능.

```python
MAX_HEATMAP_CMDS = 40
if len(active_cmds) > MAX_HEATMAP_CMDS:
    active_cmds.sort(key=lambda n: len(self.cmd_edges.get(n, set())), reverse=True)
    active_cmds = sorted(active_cmds[:MAX_HEATMAP_CMDS])
```

2. **DPI 동적 조정**: figure 크기에 따라 DPI를 `min(150, 65000 / max_dimension_inches)`로 제한. 최소 50 DPI 보장.

### 8.3 [Feature] Timeout dmesg 캡처

**배경**: timeout 발생 시 SSD 펌웨어의 stuck PC만으로는 원인 분석이 불완전하다. 특히 SSD가 idle 상태(정상)인데 timeout이 발생한 경우, 커널 NVMe 드라이버의 동작(command abort, controller reset, PCIe FLR, interrupt 유실 등)을 확인해야 원인을 특정할 수 있다.

**구현**: `_capture_dmesg(lines=80)` 메서드 추가.

```python
def _capture_dmesg(self, lines: int = 80) -> str:
    result = subprocess.run(['dmesg', '--time-format=iso', '-T'],
                            capture_output=True, text=True, timeout=5)
    all_lines = result.stdout.strip().splitlines()
    return '\n'.join(all_lines[-lines:])
```

**timeout 처리 흐름** (v4.5):

```
1. J-Link로 stuck PC 20회 샘플링          ← v4.3
2. dmesg 마지막 80줄 캡처                  ← v4.5 NEW
3. dmesg에서 NVMe 관련 라인 요약 출력      ← v4.5 NEW
4. crash 저장 (stuck PC + dmesg 포함)      ← v4.5 확장
5. SSD 펌웨어 resume 상태 유지
6. NVMe 장치 상태 안내
7. 퍼징 중단
```

**출력 파일**:
- `crash_*.json`: `dmesg_snapshot` 필드에 전체 dmesg 텍스트 포함
- `crash_*.dmesg.txt`: 별도 텍스트 파일로도 저장 (JSON에 넣기엔 길 수 있으므로)

**로그 출력 예시**:
```
[TIMEOUT] 커널 로그(dmesg)를 캡처합니다...
  dmesg NVMe 관련 (3줄):
    [Wed Feb 11 14:23:01 2026] nvme nvme0: I/O tag 42 (0002) QID 1 timeout
    [Wed Feb 11 14:23:01 2026] nvme nvme0: Abort status: 0x0
    [Wed Feb 11 14:23:02 2026] nvme nvme0: controller reset complete
```

**활용 시나리오**:

| dmesg 패턴 | 의미 | stuck PC 상태 |
|---|---|---|
| `I/O tag timeout` + `controller reset` | 커널이 CQE 미수신 → 복구 수행 | idle (0x5dd4) → 명령 처리 완료됐으나 CQE/인터럽트 유실 |
| `I/O tag timeout` + `Abort status: 0x7` | abort 실패 → SSD가 명령을 아직 처리 중 | 비idle → 실제 hang |
| `PCIe FLR` | PCIe 기능 레벨 리셋 수행 | 무관 → 하드웨어 레벨 복구 |
| NVMe 관련 메시지 없음 | 커널 timeout 전에 Python timeout이 먼저 발생 | 확인 필요 |

---

## 9. v4.5 개선사항

### 9.1 [Feature] Hit Count Bucketing

**배경**: v4.4까지는 edge를 `Set`으로만 관리하여, 동일 edge가 1번 실행된 것과 100번 실행된 것의 차이를 감지할 수 없었다. 이는 루프 반복 횟수가 달라지는 행동(예: 에러 처리 재시도, 테이블 검색 깊이 변화)을 놓치는 원인이 된다.

**구현**:

1. **`_count_to_bucket()` 함수**: AFL++ 동일한 8단계 로그 버킷팅
   ```
   hit count:  1 → bucket 1
   hit count:  2 → bucket 2
   hit count:  3 → bucket 4
   hit count: 4~7 → bucket 8
   hit count: 8~15 → bucket 16
   hit count: 16~31 → bucket 32
   hit count: 32~127 → bucket 64
   hit count: 128+ → bucket 128
   ```

2. **데이터 구조** (`JLinkPCSampler`):
   - `global_edge_counts: Dict[edge, int]` — edge별 누적 hit count
   - `global_edge_buckets: Dict[edge, int]` — edge별 현재 bucket 값
   - `current_edge_counts: Dict[edge, int]` — 이번 실행의 hit count

3. **`_sampling_worker()`**: edge 생성 시 `current_edge_counts[edge] += 1`로 카운팅

4. **`evaluate_coverage()`**: 기존 새 edge 감지 + **bucket 변화 감지** 추가
   - 이미 알려진 edge라도 누적 hit count의 bucket이 변하면 interesting
   - 예: edge A가 총 3번 → 4번(bucket 4→8)이면 bucket_change 발생

5. **저장/로드**: `coverage_edge_counts.txt` 파일로 edge별 누적 count 영속화

**기대 효과**: 루프 구조 변화, 에러 핸들링 재시도 횟수 변화, 테이블 순회 깊이 변화 등으로 인한 새로운 행동을 감지.

### 9.2 [Feature] Calibration (시드 안정성 측정)

**배경**: PC 샘플링(halt-sample-resume)은 타이밍에 따라 같은 입력도 다른 edge를 생성할 수 있다. 불안정한 edge가 corpus에 반영되면 "새로운 커버리지"의 기준이 흔들려 퍼징 효율이 저하된다.

**구현**:

1. **`_calibrate_seed(seed, N=3)`**: 동일 시드를 N번 mutation 없이 실행
   - `edge_appearances[edge]` = 등장 횟수 추적
   - `stable_edges` = 모든 N회에서 등장한 edge (100% 재현)
   - `stability` = `|stable| / |all_seen|` (0.0~1.0)

2. **글로벌 커버리지 반영**: 안정한 edge만 `global_edges`에 추가
   - 불안정한 edge는 글로벌 기준에 포함되지 않아 false interesting 방지

3. **실행 시점**:
   - 퍼징 시작 전, 모든 초기 시드에 대해 calibration 실행
   - Seed dataclass에 `is_calibrated`, `stability`, `stable_edges` 필드 추가

4. **CLI**: `--calibration-runs 3` (기본), `--calibration-runs 0`으로 비활성화 가능

**성능 영향**: 초기 시드 ~30개 × 3회 = ~90회 실행. 2~5 exec/s 기준 약 30초~1분 소요.

#### 9.2.1 [BugFix] Calibration 중 DLL stderr 노이즈 억제

**증상**: calibration 시작 직후 아래 메시지가 다량 출력된 뒤 정상 동작:
```
Cannot read register 9 (R15 (PC)) while CPU is running
CPU is not halted
```

**원인**: `JLINKARM_Halt()`(raw DLL call)는 fire-and-forget — halt 요청을 보내고 CPU 정지를 확인하지 않고 즉시 반환한다. 바로 이어지는 `JLINKARM_ReadReg()`가 CPU가 아직 running 상태일 때 호출되면 DLL이 stderr에 직접 경고를 출력한다. Python의 `except Exception`은 DLL 수준 stderr 출력을 막지 못한다.

일반 퍼징에서는 NVMe 명령 처리 시간(수 ms)이 자연적인 완충 역할을 하므로 문제가 드러나지 않는다. calibration은 `stop_sampling()` → `start_sampling()`을 딜레이 없이 반복하는 tight loop라 타이밍 위반이 빈번히 발생한다.

**수정**: calibration 블록 전체를 fd 수준으로 stderr 억제. Python `sys.stderr`가 아닌 OS fd 2를 직접 교체해야 DLL 출력도 차단된다.

```python
devnull_fd = os.open(os.devnull, os.O_WRONLY)
saved_stderr_fd = os.dup(2)
os.dup2(devnull_fd, 2)   # fd 2 → /dev/null (DLL stdout도 차단)
os.close(devnull_fd)
try:
    for seed in corpus:
        seed = self._calibrate_seed(seed)
        ...
finally:
    os.dup2(saved_stderr_fd, 2)   # 반드시 복원
    os.close(saved_stderr_fd)
```

#### 9.2.2 [BugFix] Calibration 이중 start_sampling → StableEdges 전부 0

**증상**: calibration 결과 테이블에서 모든 시드의 StableEdges 가 0으로 표시됨.

**원인**: `_calibrate_seed()` 내부 루프가 매 run 시작 시 `start_sampling()`을 명시적으로 호출하지만, `_send_nvme_command()` 내부에서도 `start_sampling()`을 다시 호출하는 이중 호출 구조:

```python
# 버그가 있는 원래 코드
for run_i in range(total_runs):
    self.sampler.start_sampling()              # Thread A 시작
    rc = self._send_nvme_command(seed.data, seed)
    #   ↑ 내부에서 start_sampling() 재호출 → Thread B 시작, current_edges = set() 리셋
    self.sampler.stop_sampling()               # Thread B만 join, Thread A는 zombie
```

문제 연쇄:
1. Thread B가 `current_edges = set()`으로 리셋 → Thread A가 이전에 수집한 edge 유실
2. `stop_sampling()`은 Thread B만 join. Thread A는 daemon thread로 살아남음
3. 다음 run에서 `stop_event.clear()` 시 Thread A가 다시 활성화되어 다음 run의 `current_edges`에 이전 run의 edge를 혼입
4. run이 쌓일수록 zombie thread가 누적 (run 1: zombie 1개, run 2: zombie 2개, run 3: zombie 3개)
5. 매 run의 edge 집합이 비결정적으로 오염 → 3회 run 모두에서 동일한 edge가 없음 → `stable = {}` → **StableEdges = 0**

**수정**: `_calibrate_seed()` 내부의 명시적 `start_sampling()` 제거. `_send_nvme_command()`가 이미 내부에서 `start_sampling()`을 호출하므로 외부에서 별도 호출 불필요. 메인 퍼징 루프와 동일한 패턴:

```python
# 수정된 코드
for run_i in range(total_runs):
    rc = self._send_nvme_command(seed.data, seed)  # 내부에서 start_sampling() 호출
    self.sampler.stop_sampling()                   # 정확히 1:1 대응
```

#### 9.2.3 [Feature] Calibration 결과 요약 테이블

calibration 완료 후, 시드별 결과를 표 형식으로 정리하여 출력하고 퍼징을 시작한다:

```
[Calibration] Results:
────────────────────────────────────────────────────────────────
   # Command              Stability  StableEdges   AllEdges
────────────────────────────────────────────────────────────────
   1 Identify              100.0%          42          42
   2 GetLogPage             83.3%          35          42
   3 GetFeatures            91.7%          78          85
  ...
────────────────────────────────────────────────────────────────
  Seeds: 26  |  Global stable edges: 847  |  Avg stability: 94.2%
────────────────────────────────────────────────────────────────
[Calibration] Complete. Starting fuzzing...
```

기존에는 각 시드가 `log.info` 한 줄씩 출력되어 전체 결과를 파악하기 어려웠다.

### 9.3 [Feature] Deterministic Stage (체계적 CDW 경계값 탐색)

**배경**: AFL++의 deterministic stage는 입력의 각 바이트/워드/더블워드에 대해 체계적으로 bitflip, arithmetic, interesting value 대입을 수행하여 새로운 경로를 빠르게 발견한다. NVMe 퍼저에서는 data payload 대신 **CDW 필드**(펌웨어 분기의 핵심)에 대해 이를 적용한다.

**대상 필드**: cdw10, cdw11, cdw12, cdw13, cdw14, cdw15 (값이 0인 필드는 건너뜀)

**Mutation 종류** (CDW 필드당):

| Phase | Mutation | 수량 |
|---|---|---|
| 1 | Walking bitflip (1bit) | 32개 |
| 2 | Arithmetic ±1~10 | 20개 |
| 3 | Interesting 32-bit 값 대입 | 8개 |
| 4 | 바이트별 interesting 8-bit 대입 | ~36개/필드 (중복 제외) |

총: 활성 CDW 필드당 ~96개, 6개 필드 전체 시 최대 ~576개/seed.

**구현**:

1. **`_deterministic_stage(seed)` 제너레이터**: 각 CDW 필드에 대해 mutation된 seed를 순차적으로 yield
2. **`_det_queue: deque`**: (seed, generator) 쌍을 관리
3. **메인 루프 통합**: `_det_queue`가 비어있지 않으면 havoc보다 우선 소비
4. **완료 처리**: `StopIteration` 발생 시 `seed.det_done = True`

**CLI**: `--no-deterministic`로 비활성화, `--det-arith-max 10`으로 arithmetic 범위 조정.

### 9.4 [Feature] MOpt (Mutation Operator Scheduling)

**배경**: AFL++의 16개 havoc mutation operator는 균등 확률(1/16)로 선택되지만, 실제로는 특정 operator가 더 효과적일 수 있다. MOpt(USENIX Security 2019)는 PSO 기반으로 operator 가중치를 동적으로 조정한다.

**구현** (Pilot/Core 2단계 모드):

1. **Pilot 단계** (기본 5000 실행):
   - 16개 operator를 균등 확률로 사용
   - 각 operator의 `finds` (새 커버리지 발견 횟수)와 `uses` (사용 횟수) 기록

2. **Core 단계** (기본 50000 실행):
   - Pilot 결과에서 성공률(`finds/uses`) 계산
   - 성공률 비례 가중치로 정규화 (최소 확률 0.01/16 보장)
   - 효과적인 operator에 더 높은 확률 부여

3. **모드 전환**: Core 종료 후 다시 Pilot로 돌아가며 통계 리셋 → 환경 변화에 적응

4. **Summary 출력**: operator별 finds/uses/성공률, 현재 모드, 가중치

**16개 operator 이름**:

| ID | 이름 | 설명 |
|---|---|---|
| 0 | bitflip1 | 1비트 반전 |
| 1 | int8 | interesting 8-bit 대입 |
| 2 | int16 | interesting 16-bit 대입 |
| 3 | int32 | interesting 32-bit 대입 |
| 4 | arith8 | 8-bit 산술 연산 |
| 5 | arith16 | 16-bit 산술 연산 |
| 6 | arith32 | 32-bit 산술 연산 |
| 7 | randbyte | 랜덤 바이트 대입 |
| 8 | byteswap | 바이트 교환 |
| 9 | delete | 바이트 삭제 |
| 10 | insert | 바이트 삽입 |
| 11 | overwrite | 바이트 덮어쓰기 |
| 12 | splice | 다른 seed에서 블록 복사 |
| 13 | shuffle | 블록 셔플 |
| 14 | blockfill | 블록을 고정값으로 채우기 |
| 15 | asciiint | ASCII 정수 삽입 |

**CLI**: `--no-mopt`로 비활성화 (기존 균등 확률), `--mopt-pilot-period 5000`, `--mopt-core-period 50000`.

---

## 10. 알려진 제한사항 및 향후 과제

### 10.1 구조적 한계

| 한계 | 설명 | 심각도 | 비고 |
|---|---|---|---|
| **PC 샘플링 해상도** | halt-sample-resume 방식은 모든 명령어를 캡처하지 못함. 짧은 함수는 놓칠 수 있음 | 중간 | - |
| ~~**Hit count 미지원**~~ | ~~동일 edge의 실행 횟수 변화를 감지 못함~~ | ~~높음~~ | **v4.5에서 해결** (hit count bucketing) |
| **subprocess 오버헤드** | 매 실행마다 fork+exec. exec/s 제한의 주 원인 | 중간 | 검토 완료: timeout 시 프로세스 kill이 필요하므로 subprocess 방식 유지 |
| **단일 코어 샘플링** | SSD가 멀티코어(예: Cortex-R8 듀얼)면 한 코어만 샘플링 | 높음 | 하드웨어 제약: J-Link 1개, JTAG/SWD 포트 1개로 불가 |
| ~~**비결정적 커버리지**~~ | ~~샘플링 타이밍에 따라 동일 입력도 다른 edge를 생성할 수 있음~~ | ~~중간~~ | **v4.5에서 완화** (calibration으로 안정성 측정 및 필터링) |

### 10.2 향후 개선 과제

| 과제 | 우선순위 | 설명 | 상태 |
|---|---|---|---|
| ~~Hit count bucketing~~ | ~~높음~~ | ~~edge별 hit count를 bucket화하여 "새로움" 기준 확장~~ | **v4.5 구현 완료** |
| ~~Calibration~~ | ~~중간~~ | ~~시드별 edge 안정성 측정, 불안정한 edge 필터링~~ | **v4.5 구현 완료** |
| ~~Deterministic stage~~ | ~~중간~~ | ~~초기 탐색에서 체계적 경계값 발견~~ | **v4.5 구현 완료** |
| ~~MOpt (mutator scheduling)~~ | ~~중간~~ | ~~mutation 연산자별 효과 추적 및 가중치 조정~~ | **v4.5 구현 완료** |
| Entropic scheduling | 중간 | 정보 이론 기반 시드 스케줄링 (corpus 성숙 후 AFLFast 대체) | 미구현 |
| NVMe 구조 인식 mutation | 중간 | Peach Pit 방식 CDW 필드별 의미론적 mutation | 미구현 |
| Directed fuzzing | 높음 | Ghidra CFG 기반 거리맵으로 특정 코드 영역 집중 탐색 | 미구현 |
| 크래시 서명 자동 분류 | 중간 | crash_pc + fault 레지스터 + NVMe status code 기반 서명 | 미구현 |
| ~~ioctl 직접 호출~~ | ~~높음~~ | ~~subprocess 대신 Python에서 직접 NVMe ioctl 호출~~ | **검토 완료: 불채택** (subprocess kill 필요) |
| ~~Trimming~~ | ~~낮음~~ | ~~불필요한 바이트 제거~~ | **검토 완료: 불필요** (NVMe CDW 고정 크기) |
| ~~멀티코어 샘플링~~ | ~~높음~~ | ~~복수 J-Link 또는 SMP 지원~~ | **검토 완료: 불가** (J-Link 1개, JTAG 포트 1개) |
| ~~QEMU 기반 에뮬레이션~~ | ~~장기~~ | ~~하드웨어 없이도 퍼징 가능~~ | **검토 완료: 불채택** (실제 HW 테스트 목적에 무의미) |

---

## 11. 관련 연구 및 도입 가능 기술

### 11.1 본 프로젝트의 학술적 위치

본 퍼저는 학술 문헌에서 독자적 위치를 차지한다:

1. **GDBFuzz, µAFL과 같은 Hardware-in-the-loop** 방식이지만, MCU(Cortex-M)가 아닌 스토리지 컨트롤러(Cortex-R8)를 대상으로 하며, HW breakpoint(GDBFuzz)나 ETM trace(µAFL) 대신 통계적 PC 샘플링을 사용
2. **State Data-Aware SSD Fuzzer와 같은 도메인 특화** 퍼저이지만, 에뮬레이션(FEMU)이 아닌 실 하드웨어에서 동작하여 진정한 펌웨어 커버리지를 수집
3. **kAFL, PTfuzz와 같은 하드웨어 트레이스 기반** 접근이지만, Intel PT가 없는 ARM JTAG 환경에 적응
4. **SPDK NVMe fuzzer와 같은 NVMe 인식** 퍼저이지만, 블랙박스 명령 랜덤화가 아닌 펌웨어 측 커버리지 피드백을 활용

핵심 독창성은 (a) J-Link JTAG halt-sample-resume으로 실 Cortex-R8 SSD 컨트롤러에서 `(prev_pc, cur_pc)` edge 커버리지 수집, (b) NVMe passthru 명령 주입을 입력 벡터로 사용, (c) 커버리지 가이드 mutation으로 표준 I/O 워크로드로는 도달하기 어려운 펌웨어 코드 경로를 체계적으로 탐색하는 조합이다.

### 11.2 Hardware-in-the-Loop 펌웨어 퍼징

| 이름 | 저자 / 연도 | 학회 | 접근 방식 | 본 프로젝트와의 관계 |
|------|------------|------|-----------|---------------------|
| **GDBFuzz** | Eisele et al. / 2023 | ISSTA 2023 | GDB 하드웨어 breakpoint로 uninstrumented 펌웨어의 basic-block 커버리지 수집. Breakpoint 회전으로 탐색 범위 확장 | **가장 유사한 선행 연구.** Halt-breakpoint-resume 루프가 우리의 halt-sample-resume과 구조적으로 동일. 단, HW breakpoint 수 제한(4~8개) → breakpoint 회전 병목 발생. 우리는 통계적 샘플링으로 이를 회피 |
| **µAFL** | Li et al. / 2022 | ICSE 2022 | ARM ETM(Embedded Trace Macrocell) 하드웨어 트레이싱으로 MCU 펌웨어의 완전한 분기 트레이스 수집. 10 zero-day (8 CVE) 발견 | **핵심 비교 대상.** ETM은 완전한 트레이스를 제공하지만 CoreSight 인프라(ETM+TPIU+trace port) 필요. Cortex-R8 SSD 컨트롤러는 ETM 핀 미노출 가능 → 우리의 JTAG halt-sample이 실용적 대안 |
| **Ember-IO** | Farrelly et al. / 2023 | ASIA CCS 2023 | 모델 프리 MMIO 퍼징. QEMU에서 AFL++로 실행하되 주변장치 모델링 없이 raw fuzzer 입력을 MMIO에 직접 전달 | SSD 펌웨어의 복잡한 주변장치(Flash, DRAM, NVMe IP)는 모델링이 어려움 → hardware-in-the-loop 필요성 동기 부여 |

### 11.3 펌웨어 Rehosting / 에뮬레이션 기반 퍼징

| 이름 | 저자 / 연도 | 학회 | 핵심 기법 | SSD 퍼징 적용성 |
|------|------------|------|-----------|----------------|
| **Fuzzware** | Scharnowski et al. / 2022 | USENIX Security 2022 | 정밀 MMIO 모델링으로 입력 공간 95.5% 축소. 15 버그 (12 CVE) | MMIO 모델링 아이디어는 NVMe mutation 구조화에 참고 가능. 단, SSD 주변장치 복잡도로 직접 적용 불가 |
| **HALucinator** | Clements et al. / 2020 | USENIX Security 2020 | HAL 함수 교체로 펌웨어 rehosting | SSD는 독자 HAL → 직접 적용 불가. 라이브러리 매칭 기법은 Ghidra 분석에 활용 |
| **P2IM** | Feng et al. / 2020 | USENIX Security 2020 | 자동 주변장치 인터페이스 모델링 | SSD의 NVMe+Flash 주변장치 세트는 P2IM 대상보다 훨씬 복잡 |
| **DICE** | Mera et al. / 2021 | IEEE S&P 2021 | DMA 입력 채널 자동 에뮬레이션 | **관련성 높음.** SSD는 NVMe CQ/SQ 처리와 Flash 데이터 전송에 DMA 광범위 사용. Rehosting 시 DICE 수준 DMA 인식 필수 |
| **FirmWire** | Hernandez et al. / 2022 | NDSS 2022 | 셀룰러 베이스밴드 전체 시스템 에뮬레이션 | 베이스밴드↔SSD 유사성: 독자 실시간 펌웨어 + 프로토콜 스택. 충분한 리버싱으로 에뮬레이션 가능함을 시사 |
| **Jetset** | Johnson et al. / 2021 | USENIX Security 2021 | 심볼릭 실행으로 주변장치 동작 추론 후 C 디바이스 모델 합성 | Flash 이외 서브시스템의 부분 rehosting에 활용 가능 |
| **FIRM-AFL** | Zheng et al. / 2019 | USENIX Security 2019 | 증강 프로세스 에뮬레이션 (시스템 모드 + 유저 모드 전환)으로 8.2x 처리량 향상 | 하이브리드 개념: 초기 탐색은 실 하드웨어, 이미 탐색된 경로는 에뮬레이션으로 고속 mutation |
| **SyzTrust** | Wang et al. / 2024 | IEEE S&P 2024 | TEE OS 상태 인식 퍼징. 코드 커버리지 + 상태 커버리지 66% 향상, 70 취약점 | **상태 인식 접근 직접 적용 가능.** SSD 내부 상태(FTL 매핑, GC 상태, 마모도)를 퍼징 전략에 반영하면 경로 탐색 대폭 개선 |

### 11.4 하드웨어 트레이스 기반 커버리지

| 이름 | 저자 / 연도 | 학회 | 트레이스 방식 | 본 퍼저와의 비교 |
|------|------------|------|-------------|-----------------|
| **kAFL** | Schumilo et al. / 2017 | USENIX Security 2017 | Intel PT로 OS 커널 분기 트레이스 수집. KVM/QEMU 기반 | **아키텍처적 영감.** Intel PT = x86 하드웨어 트레이스, 우리의 PC 샘플링 = ARM JTAG 하드웨어 커버리지. 핵심 차이: PT는 완전한 분기 트레이스, 우리는 통계적 샘플 |
| **CROWBAR** | Shan et al. / 2023 | J. HW & Sys Security 2023 | ARM CoreSight ETM/ETB로 TEE 내부 커버리지 수집 | **가장 관련 높은 ARM 트레이스 연구.** Cortex-R8에 CoreSight 트레이스가 노출되면 CROWBAR 방식으로 PC 샘플링을 대체/보완 가능 |
| **PTfuzz** | Zhang et al. / 2018 | IEEE Access 2018 | Intel PT 패킷을 AFL 호환 edge 커버리지 맵으로 디코딩 | PT 패킷→edge 맵 변환 파이프라인이 우리의 `(prev_pc, cur_pc)`→edge set 변환과 구조적으로 동일 |

### 11.5 NVMe / 스토리지 퍼징

| 이름 | 저자 / 연도 | 설명 | 본 프로젝트와의 관계 |
|------|------------|------|---------------------|
| **State Data-Aware SSD Fuzzer** | Yoon, Lee / 2025 | FEMU(NVMe SSD 에뮬레이터)에서 AFL++로 FTL/GC 상태 인식 퍼징. 67.3% 적은 명령으로 100% I/O 코드 커버리지 | **가장 직접적으로 비교 가능한 SSD 퍼징 연구.** 단, 에뮬레이션 기반 vs 우리는 실 하드웨어. 이들의 상태 인식 mutation 전략을 우리 퍼저에 도입하면 효과적 |
| **UNH-IOL NVMe 적합성 테스트** | UNH / Ongoing | NVM Express Inc.와 공동 개발한 공식 NVMe 적합성/상호운용성 테스트 스위트 | 정상/경계값 NVMe 명령의 구조화된 corpus → 고품질 시드 입력으로 활용 가능 |
| **SPDK NVMe Fuzzer** | Intel / 2023 | SPDK 내장 NVMe 퍼저(`nvme_fuzz`). LibFuzzer 통합, NVMe-oF 및 물리 드라이브 대상 | NVMe 명령 랜덤화 참조 구현. 우리 퍼저에 SPDK의 명령 생성 로직 + JTAG 커버리지 피드백 결합 가능 |
| **FEMU** | Li et al. / 2018 | QEMU 기반 NVMe SSD 에뮬레이터. FTL, GC, Flash 지연 모델링 | 실 하드웨어 배포 전 퍼징 전략 프로토타이핑용 소프트웨어 테스트베드 |
| **pydiskcmd** | jackeichen | Python으로 NVMe/SATA/SAS raw 명령 전송 (ioctl 직접 호출) | **도입 후보.** nvme-cli subprocess 대체 → fork/exec 오버헤드 제거, mutation 엔진과 긴밀 통합 |

### 11.6 샘플링 기반 커버리지 개선 기법

우리 퍼저의 핵심 한계는 halt-sample-resume 방식의 **손실성 커버리지**이다. 관련 연구에서 도출한 개선 방안:

| 기법 | 출처 | 핵심 아이디어 | 적용 방안 |
|------|------|-------------|-----------|
| **Species Richness Estimation** | Liyanage, Böhme / ICSE 2023 | 생태학의 종 다양성 추정기(Chao1, Jackknife)를 퍼징에 적용. 관찰된 edge로부터 총 도달 가능 edge 수 추정 | 관찰된 `(prev_pc, cur_pc)` edge에 Chao1 적용 → 미발견 edge 수 추정. 포화 판정 개선 |
| **Sampling Bias 보정** | Lianghong et al. / APSys 2020 | PEBS 기반 PC 샘플링의 "shadow effect" — resume 직후 코드가 체계적으로 과소 샘플링됨 | 샘플 간격을 랜덤화(jitter)하여 편향 감소. 고정 간격은 주기적 펌웨어 동작과 aliasing 유발 |
| **Adaptive Tracing** | Nagy, Hicks / S&P 2019 (UnTracer) | 새 커버리지 발견 비율이 0.01% 미만이면 트레이싱 생략 | **적응적 샘플링**: 대부분의 실행은 최소 샘플링(crash 감지만), 흥미로운 입력에만 집중 샘플링. 처리량 10-100x 향상 기대 |
| **Count-Min Sketch** | Cormode / J. Algorithms 2005 | 확률적 자료구조로 O(1) 공간에서 근사 빈도 추정 | edge hit count 근사치 추적. 정확한 카운트 불필요 — "1회 vs 100회"만 구분하면 충분 |
| **Rarity 가중 커버리지** | Wang et al. / NDSS 2020 | 희귀 edge에 높은 가중치 부여. edge 존재만으로는 행동 차이 포착 불가 | PC 샘플링은 핫 edge에 편향 → 역빈도 가중(1/(global_count+1))으로 희귀 edge 보정 |

### 11.7 시드 스케줄링 및 Mutation 최적화

| 기법 | 출처 | 접근 방식 | 도입 우선순위 |
|------|------|-----------|-------------|
| **AFLFast (explore)** | Böhme et al. / CCS 2016 | 경로 빈도의 역수에 비례하는 에너지 할당. 적게 실행된 시드 우선 | **현재 구현됨.** 초기 탐색 단계에 적합 |
| **Entropic** | Böhme et al. / FSE 2020 | 정보 엔트로피 기반. 희귀 feature를 가진 시드에 높은 에너지 | **높음.** 샘플링 편향 보정에 최적. corpus가 충분히 커지면 AFLFast에서 전환 권장 |
| **MOpt** | Lyu et al. / USENIX Security 2019 | PSO(Particle Swarm Optimization)로 mutation 연산자 확률 동적 최적화 | **중간.** 16종 havoc + NVMe 특화 mutation 중 어떤 것이 효과적인지 자동 학습 |
| **EcoFuzz** | Yue et al. / USENIX Security 2020 | Multi-Armed Bandit으로 비생산적 시드의 에너지 절약 | **높음.** JTAG 오버헤드로 처리량이 낮으므로 에너지 보존이 매우 중요 |
| **K-Scheduler** | She et al. / S&P 2022 | CFG 중심성(Katz centrality)으로 미탐색 영역 진입 시드 우선 | **높음 (Ghidra 통합 시).** 펌웨어 CFG에서 미탐색 코드 영역까지의 거리 계산 가능 |

**권장 도입 순서**: AFLFast explore (현재) → Entropic (corpus 성숙 시) → K-Scheduler (Ghidra CFG 가용 시)

### 11.8 프로토콜 인식 퍼징 / 문법 기반 Mutation

| 기법 | 출처 | 핵심 아이디어 | NVMe 퍼징 적용 |
|------|------|-------------|---------------|
| **AFLSmart** | Pham et al. / TSE 2019 | Peach Pit 입력 모델로 구조 인식 mutation. 42 zero-day (22 CVE) | NVMe 64-byte 명령 구조를 Peach Pit으로 정의. 필드 단위 mutation → 초기 파싱 통과 후 심층 코드 도달 |
| **Nautilus** | Aschermann et al. / NDSS 2019 | 문맥 자유 문법 + 커버리지 피드백. 파스 트리 기반 mutation | NVMe 명령 시퀀스를 트리로 정의 (root=시퀀스, 자식=개별 명령, 명령의 자식=typed 필드) |
| **Peach Fuzzer** | Eddington / 2004-2020 | XML 기반 데이터 모델(Peach Pit)로 프로토콜 구조 정의 | NVMe Peach Pit: opcode별 CDW10-15 시맨틱스, admin/IO 큐 구분, SQ/CQ 프로토콜 모델링 |

**권장**: 구조 인식 mutation과 AFL 스타일 havoc를 약 50:50 비율로 혼합 (AFLSmart 권장 비율)

### 11.9 Directed 퍼징 및 정적 분석 연동

| 기법 | 출처 | 접근 | SSD 퍼징 적용 |
|------|------|------|--------------|
| **AFLGo** | Böhme et al. / CCS 2017 | Simulated annealing으로 타겟 위치까지의 거리 기반 에너지 할당 | Ghidra에서 추출한 CFG/CG로 오프라인 거리 계산. 타겟: 에러 핸들러, vendor 명령 처리기, FTL 엣지 케이스 |
| **DRIFT** | Hetzelt et al. / 2024 | LibAFL + Ghidra 기반 바이너리 directed 퍼징. AFLGo 대비 2x 버그 발견, 9-40x 빠른 exploit | Ghidra로 SSD 펌웨어 디스어셈블 → CFG 추출 → 거리 맵 계산 → power schedule에 거리 메트릭 통합 |

**오프라인/온라인 아키텍처**:
1. **오프라인 (Ghidra)**: 펌웨어 디스어셈블 → CFG 복원 → 타겟 위치 식별 → 최단 경로 거리 맵 계산
2. **온라인 (퍼저)**: PC 샘플의 타겟 거리 lookup → 시드 거리 = 관찰된 최소 거리 → 거리의 역수로 에너지 할당

### 11.10 크래시 분류 및 Concolic 접근

**PC 샘플 기반 크래시 분류** (Igor/CCS 2021, DeFault/ICSE 2022 참조):

```
crash_signature = hash(
    crash_pc,                       # 크래시 지점
    fault_type,                     # ARM DFSR/IFSR 값
    fault_address >> 12,            # DFAR 페이지
    last_3_unique_sampled_prev_pcs, # 근사 콜 체인
    nvme_status_code                # 프로토콜 레벨 에러
)
```

**경량 Concolic 실행** (QSYM/USENIX Security 2018, SymCC/USENIX Security 2020 참조):
- NVMe 명령은 64바이트로 심볼릭 입력 크기가 작음 → concolic 실행에 적합
- cdw10-cdw15 (24바이트)만 심볼릭화, 나머지는 concrete 유지
- 커버리지 정체 시: JTAG로 CPU halt → 레지스터/SRAM 덤프 → angr에 로드 → 분기 해결 → 새 입력 생성

### 11.11 도입 가능 도구

| 도구 | 유형 | 용도 | 통합 방안 |
|------|------|------|-----------|
| **Ghidra + Dragon Dance/Cartographer** | 커버리지 시각화 | 디스어셈블리/그래프 위에 커버리지 오버레이 | `(prev_pc, cur_pc)` edge를 drcov 포맷으로 내보내기 → Ghidra에서 미커버 영역 식별 |
| **IDA Pro + Lighthouse** | 커버리지 시각화 | 함수별 커버리지 개요, Xref 탐색 | 어떤 NVMe 명령이 어떤 펌웨어 경로를 실행하는지 시각적 분석 |
| **pydiskcmd** | NVMe ioctl 라이브러리 | Python에서 직접 NVMe 명령 전송 | nvme-cli subprocess 대체 → fork/exec 오버헤드 제거 |
| **LibAFL** | Rust 퍼징 프레임워크 | 모듈형 퍼저 구축 (Executor, Observer, Mutator, Scheduler) | 장기 목표: Custom Executor(J-Link) + MapObserver(edge map) + HavocMutator + MOpt |
| **SEGGER SystemView** | 실시간 트레이스 | RTT로 인터럽트/태스크 타이밍 시각화 | NVMe 인터럽트 핸들링, 백그라운드 GC 타이밍 관찰 |
| **OpenOCD** | 오픈소스 디버그 프로브 | JTAG/SWD 인터페이스 (J-Link SDK 대안) | 벤더 독립성 확보. 단, halt-resume 오버헤드가 J-Link SDK보다 클 수 있음 |

### 11.12 우선순위별 도입 권장사항

| 우선순위 | 기법 | 구현 난이도 | 기대 효과 |
|---------|------|-----------|-----------|
| 1 | Rarity 가중 edge 존재 (10.6) | 낮음 | 높음 — 샘플링 편향 보정 |
| 2 | Entropic 정보 이론 스케줄링 (10.7) | 중간 | 높음 — 정보량 높은 시드 우선 |
| 3 | NVMe 구조 인식 mutation via Peach Pit (10.8) | 중간 | 높음 — 심층 펌웨어 코드 도달 |
| 4 | 적응적 샘플링 (UnTracer 기반) (10.6) | 낮음 | 중간 — 실효 처리량 대폭 증가 |
| 5 | pydiskcmd ioctl 직접 호출 (10.11) | 낮음 | 중간 — subprocess 오버헤드 제거 |
| 6 | 크래시 서명 (PC + fault 레지스터) (10.10) | 낮음 | 중간 — 트레이스 없이 분류 가능 |
| 7 | MOpt mutation 스케줄링 (10.7) | 중간 | 중간 — NVMe 특화 연산자 최적 배합 |
| 8 | Directed 퍼징 via Ghidra 거리 (10.9) | 높음 | 높음 — 특정 펌웨어 함수 타겟 |
| 9 | 경량 concolic on CDW 필드 (10.10) | 높음 | 중간 — 복잡 조건 돌파 |

---

## 12. 실행 방법 및 CLI 옵션

### 12.1 기본 실행 (안전 명령어만)

```bash
sudo python3 pc_sampling_fuzzer_v4.5.py
```

### 12.2 특정 명령어 지정

```bash
sudo python3 pc_sampling_fuzzer_v4.5.py --commands Read Write GetFeatures
```

### 12.3 전체 명령어 (파괴적 포함)

```bash
sudo python3 pc_sampling_fuzzer_v4.5.py --all-commands
```

### 12.4 전체 CLI 옵션

| 옵션 | 기본값 | 설명 |
|---|---|---|
| `--device` | Cortex-R8 | J-Link 타겟 디바이스 |
| `--nvme` | /dev/nvme0 | NVMe 장치 경로 |
| `--namespace` | 1 | NVMe 네임스페이스 ID |
| `--commands` | (기본 5개) | 활성화할 명령어 이름 |
| `--all-commands` | False | 파괴적 명령어 포함 전체 활성화 |
| `--speed` | 12000 | JTAG 속도 (kHz) |
| `--runtime` | 3600 | 총 퍼징 시간 (초) |
| `--output` | ./output/pc_sampling_v4.5/ | 출력 디렉토리 |
| `--samples` | 500 | 실행당 최대 샘플 수 |
| `--interval` | 0 | 샘플 간격 (us) |
| `--post-cmd-delay` | 0 | 명령 완료 후 추가 샘플링 (ms) |
| `--addr-start` | 0x00000000 | 펌웨어 .text 시작 주소 |
| `--addr-end` | 0x00147FFF | 펌웨어 .text 종료 주소 |
| `--resume-coverage` | None | 이전 coverage.txt 경로 |
| `--saturation-limit` | 10 | idle PC 연속 감지 임계값 |
| `--global-saturation-limit` | 20 | 글로벌 edge 포화 임계값 |
| `--max-energy` | 16.0 | Power Schedule 최대 에너지 |
| `--random-gen-ratio` | 0.2 | 완전 랜덤 입력 비율 |
| `--exclude-opcodes` | (없음) | 제외할 opcode 목록 (e.g., `"0xC1,0xC0"`) |
| `--opcode-mut-prob` | 0.10 | opcode mutation 확률 (0=비활성화) |
| `--nsid-mut-prob` | 0.10 | NSID mutation 확률 (0=비활성화) |
| `--admin-swap-prob` | 0.05 | Admin↔IO 교차 확률 (0=비활성화) |
| `--datalen-mut-prob` | 0.08 | data_len 불일치 확률 (0=비활성화) |
| `--seed-dir` | None | 시드 디렉토리 경로 (이전 corpus를 시드로 재활용) |
| `--timeout GROUP MS` | (그룹별 기본값) | 타임아웃 그룹별 오버라이드 |
| `--calibration-runs` | 3 | 초기 시드당 calibration 실행 횟수 (0=비활성화) |
| `--no-deterministic` | False | Deterministic stage 비활성화 |
| `--det-arith-max` | 10 | Deterministic arithmetic 최대 delta |
| `--no-mopt` | False | MOpt mutation scheduling 비활성화 |
| `--mopt-pilot-period` | 5000 | MOpt pilot 단계 실행 횟수 |
| `--mopt-core-period` | 50000 | MOpt core 단계 실행 횟수 |

---

## 13. 출력 디렉토리 구조

```
output/pc_sampling_v4.5/
├── fuzzer_YYYYMMDD_HHMMSS.log    # 실행 로그
├── coverage.txt                   # 글로벌 PC 커버리지 (hex, 줄당 1개)
├── coverage_edges.txt             # 글로벌 edge 커버리지 (hex,hex 줄당 1개)
├── coverage_edge_counts.txt       # v4.5: edge별 누적 hit count (hex,hex,count)
├── .nvme_input.bin                # NVMe 입력 데이터 (재사용, 임시)
├── corpus/                        # interesting 입력 저장
│   ├── input_Read_0x2_a1b2c3d4e5f6
│   ├── input_Read_0x2_a1b2c3d4e5f6.json   # CDW 메타데이터
│   ├── input_Write_0x1_...
│   └── ...
├── crashes/                       # timeout/crash 입력 저장
│   ├── crash_Identify_0x6_...
│   ├── crash_Identify_0x6_....json       # crash 메타데이터 + 이유
│   ├── crash_Identify_0x6_....dmesg.txt  # v4.5: 커널 로그 스냅샷
│   └── ...
└── graphs/                        # 시각화 출력
    ├── summary.json               # 명령어별 edge/PC 수 요약
    ├── Read_edges.json            # 명령어별 edge/PC/trace 데이터
    ├── Read_cfg.dot               # CFG 그래프 (DOT)
    ├── Read_cfg.png               # CFG 그래프 (PNG, graphviz 필요)
    ├── Write_edges.json
    ├── Write_cfg.dot
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
