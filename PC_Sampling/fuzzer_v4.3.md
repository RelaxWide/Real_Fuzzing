# PC Sampling 기반 SSD 펌웨어 Coverage-Guided Fuzzer — 기술 보고서

**버전**: v4.3
**최종 수정**: 2026-02-10
**파일**: `pc_sampling_fuzzer_v4.3.py`

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
8. [알려진 제한사항 및 향후 과제](#8-알려진-제한사항-및-향후-과제)
9. [실행 방법 및 CLI 옵션](#9-실행-방법-및-cli-옵션)
10. [출력 디렉토리 구조](#10-출력-디렉토리-구조)

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

- **Thread Safety**: CPython GIL 하에서 `set.__contains__`, `set.add`는 원자적. 메인 스레드와 샘플링 스레드가 `global_edges`를 동시 접근하지만, 직렬화된 호출 순서(stop → evaluate → start)로 실제 동시성 문제 없음.

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
| GetLogPage NUMDL 과대 | 15% | (고정) | 스펙 초과 크기의 로그 요청 |

**일반 명령어만으로 퍼징** (확장 mutation 전부 비활성화):
```bash
python3 pc_sampling_fuzzer_v4.3.py \
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
| Corpus management | 구현 완료 | interesting → corpus 추가 + AFL++ 방식 culling (1000회마다) |
| Crash detection | 구현 완료 | timeout → crash 저장 |
| Resume (coverage reload) | 구현 완료 | coverage.txt + coverage_edges.txt 로드 |

### 5.2 미구현 기능

| AFL++ 기능 | 영향 | 비고 |
|---|---|---|
| **Deterministic stages** | 중간 | bitflip walking, arith walking, dictionary. 초기 탐색에서 체계적 경계값 발견에 유용하나, AFL++에서도 `-d` 옵션으로 skip 가능 |
| **Hit count bucketing** | 높음 | 동일 edge를 1번 vs 100번 실행하는 차이를 감지 못함. 루프 반복 횟수 변화로 인한 새로운 행동 발견 불가 |
| **Trimming** | 낮음 | 시드 크기가 점진적으로 커질 수 있으나, NVMe 명령 구조상 데이터 크기가 제한적 |
| **Fork server** | 해당 없음 | NVMe 하드웨어 퍼징이므로 fork server 개념 자체가 적용 불가. subprocess 오버헤드는 별도 문제 |
| **Calibration** | 중간 | 시드별 실행 시간/edge 안정성을 모름. 불안정한 edge가 corpus를 오염시킬 수 있음 |
| **Cmplog/Redqueen** | 낮음 | 매직 바이트 자동 탐색. NVMe 명령 구조는 이미 스펙 기반 시드로 커버 |
| **Dictionary** | 낮음 | NVMe 스펙 기반 시드가 사실상 dictionary 역할 |
| **MOpt (mutator scheduling)** | 중간 | mutation 연산자별 효과를 추적하여 가중치 조정. 현재는 균등 확률 |

> **v4.3에서 추가 구현된 AFL++ 기능**: corpus culling (favored seed 선정 + 비기여 seed 제거)

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

**구현**: `_cull_corpus()` 메서드, 1000회마다 실행.
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

## 8. 알려진 제한사항 및 향후 과제

### 8.1 구조적 한계

| 한계 | 설명 | 심각도 |
|---|---|---|
| **PC 샘플링 해상도** | halt-sample-resume 방식은 모든 명령어를 캡처하지 못함. 짧은 함수는 놓칠 수 있음 | 중간 |
| **Hit count 미지원** | 동일 edge의 실행 횟수 변화를 감지 못함. 루프 관련 버그 발견 어려움 | 높음 |
| **subprocess 오버헤드** | 매 실행마다 fork+exec. exec/s 제한의 주 원인 | 중간 |
| **단일 코어 샘플링** | SSD가 멀티코어(예: Cortex-R8 듀얼)면 한 코어만 샘플링 | 높음 |
| **비결정적 커버리지** | 샘플링 타이밍에 따라 동일 입력도 다른 edge를 생성할 수 있음 | 중간 |

### 8.2 향후 개선 과제

| 과제 | 우선순위 | 설명 |
|---|---|---|
| Hit count bucketing | 높음 | edge별 hit count를 bucket화하여 "새로움" 기준 확장 |
| ioctl 직접 호출 | 높음 | subprocess 대신 Python에서 직접 NVMe ioctl 호출하여 fork 오버헤드 제거 |
| Calibration | 중간 | 시드별 edge 안정성 측정, 불안정한 edge 필터링 |
| Deterministic stage | 중간 | 초기 탐색에서 체계적 경계값 발견 |
| Trimming | 낮음 | 불필요한 바이트 제거로 시드 최소화 |
| MOpt (mutator scheduling) | 중간 | mutation 연산자별 효과 추적 및 가중치 조정 |
| 멀티코어 샘플링 | 높음 | 복수 J-Link 또는 SMP 지원 |
| QEMU 기반 에뮬레이션 | 장기 | 하드웨어 없이도 퍼징 가능하도록 SSD 펌웨어 에뮬레이션 |

---

## 9. 실행 방법 및 CLI 옵션

### 9.1 기본 실행 (안전 명령어만)

```bash
sudo python3 pc_sampling_fuzzer_v4.3.py
```

### 9.2 특정 명령어 지정

```bash
sudo python3 pc_sampling_fuzzer_v4.3.py --commands Read Write GetFeatures
```

### 9.3 전체 명령어 (파괴적 포함)

```bash
sudo python3 pc_sampling_fuzzer_v4.3.py --all-commands
```

### 9.4 전체 CLI 옵션

| 옵션 | 기본값 | 설명 |
|---|---|---|
| `--device` | Cortex-R8 | J-Link 타겟 디바이스 |
| `--nvme` | /dev/nvme0 | NVMe 장치 경로 |
| `--namespace` | 1 | NVMe 네임스페이스 ID |
| `--commands` | (기본 5개) | 활성화할 명령어 이름 |
| `--all-commands` | False | 파괴적 명령어 포함 전체 활성화 |
| `--speed` | 12000 | JTAG 속도 (kHz) |
| `--runtime` | 3600 | 총 퍼징 시간 (초) |
| `--output` | ./output/pc_sampling_v4.3/ | 출력 디렉토리 |
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
| `--timeout GROUP MS` | (그룹별 기본값) | 타임아웃 그룹별 오버라이드 |

---

## 10. 출력 디렉토리 구조

```
output/pc_sampling_v4.3/
├── fuzzer_YYYYMMDD_HHMMSS.log    # 실행 로그
├── coverage.txt                   # 글로벌 PC 커버리지 (hex, 줄당 1개)
├── coverage_edges.txt             # 글로벌 edge 커버리지 (hex,hex 줄당 1개)
├── .nvme_input.bin                # NVMe 입력 데이터 (재사용, 임시)
├── corpus/                        # interesting 입력 저장
│   ├── input_Read_0x2_a1b2c3d4e5f6
│   ├── input_Read_0x2_a1b2c3d4e5f6.json   # CDW 메타데이터
│   ├── input_Write_0x1_...
│   └── ...
├── crashes/                       # timeout/crash 입력 저장
│   ├── crash_Identify_0x6_...
│   ├── crash_Identify_0x6_....json  # crash 메타데이터 + 이유
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
