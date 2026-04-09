# PC Sampling SSD Firmware Fuzzer v6.0

OpenOCD PCSR(PC Sampling Register) 방식으로 커버리지를 수집하고, `nvme-cli` subprocess를 통해 NVMe 명령어를 SSD에 전달하는 Coverage-Guided Fuzzer.

v6.0의 핵심: **J-Link halt-sample-resume → OpenOCD PCSR 비침습 샘플링** + **3코어(Core0/1/2) 동시 수집** + **PMU POR** + **timeout hang 보존 분석**.

---

## 목차

1. [아키텍처 개요](#아키텍처-개요)
2. [요구사항](#요구사항)
3. [빠른 시작](#빠른-시작)
4. [v6.0 변경사항 상세](#v60-변경사항-상세)
5. [코드 상단 상수 설정](#코드-상단-상수-설정)
6. [CLI 옵션](#cli-옵션)
7. [OpenOCD 설정 파일](#openocd-설정-파일-r8_pcsrcfg)
8. [Power Combo 동작 원리](#power-combo-동작-원리)
9. [명령어 목록](#명령어-목록)
10. [출력 디렉터리 구조](#출력-디렉터리-구조)
11. [크래시 발생 후 처리](#크래시-발생-후-처리)
12. [정적 분석 커버리지 연동](#정적-분석-커버리지-연동)
13. [버전 이력 요약](#버전-이력-요약)

---

## 아키텍처 개요

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PC Sampling Fuzzer v6.0                      │
│                                                                     │
│  ┌──────────┐    ┌───────────────────────────────────────────────┐  │
│  │  Startup │    │               Main Fuzzing Loop               │  │
│  │          │    │                                               │  │
│  │ PMU POR  │    │  시드 선택(MOpt) → 변이 생성(Det+Havoc+Splice) │  │
│  │   ↓      │    │       ↓                                       │  │
│  │ OpenOCD  │    │  nvme-cli 명령 전송 ←──────────────────────┐  │  │
│  │  연결    │    │       ↓                          커버리지    │  │
│  │   ↓      │    │  PCSR 샘플링 (비침습)            갱신·저장  │  │
│  │diagnose  │    │  Core0 / Core1 / Core2           ↑          │  │
│  │idle_pcs  │    │       ↓                          │          │  │
│  │ 수집     │    │  BB/함수 커버리지 갱신 ───────────┘          │  │
│  │   ↓      │    │       ↓                                      │  │
│  │Calibrat- │    │  PM Combo 전환(100회마다)                     │  │
│  │  ion     │    │  PS0~4 × L0/L1/L1.2 × D0/D3hot              │  │
│  └──────────┘    └───────────────┬───────────────────────────────┘  │
│                                  │ TIMEOUT                          │
│                  ┌───────────────▼───────────────────────────────┐  │
│                  │         Timeout Crash 분석                    │  │
│                  │                                               │  │
│                  │  _reinit_target() (빠른 복구 시도)            │  │
│                  │       ↓ 성공                  ↓ 실패          │  │
│                  │  PCSR 100회 샘플         수동 확인 안내       │  │
│                  │  코어별 Counter 분석                          │  │
│                  │  HANG / busy-wait / idle 판정                 │  │
│                  │       ↓                                       │  │
│                  │  시각화 생성 (graphs/)                        │  │
│                  │       ↓                                       │  │
│                  │  PC 모니터링 루프 (10초 간격)                 │  │
│                  │  Core0=0x???? Core1=0x???? Core2=0x????      │  │
│                  │  [Ctrl+C → 루프 종료, OpenOCD 유지]           │  │
│                  └───────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    디버그 인프라                             │    │
│  │                                                             │    │
│  │  Host PC                                                    │    │
│  │  ├─ OpenOCD (telnet:4444)  ──USB──  J-Link V9              │    │
│  │  │   ├─ r8.abp (APB-AP)   ──SWD──  SSD ARM Cortex-R8      │    │
│  │  │   │   ├─ PCSR Core0 @ 0x80030084                        │    │
│  │  │   │   ├─ PCSR Core1 @ 0x80032084                        │    │
│  │  │   │   └─ PCSR Core2 @ 0x80034084                        │    │
│  │  │   └─ r8.axi (AXI-AP)                                    │    │
│  │  │       └─ Debug Power @ 0x30313f30                        │    │
│  │  └─ nvme-cli              ──PCIe── SSD NVMe Controller      │    │
│  │                                                             │    │
│  │  PMU Board  ──USB──  Host PC  (전원 사이클 제어)            │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

### 전체 실행 흐름

```
[시작]
  │
  ▼
PMU POR (전원 OFF → 방전 → ON → PCIe rescan)
  │  --no-por 시 스킵
  ▼
OpenOCD 시작 & telnet(4444) 연결
  │  _kill_stale_openocd() → fuser -k 4444/tcp
  ▼
debug power 활성화 (0x30313f30 | 0x00010101)
  │  Core0=bit0, Core1=bit8, Core2=bit16
  ▼
diagnose() — idle_pcs 수집
  │  10ms 간격, 최소 500회, 최대 10000회
  │  새 PC 없이 100회 연속 + 최소 샘플 충족 시 수렴
  ▼
Calibration — 시드별 기준 PC 집합 측정 (3회)
  │
  ▼
┌─ Main Loop ─────────────────────────────────────┐
│  시드 선택 (MOpt 가중치 기반)                    │
│  → 변이 생성 (Deterministic + Havoc + Splice)   │
│  → nvme-cli passthru 실행                       │
│  → PCSR 샘플링 (Core0/1/2, 비침습)              │
│  → BB / 함수 커버리지 갱신                       │
│  → 100회마다 PM Combo 전환 (--pm 활성화 시)     │
│  → 5000회마다 그래프 갱신                        │
└─────────────────────────────────────────────────┘
  │ TIMEOUT 발생
  ▼
_handle_timeout_crash()
  │
  ├─ _reinit_target() 성공
  │    → read_stuck_pcs(count=100) PCSR 샘플링
  │    → 코어별 top_ratio 판정
  │       ≥70% NON-IDLE → HANG
  │       40~70%         → busy-wait/에러루프
  │       <40%           → PC 분산(복구 중)
  │       all IDLE       → 정상 idle
  │
  └─ _reinit_target() 실패
       → 수동 확인 절차 출력
         (nvme id-ctrl, J-Link 연결 안내)
  │
  ▼
시각화 생성 (graphs/)
  │
  ▼
PC 모니터링 루프 (10초 간격)
  Core0=0x???? [NON-IDLE]  Core1=0x???? [NON-IDLE]  Core2=0x???? [IDLE]
  │
  ▼ Ctrl+C
telnet 닫기 (OpenOCD 프로세스 유지 — nSRST 방지)
  │
[종료]  ← 다음 실행 시 _kill_stale_openocd()가 자동 정리
```

---

## 요구사항

```
Python 3.8+
openocd               # xPack OpenOCD 0.12.0+  (libjaylink 포함)
nvme-cli              # apt install nvme-cli
setpci                # apt install pciutils
J-Link V9 / EDU       # USB 동글 (SWD 물리 연결용, pylink 불필요)
pmu_4_1.py            # PMU 보드 제어 스크립트 (POR용, 없으면 POR 스킵)
```

xPack OpenOCD 설치 예시 (Linux x64):
```bash
tar -xf xpack-openocd-0.12.0-7-linux-x64.tar.gz -C /opt/
sudo ln -sf /opt/xpack-openocd-0.12.0-7/bin/openocd /usr/local/bin/openocd
```

실행 권한:
```bash
sudo python3 pc_sampling_fuzzer_v6.0.py [옵션]
```

파일 구성:
```
PC_Sampling/
├── pc_sampling_fuzzer_v6.0.py   # 메인 퍼저
├── nvme_seeds.py                # NVMe 명령 시드 템플릿
├── pmu_4_1.py                   # PMU 보드 제어 (POR용)
└── r8_pcsr.cfg                  # OpenOCD 설정 파일 (별도 준비)
```

---

## 빠른 시작

### 기본 실행

```bash
sudo python3 pc_sampling_fuzzer_v6.0.py \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x003B7FFF \
  --output ./output/run_base
```

### POR 없이 실행 (디버깅용)

```bash
sudo python3 pc_sampling_fuzzer_v6.0.py \
  --nvme /dev/nvme0 \
  --no-por \
  --output ./output/run_no_por
```

### Power Combo 활성화

```bash
sudo python3 pc_sampling_fuzzer_v6.0.py \
  --nvme /dev/nvme0 \
  --pm \
  --output ./output/run_pm
```

---

## v6.0 변경사항 상세

### [Arch] J-Link halt-sample-resume → OpenOCD PCSR 비침습 샘플링

기존 v5.x는 `JLINKARM_Halt()` → `ReadReg(PC)` → `JLINKARM_Go()` 루프로 Core 0만 샘플링했다.

| 항목 | v5.x (J-Link halt) | v6.0 (OpenOCD PCSR) |
|------|-------------------|---------------------|
| 펌웨어 영향 | halt로 DMA 간섭 | **없음** |
| 코어 수 | Core 0만 | **Core 0/1/2 동시** |
| pylink 의존 | 있음 | **없음** |
| 샘플링 속도 | ~200/s (halt 오버헤드) | ~1000/s (1 RTT = 3코어) |
| go_settle 설정 | 필요 | **불필요** |

PCSR 주소 (CoreBase + 0x084, APB-AP):

| 코어 | CoreBase | PCSR 주소 |
|------|----------|-----------|
| Core 0 | `0x80030000` | `0x80030084` |
| Core 1 | `0x80032000` | `0x80032084` |
| Core 2 | `0x80034000` | `0x80034084` |

---

### [Feature] POR (Power-On Reset)

`run()` 시작 시 PMU 보드를 통해 SSD 전원 사이클을 수행한다.

```
PCIe 장치 제거 → PowerOffAll → 방전 대기 → PowerOnAll → 부팅 대기 → PCIe rescan → nvme id-ctrl 확인
```

PMU 명령:
```bash
python3 pmu_4_1.py 7 1              # SetPowerOffAll
python3 pmu_4_1.py 4 1 3300 0 12000 0 0  # SetPowerOnAll
```

이유: 이전 실행의 OpenOCD가 활성화한 CoreSight 디버그 도메인 파워가 SSD PM 상태에 영향을 줄 수 있어 매 실행 시 깨끗한 상태로 초기화.

CLI:
- `--no-por` : POR 건너뜀
- `--por-poweroff-wait SEC` : 전원 OFF 후 방전 대기 (기본 3.0초)
- `--por-boot-wait SEC` : 전원 ON 후 부팅 대기 (기본 8.0초)

---

### [Feature] OpenOCD 2단계 복구

| 단계 | 메서드 | 동작 |
|------|--------|------|
| 1단계 (빠름) | `_reinit_target()` | OpenOCD 유지, `_send_startup_tcl()` 재전송 |
| 2단계 (느림) | `_reconnect()` | OpenOCD kill + 재시작 + telnet 재연결 |

SSD 리셋으로 APB-AP 접근 불가 → `_reinit_target()`으로 debug power 재활성화.
OpenOCD 자체 크래시 → `_reconnect()`으로 전체 재시작.

---

### [Feature] Timeout Crash 분석 강화

timeout 발생 시 자동 수행 순서:

1. `_reinit_target()` — 인프라 상태 확인
2. 성공 시: `read_stuck_pcs(count=100)` PCSR 100회 샘플링
3. 코어별 `Counter` 분석 및 판정:

| top_ratio | 조건 | 판정 |
|-----------|------|------|
| ≥ 70% | NON-IDLE PC | **HANG** |
| 40~70% | — | busy-wait / 에러루프 |
| < 40% | — | PC 분산 (복구 중) |
| all IDLE | non_idle == 0 | 정상 idle |

4. dmesg 캡처 (NVMe / reset / timeout 관련 줄 필터)
5. FAIL CMD 상세 출력
6. crash 파일 저장 + replay .sh 생성
7. 시각화 생성

---

### [Feature] Timeout Crash 후 PC 모니터링 루프

시각화 완료 후 OpenOCD telnet을 유지한 채 10초 간격으로 PC를 출력한다.

```
[MONITOR] Core0=0x00001620[NON-IDLE]  Core1=0x00003844[NON-IDLE]  Core2=0x00001628[IDLE]
[MONITOR] Core0=0x00001620[NON-IDLE]  Core1=0x00003844[NON-IDLE]  Core2=0x00001628[IDLE]
```

- `Ctrl+C` → 루프만 종료, telnet 닫기
- **OpenOCD 프로세스는 유지** — kill 시 J-Link가 nSRST를 assert해 펌웨어 상태가 변함
- 다음 실행 시 `connect()`의 `_kill_stale_openocd()` (`fuser -k 4444/tcp`)가 자동 정리

---

### [Fix] idle_pcs 수집 신뢰도 개선

- `DIAGNOSE_MAX`: 5000 → **10000** (최대 100초)
- **최소 샘플 보장**: `min_samples = max(stability × 3, 500)`
  - stability=100이면 최소 500회 보장
  - 주기가 긴 IRQ 핸들러(예: 100ms 주기)가 stability 간격보다 늦게 등장해도 포착

---

### [Fix] 시드 순서 및 제외

- **Write → Read** 명시적 순서 정렬 (set 순서 비결정성 제거)
- **FormatNVM / Sanitize** 시드에서 제외 (파괴적 동작, 스토리지 초기화)

---

## 코드 상단 상수 설정

| 상수 | 기본값 | 설명 |
|------|--------|------|
| `FW_ADDR_START` | `0x00000000` | 펌웨어 .text 시작 주소 |
| `FW_ADDR_END` | `0x003B7FFF` | 펌웨어 .text 끝 주소 |
| `OPENOCD_BINARY` | `'openocd'` | OpenOCD 바이너리 경로 |
| `OPENOCD_CONFIG` | `'r8_pcsr.cfg'` | OpenOCD 설정 파일 |
| `OPENOCD_TELNET_PORT` | `4444` | OpenOCD telnet 포트 |
| `OPENOCD_STARTUP_TIMEOUT` | `10.0` | OpenOCD 시작 대기 (초) |
| `PCSR_CORE0` | `0x80030084` | Core 0 PCSR 주소 |
| `PCSR_CORE1` | `0x80032084` | Core 1 PCSR 주소 |
| `PCSR_CORE2` | `0x80034084` | Core 2 PCSR 주소 |
| `PCSR_POWER_ADDR` | `0x30313f30` | 디버그 전원 레지스터 (AXI-AP) |
| `PCSR_POWER_MASK` | `0x00010101` | Core0=bit0, Core1=bit8, Core2=bit16 |
| `ENABLE_POR` | `True` | 시작 시 SSD POR 수행 |
| `POR_POWEROFF_WAIT` | `3.0` | POR 전원 OFF 후 방전 대기 (초) |
| `POR_BOOT_WAIT` | `8.0` | POR 전원 ON 후 부팅 대기 (초) |
| `DIAGNOSE_STABILITY` | `100` | idle 수렴 연속 횟수 |
| `DIAGNOSE_MAX` | `10000` | 최대 샘플 수 (상한) |
| `DIAGNOSE_SAMPLE_MS` | `10` | diagnose() 샘플 간격 (ms) |
| `IDLE_WINDOW_SIZE` | `30` | window-ratio 윈도우 크기 |
| `IDLE_RATIO_THRESH` | `0.80` | idle 비율 임계값 |
| `SATURATION_LIMIT` | `10` | 연속 idle 카운터 임계값 |
| `GLOBAL_SATURATION_LIMIT` | `20` | 연속 알려진 PC 임계값 |
| `MAX_SAMPLES_PER_RUN` | `500` | 실행당 최대 샘플 수 |
| `CALIBRATION_RUNS` | `3` | 시드당 calibration 반복 횟수 |
| `GRAPH_REFRESH_INTERVAL` | `5000` | 주기 그래프 갱신 간격 (exec 단위) |

---

## CLI 옵션

```
--openocd-binary PATH    OpenOCD 바이너리 경로 (기본: openocd)
--openocd-config PATH    OpenOCD 설정 파일 경로 (기본: r8_pcsr.cfg)
--openocd-host HOST      OpenOCD telnet 호스트 (기본: 127.0.0.1)
--openocd-port PORT      OpenOCD telnet 포트 (기본: 4444)
--openocd-timeout SEC    OpenOCD 시작 대기 타임아웃 (기본: 10.0)

--nvme DEVICE            NVMe 장치 경로 (기본: /dev/nvme0)
--namespace N            NVMe 네임스페이스 ID (기본: 1)
--lba-size N             NVMe LBA 크기(바이트). 0=자동 감지 (기본: 0)
--addr-start HEX         펌웨어 .text 시작 주소
--addr-end HEX           펌웨어 .text 끝 주소
--output DIR             출력 디렉터리
--runtime SEC            퍼징 총 실행 시간 (기본: 604800 = 1주)
--pm                     Power Combo 활성화 (NVMe PS + PCIe L/D-state)
--no-por                 시작 시 POR(전원 사이클) 건너뜀
--por-boot-wait SEC      POR 후 부팅 완료 대기 (기본: 8.0)
--por-poweroff-wait SEC  POR 전원 OFF 후 방전 대기 (기본: 3.0)
--samples N              실행당 최대 샘플 수 (기본: 500)
--interval US            샘플 간격 µs (기본: 0 = 최대 밀도)
--diagnose-sleep-ms MS   diagnose() 샘플 간격 ms (기본: 10)
--diagnose-stability N   idle 수렴 연속 횟수 (기본: 100)
--calibration-runs N     시드당 calibration 반복 횟수 (기본: 3)
--exclude-opcodes A,B    제외할 opcode (hex). 예: "0xC1,0xC0"
--random-gen-ratio F     랜덤 생성 비율 (기본: 0.2)
--admin-swap-prob F      admin↔IO 교체 확률 (기본: 0.05)
--fw-bin PATH            FWDownload용 펌웨어 바이너리 경로
--fw-xfer BYTES          FWDownload 청크 크기 (기본: 32768)
--fw-slot N              FWCommit 슬롯 번호 (기본: 1)
--passthru-timeout MS    nvme-cli --timeout 값 (기본: 30일)
--kernel-timeout SEC     nvme_core 모듈 타임아웃 (기본: 30일)
--timeout GROUP MS       명령 그룹별 타임아웃 설정
--post-cmd-delay MS      명령 후 추가 대기 (기본: 0)
--seed-dir DIR           초기 시드 디렉터리
--resume-coverage FILE   이전 coverage.txt 경로
--commands CMD ...       활성화할 명령어 목록
--all-commands           위험 명령어 포함 전체 활성화
```

---

## OpenOCD 설정 파일 (`r8_pcsr.cfg`)

```tcl
adapter driver jlink
adapter speed 4000
transport select swd
reset_config none
swd newdap r8 cpu -enable
dap create r8.dap -chain-position r8.cpu
target create r8.abp mem_ap -dap r8.dap -ap-num 0
target create r8.axi mem_ap -dap r8.dap -ap-num 1
init
```

> **주의**: `mem_ap` 타입이므로 `halt` / `reg` / `resume` 명령은 동작하지 않음.  
> PC 읽기는 PCSR 메모리 읽기(`r8.abp read_memory 0x80030084 32 1`)로만 가능.

OpenOCD 단독 동작 확인:
```bash
openocd -f r8_pcsr.cfg
# 출력 예:
# SWD DPIDR 0x6ba02477
# [r8.abp] Examination succeeded
# [r8.axi] Examination succeeded
```

---

## Power Combo 동작 원리

`--pm` 활성화 시 30개 조합(PS0~4 × L0/L1/L1.2 × D0/D3hot) 랜덤 전환.

- `PM_ROTATE_INTERVAL`(기본 100)회 exec마다 combo 전환
- Non-Operational 상태(PS3/4, D3hot) 진입 시 NVMe 명령 전 강제 복귀
- preflight: 30개 combo 모두 검증 (~21초)
- calibration 완료 후 APST 재비활성화

---

## 명령어 목록

### 기본 활성화 (I/O 위주, 시드 순서: Write → Read 우선)

| 명령 | Opcode | 비고 |
|------|--------|------|
| Write | 0x01 (IO) | weight=2, **시드 1순위** |
| Read | 0x02 (IO) | weight=2, **시드 2순위** |
| Identify | 0x06 | — |
| GetLogPage | 0x02 | — |
| GetFeatures | 0x0A | — |
| SetFeatures | 0x09 | weight=1 |

### 확장 명령어 (`--all-commands` 또는 `--commands`로 활성화)

FWDownload, FWCommit, FormatNVM\*, Sanitize\*, TelemetryHostInitiated, Flush,
DatasetManagement, WriteZeroes, Compare, WriteUncorrectable, Verify,
DeviceSelfTest, SecuritySend, SecurityReceive, GetLBAStatus

\* FormatNVM / Sanitize: 기본 시드에서 **제외** (파괴적 동작). `--all-commands`로만 포함.

---

## 출력 디렉터리 구조

```
output/pc_sampling_v6.0/
├── fuzzer_YYYYMMDD_HHMMSS.log
├── coverage.txt
├── corpus/
│   └── seed_NNNN.bin
├── crashes/
│   ├── crash_<cmd>_<opcode>_<md5>
│   ├── crash_<cmd>_<opcode>_<md5>.json
│   ├── crash_<cmd>_<opcode>_<md5>.dmesg.txt
│   ├── replay_<tag>.sh
│   └── replay_data_<tag>/
│       └── data_NNN.bin
└── graphs/
    ├── command_comparison.png
    ├── mutation_chart.png
    ├── coverage_heatmap_1d.png
    ├── edge_heatmap_2d.png
    ├── {cmd}_cfg.dot/.png
    ├── coverage_growth.png       (* Ghidra 연동 시)
    ├── firmware_map.png          (* Ghidra 연동 시)
    └── uncovered_funcs.png       (* Ghidra 연동 시)
```

---

## 크래시 발생 후 처리

```
timeout 감지
  → _reinit_target() (인프라 확인)
  → read_stuck_pcs(count=100) PCSR 100회 샘플
  → 코어별 판정 로그 출력
  → dmesg 캡처
  → FAIL CMD 상세 출력
  → crash 파일 저장 (.bin / .json / .dmesg.txt)
  → replay .sh 자동 생성
  → UFAS 펌웨어 덤프 (./ufas 존재 시)
  → 시각화 생성 (graphs/)
  → PC 모니터링 루프 (10초 간격, Ctrl+C로 종료)
  → OpenOCD 유지 (nSRST 방지, hang 상태 보존)
```

다음 실행 시 OpenOCD 자동 정리:
```bash
# 수동 종료가 필요한 경우
sudo pkill openocd
```

---

## 정적 분석 커버리지 연동

퍼저와 같은 디렉터리에 `basic_blocks.txt` / `functions.txt` (Ghidra `ghidra_export.py` 생성)를 두면 자동 로드.

```
[StatCov] BB: 12.3% (4567/37120) | funcs: 234/1820 (12.9%)
```

그래프 3종 자동 생성:
- `coverage_growth.png` : BB_cov% / funcs_cov% 성장 곡선 + wall-clock time 이중 X축
- `firmware_map.png` : 함수 공간 전체 맵 (커버=초록 / 미커버=회색)
- `uncovered_funcs.png` : 미커버(빨강) + 부분 커버(주황) 함수 Top-25 × 2

> v6.0 커버리지 향상: 3코어 동시 수집으로 Core 1/2 코드 경로까지 포함.

---

## 버전 이력 요약

| 버전 | 주요 변경 |
|------|-----------|
| **v6.0** | OpenOCD PCSR 비침습 샘플링, 3코어 동시 수집(Core0/1/2), pylink 제거, PMU POR, 2단계 복구, timeout hang 보존 분석, PC 모니터링 루프, idle_pcs 수집 강화, Write→Read 시드 우선순위 |
| v5.6 | 시각화 개선: coverage_growth 이중 X축, command_comparison RC 오류율, uncovered_funcs 부분커버, mutation_chart 신규, 주기 갱신 |
| v5.5 | 시드 템플릿 분리(nvme_seeds.py), CLI 인자 정리, FWDownload 32KB 기본값 |
| v5.4 | SetFeatures 기본 승격, APST calibration 버그 수정, LBA 자동 감지 |
| v5.3 | idle 시간 최적화: L1_SETTLE 0.05s, DIAGNOSE_SAMPLE_MS=10ms, window-ratio 조기 감지 |
| v5.2 | Power Combo (NVMe PS + PCIe L/D-state 30개 조합), APST/Keep-Alive 자동 비활성화 |
| v5.1 | PM Rotation(`--pm`), Basic Block 커버리지(Ghidra), 시각화 그래프 3종 |
| v5.0 | J-Link JTAG/SWD auto-detect, diagnose() 수렴 기반 idle 유니버스 수집 |
| v4.7 | FUA 비트 수정(CDW12[29]), FWDownload `--fw-bin` |
| v4.6 | passthru timeout 분리, crash 시 nvme driver unbind |
| v4.5 | Calibration, Deterministic stage, MOpt mutation scheduling |
