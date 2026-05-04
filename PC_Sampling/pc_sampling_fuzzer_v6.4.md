# PC Sampling SSD Firmware Fuzzer v6.4

OpenOCD PCSR(PC Sampling Register) 방식으로 커버리지를 수집하고, `nvme-cli` subprocess를 통해 NVMe 명령어를 SSD에 전달하는 Coverage-Guided Fuzzer.

v6.4의 핵심: **PS3/PS4 강제 idle 진입 슬롯** — POST_CMD_DELAY_MS=0 + APST 비활성화 환경에서도 Non-Operational Power State(NOPS) 커버리지를 확보하기 위해 PM 로테이션 중 1/6 확률로 명시적 idle 대기를 수행.

---

## 목차

1. [아키텍처 개요](#아키텍처-개요)
2. [요구사항](#요구사항)
3. [빠른 시작](#빠른-시작)
4. [v6.4 변경사항 상세](#v64-변경사항-상세)
5. [제품별 설정 (--product)](#제품별-설정---product)
6. [Power Management 설계](#power-management-설계)
7. [JTAG 지원 (BM9H1)](#jtag-지원-bm9h1)
8. [Defect 처리 흐름](#defect-처리-흐름)
9. [JLink 기반 PC 모니터링](#jlink-기반-pc-모니터링)
10. [코드 상단 상수 설정](#코드-상단-상수-설정)
11. [CLI 옵션](#cli-옵션)
12. [OpenOCD 설정 파일](#openocd-설정-파일)
13. [출력 디렉터리 구조](#출력-디렉터리-구조)
14. [버전 이력 요약](#버전-이력-요약)

---

## 아키텍처 개요

```
┌──────────────────────────────────────────────────────────────────────┐
│                     PC Sampling Fuzzer v6.4                          │
│                                                                      │
│  ┌──────────┐    ┌────────────────────────────────────────────────┐  │
│  │  Startup │    │                Main Fuzzing Loop               │  │
│  │          │    │                                                │  │
│  │ PMU POR  │    │  시드 선택(IO/Admin 비율 3:1)                   │  │
│  │   ↓      │    │  → 변이(Det+Havoc+Splice+Schema)               │  │
│  │ OpenOCD  │    │       ↓                                        │  │
│  │  연결    │    │  nvme-cli passthru                             │  │
│  │   ↓      │    │       ↓                                        │  │
│  │diagnose  │    │  PCSR 샘플링 (비침습 OpenOCD)                   │  │
│  │idle_pcs  │    │  Core0 / Core1 [/ Core2 — SWD 제품만]          │  │
│  │   ↓      │    │       ↓                                        │  │
│  │Calibrat- │    │  BB/함수 커버리지 갱신                           │  │
│  │  ion     │    │                                                │  │
│  └──────────┘    │  [PM 로테이션 — 100회마다]                      │  │
│                  │   1/6: PS3/PS4 강제 idle 슬롯 (v6.4 신규)       │  │
│                  │   5/6: POWER_COMBOS 랜덤 전환                   │  │
│                  └────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │   Defect 처리 (timeout / hang)                                │    │
│  │                                                              │    │
│  │  1. read_stuck_pcs(count=1000) — PCSR 대량 샘플링            │    │
│  │  2. hang 분석 (top_ratio 기반 HANG / busy-wait / 분산)       │    │
│  │  3. JLink 메모리 덤프 (run_smi_mem_dump_JLINK_USB.sh)        │    │
│  │       ← OpenOCD shutdown 후 실행 (USB 점유 해제)             │    │
│  │  4. UFAS 덤프                                                │    │
│  │  5. JLink 기반 PC 모니터링 루프 (30초 간격, Ctrl+C 종료)      │    │
│  └──────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
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
  ▼
debug power 활성화
  ▼
diagnose() — idle_pcs 수집 (10ms 간격, 최소 500회, 최대 10000회)
  ▼
[Calibration]
  FormatNVM 1회 → Sanitize 1회 → commands 풀에서 제거
  시드별 기준 PC 집합 측정 (3회)
  ▼
┌─ Main Loop ────────────────────────────────────────┐
│  시드 선택 (IO:Admin = 3:1 + MOpt 가중치)           │
│  → 변이 (Schema/Det/Havoc/Splice)                  │
│  → nvme-cli passthru 실행                         │
│  → PCSR 샘플링                                    │
│  → BB / 함수 커버리지 갱신                          │
│                                                    │
│  [PM 로테이션 — 100회마다]                          │
│    random(0,5)==0 → PS3/PS4 강제 idle 슬롯         │
│    그 외          → POWER_COMBOS 랜덤 전환          │
└────────────────────────────────────────────────────┘
  ↓ timeout / hang 감지
[Defect 처리]
  1. read_stuck_pcs(1000) + hang 분석
  2. OpenOCD shutdown → JLink 메모리 덤프
  3. UFAS 덤프
  4. JLink PC 모니터링 루프
```

---

## 요구사항

```
Python 3.8+
openocd               # xPack OpenOCD 0.12.0+
nvme-cli              # apt install nvme-cli
setpci                # apt install pciutils
JLinkExe              # SEGGER J-Link Software (PC 모니터링 / 덤프용)
J-Link V9 / EDU       # USB 동글 (SWD/JTAG 물리 연결)
pmu_4_1.py            # PMU 보드 제어 스크립트 (POR용, 없으면 POR 스킵)
```

파일 구성:

```
PC_Sampling/
├── pc_sampling_fuzzer_v6.4.py          # 메인 퍼저
├── nvme_seeds.py                        # NVMe 명령 시드 템플릿
├── pmu_4_1.py                           # PMU 보드 제어 (POR용)
├── r8_pcsr.cfg                          # OpenOCD 설정 — SWD (PM9M1)
├── r8_pcsr_jtag.cfg                     # OpenOCD 설정 — JTAG (BM9H1)
└── run_smi_mem_dump_JLINK_USB.sh        # JLink 메모리 덤프 스크립트
```

---

## 빠른 시작

### PM9M1 (SWD, 3코어)

```bash
sudo python3 pc_sampling_fuzzer_v6.4.py \
  --product PM9M1 \
  --nvme /dev/nvme0 \
  --addr-start 0xA4000 \
  --addr-end 0x3B7FFF \
  --output ./output/run_pm9m1
```

### BM9H1 (JTAG, 2코어)

```bash
sudo python3 pc_sampling_fuzzer_v6.4.py \
  --product BM9H1 \
  --nvme /dev/nvme0 \
  --addr-start 0x28000 \
  --addr-end 0x1FFFF \
  --output ./output/run_bm9h1
```

### PM + PS3/PS4 강제 idle 활성화

```bash
sudo python3 pc_sampling_fuzzer_v6.4.py \
  --product PM9M1 \
  --nvme /dev/nvme0 \
  --pm \
  --addr-start 0xA4000 --addr-end 0x3B7FFF \
  --output ./output/run_pm_nops
```

### POR 없이 실행 (디버깅용)

```bash
sudo python3 pc_sampling_fuzzer_v6.4.py \
  --product PM9M1 \
  --nvme /dev/nvme0 \
  --no-por \
  --output ./output/run_no_por
```

---

## v6.4 변경사항 상세

### [PM] PS3/PS4 강제 idle 진입 슬롯

#### 배경: NOPS 진입이 안 되는 이유

| 조건 | 설명 |
|------|------|
| `POST_CMD_DELAY_MS=0` | 명령과 명령 사이에 idle 시간 없음 |
| `APST 비활성화` | 컨트롤러 자율 PS 전환 차단 |
| 결과 | NVMe 컨트롤러가 PS3/PS4 진입 조건(ENLAT 이상 idle) 충족 불가 |

APST를 켜두면 퍼징과 무관한 타이밍에 PS가 전환되어 커버리지 오염이 발생하므로 끄는 것이 맞다. 하지만 이 경우 NOPS 진입은 퍼저가 명시적으로 idle 시간을 만들어야만 가능하다.

#### 구현

```
PM 로테이션 (100회마다)
  │
  ├─ random.randint(0,5) == 0 → PS3/PS4 강제 idle 슬롯 (약 16.7%)
  │     ↓
  │   PS3 또는 PS4 중 랜덤 선택
  │     ↓
  │   POWER_COMBOS에서 nvme_ps==선택PS, pcie_l==L0, pcie_d==D0 항목 검색
  │     ↓ (없으면 슬롯 건너뜀)
  │   sampler.start_sampling()
  │   _pm_set_state(선택PS)          ← NVMe Set Features (Power Mgmt)
  │   time.sleep(_ps_settle[PS])     ← enlat 기반 최소 진입 대기
  │   time.sleep(_ps_settle[PS])     ← 추가 idle → 실제 NOPS 진입 보장
  │   sampler.stop_sampling()
  │   global_coverage.update(...)    ← 커버리지 갱신
  │   _pm_set_state(0)               ← PS0 복귀
  │   ps_enter_counts[PS] += 1
  │
  └─ 그 외 (5/6) → POWER_COMBOS 랜덤 전환 (기존 동작)
```

#### settle 시간 계산

`_init_ps_settle()` 가 NVMe Identify Power State Descriptor에서 ENLAT 값을 읽어 계산.

```python
# fallback (ENLAT 읽기 실패 시)
PS3 → 0.5s
PS4 → 2.0s (PS4_MIN_SETTLE)

# 상한 clamp
PS_SETTLE_CAP_S = 1.0s
```

`_ps_settle[PS]` × 2 idle → PS 진입 최소 조건을 2배 여유로 보장.

---

## 제품별 설정 (`--product`)

| 옵션 | 제품 | Interface | OpenOCD 설정 | 코어 수 | PCSR 주소 |
|------|------|-----------|-------------|--------|----------|
| `PM9M1` | Samsung PM9M1 | SWD | `r8_pcsr.cfg` | 3 | 0x80030084, 0x80032084, 0x80034084 |
| `BM9H1` | Samsung BM9H1 | JTAG | `r8_pcsr_jtag.cfg` | 2 | 0x80030084, 0x80032084 |

`--product`는 `--interface`와 `--openocd-config`를 자동 설정한다. `--openocd-config`를 명시하면 cfg만 오버라이드되고 interface는 product 값을 따른다.

```bash
# product 자동 설정
--product PM9M1  →  interface=swd,  cfg=r8_pcsr.cfg
--product BM9H1  →  interface=jtag, cfg=r8_pcsr_jtag.cfg

# 수동 override
--product BM9H1 --openocd-config custom.cfg
#  → interface=jtag (product 우선), cfg=custom.cfg (명시값 우선)
```

---

## Power Management 설계

### POWER_COMBOS 구성

NVMe PS(0~4) × PCIe L-state(L0/L1/L1.2) × D-state(D0/D3hot) = 30가지 조합.

```
nvme_ps | pcie_l | pcie_d | 비고
  0     |  L0    |  D0    | 기본값 (active)
  1     |  L0    |  D0    | light idle
  2     |  L0    |  D0    | medium idle
  3     |  L0    |  D0    | NOPS entry (v6.4 강제 슬롯 대상)
  4     |  L0    |  D0    | NOPS entry (v6.4 강제 슬롯 대상)
  ...   | L1/L1.2| D0/D3  | PCIe deep power save
```

### PM 전환 흐름

```
[PM 로테이션 — 100회마다 (PM_ROTATE_INTERVAL)]
  ├─ 1/6: PS3/PS4 강제 idle 슬롯 (v6.4)
  │         settle×2 idle → 실제 NOPS 진입
  └─ 5/6: POWER_COMBOS 랜덤 선택
            _set_power_combo() 호출
            → NVMe Set Features + setpci L/D-state
```

### APST/ASPM 정책

| 항목 | 설정 | 이유 |
|------|------|------|
| APST | 비활성화 | 퍼저와 무관한 타이밍에 PS 전환 → 커버리지 오염 |
| ASPM | 비활성화 권장 | PCIe 링크 불안정으로 JTAG/PCSR 샘플링 간섭 가능성 |
| PS3/PS4 진입 | 퍼저가 명시적 idle로 강제 | APST 끈 상태에서 유일한 NOPS 진입 경로 |

---

## JTAG 지원 (BM9H1)

### ROM Table 기반 코어 주소 발견

BM9H1은 JTAG 인터페이스를 사용하며 ARM Cortex-R8 2코어 구성이다.

```
JTAG IDCODE: 0x6BA00477  (irlen=4)
ROM Table 기반 CoreSight 블록:
  Core0 Debug Base: 0x80030000  → PCSR: 0x80030084
  Core1 Debug Base: 0x80032000  → PCSR: 0x80032084
  Core2 (0x80040000) → "Timeout during WAIT recovery" — 미장착 또는 비파워
```

Core2 주소(0x80040000) 접근 시 APB bus ACK 없이 WAIT 상태 → DP STICKY ERROR 전파.  
`r8_pcsr_jtag.cfg`에서 `init` 직후 DP CTRL/STAT=0x50000000, ABORT=0x1e로 sticky 클리어.

### 펌웨어 시작 주소 (BM9H1)

ARM Cortex-R 벡터 테이블 패턴(`xx xx xx EA`, ARM B 명령) 탐색 기준:

| 제품 | 벡터 테이블 위치 | 펌웨어 시작 |
|------|--------------|-----------|
| PM9M1 (SWD) | 0x24000, 0x44000, 0x64000, 0x84000, 0xA4000 | `0xA4000` |
| BM9H1 (JTAG) | 0x8000, 0x28000 | `0x28000` |

BM9H1 ITCM 주소 범위: `--addr-start 0x0 --addr-end 0x1FFFF` (펌웨어 시작 0x28000 기준 오프셋).

### `r8_pcsr_jtag.cfg` 요점

```tcl
transport select jtag                  # adapter driver보다 앞에 선언 필수
adapter driver jlink
jtag newtap r8 cpu -irlen 4 -expected-id 0x6BA00477
dap create r8.dap -chain-position r8.cpu
target create r8.abp mem_ap -dap r8.dap -ap-num 0
target create r8.axi mem_ap -dap r8.dap -ap-num 1
init

# debug power 활성화 + sticky error 클리어 (자동 설정 안 됨 in JTAG mode)
r8.dap dpreg 4 0x50000000   # CSYSPWRUPREQ | CDBGPWRUPREQ
after 100
r8.dap dpreg 0 0x1e         # ABORT: sticky error 클리어
```

---

## Defect 처리 흐름

timeout/hang 감지 시 다음 순서로 처리한다.

```
[Defect 감지 — timeout or hang]
  │
  ▼
1. read_stuck_pcs(count=1000)
     PCSR 1000회 연속 샘플링 → 코어별 Counter 분석
     top_ratio ≥ 70% → HANG
     top_ratio 40~70% → busy-wait
     top_ratio < 40%  → 분산 (복구 중)
  │
  ▼
2. OpenOCD shutdown
     telnet: "shutdown\n" 전송 → 1s 대기
     → J-Link USB 점유 해제
  │
  ▼
3. JLink 메모리 덤프 (run_smi_mem_dump_JLINK_USB.sh)
     OpenOCD 종료 후 J-Link 재연결 가능 상태에서 실행
     최대 300초 대기, timeout 시 SIGKILL
  │
  ▼
4. UFAS 덤프 (--enable-ufas 시)
  │
  ▼
5. JLink 기반 PC 모니터링 루프 (30초 간격)
     OpenOCD 없이 JLinkExe로 직접 halt→PC 읽기→resume
     Ctrl+C로 루프만 종료
```

### JLink 덤프 스크립트 요구사항

```bash
# 퍼저 스크립트와 같은 디렉터리에 위치해야 함
./run_smi_mem_dump_JLINK_USB.sh

# 실행 권한 부여
chmod +x run_smi_mem_dump_JLINK_USB.sh
```

---

## JLink 기반 PC 모니터링

timeout crash 후 OpenOCD가 종료된 상태에서 JLinkExe를 직접 실행해 PC를 주기적으로 읽는다.

### 동작 방식

```python
# 코어별로: core N → h → r → go → exit
# JLinkExe stdout에서 "PC = XXXXXXXX" 패턴 추출
pcs = [int(p, 16) & ~1
       for p in re.findall(r'\bPC\s*=\s*([0-9A-Fa-f]+)', output)]
```

```
[MONITOR] Core0: PC=0x12345678 [NON-IDLE]
[MONITOR] Core1: PC=0x80031ABC [IDLE]
```

| 항목 | 값 |
|------|---|
| 샘플 간격 | 30초 |
| 종료 방법 | Ctrl+C (루프만 종료, 펌웨어 상태 유지) |
| interface | `SWD` (PM9M1) / `JTAG` (BM9H1) — config.interface 자동 참조 |
| JLink device | `Cortex-R8` |

---

## 코드 상단 상수 설정

### v6.4 신규/변경 상수

| 상수 | 기본값 | 설명 |
|------|--------|------|
| `JLINK_BINARY` | `'JLinkExe'` | JLink 실행 파일 이름 |
| `JLINK_DEVICE` | `'Cortex-R8'` | JLinkExe `-device` 옵션값 |
| `PRODUCT_CONFIGS` | — | `{PM9M1: swd/r8_pcsr.cfg, BM9H1: jtag/r8_pcsr_jtag.cfg}` |
| `PCSR_ADDRS_SWD` | 3주소 | Core0/1/2 PCSR (PM9M1) |
| `PCSR_ADDRS_JTAG` | 2주소 | Core0/1 PCSR (BM9H1) |
| `OPENOCD_CONFIG_JTAG` | `'r8_pcsr_jtag.cfg'` | JTAG용 OpenOCD cfg |

### 기존 유지 주요 상수

| 상수 | 기본값 | 설명 |
|------|--------|------|
| `PM_ROTATE_INTERVAL` | `100` | PM 전환 주기 (실행 횟수) |
| `PS_SETTLE_CAP_S` | `1.0` | NOPS settle 상한 (초) |
| `SCHEMA_MUT_PROB` | `0.30` | Schema Mutation 적용 확률 |
| `IO_ADMIN_RATIO` | `3` | I/O 커맨드 선택 가중치 |
| `DIAGNOSE_MAX` | `10000` | idle 수집 최대 샘플 수 |
| `DIAGNOSE_STABILITY` | `100` | idle 수렴 연속 횟수 |

---

## CLI 옵션

### v6.4 신규 옵션

```
--product PRODUCT        제품명 자동 설정 (PM9M1 | BM9H1).
                         interface와 openocd-config를 자동 결정.
                         --interface보다 우선 적용.
--interface swd|jtag     디버그 transport 선택 (기본: swd).
                         --product 지정 시 무시됨.
```

### 전체 옵션

```
# 제품/연결
--product PRODUCT        제품 자동 설정 (PM9M1 | BM9H1)
--interface swd|jtag     디버그 transport (기본: swd)
--openocd-binary PATH    OpenOCD 바이너리 경로 (기본: openocd)
--openocd-config PATH    OpenOCD 설정 파일 (미지정 시 interface로 자동 선택)
--openocd-host HOST      OpenOCD telnet 호스트 (기본: 127.0.0.1)
--openocd-port PORT      OpenOCD telnet 포트 (기본: 4444)
--openocd-timeout SEC    OpenOCD 시작 대기 타임아웃 (기본: 10.0)

# NVMe 대상
--nvme DEVICE            NVMe 장치 경로 (기본: /dev/nvme0)
--namespace N            네임스페이스 ID (기본: 1)
--lba-size N             LBA 크기(바이트). 0=자동 감지 (기본: 0)

# 펌웨어 주소 범위
--addr-start HEX         펌웨어 .text 시작 주소
--addr-end HEX           펌웨어 .text 끝 주소
--pcsr-addrs A,B[,C]     PCSR 주소 오버라이드 (hex). 미지정 시 product/interface로 자동 결정

# 실행 제어
--output DIR             출력 디렉터리
--runtime SEC            총 실행 시간 (기본: 604800 = 1주)
--pm                     Power Combo 활성화 (NVMe PS + PCIe L/D-state + PS3/PS4 idle 슬롯)
--no-por                 시작 시 POR(전원 사이클) 건너뜀
--por-boot-wait SEC      POR 후 부팅 완료 대기 (기본: 8.0)
--por-poweroff-wait SEC  POR 전원 OFF 후 방전 대기 (기본: 3.0)

# 샘플링
--samples N              실행당 최대 샘플 수 (기본: 500)
--interval US            샘플 간격 µs (기본: 0 = 최대 밀도)
--diagnose-sleep-ms MS   diagnose() 샘플 간격 ms (기본: 10)
--diagnose-stability N   idle 수렴 연속 횟수 (기본: 100)
--calibration-runs N     시드당 calibration 반복 횟수 (기본: 3)

# 명령어 제어
--commands CMD ...       활성화할 명령어 목록
--all-commands           위험 명령어 포함 전체 활성화
--exclude-opcodes A,B    제외할 opcode (hex). 예: "0xC1,0xC0"

# 퍼징 파라미터
--random-gen-ratio F     랜덤 생성 비율 (기본: 0.2)
--admin-swap-prob F      admin↔IO 교체 확률 (기본: 0.05)
--post-cmd-delay MS      명령 후 추가 대기 (기본: 0)
--timeout GROUP MS       명령 그룹별 타임아웃 설정
--passthru-timeout MS    nvme-cli --timeout 값 (기본: 30일)
--kernel-timeout SEC     nvme_core 모듈 타임아웃 (기본: 30일)

# 펌웨어 다운로드
--fw-bin PATH            FWDownload용 펌웨어 바이너리
--fw-xfer BYTES          FWDownload 청크 크기 (기본: 32768)
--fw-slot N              FWCommit 슬롯 번호 (기본: 1)

# 재개/시드
--seed-dir DIR           초기 시드 디렉터리
--resume-coverage FILE   이전 coverage.txt 경로
```

---

## OpenOCD 설정 파일

### SWD (`r8_pcsr.cfg`) — PM9M1

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

### JTAG (`r8_pcsr_jtag.cfg`) — BM9H1

```tcl
transport select jtag           # adapter driver보다 앞에 선언 필수
adapter driver jlink
adapter speed 4000
reset_config none
jtag newtap r8 cpu -irlen 4 -expected-id 0x6BA00477
dap create r8.dap -chain-position r8.cpu
target create r8.abp mem_ap -dap r8.dap -ap-num 0
target create r8.axi mem_ap -dap r8.dap -ap-num 1
init
r8.dap dpreg 4 0x50000000      # CSYSPWRUPREQ | CDBGPWRUPREQ
after 100
r8.dap dpreg 0 0x1e            # sticky error 클리어
```

> **주의**: JTAG 모드에서는 OpenOCD가 CDBGPWRUPREQ를 자동 설정하지 않으므로 `init` 직후 수동 설정 필수.

---

## 출력 디렉터리 구조

```
output/pc_sampling_v6.4/
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

## 버전 이력 요약

| 버전 | 주요 변경 |
|------|-----------|
| **v6.4** | PS3/PS4 강제 idle 슬롯 (1/6 확률, settle×2 대기) — NOPS 커버리지 확보 |
| v6.3 | JTAG 지원(BM9H1, 2코어), `--product` / `--interface` 옵션, JLink 덤프(OpenOCD shutdown 후), JLink 기반 PC 모니터링, defect PC 샘플링 1000회, 시작 로그 정리 |
| v6.2 | Rule-Based Schema Mutation (42커맨드/~150필드/8타입), IO_ADMIN_RATIO=3 |
| v6.0 | OpenOCD PCSR 비침습 샘플링, 3코어(Core0/1/2), PMU POR, 2단계 복구, hang 보존 분석 |
| v5.6 | 시각화 개선: coverage_growth 이중 X축, command_comparison RC 오류율, mutation_chart |
| v5.5 | 시드 템플릿 분리(nvme_seeds.py), CLI 인자 정리, FWDownload 32KB |
| v5.3 | idle 최적화: L1_SETTLE 50ms, DIAGNOSE_SAMPLE_MS=10ms, window-ratio 조기 감지 |
| v5.2 | Power Combo (NVMe PS + PCIe L/D-state 30개 조합) |
| v5.1 | PM Rotation(`--pm`), Basic Block 커버리지(Ghidra), 시각화 3종 |
| v5.0 | J-Link JTAG/SWD auto-detect, diagnose() 수렴 기반 idle 수집 |
