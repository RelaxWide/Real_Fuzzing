# PC Sampling Fuzzer v5.2 — 구현 컨셉 Overview

> **파일**: `pc_sampling_fuzzer_v5.2.py`
> **기반**: v5.1 → Power Combo (NVMe PS + PCIe L/D-state) 동시 제어 추가

---

## 목차

1. [전체 아키텍처](#1-전체-아키텍처)
2. [PC 샘플링 기반 커버리지](#2-pc-샘플링-기반-커버리지)
3. [정적 분석 연동 (BB Coverage)](#3-정적-분석-연동-bb-coverage)
4. [퍼징 입력 생성 및 뮤테이션](#4-퍼징-입력-생성-및-뮤테이션)
5. [전원 상태 제어 (Power Combo)](#5-전원-상태-제어-power-combo)
6. [PCIe ASPM 제어 (L-state)](#6-pcie-aspm-제어-l-state)
7. [PCIe D-state 제어](#7-pcie-d-state-제어)
8. [타임아웃 및 크래시 처리](#8-타임아웃-및-크래시-처리)
9. [메인 루프 흐름](#9-메인-루프-흐름)
10. [통계 및 출력](#10-통계-및-출력)
11. [주요 상수 및 설정](#11-주요-상수-및-설정)
12. [버전 히스토리](#12-버전-히스토리)

---

## 1. 전체 아키텍처

```
┌─────────────────────────────────────────────────────────────────┐
│                  pc_sampling_fuzzer_v5.2.py                     │
│                                                                 │
│   ┌──────────┐    ┌──────────────┐    ┌──────────────────────┐ │
│   │  J-Link  │    │  nvme-cli    │    │   setpci (PCIe)      │ │
│   │  V9      │    │  subprocess  │    │   subprocess         │ │
│   │  (JTAG/  │    │  passthru    │    │   write-with-mask    │ │
│   │   SWD)   │    │              │    │                      │ │
│   └────┬─────┘    └──────┬───────┘    └──────────┬───────────┘ │
│        │                 │                       │             │
│   PC Sampling       NVMe Commands          PCIe State         │
│   Halt→Read→Go      (Admin/IO)             (L/D-state)        │
│        │                 │                       │             │
│   ┌────▼─────────────────▼───────────────────────▼───────────┐ │
│   │                  Main Fuzzing Loop                        │ │
│   │  [Mutate] → [Execute] → [Sample PCs] → [Update Coverage] │ │
│   │                    ↕ every 100 execs                      │ │
│   │             [Power Combo Rotation]                        │ │
│   └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### 핵심 컴포넌트

| 컴포넌트 | 역할 |
|----------|------|
| `JLinkPCSampler` | J-Link SDK 래퍼. Halt→PC 레지스터 읽기→Go 반복으로 PC 수집 |
| `NVMeCommand` | NVMe Admin/IO 명령 정의 (opcode, CDW 필드, data 요구사항) |
| `Seed` | 퍼징 입력 단위 (CDW 값 + 뮤테이션 메타데이터 + 커버리지) |
| `FuzzConfig` | CLI 인자 → 설정 dataclass |
| `PowerCombo` | (nvme_ps, pcie_l, pcie_d) 3-tuple frozen dataclass |

---

## 2. PC 샘플링 기반 커버리지

### 동작 원리

```
J-Link                 SSD 펌웨어
  │                       │
  │── JLINKARM_Halt() ──→ │ (CPU 정지)
  │←── PC 레지스터 값 ───  │
  │── JLINKARM_GoEx() ──→ │ (CPU 재개)
  │                       │
  └─ 반복 (sample_interval_us 주기)
```

- **방식**: Halt-Sample-Resume (통계적 샘플링)
- **대상**: NVMe 명령 처리 중 펌웨어의 실제 실행 경로
- **정밀도**: 샘플링 주기보다 짧은 코드 경로는 확률적으로 누락될 수 있음 → BB 단위로 보완

### 커버리지 집합

```python
global_coverage: Set[int]       # 전체 실행에서 수집된 고유 PC
per_seed_coverage: Set[int]     # 현재 실행의 새 PC
cmd_pcs: Dict[str, Set[int]]    # 명령별 누적 PC 집합
```

- `new_pcs = current_pcs - global_coverage` 로 흥미로운 입력 판별
- 새 PC가 있으면 corpus에 추가 (커버리지 가이드 방식)

---

## 3. 정적 분석 연동 (BB Coverage)

### Ghidra Export → 퍼저 연동

```
Ghidra (ghidra_export.py)
  └─ BasicBlockModel.getCodeBlocks()
  └─ basic_blocks.txt: "0xSTART 0xEND_exclusive" (한 줄에 하나)
  └─ functions.txt:    "0xENTRY SIZE NAME"

퍼저 (_load_static_analysis)
  └─ bisect용 정렬 리스트로 로드:
     _sa_bb_starts[]  ← BB 시작 주소 (sorted)
     _sa_bb_ends[]    ← BB 종료 주소 (exclusive, sorted)
     _sa_func_entries[] ← 함수 진입점 (sorted)
```

### PC → BB 매핑 (O(log N))

```python
# Thumb bit 자동 탐지: ARM Thumb 모드에서 PC LSB=1
idx = bisect_right(_sa_bb_starts, pc & ~thumb_mask) - 1
if idx >= 0 and (pc & ~thumb_mask) < _sa_bb_ends[idx]:
    _sa_covered_bbs.add(_sa_bb_starts[idx])
```

- 샘플 1개가 BB 내 어느 위치든 → 해당 BB 전체를 실행된 것으로 표시
- 명령(instruction) 단위보다 BB 단위가 PC 샘플링에 더 정확

### 커버리지 지표

| 지표 | 계산 | 출력 예시 |
|------|------|-----------|
| BB Coverage | `covered_bbs / total_bbs` | `BB: 45.1% (1,220/2,700)` |
| Func Coverage | `entered_funcs / total_funcs` | `funcs: 55/88 (62.5%)` |

100회 실행마다 스냅샷 → `coverage_growth.png`, `firmware_map.png` 생성

---

## 4. 퍼징 입력 생성 및 뮤테이션

### 입력 구조 (Seed)

```python
@dataclass
class Seed:
    cmd: NVMeCommand          # 기반 명령 (Identify, Read, Write ...)
    cdw2, cdw3, cdw10~cdw15  # Command Dword 필드 (32-bit each)
    data: bytes               # 호스트→SSD 데이터 버퍼
    opcode_override: Optional[int]   # 다른 opcode로 전송
    nsid_override: Optional[int]     # Namespace ID 변조
    force_admin: Optional[bool]      # Admin/IO passthru 강제 전환
    data_len_override: Optional[int] # 데이터 길이 불일치
```

### 뮤테이션 파이프라인

```
1. Deterministic Stage (corpus seed 첫 처리)
   └─ CDW 필드 bitflip, arith(+/-35), interesting values (0, 0xFF, 0xFFFF ...)

2. Random/Havoc Stage
   └─ Corpus 선택 (power schedule 기반)
   └─ CDW 필드 랜덤 변이 (bitflip, byte flip, block replace ...)
   └─ Opcode Override    (prob: opcode_mut_prob)
   └─ NSID Override      (prob: nsid_mut_prob)
   └─ Admin↔IO swap      (prob: admin_swap_prob)
   └─ DataLen Override   (prob: datalen_mut_prob)

3. MOpt (Mutation Operator Scheduling)
   Pilot phase: 각 연산자 효율 측정
   Core phase:  성공률 기반 가중치 재계산 → 고효율 연산자 우선 사용
```

### Corpus 관리

- **추가 조건**: `new_pcs > 0` (새 커버리지 포함 시)
- **컬링**: 1000회마다 중복 커버리지 seed 제거 (favored/unfavored 구분)
- **에너지 스케줄**: 커버리지 희소 seed에 더 많은 실행 기회 부여

---

## 5. 전원 상태 제어 (Power Combo)

### Power Combo 구조

```python
@dataclass(frozen=True)
class PowerCombo:
    nvme_ps: int        # NVMe Power State: 0~4
    pcie_l: PCIeLState  # PCIe Link State: L0(0) / L1(1) / L1.2(2)
    pcie_d: PCIeDState  # PCIe Device State: D0(0) / D3hot(3)

    @property
    def label(self) -> str:
        return f"PS{self.nvme_ps}+{l_name}+{d_name}"
        # 예: "PS3+L1.2+D3"

POWER_COMBOS: List[PowerCombo]  # 5 × 3 × 2 = 30개 전체 조합
```

### NVMe PS 전환 (`_pm_set_state`)

```
nvme-cli admin-passthru --opcode=0x09 \
    --cdw10=0x00000002 \    # FID=0x02 (Power Management)
    --cdw11=<ps>            # PS 값 (0~4)
```

- SetFeatures(FID=0x02) 명령으로 전환
- `cmd_history`에 기록 → replay .sh에 재현

### PS 전환 주기 및 통계

```python
PM_ROTATE_INTERVAL = 100  # 100회 실행마다 랜덤 combo 선택

# 매 100회 실행 시:
next_combo = random.choice(POWER_COMBOS)
_set_power_combo(next_combo)

# 통계:
ps_enter_counts[ps]       # PS별 진입 횟수
combo_enter_counts[combo] # combo별 진입 횟수
combo_exec_counts[combo]  # combo별 실행 횟수 (진입 후 다음 전환까지)
```

---

## 6. PCIe ASPM 제어 (L-state)

### 구현 기반

**PCIe spec r5.0 §5.5.4.1** 절차 준수. setpci(write-with-mask) 방식으로 config space 직접 조작.

### 탐지 (`_detect_pcie_info`)

```
sysfs /sys/class/nvme/nvme0/address  →  endpoint BDF (예: 0000:02:00.0)
lspci -v -s <BDF>                    →  capability offsets
  - PCIe Express cap (LNKCTL, DEVCTL2 위치)
  - PCI PM cap (PMCSR 위치)
  - L1 Sub-States cap (L1SSCTL1, L1SSCAP 위치)
setpci -s <BDF> <LNKCAP offset>.l   →  ASPMS(bit[11:10]), CPM(bit18) 캐시
setpci -s <BDF> <L1SSCAP offset>.l  →  지원 substate 비트[3:0] 캐시

sysfs realpath 역추적                →  루트 포트 BDF + RP capability offsets
/sys/module/pcie_aspm/parameters/policy  →  원본 ASPM policy 저장
```

### L-state 전환 시퀀스

#### L0 (ASPM 비활성화)

```
[PMU] CLKREQ# Assert      ← 클록 복원 먼저 (config space write 전 필수)
  ↓
LNKCTL ASPMC = 0b00       (EP + RP)   setpci offset+0x10 .w=0000:0003
L1SSCTL1 enable bits = 0  (EP + RP)   setpci offset+0x08 .l=00000000:0000000f
DEVCTL2 LTRE = 0           (EP + RP)   setpci offset+0x28 .w=0000:0400
LNKCTL ECPM = 0            (EP + RP)   setpci offset+0x10 .w=0000:0100
ASPM policy 복원           echo <orig> > /sys/module/pcie_aspm/parameters/policy
```

#### L1 (ASPM L1 활성화)

```
L1SSCTL1 enable bits = 0   (L1.2 잔류 제거)
policy = powersave
LNKCTL ASPMC = ASPMS & 0x2 (RP 먼저 → EP)   spec: upstream first
LNKCTL ECPM = 1            (CPM 지원 시)
검증: setpci read-back
```

#### L1.2 (ASPM L1 + L1 PM Substates)

```
Step 1: L1SSCTL1 enable bits = 0   (EP + RP)   기존 상태 초기화
Step 2: policy = powersave
Step 3: DEVCTL2 LTRE = 1           (EP + RP)   LTR 메커니즘 전제조건
Step 4: L1SSCTL1 LTR threshold 설정 (EP + RP)
        LL1_2TV = 0xa at bits[25:16]  →  0x000a0000
        LL1_2TS = 2   at bits[31:29]  →  0x40000000
        combined: 0x400a0000, mask: 0xe3ff0000
        → threshold = 10 × 1024ns = 10.24µs
Step 5: L1SSCTL1 enable bits = L1SSCAP & 0xF   (RP 먼저 → EP)
        bit0: PCI-PM L1.2, bit1: PCI-PM L1.1
        bit2: ASPM L1.2,   bit3: ASPM L1.1
Step 6: LNKCTL ASPMC = ASPMS & 0x2  (RP 먼저 → EP)
Step 7: LNKCTL ECPM = 1             (CPM 지원 시)
Step 8: 검증 (LNKCTL + L1SSCTL1 read-back)  ← CLKREQ# deassert 전 필수
        (deassert 후에는 클록 없어 config space read 불가)

[PMU] CLKREQ# Deassert    ← 레지스터 설정 완료 후 마지막 수행
                             루트 포트가 CLKREQ# 비활성 감지 → 클록 제거 → L1.2 진입
```

### setpci 헬퍼

```python
def _setpci_read(bdf, offset, width='l') -> Optional[int]:
    # setpci -s <bdf> <offset>.l  →  hex → int

def _setpci_write(bdf, offset, value, mask, width='l') -> bool:
    # setpci -s <bdf> <offset>.l=<value&mask:8x>:<mask:8x>
    # mask=1인 비트만 수정, 나머지 보존
```

### PMU CLKREQ# 삽입 위치

| 위치 | 동작 | 이유 |
|------|------|------|
| L0 블록 최상단 (레지스터 write 전) | `pmu.clkreq_assert()` | L1.2 상태에서 클록 없음 → config space write 전 클록 복원 필수 |
| L1.2 Step8 검증 직후 (return 전) | `pmu.clkreq_deassert()` | 레지스터·검증 완료 후 마지막 → 루트포트가 클록 제거 |

```python
# L0 블록 최상단
# >>> your_pmu_api.clkreq_assert()
# >>> time.sleep(0.001)   # 클록 안정화 대기

# L1.2 Step8 직후
# >>> your_pmu_api.clkreq_deassert()
```

---

## 7. PCIe D-state 제어

### PMCSR 레지스터 조작

```
PCI PM cap + 0x04 = PMCSR (Power Management Control/Status Register)
bits[1:0]:
  0b00 = D0 (활성)
  0b11 = D3hot (절전)

setpci -s <BDF> <PMCSR_offset>.w=0000:0003  # D0
setpci -s <BDF> <PMCSR_offset>.w=0003:0003  # D3hot
```

### D3 타임아웃 배수

```python
D3_TIMEOUT_MULT = 4  # D3hot wake-up 지연 보상

# 타임아웃 계산:
if _current_combo.pcie_d == PCIeDState.D3:
    _timeout_mult = max(_timeout_mult, D3_TIMEOUT_MULT)
```

---

## 8. 타임아웃 및 크래시 처리

### 이중 타임아웃 구조

| 계층 | 값 | 역할 |
|------|----|------|
| `nvme-cli --timeout` | **3,600,000ms (1시간)** | ioctl blocking 유지 → 크래시 상태 보존 |
| `nvme_core.admin_timeout` (커널) | **30일** | 커널 abort/reset 방지 → 펌웨어 상태 유지 |

- 타임아웃 발생 → nvme-cli 프로세스가 1시간 동안 blocking → 그동안 크래시 SSD 상태 분석 가능

### 타임아웃 배수 계산

```python
# PS3/PS4는 이전 operational PS(0~2)의 배수 적용
_ps_for_timeout = (
    _prev_op_ps if pm_inject_prob > 0 and _current_ps in (3, 4)
    else _current_ps
)
_timeout_mult = PS_TIMEOUT_MULT.get(_ps_for_timeout, 1)

PS_TIMEOUT_MULT = {
    0: 1,   # PS0: 기본
    1: 16,  # PS1: 16×  (wake-up 지연 큼)
    2: 32,  # PS2: 32×  (wake-up 지연 가장 큼)
    3: 1,   # PS3: _prev_op_ps 기준 적용
    4: 1,   # PS4: _prev_op_ps 기준 적용
}

# D3hot 추가 배수
if _current_combo.pcie_d == PCIeDState.D3:
    _timeout_mult = max(_timeout_mult, D3_TIMEOUT_MULT)  # 최소 4×
```

### 크래시 발생 시

```
1. _timeout_crash = True 기록
2. nvme-cli PID 보존 (_crash_nvme_pid)
3. dmesg 캡처
4. UFAS dump 실행 (./ufas 존재 시)
5. Replay .sh 자동 생성
   - cmd_history의 모든 명령 재현
   - pcie_state 항목 → setpci 시퀀스로 변환 (L-state별 전체 순서)
   - nvme-cli --timeout=3600000 으로 crash 상태 재현
```

---

## 9. 메인 루프 흐름

```
run() 진입
  │
  ├─ J-Link 연결 + PC 레지스터 인덱스 탐지
  ├─ nvme_core 커널 타임아웃 30일로 설정
  ├─ _detect_pcie_info()   [--pm 활성 시]
  ├─ _load_static_analysis() [basic_blocks.txt/functions.txt]
  │
  ├─ Idle Universe 탐지 (diagnose)
  │   J-Link PC 샘플링으로 NVMe idle 상태 PCs 수집
  │   새 idle PC 없으면 수렴 → idle_pcs 확정
  │
  ├─ Calibration (초기 seed × calibration_runs 실행)
  │   초기 corpus 구성
  │
  └─ Fuzzing Loop ─────────────────────────────────────────
       while elapsed < total_runtime_sec:
         │
         ├─ [입력 선택]
         │   Deterministic queue 있으면 → deterministic mutation
         │   없으면 → corpus 기반 havoc 또는 random 생성
         │
         ├─ [실행]
         │   timeout_mult = PS×배수 × D3배수
         │   rc = _send_nvme_command(data, seed, timeout_mult)
         │
         ├─ [커버리지 업데이트]
         │   new_pcs = current_pcs - global_coverage
         │   _update_static_coverage(new_pcs)
         │
         ├─ [흥미로운 입력 → corpus 추가]
         │   new_pcs > 0 → corpus append + deterministic queue push
         │
         ├─ [매 100회 실행]
         │   Power Combo 랜덤 전환 (_set_power_combo)
         │   BB coverage 스냅샷
         │   _print_status() 출력
         │
         ├─ [매 1000회 실행]
         │   _cull_corpus()
         │   MOpt 페이즈 업데이트
         │   J-Link heartbeat
         │
         └─ [매 10000회 실행]
             _log_smart()

  Summary 출력 → coverage 그래프 생성 → 종료
```

---

## 10. 통계 및 출력

### 실행 중 상태 표시 (100회마다)

```
[Stats] exec: 1,000 | corpus: 50 | crashes: 0 | pcs: 1,200 | samples: 50,000 |
        last_run: 150 | exec/s(avg): 12.5 | exec/s(win): 14.2 | PS3+L1.2+D3(×32TO)
[StatCov] BB: 45.1% (1,220/2,700) | funcs: 55/88 (62.5%)
```

### 종료 시 Summary

```
========== Fuzzing Complete ==========
Total executions     : X,XXX
BB Coverage          : 45.67% (1,234 / 2,700 basic blocks)
Func Coverage        : 62.34% (55 / 88 functions)

Power Combo Stats:
  PS0+L0+D0   : 실행 170회 (3.4%), 진입 50회
  PS1+L1.2+D3 : 실행 160회 (3.2%), 진입 50회  [TO×32]
  PS2+L1+D0   : 실행 155회 (3.1%), 진입 50회  [TO×32]
  ... (전체 30개 combo)

Mutation stats:
  corpus_mutated: 4,000 (80.0%)  random_gen: 1,000 (20.0%)
  opcode_override: 200 / nsid_override: 150 / admin↔io: 100
========================================
```

---

## 11. 주요 상수 및 설정

| 상수 | 값 | 의미 |
|------|----|------|
| `PM_ROTATE_INTERVAL` | 100 | PS 전환 주기 (실행 횟수) |
| `PS_TIMEOUT_MULT` | `{0:1, 1:16, 2:32, 3:1, 4:1}` | PS별 타임아웃 배수 |
| `D3_TIMEOUT_MULT` | 4 | D3hot wake-up 추가 배수 |
| `DIAGNOSE_STABILITY` | 100 | idle 수렴 판정 (새 PC 없는 연속 횟수) |
| `DIAGNOSE_MAX` | 5000 | idle 탐지 최대 샘플 수 |
| `CALIBRATION_RUNS` | 3 | 초기 seed 반복 실행 횟수 |
| `MOPT_PILOT_PERIOD` | 5,000 | MOpt pilot 페이즈 실행 수 |
| `MOPT_CORE_PERIOD` | 50,000 | MOpt core 페이즈 실행 수 |

### CLI 주요 인자

```bash
python3 pc_sampling_fuzzer_v5.2.py \
  --nvme /dev/nvme0 \          # NVMe 장치
  --namespace 1 \              # Namespace ID
  --bb-addrs basic_blocks.txt \# Ghidra export BB 파일
  --func-addrs functions.txt \ # Ghidra export 함수 파일
  --pm \                       # Power Combo 활성화
  --commands Read Write Identify \  # 활성화할 명령
  --speed 4000                 # J-Link JTAG 속도 (kHz)
```

---

## 12. 버전 히스토리

| 버전 | 주요 변경사항 |
|------|---------------|
| **v5.2** | Power Combo (NVMe PS × PCIe L-state × D-state) 30개 조합 동시 제어. PCIe ASPM spec 준수 재구현 (루트 포트 양측, LTR threshold, DEVCTL2 LTRE). PMU CLKREQ# 삽입 위치 주석. |
| **v5.1** | PS3/PS4 IO 필터 제거 + `_prev_op_ps` 타임아웃 기준. Instruction → **Basic Block 기준 커버리지** 전환 (Ghidra `BasicBlockModel` export). Replay `--timeout=3600000` (크래시 상태 보존). |
| **v5.0** | subprocess(nvme-cli) passthru 방식으로 전환. nvme_core 커널 타임아웃 30일 설정. |
| **v4.7** | PC 기반 커버리지 (edge → PC). NVMe SMART 진단 로그. |
| **v4.x** | MOpt 뮤테이션 스케줄러. Deterministic stage. Power schedule (corpus energy). |
| **v3.x** | 초기 커버리지 가이드 구조. J-Link PC 샘플링 기반 아키텍처 확립. |
