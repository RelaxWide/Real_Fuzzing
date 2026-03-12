# PC Sampling Fuzzer v5.2 — System Overview

---

## 전체 구조 다이어그램

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║                        PC Sampling Fuzzer v5.2                                 ║
║                                                                                ║
║  ┌─────────────────────────────────────────────────────────────────────────┐   ║
║  │                        Host PC (Linux)                                  │   ║
║  │                                                                         │   ║
║  │  ┌──────────────────────────────────────────────────────────────────┐  │   ║
║  │  │                   Fuzzer Main Loop                               │  │   ║
║  │  │                                                                  │  │   ║
║  │  │  ┌────────────┐   ┌──────────────┐   ┌────────────────────────┐ │  │   ║
║  │  │  │  Mutation  │──▶│   Execute    │──▶│   Coverage Update      │ │  │   ║
║  │  │  │  Engine    │   │  (nvme-cli)  │   │   (PC → BB bisect)     │ │  │   ║
║  │  │  └────────────┘   └──────┬───────┘   └────────────────────────┘ │  │   ║
║  │  │       ▲                  │                      │                │  │   ║
║  │  │       │            ┌─────▼──────┐               ▼                │  │   ║
║  │  │  ┌────┴──────┐     │ Timeout /  │      ┌───────────────────┐     │  │   ║
║  │  │  │  Corpus   │     │ Crash Det. │      │ Corpus / MOpt     │     │  │   ║
║  │  │  │  (Seeds)  │◀────│            │      │ Schedule Update   │     │  │   ║
║  │  │  └───────────┘     └────────────┘      └───────────────────┘     │  │   ║
║  │  │                                                                  │  │   ║
║  │  │         every 100 execs                                          │  │   ║
║  │  │  ┌───────────────────────────────────────────────────────────┐   │  │   ║
║  │  │  │             Power Combo Rotation                          │   │  │   ║
║  │  │  │  random.choice(POWER_COMBOS)  →  _set_power_combo()       │   │  │   ║
║  │  │  │  NVMe PS ──▶ SetFeatures(FID=0x02)                        │   │  │   ║
║  │  │  │  PCIe L  ──▶ setpci LNKCTL / L1SS / DEVCTL2              │   │  │   ║
║  │  │  │  PCIe D  ──▶ setpci PMCSR                                 │   │  │   ║
║  │  │  └───────────────────────────────────────────────────────────┘   │  │   ║
║  │  └──────────────────────────────────────────────────────────────────┘  │   ║
║  │                                                                         │   ║
║  │   ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────┐  │   ║
║  │   │  J-Link SDK  │    │  nvme-cli    │    │  setpci / sysfs          │  │   ║
║  │   │  (DLL)       │    │  subprocess  │    │  subprocess              │  │   ║
║  │   └──────┬───────┘    └──────┬───────┘    └────────────┬─────────────┘  │   ║
║  └──────────┼────────────────── ┼─────────────────────────┼────────────────┘   ║
║             │                   │                          │                   ║
║   ┌─────────▼──────┐    ┌───────▼──────┐    ┌─────────────▼──────────────┐    ║
║   │  J-Link V9     │    │  NVMe SSD    │    │  PCIe Bus (config space)   │    ║
║   │  JTAG/SWD      │    │  /dev/nvme0  │    │                            │    ║
║   │                │    │              │    │  [Root Port]──[Endpoint]   │    ║
║   │  Halt──Read──  │    │  Admin/IO    │    │   LNKCTL    LNKCTL         │    ║
║   │  Go (반복)     │    │  Passthru    │    │   L1SSCTL1  L1SSCTL1       │    ║
║   └────────────────┘    └──────────────┘    └────────────────────────────┘    ║
║          ║                      ║                         ║                   ║
║    PC 샘플링                NVMe 명령              PCIe State 제어             ║
║    (커버리지)               (퍼징 입력)             (PM 제어)                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
```

---

## 1. PC 샘플링 기반 커버리지 수집

### 동작 원리

```
J-Link V9 (JTAG/SWD)
       │
       ├── JLINKARM_Halt()         CPU 정지 (수십µs)
       ├── JLINKARM_ReadReg(PC)    PC 레지스터 값 읽기
       └── JLINKARM_GoEx(0,0)      CPU 재개

 ──▶ 반복 (sample_interval_us 주기)
 ──▶ NVMe 명령 처리 중 펌웨어 실행 경로를 통계적으로 수집
```

- **아키텍처 대응**: Cortex-R8(PC=R15), Cortex-M(R15), RISC-V(MEPC/SEPC/EPC) 자동 탐지
- **인터페이스 자동 전환**: JTAG 실패 시 SWD 자동 재시도 (`--interface auto`)
- **커버리지 집합**: `global_coverage: Set[int]` — 전체 실행에서 수집된 고유 PC
- **흥미로운 입력 판별**: `new_pcs = current_run_pcs - global_coverage`, `new_pcs > 0` 이면 corpus 추가

### Idle Universe 수렴 탐지 (진단 단계)

```
fuzzer 시작 시 1회 수행:

  샘플링 반복 ──▶ idle PC 집합 누적
      │
      ├── 새 PC 발생 → consecutive_stable = 0 리셋
      └── 새 PC 없음 → consecutive_stable += 1
              │
              └── consecutive_stable ≥ DIAGNOSE_STABILITY(100) → 수렴 완료

  수집된 idle_pcs = "아무 명령 없을 때 나타나는 PC 집합"
  → 퍼징 중 커버리지 판별에서 idle_pcs는 제외
```

### Basic Block 커버리지 (Ghidra 연동)

```
Ghidra (ghidra_export.py)
  └── BasicBlockModel.getCodeBlocks()
  └── basic_blocks.txt:  "0xSTART 0xEND_exclusive"  ← 한 줄에 BB 하나

퍼저 로드 (_load_static_analysis):
  _sa_bb_starts[] = [0x08001000, 0x08001020, ...]  (정렬)
  _sa_bb_ends[]   = [0x08001020, 0x08001040, ...]  (대응하는 exclusive end)

PC → BB 매핑 (_update_static_coverage):
  idx = bisect_right(_sa_bb_starts, pc) - 1
  if _sa_bb_starts[idx] ≤ pc < _sa_bb_ends[idx]:
      _sa_covered_bbs.add(_sa_bb_starts[idx])   ← O(log N)

  근거: 샘플 1개가 BB 내 어느 위치든 → 해당 BB 전체가 실행된 것
        (instruction 단위 집계보다 샘플링 노이즈에 강인)
```

---

## 2. 퍼징 입력 (NVMe 명령) 구성

### 입력 단위: Seed

```python
Seed(
    cmd      = NVMeCommand(name, opcode, cmd_type, ...),
    cdw2..15 = 32-bit fields,          # NVMe Command Dword
    data     = bytes,                  # 호스트→SSD 데이터 버퍼

    # 뮤테이션 메타데이터 (None = 원본 그대로)
    opcode_override   : Optional[int],   # 다른 opcode로 전송
    nsid_override     : Optional[int],   # Namespace ID 변조
    force_admin       : Optional[bool],  # Admin↔IO passthru 강제
    data_len_override : Optional[int],   # 데이터 길이 불일치
)
```

### 뮤테이션 파이프라인

```
┌──────────────────────────────────────────────────────┐
│  Stage 1: Deterministic (corpus seed 첫 처리 시)     │
│                                                      │
│  CDW 필드 순서대로:                                   │
│  ① bitflip 1/1, 2/1, 4/1, 8/8, 16/8, 32/8          │
│  ② arith ±1 ~ ±35                                   │
│  ③ interesting values: 0, 0x7F, 0x80, 0xFF,         │
│     0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF, 0x80000000  │
└──────────────────────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────────────┐
│  Stage 2: Havoc (random / corpus 기반)               │
│                                                      │
│  CDW 필드 랜덤 변이 (MOpt 가중치 적용)               │
│  + Opcode override    (prob: opcode_mut_prob)         │
│  + NSID override      (prob: nsid_mut_prob)           │
│  + Admin↔IO swap      (prob: admin_swap_prob)         │
│  + DataLen override   (prob: datalen_mut_prob)        │
└──────────────────────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────────────┐
│  MOpt: Mutation Operator Scheduling                  │
│                                                      │
│  Pilot phase (5,000 exec):                           │
│    각 연산자별 성공(new coverage) 카운트             │
│  Core phase (50,000 exec):                           │
│    성공률 기반 가중치 재계산                         │
│    → 고효율 연산자 우선 선택                         │
└──────────────────────────────────────────────────────┘
```

### NVMe 명령 전송

```bash
# Admin 명령 예시 (Identify)
sudo nvme admin-passthru /dev/nvme0 \
  --opcode=0x06 --namespace-id=0 \
  --cdw10=0x00000001 --data-len=4096 -r \
  --timeout=3600000    ← crash 상태 보존용 1시간

# IO 명령 예시 (Read)
sudo nvme io-passthru /dev/nvme0 \
  --opcode=0x02 --namespace-id=1 \
  --cdw10=<slba_lo> --cdw12=<nlb> \
  --data-len=4096 -r --timeout=3600000
```

---

## 3. Power Management (PM) 제어 — 상세

### 3.1 전체 PM 구조

```
NVMe PS (0~4)          PCIe L-state           PCIe D-state
   │                       │                       │
   │  SetFeatures          │  setpci               │  setpci
   │  FID=0x02             │  LNKCTL/L1SS          │  PMCSR
   ▼                       ▼                       ▼
┌──────┐             ┌───────────┐           ┌──────────┐
│ PS0  │  활성       │    L0     │  활성      │    D0    │  활성
│ PS1  │  저전력     │    L1     │  ASPM L1   │    D3    │  D3hot
│ PS2  │  저전력     │   L1.2   │  L1+클록제거│          │
│ PS3  │  비작동     └───────────┘           └──────────┘
│ PS4  │  비작동
└──────┘

PowerCombo = (NVMe PS) × (PCIe L) × (PCIe D)
           = 5         × 3        × 2
           = 30가지 조합
```

### 3.2 Power Combo 정의

```python
@dataclass(frozen=True)
class PowerCombo:
    nvme_ps : int          # 0~4
    pcie_l  : PCIeLState   # L0=0 / L1=1 / L1_2=2
    pcie_d  : PCIeDState   # D0=0 / D3=3

    @property
    def label(self) -> str:
        # 예: "PS3+L1.2+D3",  "PS0+L0+D0",  "PS2+L1+D3"

POWER_COMBOS = [
    PowerCombo(ps, PCIeLState(l), PCIeDState(d))
    for ps in range(5)        # PS0 ~ PS4
    for l  in (0, 1, 2)       # L0 / L1 / L1.2
    for d  in (0, 3)          # D0 / D3hot
]
# → 총 30개 조합
```

### 3.3 PM 전환 주기

```
Fuzzing Loop
    │
    ├── exec 1   ─┐
    ├── exec 2    │  100회 실행
    ├── ...       │  (PM_ROTATE_INTERVAL = 100)
    ├── exec 99   │
    └── exec 100 ─┘
            │
            ▼
    next_combo = random.choice(POWER_COMBOS)  ← 30개 중 랜덤 1개
    _set_power_combo(next_combo)
            │
            ├── _pm_set_state(combo.nvme_ps)   NVMe PS 전환
            ├── _set_pcie_l_state(combo.pcie_l) PCIe L-state 전환
            └── _set_pcie_d_state(combo.pcie_d) PCIe D-state 전환
```

---

### 3.4 NVMe Power State (PS) 제어

#### SetFeatures 명령 전송

```
Admin Passthru:
  Opcode : 0x09  (Set Features)
  CDW10  : 0x00000002  (FID = 0x02, Power Management)
  CDW11  : <ps>        (0~4)

예: PS2로 전환
  nvme admin-passthru ... --opcode=0x09 --cdw10=0x2 --cdw11=0x2
```

#### PS별 특성 및 타임아웃 배수

| PS | 상태 | 특성 | 타임아웃 배수 |
|----|------|------|---------------|
| PS0 | 활성 | 최대 성능, 클록 전체 활성 | ×1 |
| PS1 | 저전력 | 일부 클록 게이팅, wake-up ~수ms | ×16 |
| PS2 | 저전력 | 더 깊은 절전, wake-up ~수십ms | ×32 |
| PS3 | 비작동 | 펌웨어 절전 진입, wake-up 느림 | `_prev_op_ps` 기준 |
| PS4 | 비작동 | 최대 절전, wake-up 매우 느림 | `_prev_op_ps` 기준 |

#### PS3/PS4 타임아웃 처리

```
PS3, PS4는 진입 직전 마지막 operational PS(0~2)를 _prev_op_ps에 기억:

  if next_combo.nvme_ps not in (3, 4):
      _prev_op_ps = next_combo.nvme_ps   ← PS0~2일 때만 갱신

타임아웃 배수 계산:
  _ps_for_timeout = (
      _prev_op_ps         ← PS3/4일 때: 이전 PS의 배수 사용
      if _current_ps in (3, 4)
      else _current_ps    ← PS0~2일 때: 현재 PS 배수
  )
  _timeout_mult = PS_TIMEOUT_MULT[_ps_for_timeout]

이유: PS3/PS4에서 명령을 보내면 SSD는 일단 wake-up 후 처리.
     wake-up 시간은 진입 전 PS(0~2) 수준에 비례하므로
     그 배수를 그대로 사용.
```

---

### 3.5 PCIe L-state (ASPM) 제어

#### PCIe 정보 탐지 (`_detect_pcie_info`)

```
① endpoint BDF 탐지
   /sys/class/nvme/nvme0/address → "0000:02:00.0"
   실패 시 lspci fallback

② lspci -v -s <BDF> → capability offsets
   PCIe Express cap offset  → LNKCTL, DEVCTL2 위치
   PCI PM cap offset        → PMCSR 위치
   L1 Sub-States cap offset → L1SSCTL1, L1SSCAP 위치

③ 레지스터 캐시 읽기
   LNKCAP (PCIe_cap + 0x0C):
     bits[11:10] = ASPMS  ← L1 지원 여부
     bit18       = CPM    ← Clock PM 지원 여부
   L1SSCAP (L1SS_cap + 0x04):
     bit0 = PCI-PM L1.2 지원
     bit1 = PCI-PM L1.1 지원
     bit2 = ASPM L1.2 지원
     bit3 = ASPM L1.1 지원

④ 루트 포트 BDF 탐지
   /sys/bus/pci/devices/0000:02:00.0  (symlink)
   → realpath → 부모 디렉터리명 = 루트 포트 BDF
   루트 포트 PCIe Express cap, L1SS cap offset 별도 탐지

⑤ 원본 ASPM policy 저장
   /sys/module/pcie_aspm/parameters/policy
   → _orig_aspm_policy (L0 복원 시 사용)
```

#### L0 전환 시퀀스 (ASPM 비활성화)

```
[PMU] CLKREQ# Assert ◀── 반드시 레지스터 조작 전에 수행!
      L1.2 상태에서는 레퍼런스 클록이 없음.
      config space write (setpci) 를 하려면 클록이 있어야 함.
      → PMU로 CLKREQ# 먼저 assert → 루트 포트가 클록 복원 → 링크 L0 재진입
      → 그 다음 setpci 실행

① LNKCTL ASPMC = 0b00      EP + RP 양측
   setpci -s <EP> <LNKCTL>.w=0000:0003
   setpci -s <RP> <LNKCTL>.w=0000:0003

② L1SSCTL1 enable bits = 0   EP + RP 양측
   setpci -s <EP> <L1SSCTL1>.l=00000000:0000000f

③ DEVCTL2 LTRE = 0            EP + RP 양측
   setpci -s <EP> <DEVCTL2>.w=0000:0400

④ LNKCTL ECPM = 0             EP + RP 양측
   setpci -s <EP> <LNKCTL>.w=0000:0100

⑤ ASPM policy 복원
   echo <_orig_aspm_policy> > /sys/module/pcie_aspm/parameters/policy

⑥ 검증: setpci read-back → LNKCTL ASPMC == 0 확인
```

#### L1 전환 시퀀스 (ASPM L1 활성화)

```
전제: LNKCAP.ASPMS bit1 == 1  (L1 지원 확인)

① L1SSCTL1 enable bits = 0    L1.2 잔류 제거 (EP + RP)

② /sys/module/pcie_aspm/parameters/policy = powersave
   (커널이 performance policy로 ASPM을 막지 못하도록)

③ LNKCTL ASPMC = ASPMS & 0x2   ← LNKCAP에서 읽은 지원값만 세팅
   루트 포트(RP) 먼저 → endpoint(EP) 이후  (spec 권고 순서)
   setpci -s <RP> <LNKCTL>.w=0002:0003
   setpci -s <EP> <LNKCTL>.w=0002:0003

④ LNKCTL ECPM = 1  (CPM 지원 시만)
   Active-State Clock PM 활성화 (L0 상태에서 idle 시 CLKREQ# 관리)

⑤ 검증: setpci read-back → LNKCTL ASPMC == 0x02 확인
```

#### L1.2 전환 시퀀스 (ASPM L1 + L1 PM Substates — spec §5.5.4.1)

```
전제 확인:
  LNKCAP.ASPMS bit1 == 1     L1 지원
  L1SSCAP bit2 == 1          ASPM L1.2 지원

Step 1: L1SSCTL1 enable bits = 0      EP + RP 양측
        기존 L1.2 설정 초기화 (spec 요구: enable 전 반드시 disable)
        setpci -s <EP> <L1SSCTL1>.l=00000000:0000000f
        setpci -s <RP> <L1SSCTL1>.l=00000000:0000000f

Step 2: ASPM policy = powersave

Step 3: DEVCTL2 LTRE (bit10) = 1     EP + RP 양측
        LTR(Latency Tolerance Reporting) 메커니즘 활성화
        → LTR threshold가 의미를 가지려면 반드시 선행 필요
        setpci -s <EP> <DEVCTL2>.w=0400:0400
        setpci -s <RP> <DEVCTL2>.w=0400:0400

Step 4: L1SSCTL1 LTR threshold 설정   EP + RP 양측
        (enable bits 제외하고 threshold 필드만 쓰기)

        ┌─────────────────────────────────────────────────┐
        │ L1SSCTL1 레지스터 (32-bit, L1SS_cap + 0x08)    │
        │                                                 │
        │ bit31..29 = LTR_L1.2_THRESHOLD_Scale (LL1_2TS) │
        │ bit25..16 = LTR_L1.2_THRESHOLD_Value (LL1_2TV) │
        │ bit11..4  = CM_RESTORE_TIME  ← 건드리지 않음   │
        │ bit3..0   = enable bits      ← Step5에서 설정  │
        └─────────────────────────────────────────────────┘

        LL1_2TS = 2  → scale = 1024ns 단위
        LL1_2TV = 0xa → value = 10

        threshold = 10 × 1024ns = 10,240ns ≈ 10.24µs
        (관측 LTR latency < 10.24µs 이면 CLKREQ# deassert 가능)

        write value : 0x400A_0000
          (2 << 29) | (0xa << 16) = 0x4000_0000 | 0x000A_0000
        write mask  : 0xE3FF_0000
          bits[31:29] mask : 0xE000_0000
          bits[25:16] mask : 0x03FF_0000

        setpci -s <EP> <L1SSCTL1>.l=400a0000:e3ff0000
        setpci -s <RP> <L1SSCTL1>.l=400a0000:e3ff0000

Step 5: L1SSCTL1 enable bits 활성화   upstream(RP) 먼저 → EP (spec 규정)
        enable 비트 = L1SSCAP & 0xF  (지원하는 substate만 켬)
          bit0: PCI-PM L1.2
          bit1: PCI-PM L1.1
          bit2: ASPM L1.2
          bit3: ASPM L1.1
        setpci -s <RP> <L1SSCTL1>.l=<l1ss_en>:0000000f   ← RP 먼저
        setpci -s <EP> <L1SSCTL1>.l=<l1ss_en>:0000000f

Step 6: LNKCTL ASPMC = ASPMS & 0x2   upstream(RP) 먼저 → EP
        setpci -s <RP> <LNKCTL>.w=0002:0003
        setpci -s <EP> <LNKCTL>.w=0002:0003

Step 7: LNKCTL ECPM = 1  (CPM 지원 시)

Step 8: 검증 (read-back) — CLKREQ# deassert 전에 반드시 수행
        setpci read → LNKCTL ASPMC, L1SSCTL1 enable bits, LTR threshold 확인
        ※ deassert 후에는 클록이 없어 config space read 불가

[PMU] CLKREQ# Deassert ◀── 모든 레지스터 설정·검증 완료 후 마지막 수행
      루트 포트가 CLKREQ# 비활성 감지
      → 레퍼런스 클록 제거
      → 실제 L1.2 링크 상태 진입
```

#### PMU CLKREQ# 연동 위치 (코드 주석)

```python
# _set_pcie_l_state() 내부

# ─── L0 블록 최상단 ──────────────────────────────────────
if state == PCIeLState.L0:
    # [PMU] CLKREQ# Assert
    # >>> your_pmu_api.clkreq_assert()
    # >>> time.sleep(0.001)   # 클록 안정화 대기 (T_COMMON_MODE)
    ...setpci 레지스터 조작...

# ─── L1.2 블록 Step8 직후 ────────────────────────────────
else:  # L1.2
    ...Steps 1~8...
    # Step 8: 검증 (config read-back, 클록 있을 때)
    rb_lnk = self._setpci_read(ep, ec + 0x10, 'w')
    ...

    # [PMU] CLKREQ# Deassert
    # >>> your_pmu_api.clkreq_deassert()
    return ok
```

---

### 3.6 PCIe D-state (PCI PM) 제어

#### PMCSR 레지스터 조작

```
PCI PM cap + 0x04 = PMCSR (Power Management Control/Status Register)
                    bits[1:0]:
                      00b = D0    (완전 활성)
                      11b = D3hot (절전, PCIe 설정 공간 접근 가능)

D0 전환:  setpci -s <EP> <PMCSR>.w=0000:0003
D3 전환:  setpci -s <EP> <PMCSR>.w=0003:0003
```

#### D3hot 특성

- **D3hot**: PCIe config space는 접근 가능, 장치 기능은 중단
- **D3cold**: PCIe config space 접근 불가 (본 퍼저는 미사용)
- 본 구현에서는 **endpoint만** D-state 전환 (루트 포트는 D-state 유지)

---

### 3.7 타임아웃 최종 계산

```
전체 타임아웃 배수 = PS 배수 × D3 배수

PS_TIMEOUT_MULT = {0: 1,  1: 16,  2: 32,  3: 1,  4: 1}
D3_TIMEOUT_MULT = 4

예시:
  PS2 + L1.2 + D3  →  _ps_for_timeout = 2  →  32 × max(32, 4) = ×32
  PS4 + L1   + D3  →  _ps_for_timeout = _prev_op_ps (예: PS1)
                    →  16 × max(16, 4) = ×16
  PS0 + L0   + D0  →  1 × 1 = ×1  (기본)
  PS1 + L1.2 + D0  →  16 × 1 = ×16

코드:
  _ps_for_timeout = _prev_op_ps if _current_ps in (3,4) else _current_ps
  _timeout_mult   = PS_TIMEOUT_MULT[_ps_for_timeout]
  if _current_combo.pcie_d == PCIeDState.D3:
      _timeout_mult = max(_timeout_mult, D3_TIMEOUT_MULT)
```

---

### 3.8 이중 타임아웃 구조 (크래시 상태 보존)

```
┌─────────────────────────────────────────────────────────────────┐
│  계층 1: nvme-cli --timeout=3,600,000ms (1시간)                │
│                                                                 │
│  역할: ioctl blocking 유지                                      │
│  효과: crash 발생 명령에서 nvme-cli 가 최대 1시간 대기         │
│        → 그동안 SSD 크래시 상태 분석 가능                      │
│        → Ctrl+C 또는 분석 완료 후 수동 종료                    │
├─────────────────────────────────────────────────────────────────┤
│  계층 2: nvme_core.admin_timeout = 30일 (커널 파라미터)        │
│                                                                 │
│  역할: 커널 abort / PCIe reset 방지                            │
│  효과: 커널이 자체적으로 NVMe 리셋하는 것을 막음               │
│        → 펌웨어 crash 상태 그대로 보존                         │
└─────────────────────────────────────────────────────────────────┘

실제 퍼저 타임아웃 (subprocess timeout):
  base_timeout × _timeout_mult
  (이것이 만료되면 nvme-cli 프로세스를 SIGKILL, crash 판정)
```

---

### 3.9 Power Combo 통계 및 출력

#### 실행 중 상태 표시 (100회마다)

```
[Stats] exec: 5,000 | ... | PS2+L1.2+D3(×32TO)
[StatCov] BB: 45.1% (1,220/2,700) | funcs: 55/88 (62.5%)
```

`(×32TO)` = 현재 combo에서 타임아웃 배수가 32×임을 표시

#### 종료 시 Power Combo 통계

```
Power Combo Stats (PM_ROTATE_INTERVAL=100, 총 30개 조합):
  combo               | 실행    | 비율  | 진입 | 비고
  PS0+L0+D0           |   320회 | 6.4%  |  11회 |
  PS3+L1.2+D3         |    98회 | 2.0%  |   3회 | [TO×32]
  PS2+L1+D0           |   154회 | 3.1%  |   5회 | [TO×32]
  PS1+L1.2+D3         |   160회 | 3.2%  |   5회 | [TO×32]
  ...
```

- **실행 횟수**: 해당 combo 상태에서 처리된 NVMe 명령 수
- **진입 횟수**: 해당 combo로 전환된 횟수
- **[TO×N]**: 이 combo에서 적용된 타임아웃 배수

---

### 3.10 PM 상태 및 Replay Script

crash 발생 시 자동 생성되는 `replay_<tag>.sh` 에 PM 동작이 포함됨:

```bash
# [005/050] PCIe PS2+L1.2+D3  <- CRASH CMD

# echo powersave > /sys/module/pcie_aspm/parameters/policy

# Step1 EP L1SSCTL1 enable bits=0
sudo setpci -s 0000:02:00.0 0x208.l=00000000:0000000f
# Step3 EP DEVCTL2 LTRE=1
sudo setpci -s 0000:02:00.0 0x88.w=0400:0400
# Step4 EP LTR threshold=10.24µs
sudo setpci -s 0000:02:00.0 0x208.l=400a0000:e3ff0000
# Step5 RP L1SSCTL1 enable  (RP 먼저)
sudo setpci -s 0000:00:01.0 0x198.l=00000005:0000000f
# Step5 EP L1SSCTL1 enable
sudo setpci -s 0000:02:00.0 0x208.l=00000005:0000000f
# Step6 RP LNKCTL ASPMC=L1
sudo setpci -s 0000:00:01.0 0x70.w=0002:0003
# Step6 EP LNKCTL ASPMC=L1
sudo setpci -s 0000:02:00.0 0x70.w=0002:0003
# PMCSR D-state=D3hot
sudo setpci -s 0000:02:00.0 0x84.w=0003:0003

# [PMU] CLKREQ# Deassert 위치 (PMU API 삽입)

# NVMe 명령 (crash 재현)
sudo nvme admin-passthru /dev/nvme0 --opcode=0x09 ... --timeout=3600000
```

---

## 4. 크래시 감지 및 처리

```
NVMe 명령 실행 중 타임아웃 발생
        │
        ├── _timeout_crash = True
        ├── dmesg 캡처 (커널 로그)
        ├── nvme-cli PID 보존 (_crash_nvme_pid)
        ├── UFAS dump 실행 (./ufas 존재 시)
        │     PCIe bus 번호: sysfs 우선 탐지 → lspci fallback
        │     덤프 파일: <YYYYMMDD>_UFAS_Dump.bin
        │
        └── Replay script 생성
              crashes/replay_<tag>.sh
              crashes/replay_data_<tag>/data_NNN.bin
```

---

## 5. 메인 루프 흐름 요약

```
run() 시작
  │
  ├─ J-Link 연결 (JTAG → SWD 자동 전환)
  ├─ nvme_core 커널 타임아웃 = 30일 설정
  ├─ _detect_pcie_info()         [--pm 활성 시]
  ├─ _load_static_analysis()     [basic_blocks.txt 존재 시]
  ├─ diagnose()                  idle universe 수렴 탐지
  ├─ calibrate()                 초기 corpus 구성
  │
  └─ while elapsed < total_runtime_sec:
       │
       ├─ 입력 생성 (deterministic 또는 havoc)
       │
       ├─ 실행:  _send_nvme_command(data, seed, timeout_mult)
       │
       ├─ 커버리지 업데이트 + corpus 추가 (new_pcs > 0 시)
       │
       ├─ [매 100회] ─────────────────────────────────────────
       │     Power Combo 랜덤 전환
       │     BB coverage 스냅샷
       │     _print_status() 출력
       │
       ├─ [매 1000회] ────────────────────────────────────────
       │     corpus cull
       │     MOpt 페이즈 업데이트
       │     J-Link heartbeat
       │
       └─ [매 10000회] ───────────────────────────────────────
             NVMe SMART 로그 수집
```

---

## 6. 주요 상수 참조

| 상수 | 기본값 | 의미 |
|------|--------|------|
| `PM_ROTATE_INTERVAL` | 100 | PS 전환 주기 (실행 횟수) |
| `PS_TIMEOUT_MULT` | `{0:1, 1:16, 2:32, 3:1, 4:1}` | PS별 타임아웃 배수 |
| `D3_TIMEOUT_MULT` | 4 | D3hot wake-up 추가 배수 |
| `DIAGNOSE_STABILITY` | 100 | idle 수렴 판정 임계값 |
| `DIAGNOSE_MAX` | 5000 | idle 탐지 최대 샘플 수 |
| `LTR_VAL` | `0x400A_0000` | L1.2 LTR threshold (10.24µs) |
| `LTR_MASK` | `0xE3FF_0000` | LTR threshold 쓰기 마스크 |
