# PC Sampling SSD Firmware Fuzzer v6.2

OpenOCD PCSR(PC Sampling Register) 방식으로 커버리지를 수집하고, `nvme-cli` subprocess를 통해 NVMe 명령어를 SSD에 전달하는 Coverage-Guided Fuzzer.

v6.2의 핵심: **libFuzzer 스타일 Rule-Based Schema Mutation** — 42개 NVMe 커맨드 CDW 필드를 타입별 전략(ENUM/LBA/FLAGS/SIZE_DW/…)으로 자동 변형 + **IO_ADMIN_RATIO=3** (I/O 명령 75% 우선) + **Calibration-only FormatNVM/Sanitize** (FTL 상태 리셋 후 퍼징 풀에서 제거).

---

## 목차

1. [아키텍처 개요](#아키텍처-개요)
2. [요구사항](#요구사항)
3. [빠른 시작](#빠른-시작)
4. [v6.2 변경사항 상세](#v62-변경사항-상세)
5. [Rule-Based Schema Mutation](#rule-based-schema-mutation)
6. [커맨드 스키마 정의](#커맨드-스키마-정의)
7. [스펙 커버리지](#스펙-커버리지)
8. [코드 상단 상수 설정](#코드-상단-상수-설정)
9. [CLI 옵션](#cli-옵션)
10. [OpenOCD 설정 파일](#openocd-설정-파일-r8_pcsrcfg)
11. [명령어 목록](#명령어-목록)
12. [시드 설계](#시드-설계)
13. [출력 디렉터리 구조](#출력-디렉터리-구조)
14. [버전 이력 요약](#버전-이력-요약)

---

## 아키텍처 개요

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PC Sampling Fuzzer v6.2                      │
│                                                                     │
│  ┌──────────┐    ┌───────────────────────────────────────────────┐  │
│  │  Startup │    │               Main Fuzzing Loop               │  │
│  │          │    │                                               │  │
│  │ PMU POR  │    │  시드 선택(IO/Admin 비율 3:1)                  │  │
│  │   ↓      │    │  → 변이 생성(Det+Havoc+Splice+Schema)         │  │
│  │ OpenOCD  │    │       ↓                                       │  │
│  │  연결    │    │  nvme-cli 명령 전송                            │  │
│  │   ↓      │    │       ↓                                       │  │
│  │diagnose  │    │  PCSR 샘플링 (비침습)                          │  │
│  │idle_pcs  │    │  Core0 / Core1 / Core2                        │  │
│  │ 수집     │    │       ↓                                       │  │
│  │   ↓      │    │  BB/함수 커버리지 갱신                          │  │
│  │Calibrat- │    │                                               │  │
│  │  ion     │    │  [Schema Mutation 슬롯]                        │  │
│  │(FormatNVM│    │  CMD_SCHEMAS[cmd] → 필드 선택 → 타입별 변형    │  │
│  │+Sanitize │    │  → CDW 비트마스킹 적용                         │  │
│  │ 1회실행) │    └───────────────────────────────────────────────┘  │
│  └──────────┘                                                       │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │   Schema Mutation 엔진                                       │    │
│  │                                                             │    │
│  │  CMD_SCHEMAS["Read"] → [SLBA_LO, SLBA_HI, NLB, FUA, ...]  │    │
│  │       ↓ random.choice(fields)                               │    │
│  │  CDWField(name="NLB", word=12, hi=15, lo=0, LBA_CNT)        │    │
│  │       ↓ _mutate_field_by_type()                             │    │
│  │  → [0, 1, 7, 0xFF, 0xFFFF, random_val] 중 선택              │    │
│  │       ↓                                                     │    │
│  │  cdw12 = (cdw12 & ~mask) | (new_val << lo)                  │    │
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
  ▼
debug power 활성화 (0x30313f30 | 0x00010101)
  ▼
diagnose() — idle_pcs 수집
  │  10ms 간격, 최소 500회, 최대 10000회
  ▼
[Calibration 전처리]
  │  FormatNVM 1회 실행 (SES=0, FTL 리셋)
  │  Sanitize 1회 실행 (SANACT=001, Exit Failure Mode)
  │  → self.commands에서 두 커맨드 제거
  ▼
Calibration — 시드별 기준 PC 집합 측정 (3회)
  │
  ▼
┌─ Main Loop ─────────────────────────────────────┐
│  시드 선택 (IO:Admin = 3:1 가중치 + MOpt)        │
│  → 변이 생성                                     │
│    [1] opcode_override (확장 opcode 탐색)         │
│    [2] nsid_override                             │
│    [3] admin_swap                                │
│    [4] datalen_override                          │
│    [5] Schema Mutation (SCHEMA_MUT_PROB=0.30)    │
│        CMD_SCHEMAS → 필드 타입별 경계값 변형      │
│    [6] _mutate_bytes() — MOpt byte-level 16연산  │
│  → nvme-cli passthru 실행                       │
│  → PCSR 샘플링 (Core0/1/2, 비침습)              │
│  → BB / 함수 커버리지 갱신                       │
│  → 5000회마다 그래프 갱신                        │
└─────────────────────────────────────────────────┘
```

---

## 요구사항

```
Python 3.8+
openocd               # xPack OpenOCD 0.12.0+
nvme-cli              # apt install nvme-cli
setpci                # apt install pciutils
J-Link V9 / EDU       # USB 동글 (SWD 물리 연결용)
pmu_4_1.py            # PMU 보드 제어 스크립트 (POR용, 없으면 POR 스킵)
```

파일 구성:
```
PC_Sampling/
├── pc_sampling_fuzzer_v6.1.py   # 메인 퍼저 (내부 버전: v6.2)
├── nvme_seeds.py                # NVMe 명령 시드 템플릿 (253개 시드)
├── pmu_4_1.py                   # PMU 보드 제어 (POR용)
└── r8_pcsr.cfg                  # OpenOCD 설정 파일 (별도 준비)
```

---

## 빠른 시작

### 기본 실행

```bash
sudo python3 pc_sampling_fuzzer_v6.1.py \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x003B7FFF \
  --output ./output/run_v62
```

### POR 없이 실행 (디버깅용)

```bash
sudo python3 pc_sampling_fuzzer_v6.1.py \
  --nvme /dev/nvme0 \
  --no-por \
  --output ./output/run_no_por
```

### Power Combo + 전체 커맨드 활성화

```bash
sudo python3 pc_sampling_fuzzer_v6.1.py \
  --nvme /dev/nvme0 \
  --pm \
  --all-commands \
  --output ./output/run_full
```

---

## v6.2 변경사항 상세

### [Arch] Rule-Based Schema Mutation 도입

v6.0/v6.1까지 CDW 변형은 두 레이어로 구성되었다:
- **범용 레이어** [1-4]: opcode/nsid/admin_swap/datalen (모든 커맨드 동일 적용)
- **명령어별 특화** [5-8]: LBA boundary(Read/Write/Compare만), FID(Features만), CNS(Identify만), NUMDL(GetLogPage만)

문제: 21개 커맨드 중 특화 변형이 적용되는 건 5개뿐. 나머지 16개는 CDW 구조를 무시한 채 랜덤 32-bit 변형만 받는다.

**v6.2 해결**: 각 커맨드의 CDW 필드 스키마를 정의하고, 필드 타입에 따라 적절한 변형을 자동 적용.

| 항목 | v6.0/v6.1 | v6.2 |
|------|-----------|------|
| 특화 변형 커맨드 | 5개 (LBA/FID/CNS/NUMDL) | **42개** (전 커맨드) |
| 변형 필드 | 4개 | **~150개 필드** |
| 확장성 | ad-hoc if문 추가 | 스키마 dict에 커맨드 추가만 |
| LBA 인식 | NSZE 경계 없음 | **NSZE 캐싱** (5000 exec TTL) |
| 커맨드 비율 | 균등 | **IO 3 : Admin 1** |

### [Feature] IO_ADMIN_RATIO=3 (I/O 명령 우선)

```python
IO_ADMIN_RATIO = 3   # I/O 커맨드가 Admin 커맨드 대비 3배 높은 선택 비중
```

이유: Read/Write가 NVM media controller/ECC/wear-leveling 경로를 직접 탐색. Admin은 한 번 설정되면 이후 영향 감소.

`self.commands` 빌드 시:
```python
for c in base:
    extra = IO_ADMIN_RATIO if c.cmd_type == NVMeCommandType.IO else 1
    self.commands.extend([c] * (c.weight * extra))
```

→ 별도 선택 로직 없이 기존 MOpt 가중치 랜덤에 자동 적용.

### [Feature] Calibration-only FormatNVM + Sanitize

**목적**: Read/Write로 쌓아놓은 FTL의 복잡한 mapping 상태를 리셋하여 calibration 기준점을 깨끗하게 확보.

```
[Calibration 전]
  FormatNVM 1회 (SES=0, LBAFL=0 — 포맷만, 데이터 파괴 없음)
  Sanitize 1회 (SANACT=001 — Exit Failure Mode, FTL 메타데이터 정리)
  → self.commands에서 FormatNVM/Sanitize 영구 제거
[Calibration 시작]
  깨끗한 FTL 상태에서 시드별 기준 PC 집합 측정
[퍼징 루프]
  FormatNVM/Sanitize는 선택되지 않음 (commands 풀에서 제거됨)
```

보호 레이어:
1. `_DESTRUCTIVE` 플래그: FormatNVM/Sanitize를 corpus에 추가하지 않음
2. calibration 후 `self.commands` 제거: 퍼징 루프에서 선택 불가

### [Fix] mutation_stats 정리

| 제거 | 추가 |
|------|------|
| `lba_boundary` | `schema_field` |
| `fid_mutation` | |
| `cns_mutation` | |

`schema_field`는 어떤 커맨드의 어떤 필드가 변형됐는지 단일 카운터로 집계.

---

## Rule-Based Schema Mutation

### FieldType 분류

```python
class FieldType(Enum):
    ENUM       = "enum"       # 이산 열거형 — valid 목록 + reserved/vendor 범위
    LBA        = "lba"        # LBA 주소 — NSZE 캐싱 기반 경계값
    LBA_CNT    = "lba_cnt"    # LBA 개수 — MDTS 경계 포함
    FLAGS      = "flags"      # 비트마스크 — 개별 비트 / 조합 / all-set/clear
    SIZE_DW    = "size_dw"    # Dword 단위 크기 — 0/1/최대/초과 경계
    OFFSET_DW  = "offset_dw"  # Dword 단위 오프셋 — 비정렬 / 큰 오프셋
    SLOT       = "slot"       # 슬롯/인덱스 번호 — [0, 1, max, max+1]
    OPAQUE     = "opaque"     # 비구조 — 기존 _mutate_cdw() 위임
```

### 타입별 변형 전략

| 타입 | 변형 후보 |
|------|----------|
| ENUM | `valid_values` + `reserved_range` 내 랜덤 + `vendor_range` 내 랜덤 |
| LBA | `[0, 1, NSZE-1, NSZE, NSZE+1, 0xFFFF, 0xFFFFFFFF, random_valid]` |
| LBA_CNT | `[0, 1, 7, 0xFF, 0xFFFF, 0xFFFFFFFF, random]` |
| FLAGS | `valid` 리스트 선택 또는 `random.randint(0, mask)` |
| SIZE_DW | `[0, 1, 0x7F, 0xFF, 0x3FF, 0x7FF, 0xFFFF, random]` |
| OFFSET_DW | `[0, 1, 0x100, 0x1000, 0xFFFF, 0xFFFFFFFF, random]` |
| SLOT | `[0, 1, max_val, max_val+1, random(0..max_val+2)]` |
| OPAQUE | `_mutate_cdw(0) & field_mask` |

### CDWField 적용 메커니즘

```python
# 필드 비트마스킹으로 CDW에 정밀 적용
cdw_attr = f"cdw{field.word}"          # "cdw10" ~ "cdw15"
old = getattr(seed, cdw_attr, 0)
width = field.hi - field.lo + 1
mask  = ((1 << width) - 1) << field.lo
setattr(seed, cdw_attr, (old & ~mask) | ((new_val << field.lo) & mask))
```

### NSZE 캐싱

```python
NSZE_CACHE_TTL = 5000   # 5000 exec마다 재조회

def _get_nsze(self) -> int:
    # nvme id-ns -o json 으로 NSZE 조회
    # 실패 시 보수적 기본값 0x100000 (1M blocks)
```

---

## 커맨드 스키마 정의

### Admin Commands (26개 스키마)

| 커맨드 | Opcode | 주요 스키마 필드 |
|--------|--------|----------------|
| GetLogPage | 0x02 | LID(ENUM), LSP(OPAQUE), RAE(FLAGS), NUMDL/NUMDU(SIZE_DW), LPOL/LPOU(OFFSET_DW) |
| Identify | 0x06 | CNS(ENUM, 19개 유효값), CNTID(SLOT), CNSSI(OPAQUE), CSI(ENUM), UIDX(SLOT) |
| SetFeatures | 0x09 | FID(ENUM, 전체 FID), SV(FLAGS), CDW11(OPAQUE), UIDX(SLOT) |
| GetFeatures | 0x0A | FID(ENUM), SEL(ENUM, 0-3), UIDX(SLOT) |
| FirmwareCommit | 0x10 | FS(SLOT, 0-7), CA(ENUM, 0-5), BPID(FLAGS) |
| FirmwareDownload | 0x11 | NUMD(SIZE_DW), OFST(OFFSET_DW) |
| DeviceSelfTest | 0x14 | STC(ENUM, 0x1/0x2/0x3/0xE/0xF + reserved) |
| NamespaceManagement | 0x0D | SEL(ENUM, Create=0만), CSI(ENUM) |
| NamespaceAttachment | 0x15 | SEL(ENUM, Attach=0만) |
| KeepAlive | 0x18 | KATO(SIZE_DW) |
| DirectiveSend | 0x19 | DOPER(ENUM), DTYPE(ENUM), DSPEC(SLOT), NUMD(SIZE_DW) |
| DirectiveReceive | 0x1A | DOPER(ENUM), DTYPE(ENUM), DSPEC(SLOT), NUMD(SIZE_DW) |
| VirtMgmt | 0x1C | ACT(ENUM), RT(ENUM), CNTLID(SLOT), NR(SLOT) |
| Abort | 0x08 | SQID(SLOT), CID(SLOT) |
| AER | 0x0C | (CDW 없음, 시드만) |
| TelemetryHostInitiated | 0x02\* | CTHID(FLAGS), RAE(FLAGS), NUMDL(SIZE_DW) |
| FormatNVM | 0x80 | LBAFL(SLOT), MSET(FLAGS), PI(ENUM), PIL(FLAGS), LBAFU(SLOT) — SES 고정=0 |
| SecuritySend | 0x81 | NSSF(FLAGS), SPSP0/1(OPAQUE), SECP(ENUM), TL(SIZE_DW) |
| SecurityReceive | 0x82 | NSSF(FLAGS), SPSP0/1(OPAQUE), SECP(ENUM), AL(SIZE_DW) |
| Sanitize | 0x84 | SANACT(ENUM, Exit Failure/Media Verification만) |
| GetLBAStatus | 0x86 | SLBA\_LO/HI(LBA), MNDW(SIZE_DW), RL(SLOT), ATYPE(ENUM) |
| CapacityMgmt | 0x20 | OP(ENUM), EGID(SLOT), ENDGCAP\_LO/HI(SIZE_DW) |
| Lockdown | 0x24 | PRHBT(ENUM, 0=unlock만), SCP(ENUM), UUID(SLOT) |
| MigrationSend | 0x41 | MSO(ENUM), UIDX(SLOT), NUMD(SIZE_DW) |
| MigrationReceive | 0x42 | MSO(ENUM), UIDX(SLOT), NUMD(SIZE_DW) |
| ControllerDataQueue | 0x45 | OP(ENUM), QID(SLOT), QSIZE(SIZE_DW) |

\* TelemetryHostInitiated는 GetLogPage(LID=0x07)로 전송

### NVM I/O Commands (16개 스키마)

| 커맨드 | Opcode | 주요 스키마 필드 |
|--------|--------|----------------|
| Flush | 0x00 | (CDW 없음) |
| Write | 0x01 | SLBA\_LO/HI(LBA), NLB(LBA_CNT), DTYPE(ENUM), PRINFO(FLAGS), FUA/LR/STCW(FLAGS) |
| Read | 0x02 | SLBA\_LO/HI(LBA), NLB(LBA_CNT), PRINFO(FLAGS), FUA/LR/STCR(FLAGS) |
| WriteUncorrectable | 0x04 | SLBA\_LO/HI(LBA), NLB(LBA_CNT) |
| Compare | 0x05 | SLBA\_LO/HI(LBA), NLB(LBA_CNT), PRINFO(FLAGS), FUA/LR/STCR(FLAGS) |
| WriteZeroes | 0x08 | SLBA\_LO/HI(LBA), NLB(LBA_CNT), DEAC(FLAGS), PRINFO(FLAGS), FUA/LR(FLAGS) |
| DatasetManagement | 0x09 | NR(LBA_CNT), IDR/IDW/AD(FLAGS) |
| Verify | 0x0C | SLBA\_LO/HI(LBA), NLB(LBA_CNT), PRINFO(FLAGS), LR/STC(FLAGS) |
| ReservationRegister | 0x0D | RREGA(ENUM, 0-2), IEKEY/DISNSRS(FLAGS), CPTPL(ENUM) |
| ReservationReport | 0x0E | NUMD(SIZE_DW), EDS(FLAGS) |
| ReservationAcquire | 0x11 | RACQA(ENUM, 0-2), IEKEY/DISNSRS(FLAGS), RTYPE(ENUM, 0-6) |
| IOMgmtReceive | 0x12 | MO(ENUM), NUMD(SIZE_DW) |
| ReservationRelease | 0x15 | RRELA(ENUM, 0-1), IEKEY(FLAGS), RTYPE(ENUM, 0-6) |
| Cancel | 0x18 | CID(SLOT), SQID(SLOT), CA(ENUM, 0-2) |
| Copy | 0x19 | SDLBA\_LO/HI(LBA), NR(SLOT), DF(ENUM, 0-3), PRINFOW/PRINFOR(FLAGS), FUA/LR(FLAGS) |
| IOMgmtSend | 0x1D | MO(ENUM), NUMD(SIZE_DW) |

---

## 스펙 커버리지

NVMe Base Spec 2.2 + NVM Command Set 1.2 기준:

| 구분 | 전체 | 스키마 정의 | 제외 (의도적) |
|------|------|-------------|--------------|
| Admin Commands | 36 | 26 | 10 |
| NVM I/O Commands | 16 | 16 | 0 |
| **합계** | **52** | **42 (81%)** | **10 (19%)** |

### 제외 커맨드 (10개)

| Opcode | 커맨드 | 제외 이유 |
|--------|--------|----------|
| 00h | Delete I/O Submission Queue | 커널 I/O 큐 파괴 → OS 크래시 |
| 01h | Create I/O Submission Queue | 동일 |
| 04h | Delete I/O Completion Queue | 동일 |
| 05h | Create I/O Completion Queue | 동일 |
| 7Ch | Doorbell Buffer Config | 호스트 메모리 포인터 직접 조작 |
| 7Fh | Fabrics Commands | PCIe에서 Prohibited |
| 85h | Load Program | SSD에서 임의 코드 실행 — 극위험 |
| 88h | Program Activation | Computational Programs 전용 |
| 89h | Memory Range Set | 동일 |
| C0h-FFh | Vendor Specific (Admin) | opcode_override 슬롯 [1]로 탐색 |

### 커맨드별 Mutation 수준

| 레벨 | 커맨드 | 변형 필드 수 |
|------|--------|------------|
| **높음** (LBA+플래그) | Read, Write, Compare, WriteZeroes, Verify, WriteUncorrectable, Copy | 6-9 필드 |
| **높음** (ENUM+SIZE) | GetLogPage, Identify, SetFeatures, GetFeatures | 4-8 필드 |
| **중간** | DatasetManagement, GetLBAStatus, FirmwareDownload, SecuritySend/Receive, Reservation×4, Cancel | 2-5 필드 |
| **낮음** (CDW 없거나 1-2 필드) | Flush, AER, FirmwareCommit, DeviceSelfTest, Sanitize, FormatNVM | 0-3 필드 |

---

## 코드 상단 상수 설정

### v6.2 신규/변경 상수

| 상수 | 기본값 | 설명 |
|------|--------|------|
| `SCHEMA_MUT_PROB` | `0.30` | Schema Mutation 슬롯 적용 확률 (슬롯 [5]-[8] 대체) |
| `IO_ADMIN_RATIO` | `3` | I/O 커맨드 선택 가중치 배수 (Admin 대비) |
| `NSZE_CACHE_TTL` | `5000` | NSZE 캐시 유효 실행 횟수 |

### 기존 유지 상수

| 상수 | 기본값 | 설명 |
|------|--------|------|
| `FW_ADDR_START` | `0x00000000` | 펌웨어 .text 시작 주소 |
| `FW_ADDR_END` | `0x003B7FFF` | 펌웨어 .text 끝 주소 |
| `OPENOCD_BINARY` | `'openocd'` | OpenOCD 바이너리 경로 |
| `OPENOCD_CONFIG` | `'r8_pcsr.cfg'` | OpenOCD 설정 파일 |
| `DIAGNOSE_MAX` | `10000` | 최대 샘플 수 |
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

---

## 명령어 목록

### 기본 활성화 (NVME_COMMANDS_DEFAULT)

| 명령 | Opcode | Type | Weight | 비고 |
|------|--------|------|--------|------|
| Write | 0x01 | IO | 2 | I/O 우선, 실질 선택 비중 최상위 |
| Read | 0x02 | IO | 2 | 동일 |
| Identify | 0x06 | Admin | 1 | — |
| GetLogPage | 0x02 | Admin | 1 | — |
| GetFeatures | 0x0A | Admin | 1 | — |
| SetFeatures | 0x09 | Admin | 1 | — |

### 확장 명령어 (NVME_COMMANDS_EXTENDED, `--all-commands`)

**Admin**: FWDownload, FWCommit, DeviceSelfTest, NamespaceManagement (Create만),
NamespaceAttachment (Attach만), KeepAlive, DirectiveSend, DirectiveReceive,
VirtMgmt, CapacityMgmt, Lockdown (PRHBT=0만), MigrationSend, MigrationReceive,
ControllerDataQueue, Abort, AER, TelemetryHostInitiated, FormatNVM\*, Sanitize\*,
SecuritySend, SecurityReceive, GetLBAStatus

**I/O**: Flush, WriteUncorrectable, Compare, WriteZeroes, DatasetManagement,
Verify, ReservationRegister, ReservationReport, ReservationAcquire, IOMgmtReceive,
ReservationRelease, Cancel, Copy, IOMgmtSend

\* **FormatNVM / Sanitize**: Calibration 전처리에서 1회만 실행 후 퍼징 풀 제거. Calibration 이후 선택 불가.

---

## 시드 설계

### 설계 원칙: 최소 앵커 시드 + 스키마 주도 변형

```
[앵커 시드] — 커맨드당 1-2개
  목적: "이 커맨드가 정상 완료되는 최소한의 CDW"
  CDW: 단순 유효값
  data: 최소 크기

[스키마 변형] — SCHEMA_MUT_PROB=0.30
  CDW 변형의 모든 다양성은 CMD_SCHEMAS가 담당
  앵커 시드 자체는 단순하게 유지
```

### 시드 통계 (nvme_seeds.py)

| 구분 | 커맨드 수 | 시드 수 |
|------|----------|--------|
| Admin (기본) | 6 | ~40 |
| Admin (확장) | 20 | ~80 |
| I/O 기본 (Read/Write/Flush) | 3 | ~60 |
| I/O 확장 | 13 | ~73 |
| **합계** | **42** | **~253** |

### 주요 시드 예시

```python
# Write — 1 LBA write, FUA set
dict(cdw10=0, cdw11=0, cdw12=0x80000000, data=b'\x00'*512)

# GetLogPage — Error Log (LID=0x01)
dict(cdw10=0x007F0001)  # NUMDL=0x7F, LID=0x01

# Copy — Format 0, NR=0, src LBA 0 → dst LBA 0
dict(cdw10=0, cdw11=0, cdw12=0x00,
     data=struct.pack('<QHH', 0, 1, 0) + b'\x00'*20)

# ReservationRegister — Register (RREGA=0)
dict(cdw10=0x00, data=b'\x00'*16)

# Abort — 랜덤 SQID=1, CID=1
dict(cdw10=(0x0001<<16)|0x0001, nsid_override=0)
```

---

## 출력 디렉터리 구조

```
output/pc_sampling_v6.2/
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
    ├── mutation_chart.png        ← schema_field 비율 포함
    ├── coverage_heatmap_1d.png
    ├── edge_heatmap_2d.png
    ├── {cmd}_cfg.dot/.png
    ├── coverage_growth.png       (* Ghidra 연동 시)
    ├── firmware_map.png          (* Ghidra 연동 시)
    └── uncovered_funcs.png       (* Ghidra 연동 시)
```

`mutation_chart.png` subplot 3: schema_field / opcode_override / nsid_override / admin_swap / datalen 비율 포함.

---

## 버전 이력 요약

| 버전 | 주요 변경 |
|------|-----------|
| **v6.2** | Rule-Based Schema Mutation (42커맨드/~150필드/8타입), IO_ADMIN_RATIO=3, Calibration-only FormatNVM+Sanitize, NSZE 캐싱, mutation_stats schema_field, 신규 커맨드 21개 추가 |
| v6.0 | OpenOCD PCSR 비침습 샘플링, 3코어 동시 수집(Core0/1/2), pylink 제거, PMU POR, 2단계 복구, timeout hang 보존 분석, PC 모니터링 루프 |
| v5.6 | 시각화 개선: coverage_growth 이중 X축, command_comparison RC 오류율, uncovered_funcs 부분커버, mutation_chart 신규 |
| v5.5 | 시드 템플릿 분리(nvme_seeds.py), CLI 인자 정리, FWDownload 32KB 기본값 |
| v5.4 | SetFeatures 기본 승격, APST calibration 버그 수정, LBA 자동 감지 |
| v5.3 | idle 시간 최적화: L1_SETTLE, DIAGNOSE_SAMPLE_MS=10ms, window-ratio 조기 감지 |
| v5.2 | Power Combo (NVMe PS + PCIe L/D-state 30개 조합) |
| v5.1 | PM Rotation(`--pm`), Basic Block 커버리지(Ghidra), 시각화 그래프 3종 |
| v5.0 | J-Link JTAG/SWD auto-detect, diagnose() 수렴 기반 idle 유니버스 수집 |
| v4.7 | FUA 비트 수정(CDW12[29]), FWDownload `--fw-bin` |
| v4.6 | passthru timeout 분리, crash 시 nvme driver unbind |
| v4.5 | Calibration, Deterministic stage, MOpt mutation scheduling |
