# PC Sampling SSD Firmware Fuzzer v7.4

OpenOCD PCSR(PC Sampling Register) 방식으로 커버리지를 수집하고, `nvme-cli` subprocess를 통해 NVMe 명령어를 SSD에 전달하는 Coverage-Guided + State-Aware Fuzzer.

v7.4의 핵심: **Phase 1~3 Mutation 확장** — NLB-relative/MDTS boundary data_len(Phase 1), 64-bit LBA pair + DSM/Copy structured payload(Phase 2), Write→Compare/FWDownload→FWCommit builtin sequence(Phase 3). PC 숫자 늘리기에서 벗어나 경계값·구조·시퀀스 기반 탐색으로 전략을 확장.

---

## 목차

1. [아키텍처 개요](#아키텍처-개요)
2. [요구사항](#요구사항)
3. [빠른 시작](#빠른-시작)
4. [v7.4 변경사항 상세](#v74-변경사항-상세)
5. [v7.3 변경사항](#v73-변경사항)
6. [v7.0 — State-Aware Fuzzer](#v70--state-aware-fuzzer)
7. [제품별 설정 (--product)](#제품별-설정---product)
8. [CSFuzz 적응형 corpus selection](#csfuzz-적응형-corpus-selection)
9. [Power Management 설계](#power-management-설계)
10. [JTAG 지원 (BM9H1)](#jtag-지원-bm9h1)
11. [Defect 처리 흐름](#defect-처리-흐름)
12. [JLink 기반 PC 모니터링](#jlink-기반-pc-모니터링)
13. [코드 상단 상수 설정](#코드-상단-상수-설정)
14. [CLI 옵션](#cli-옵션)
15. [OpenOCD 설정 파일](#openocd-설정-파일)
16. [출력 디렉터리 구조](#출력-디렉터리-구조)
17. [버전 이력 요약](#버전-이력-요약)

---

## 아키텍처 개요

```
┌────────────────────────────────────────────────────────────────────────┐
│                     PC Sampling Fuzzer v7.4                             │
│                                                                        │
│  ┌──────────┐    ┌──────────────────────────────────────────────────┐  │
│  │  Startup │    │                Main Fuzzing Loop                  │  │
│  │          │    │                                                  │  │
│  │ PMU POR  │    │  ① PM 로테이션 (100회마다, seed 선택 전)          │  │
│  │   ↓      │    │  ② 시드 선택                                     │  │
│  │ OpenOCD  │    │    ├─ Phase 3: builtin sequence (Write→Compare 등)│  │
│  │  연결    │    │    └─ Power Schedule + CSFuzz (C1/C2 경로)        │  │
│  │   ↓      │    │  ③ 변이                                          │  │
│  │diagnose  │    │    ├─ Phase 1: NLB-relative / MDTS data_len      │  │
│  │idle_pcs  │    │    ├─ Phase 2: 64-bit LBA pair                   │  │
│  │   ↓      │    │    ├─ Phase 2: DSM/Copy structured payload       │  │
│  │Calibrat- │    │    └─ 기존: Det/Havoc/Splice/Schema              │  │
│  │  ion     │    │  ④ nvme-cli passthru → PCSR 샘플링               │  │
│  │          │    │  ⑤ _account_command() [v7.3]                    │  │
│  └──────────┘    │   ├─ coverage 평가 + corpus 추가                  │  │
│                  │   ├─ C1 reward 기록 (per-command)                │  │
│                  │   └─ Stats / state / cull / graph 주기 처리      │  │
│                  │                                                  │  │
│                  │  [State 모니터링 — 100회마다]                     │  │
│                  │   state corpus 발견 → State-Replay               │  │
│                  │   _replay_state_sequence() → _account_command()  │  │
│                  │   EMA score + C2 reward 기록                     │  │
│                  │                                                  │  │
│                  │  [CSFuzz p 갱신 — 10000회마다]                   │  │
│                  │   m1(edge) vs m2(state) 비교 → p 조정            │  │
│                  └──────────────────────────────────────────────────┘  │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │   Defect 처리 (timeout / hang)                                    │  │
│  │   read_stuck_pcs → JLink 덤프 → UFAS → JLink PC 모니터링         │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
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
diagnose() — idle_pcs 수집 (10ms 간격, 최소 500회, 최대 10000회)
  ▼
[Calibration] FormatNVM 1회 → Sanitize 1회 → 시드별 기준 PC 집합 측정 (3회)
  ▼
┌─ Main Loop ──────────────────────────────────────────────────────┐
│  ① PM 로테이션 (100회마다, seed 선택 전)  [v7.4 이동]             │
│                                                                  │
│  ② 시드 선택                                                     │
│    [Phase 3] pending sequence → _pick_seq_seed()                 │
│      └─ builtin sequence 시작 조건:                              │
│           SEQ_PROB=0.05, 100-exec window당 SEQ_MAX_PER_100=10    │
│           활성 명령어에 포함된 시퀀스만 선택 (_valid_seqs 필터)  │
│                                                                  │
│    [CSFuzz p] state corpus 선택                                   │
│      → _replay_state_sequence() → _account_command() (source='c2')│
│    [70%] edge corpus 선택 (c1 경로)                              │
│                                                                  │
│  ③ 변이                                                          │
│    [Phase 1] NLB-relative data_len                               │
│      NLB×LBA_SIZE ±1, +PAGE_SIZE, MDTS 경계 후보               │
│    [Phase 2] 64-bit LBA pair (cdw10+cdw11 동시 변이)             │
│      후보: 0, 1, nsze-2, nsze-1, nsze, nsze+1, 0xFFFFFFFF,      │
│            0x100000000, random                                   │
│    [Phase 2] DSM/Copy structured payload                         │
│      4가지 케이스: 1entry / 256entry / 선언-실제 불일치 / 빈payload│
│    [기존] Det/Havoc/Splice/Schema mutation                       │
│                                                                  │
│  ④ nvme-cli passthru → PCSR 샘플링                               │
│  ⑤ _account_command() — coverage/corpus/stats/state             │
│                                                                  │
│  [10000회마다] CSFuzz p 갱신 (m1 vs m2 비교)                     │
└──────────────────────────────────────────────────────────────────┘
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
state_fields.py       # 상태 필드 정의 (State-Aware Fuzzer용)
nvme_seeds.py         # NVMe 명령 시드 템플릿
```

파일 구성:

```
PC_Sampling/
├── pc_sampling_fuzzer_v7.4.py          # 메인 퍼저
├── nvme_seeds.py                        # NVMe 명령 시드 템플릿
├── state_fields.py                      # 상태 필드 정의 (NVMeStateMonitor 관측 대상)
├── pmu_4_1.py                           # PMU 보드 제어 (POR용)
├── r8_pcsr.cfg                          # OpenOCD 설정 — SWD (PM9M1)
├── r8_pcsr_jtag.cfg                     # OpenOCD 설정 — JTAG (BM9H1)
└── run_smi_mem_dump_JLINK_USB.sh        # JLink 메모리 덤프 스크립트
```

---

## 빠른 시작

### PM9M1 (SWD, 3코어)

```bash
sudo python3 pc_sampling_fuzzer_v7.4.py \
  --product PM9M1 \
  --nvme /dev/nvme0 \
  --addr-start 0xA4000 \
  --addr-end 0x3B7FFF \
  --output ./output/run_pm9m1
```

### BM9H1 (JTAG, 2코어)

```bash
sudo python3 pc_sampling_fuzzer_v7.4.py \
  --product BM9H1 \
  --nvme /dev/nvme0 \
  --addr-start 0x00000 \
  --addr-end 0x27FFF \
  --output ./output/run_bm9h1
```

### State-Aware + PM 활성화

```bash
sudo python3 pc_sampling_fuzzer_v7.4.py \
  --product PM9M1 \
  --nvme /dev/nvme0 \
  --pm \
  --addr-start 0xA4000 --addr-end 0x3B7FFF \
  --output ./output/run_state_pm
```

### FWDownload→FWCommit 시퀀스 포함 (위험 명령어 활성화)

```bash
sudo python3 pc_sampling_fuzzer_v7.4.py \
  --product PM9M1 \
  --nvme /dev/nvme0 \
  --all-commands \
  --addr-start 0xA4000 --addr-end 0x3B7FFF \
  --output ./output/run_all_cmds
```

> `FWDownload→FWCommit` 시퀀스는 `--all-commands` 없이는 활성화되지 않는다. `_valid_seqs` 필터가 비활성 명령을 포함한 시퀀스를 자동 차단한다.

---

## v7.4 변경사항 상세

### 배경

ITCM 0x20000 이내 PC coverage가 hot path 위주로 포화되고 있다. "새 PC 확보" 전략만으로는 탐색 한계에 다가가고 있어, 경계값·구조·시퀀스 기반으로 확장한다. 탐지 기준은 **hang/timeout만** — Spec Violation 응답은 정상 동작으로 간주한다.

---

### [Phase 1] NLB-relative + MDTS boundary data_len

#### 배경

기존 data_len mutation은 고정 후보 리스트(0, 4, 64, 512 …)를 사용했다. NLB로 계산한 "정확한 transfer size" 주변 ±1 오차와 MDTS(Maximum Data Transfer Size) 경계를 직접 노리지 못했다.

#### 구현

```
Write/Read/Compare 명령에 대해:

NLB-relative 후보 (CDW12[15:0] = NLB, 0-based):
  expected = (NLB + 1) × LBA_SIZE
  후보: expected-1, expected, expected+1, expected+PAGE_SIZE

MDTS boundary 후보 (nvme id-ctrl의 mdts 필드):
  max_bytes = (1 << mdts) × PAGE_SIZE
  후보: max_bytes-1, max_bytes, max_bytes+1

static fallback (항상 포함):
  0, 4, 64, 512, 4096, 8192, 65536, random

중복 제거 후 random.choice() → 선택된 값의 출처로 통계 집계
```

#### 통계

| 키 | 의미 |
|----|------|
| `datalen_nlb` | NLB-relative 후보에서 선택된 횟수 |
| `datalen_mdts` | MDTS boundary 후보에서 선택된 횟수 |

#### 관련 상수

| 상수 | 값 | 설명 |
|------|---|------|
| `DATALEN_MUT_PROB` | 기존값 | data_len mutation 적용 확률 |
| `MDTS_CACHE_TTL` | `5000` | `nvme id-ctrl` 조회 캐시 갱신 주기 (exec 단위) |

---

### [Phase 2] 64-bit LBA pair mutation

#### 배경

기존 Schema mutation은 cdw10(SLBA_LO), cdw11(SLBA_HI)를 독립적으로 변이했다. 64-bit LBA를 한 쌍으로 변이하지 않으면 `0x100000000` 이상의 경계를 올바르게 노릴 수 없다.

#### 구현

```
대상: Read, Write, Compare, Verify, Copy

_slba 후보:
  0, 1, nsze-2, nsze-1, nsze, nsze+1,
  0xFFFFFFFF, 0x100000000, random_valid

cdw10 = _slba & 0xFFFFFFFF
cdw11 = (_slba >> 32) & 0xFFFFFFFF
```

| 상수 | 값 | 설명 |
|------|---|------|
| `LBA_PAIR_MUT_PROB` | `0.15` | 64-bit LBA pair mutation 적용 확률 |

통계 키: `lba_pair_64bit`

---

### [Phase 2] DSM/Copy structured payload mutation

#### 배경

DatasetManagement와 Copy는 CDW + payload 구조가 연동된다. payload만 또는 CDW만 변이하면 FW가 먼저 파라미터 오류로 기각하여 실제 처리 경로에 도달하지 못한다.

#### DatasetManagement payload

NVMe spec: 각 range entry = 16B (Context Attrs 4B + LBA Count 4B + SLBA 8B), CDW10[7:0] = NR (0-based, 실제 entry 수 = NR+1)

| 케이스 | CDW10(NR) | payload |
|--------|-----------|---------|
| 1 entry | 0 | 16B, SLBA/LBA Count = 경계값 |
| 256 entry | 255 | 4096B, 경계값 혼합 |
| 선언-실제 불일치 | 255 선언 | 16B(1 entry 분량만) |
| 0+빈 payload | 0 | b'' |

SLBA/LBA Count 후보: `0, 1, nsze-2, nsze-1, nsze, nsze+1, 0x100000000, random`

통계 키: `dsm_structured`

#### Copy payload

NVMe spec: Format 0h, 각 source range entry = 32B (SLBA 8B + NLB 2B + RSVD 2B + EILBRT 4B + ELBATM 2B + ELBAT 2B + RSVD 12B), CDW12[11:8] = NR (0-based)

| 케이스 | CDW12 NR | payload |
|--------|----------|---------|
| 1 entry | 0 | 32B, SLBA/NLB = 경계값 |
| 4 entry | 3 | 128B, 경계값 혼합 |
| 선언-실제 불일치 | 3 선언 | 32B(1 entry 분량만) |
| 0+빈 payload | 0 | b'' |

destination SLBA (cdw10/cdw11)도 경계값 후보에서 선택.

통계 키: `copy_structured`

---

### [Phase 3] Builtin sequence mini-set

#### 설계 원칙

- 단일 명령 변이로는 커버하기 어려운 **시퀀스 의존 경로** 탐색
- 탐지 기준은 동일: **hang/timeout만** (sequence 중 에러 응답은 정상)
- 100-exec window당 `SEQ_MAX_PER_100=10` 개 이하로 제한하여 단일 명령 탐색 비율 유지

#### 시퀀스 목록

| 시퀀스 | 활성 조건 | 목적 |
|--------|-----------|------|
| `Write → Compare` | 기본 활성 | 같은 SLBA/NLB에 동일 데이터 Write 후 Compare — 데이터 정합성 검증 경로 탐색 |
| `FWDownload → FWCommit` | `--all-commands` 필요 | 잘못된(무효) FW 이미지 업로드 후 활성화 시도 — FW 에러 핸들링 경로 탐색 |

#### Write→Compare 공유 컨텍스트

Compare는 지정된 LBA 범위를 읽어 host가 제공한 buffer와 비교한다. Compare가 의미 있으려면 Write와 동일한 SLBA/NLB/data를 사용해야 한다.

```
시퀀스 시작 시 ctx 한 번 생성:
  ctx = {
    'slba': 경계값 중 하나,
    'nlb':  [0, 1, 3, 7, 15, random(0~255)] 중 하나,
    'data': os.urandom((nlb+1) × LBA_SIZE),
  }

Write:  cdw10/11=slba, cdw12[15:0]=nlb, data=ctx['data']
Compare: 동일 ctx 적용

_apply_seq_ctx()가 opcode_override/force_admin/nsid_override를 None으로
초기화하여 시퀀스 명령이 정상 opcode/queue/nsid로 실행되도록 보장.
```

#### 시퀀스 게이팅

```python
# 활성화된 명령어에 포함된 시퀀스만 선택
_enabled_names = {c.name for c in self.commands}
_valid_seqs = [s for s in BUILTIN_SEQUENCES
               if all(n in _enabled_names for n in s)]
```

FWDownload/FWCommit는 `--all-commands` 없이는 `self.commands`에 없으므로 자동으로 제외된다. 별도 플래그가 필요 없다.

#### 관련 상수

| 상수 | 값 | 설명 |
|------|---|------|
| `SEQ_PROB` | `0.05` | builtin sequence 시작 확률 |
| `SEQ_MAX_PER_100` | `10` | 100-exec window당 sequence 명령 최대 개수 |

통계 키: `seq_builtin`

---

### [Fix] PM 로테이션 순서 조정

v7.3까지 PM 로테이션이 seed 선택 후 명령 실행 직전에 위치했다. PM 전환 구간과 NVMe 명령 블록이 같은 iteration에 섞여 결과 분석이 어렵다는 문제가 있었다.

v7.4에서 PM 로테이션을 **seed 선택 전**으로 이동:

```
[Before v7.4]  시드 선택 → 변이 → PM 로테이션 → nvme 실행
[v7.4]         PM 로테이션 → 시드 선택 → 변이 → nvme 실행
```

PM 전환이 완료된 상태에서 첫 번째 NVMe 명령이 실행되므로 PM 복귀 직후 명령 블록이 명확히 분리된다.

---

### [Fix] _get_nsze() namespace

`-n 1` 하드코딩을 `self.config.nvme_namespace or 1`로 변경. `--namespace` 옵션으로 지정한 namespace에 맞는 NSZE를 조회한다.

---

## v7.3 변경사항

### [Refactor] `_account_command()` 헬퍼 도입

NVMe 명령 실행 후 모든 회계 처리(executions 증가, coverage 평가, corpus 추가, Stats 출력, state 모니터링 트리거)를 단일 메서드로 통합. State-Replay 경로가 `_account_command()`를 재사용하도록 리팩터링.

```
_account_command(seed, fuzz_data, rc, last_samples, source)
  ├─ executions += 1
  ├─ coverage 평가 + corpus 추가
  ├─ C1/C2 reward 기록 (source 파라미터로 분기)
  ├─ MOpt operator reward 갱신
  ├─ 100회 주기: Stats 출력 + state 스냅샷
  └─ RC_TIMEOUT → _handle_timeout_crash
```

### [Fix] State-Replay cmd 복원 정확도

label → opcode+cmd_type → fallback 3단계 복원. `force_admin`, `opcode_override`, `nsid_override`, `data_len_override` 모두 복원.

### [Fix] State-Replay EMA score + C2 reward

replay 전후 state 스냅샷 비교로 EMA score 갱신. `seq_len = max(nvme_count, 1)` (PM 항목 제외).

### [Fix] CSFuzz m2 정규화

`m2 = m2_raw / avg_seq` — per-replay → per-command 단위 변환으로 m1과 동일한 스케일 비교.

---

## v7.0 — State-Aware Fuzzer

### 설계 배경

PC sampling은 코드 경로를 추적하지만, SSD 내부 상태 변화(ECC 에러, 헬스 비트, 벤더 내부 카운터)를 일으키는 입력을 우선 탐색하지 못한다.

### 구성 요소

| 구성 요소 | 역할 |
|-----------|------|
| `state_fields.py` | 관측 필드 정의 (퍼저 수정 없이 필드 추가/삭제 가능) |
| `NVMeStateMonitor` | 100회마다 `nvme smart-log` / `nvme get-log` 실행, before/after delta 계산, 새 state 버킷 감지 |
| `StateCorpusEntry` | state 변화를 일으킨 최근 100개 명령 시퀀스 저장, replay .sh 자동 생성 |

### dual interesting 기준

```
new PC    → edge corpus 추가 (C1 경로)
new state → state corpus 추가 (C2 경로)
두 기준은 독립적으로 작동 (동일 명령이 양쪽 모두 추가 가능)
```

### seed 선택

```
CSFuzz p 확률: state corpus 선택
  → _replay_state_sequence(): 저장된 100개 시퀀스 replay
  → EMA score + C2 reward 갱신

(1-p) 확률: edge corpus 선택 (C1 경로)
```

---

## 제품별 설정 (`--product`)

| 옵션 | 제품 | Interface | OpenOCD 설정 | 코어 수 | PCSR 주소 |
|------|------|-----------|-------------|--------|----------|
| `PM9M1` | Samsung PM9M1 | SWD | `r8_pcsr.cfg` | 3 | 0x80030084, 0x80032084, 0x80034084 |
| `BM9H1` | Samsung BM9H1 | JTAG | `r8_pcsr_jtag.cfg` | 2 | 0x80030084, 0x80032084 |

```bash
# product 자동 설정
--product PM9M1  →  interface=swd,  cfg=r8_pcsr.cfg
--product BM9H1  →  interface=jtag, cfg=r8_pcsr_jtag.cfg

# 수동 override
--product BM9H1 --openocd-config custom.cfg
#  → interface=jtag (product 우선), cfg=custom.cfg (명시값 우선)
```

---

## CSFuzz 적응형 corpus selection

CSFuzz §III-B/C/D 기반. edge coverage(C1)와 state diversity(C2) 중 더 유익한 경로를 동적으로 선택한다.

### p 갱신 (10000회마다)

```
m1 = sum(C1_rewards) / len(C1_rewards)    # per-command edge 성공률
m2_raw = sum(C2_rewards) / len(C2_rewards) # per-replay state 재현 성공률
m2 = m2_raw / avg_seq                      # per-command 단위로 변환

δ = (m2 - m1) × CSFUZZ_DELTA_SCALE        # state가 더 유익하면 δ > 0
p = clamp(p + δ, P_MIN, P_MAX)            # state corpus 선택 확률
```

| 상수 | 값 | 의미 |
|------|---|------|
| `P_MIN` | 0.05 | state corpus 최소 선택 확률 |
| `P_MAX` | 0.60 | state corpus 최대 선택 확률 |
| 초기값 | 0.30 | 시작 시 30% state corpus |

---

## Power Management 설계

### POWER_COMBOS 구성

NVMe PS(0~4) × PCIe L-state(L0/L1/L1.2) × D-state(D0/D3hot) = 30가지 조합.

### PM 전환 흐름

```
[PM 로테이션 — 100회마다, seed 선택 전 실행]  [v7.4 이동]
  ├─ 1/6: PS3/PS4 강제 idle 슬롯
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

### ROM Table 기반 코어 주소

```
JTAG IDCODE: 0x6BA00477  (irlen=4)
  Core0 Debug Base: 0x80030000  → PCSR: 0x80030084
  Core1 Debug Base: 0x80032000  → PCSR: 0x80032084
  Core2 (0x80040000) → 미장착 / 비파워 — WAIT 상태
```

### `r8_pcsr_jtag.cfg` 요점

```tcl
transport select jtag           # adapter driver보다 앞에 선언 필수
adapter driver jlink
jtag newtap r8 cpu -irlen 4 -expected-id 0x6BA00477
dap create r8.dap -chain-position r8.cpu
target create r8.abp mem_ap -dap r8.dap -ap-num 0
target create r8.axi mem_ap -dap r8.dap -ap-num 1
init
r8.dap dpreg 4 0x50000000      # CSYSPWRUPREQ | CDBGPWRUPREQ
after 100
r8.dap dpreg 0 0x1e            # ABORT: sticky error 클리어
```

---

## Defect 처리 흐름

```
[Defect 감지 — timeout or hang]
  │
  ▼
1. read_stuck_pcs(count=1000)
     PCSR 1000회 연속 샘플링 → top_ratio 분석
     ≥ 70% → HANG  /  40~70% → busy-wait  /  < 40% → 분산(복구 중)
  │
  ▼
2. OpenOCD shutdown (J-Link USB 점유 해제)
  │
  ▼
3. JLink 메모리 덤프 (run_smi_mem_dump_JLINK_USB.sh)
  │
  ▼
4. UFAS 덤프 (--enable-ufas 시)
  │
  ▼
5. JLink 기반 PC 모니터링 루프 (30초 간격, Ctrl+C 종료)
```

---

## JLink 기반 PC 모니터링

timeout crash 후 OpenOCD 종료 상태에서 JLinkExe를 직접 실행해 PC를 주기적으로 읽는다.

```
[MONITOR] Core0: PC=0x12345678 [NON-IDLE]
[MONITOR] Core1: PC=0x80031ABC [IDLE]
```

| 항목 | 값 |
|------|---|
| 샘플 간격 | 30초 |
| 종료 방법 | Ctrl+C (루프만 종료, 펌웨어 상태 유지) |
| interface | `SWD` (PM9M1) / `JTAG` (BM9H1) |
| JLink device | `Cortex-R8` |

---

## 코드 상단 상수 설정

### v7.4 신규 상수

| 상수 | 기본값 | 설명 |
|------|--------|------|
| `FUZZER_VERSION` | `'7.4.0'` | 버전 문자열 |
| `LBA_PAIR_MUT_PROB` | `0.15` | 64-bit LBA pair mutation 확률 |
| `STRUCT_PAYLOAD_MUT_PROB` | `0.10` | DSM/Copy structured payload mutation 확률 |
| `SEQ_PROB` | `0.05` | builtin sequence 시작 확률 |
| `SEQ_MAX_PER_100` | `10` | 100-exec window당 sequence 명령 최대 개수 |
| `MDTS_CACHE_TTL` | `5000` | MDTS 캐시 갱신 주기 (exec 단위) |

### 주요 상수 (기존)

| 상수 | 기본값 | 설명 |
|------|--------|------|
| `PM_ROTATE_INTERVAL` | `100` | PM 전환 주기 (실행 횟수) |
| `SCHEMA_MUT_PROB` | `0.30` | Schema Mutation 적용 확률 |
| `DATALEN_MUT_PROB` | 기존값 | data_len mutation 적용 확률 |
| `IO_ADMIN_RATIO` | `3` | I/O 커맨드 선택 가중치 |
| `DIAGNOSE_MAX` | `10000` | idle 수집 최대 샘플 수 |
| `RANDOM_GEN_RATIO` | `0.2` | 랜덤 생성 비율 |
| `ADMIN_SWAP_PROB` | `0.05` | Admin↔IO 교차 전송 확률 |
| `MAX_SAMPLES_PER_RUN` | `500` | 명령 1회당 최대 샘플 수 |
| `DET_BUDGET` | `0.20` | det stage 최대 비율 |

---

## CLI 옵션

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
--pcsr-addrs A,B[,C]     PCSR 주소 오버라이드 (hex)

# 실행 제어
--output DIR             출력 디렉터리
--runtime SEC            총 실행 시간 (기본: 604800 = 1주)
--pm                     Power Combo 활성화 (NVMe PS + PCIe L/D-state + PS3/PS4 idle 슬롯)
--no-por                 시작 시 POR(전원 사이클) 건너뜀
--no-state               State-Aware Fuzzer 비활성화 (edge coverage만)
--allow-no-openocd       OpenOCD 연결 실패 시에도 PM preflight 후 종료 (PM 독립 검증용)

# 샘플링
--samples N              실행당 최대 샘플 수 (기본: 500)
--interval US            샘플 간격 µs (기본: 0 = 최대 밀도)
--diagnose-sleep-ms MS   diagnose() 샘플 간격 ms (기본: 10)
--diagnose-stability N   idle 수렴 연속 횟수 (기본: 100)
--calibration-runs N     시드당 calibration 반복 횟수 (기본: 3)

# 명령어 제어
--commands CMD ...       활성화할 명령어 목록
--all-commands           위험 명령어 포함 전체 활성화 (FWDownload/FWCommit 시퀀스 포함)
--exclude-opcodes A,B    제외할 opcode (hex). 예: "0xC1,0xC0"

# 퍼징 파라미터
--random-gen-ratio F     랜덤 생성 비율 (기본: 0.2)
--admin-swap-prob F      admin↔IO 교체 확률 (기본: 0.05)
--post-cmd-delay MS      명령 후 추가 대기 (기본: 0)
--timeout GROUP MS       명령 그룹별 타임아웃 설정

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
output/pc_sampling_v7.4.0/
├── fuzzer_YYYYMMDD_HHMMSS.log
├── coverage.txt
├── corpus/
│   └── input_<cmd>_<opcode>_<md5>
├── state_corpus/
│   ├── replay_<tag>.sh
│   └── replay_data_<tag>/
│       └── data_NNN.bin
├── crashes/
│   ├── crash_<cmd>_<opcode>_<md5>
│   ├── crash_<cmd>_<opcode>_<md5>.json
│   ├── crash_<cmd>_<opcode>_<md5>.dmesg.txt
│   ├── replay_<tag>.sh
│   └── replay_data_<tag>/
│       └── data_NNN.bin
└── graphs/
    ├── command_comparison.png
    ├── mutation_chart.png          # v7.4 신규 stats 포함
    ├── coverage_heatmap_1d.png
    ├── edge_heatmap_2d.png
    ├── {cmd}_cfg.dot/.png
    ├── coverage_growth.png         (* Ghidra 연동 시)
    ├── firmware_map.png            (* Ghidra 연동 시)
    └── uncovered_funcs.png         (* Ghidra 연동 시)
```

---

## 버전 이력 요약

| 버전 | 주요 변경 |
|------|-----------|
| **v7.4** | Phase 1: NLB-relative/MDTS boundary data_len mutation. Phase 2: 64-bit LBA pair + DSM/Copy structured payload. Phase 3: Write→Compare/FWDownload→FWCommit builtin sequence (공유 ctx, _valid_seqs 게이팅). PM 로테이션을 seed 선택 전으로 이동. |
| v7.3 | `_account_command()` 헬퍼 도입. State-Replay cmd 복원 정확도 개선. EMA score + C2 reward를 replay 후 state 재현 기반으로 갱신. m2 정규화 단위 명확화. |
| v7.2 | DET_BUDGET(20%) 도입. MOpt operator reward 누적 버그 수정. |
| v7.1 | `--allow-no-openocd --pm` 조합 PM-only 독립 검증 경로 추가. |
| v7.0 | State-Aware Fuzzer 도입: `NVMeStateMonitor`, `StateCorpusEntry`, CSFuzz 적응형 p 갱신, dual interesting(PC + state), state corpus replay. |
| v6.4 | PS3/PS4 강제 idle 슬롯 (1/6 확률, settle×2 대기) — NOPS 커버리지 확보. |
| v6.3 | JTAG 지원(BM9H1, 2코어), `--product` / `--interface` 옵션, JLink 덤프, JLink PC 모니터링. |
| v6.2 | Rule-Based Schema Mutation (42커맨드/~150필드/8타입), IO_ADMIN_RATIO=3. |
| v6.0 | OpenOCD PCSR 비침습 샘플링, 3코어(Core0/1/2), PMU POR, 2단계 복구, hang 보존 분석. |
| v5.x | J-Link halt-sample-resume, MOpt, Power Combo(NVMe PS + PCIe L/D), Basic Block 커버리지, 시각화 그래프. |
