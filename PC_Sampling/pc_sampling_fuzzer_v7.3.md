# PC Sampling SSD Firmware Fuzzer v7.3

OpenOCD PCSR(PC Sampling Register) 방식으로 커버리지를 수집하고, `nvme-cli` subprocess를 통해 NVMe 명령어를 SSD에 전달하는 Coverage-Guided + State-Aware Fuzzer.

v7.3의 핵심: **`_account_command()` 헬퍼 도입 + CSFuzz/State-Replay 전면 개선** — NVMe 명령 1회 실행 후 모든 회계 처리(coverage 평가, corpus 추가, Stats, state 모니터링)를 단일 메서드로 통합. State-Replay 경로가 `_account_command()`를 재사용하도록 리팩터링하여 C1/C2 reward, EMA score, edge coverage가 replay에서도 정확히 반영됨.

---

## 목차

1. [아키텍처 개요](#아키텍처-개요)
2. [요구사항](#요구사항)
3. [빠른 시작](#빠른-시작)
4. [v7.3 변경사항 상세](#v73-변경사항-상세)
5. [v7.2 변경사항](#v72-변경사항)
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
│                     PC Sampling Fuzzer v7.3                             │
│                                                                        │
│  ┌──────────┐    ┌──────────────────────────────────────────────────┐  │
│  │  Startup │    │                Main Fuzzing Loop                  │  │
│  │          │    │                                                  │  │
│  │ PMU POR  │    │  시드 선택 (IO/Admin 비율 3:1 + MOpt)             │  │
│  │   ↓      │    │  → 변이 (Det+Havoc+Splice+Schema)                │  │
│  │ OpenOCD  │    │       ↓                                          │  │
│  │  연결    │    │  nvme-cli passthru                               │  │
│  │   ↓      │    │       ↓                                          │  │
│  │diagnose  │    │  PCSR 샘플링 (비침습 OpenOCD)                     │  │
│  │idle_pcs  │    │       ↓                                          │  │
│  │   ↓      │    │  _account_command() [v7.3 신규]                  │  │
│  │Calibrat- │    │   ├─ coverage 평가 + corpus 추가                  │  │
│  │  ion     │    │   ├─ C1 reward 기록 (per-command)                │  │
│  │          │    │   └─ Stats / state / cull / graph 주기 처리      │  │
│  └──────────┘    │                                                  │  │
│                  │  [State 모니터링 — 100회마다]                     │  │
│                  │   state corpus 발견 → State-Replay               │  │
│                  │   _replay_state_sequence() → _account_command()  │  │
│                  │   EMA score + C2 reward 기록 (per-replay)        │  │
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
│  시드 선택 (IO:Admin = 3:1 + CSFuzz p + MOpt 가중치)              │
│                                                                  │
│  [30% 확률] state corpus 선택                                     │
│    → _replay_state_sequence() — 저장된 시퀀스 replay              │
│    →   _account_command() 호출 (source='c2')                     │
│    → EMA score 갱신 + C2 reward 기록                             │
│                                                                  │
│  [70% 확률] edge corpus 선택 (c1 경로)                            │
│    → 변이 (Schema/Det/Havoc/Splice)                               │
│    → nvme-cli passthru 실행                                      │
│    → PCSR 샘플링                                                 │
│    → _account_command() 호출 (source='c1')                       │
│       ├─ coverage 평가, corpus 추가                               │
│       ├─ C1 reward 기록                                          │
│       └─ Stats / state / cull / graph 주기 처리                  │
│                                                                  │
│  [10000회마다] CSFuzz p 갱신 (m1 vs m2 비교)                     │
│  [100회마다] PM 로테이션 (--pm 활성화 시)                         │
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
├── pc_sampling_fuzzer_v7.3.py          # 메인 퍼저
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
sudo python3 pc_sampling_fuzzer_v7.3.py \
  --product PM9M1 \
  --nvme /dev/nvme0 \
  --addr-start 0xA4000 \
  --addr-end 0x3B7FFF \
  --output ./output/run_pm9m1
```

### BM9H1 (JTAG, 2코어)

```bash
sudo python3 pc_sampling_fuzzer_v7.3.py \
  --product BM9H1 \
  --nvme /dev/nvme0 \
  --addr-start 0x28000 \
  --addr-end 0x1FFFF \
  --output ./output/run_bm9h1
```

### State-Aware + PM 활성화

```bash
sudo python3 pc_sampling_fuzzer_v7.3.py \
  --product PM9M1 \
  --nvme /dev/nvme0 \
  --pm \
  --addr-start 0xA4000 --addr-end 0x3B7FFF \
  --output ./output/run_state_pm
```

### State 비활성화 (edge coverage만)

```bash
sudo python3 pc_sampling_fuzzer_v7.3.py \
  --product PM9M1 \
  --nvme /dev/nvme0 \
  --no-state \
  --addr-start 0xA4000 --addr-end 0x3B7FFF \
  --output ./output/run_no_state
```

### POR 없이 실행 (디버깅용)

```bash
sudo python3 pc_sampling_fuzzer_v7.3.py \
  --product PM9M1 \
  --nvme /dev/nvme0 \
  --no-por \
  --output ./output/run_no_por
```

---

## v7.3 변경사항 상세

### [Refactor] `_account_command()` 헬퍼 도입

#### 배경

v7.2까지 NVMe 명령 실행 후 회계 처리(executions 증가, coverage 평가, corpus 추가, Stats 출력, state 모니터링 트리거)가 main loop와 `_replay_state_sequence()` 두 경로에 각각 중복 구현되어 있었다. State-Replay 경로는 일부 회계가 누락되어 C1 reward, edge coverage 누적, 주기적 처리가 replay에 반영되지 않는 문제가 있었다.

#### 구현

```
_send_nvme_command() + sampler.stop_sampling() 호출 직후
  ↓
_account_command(seed, fuzz_data, rc, last_samples, source)
  ├─ executions += 1
  ├─ passthru_stats, rc_stats 갱신
  ├─ evaluate_coverage() — BB 또는 PC 기준 interesting 판정
  ├─ corpus 추가 (is_interesting 시) + det stage 큐 등록
  ├─ C1 reward 기록 (source='c1' 경로)
  ├─ MOpt operator reward 갱신
  ├─ 100회 주기: Stats 출력 + state 스냅샷
  ├─ 10000회 주기: SMART log + state snapshot
  └─ RC_TIMEOUT → _handle_timeout_crash → ('break') 반환
     RC_ERROR   → ('continue') 반환
     정상       → ('ok') 반환
```

- **`source` 파라미터**: `'c1'`(main loop) / `'c2'`(state-replay). source에 따라 C1/C2 reward 경로 분기.
- **`is_det_stage` 파라미터**: Det stage 실행 시 로그에 `[Det]` 태그 표시.

#### 효과

| 항목 | v7.2 | v7.3 |
|------|------|------|
| replay 중 edge coverage 누적 | 없음 | `_replay_new_pcs` 누적 후 EMA score 반영 |
| replay 중 Stats 출력 | 없음 | `_account_command()` 내 주기 처리 동작 |
| replay 중 RC_TIMEOUT 처리 | `_handle_timeout_crash` 직접 호출 | `_account_command()` 통해 동일 경로 |
| 코드 중복 | main loop + replay 각각 | `_account_command()` 단일 구현 |

---

### [Fix] State-Replay 시퀀스 재현 정확도 개선

#### 배경

v7.2의 `_replay_state_sequence()`는 `_cmd_history` 항목에서 cmd 객체를 opcode만으로 복원했다. Admin↔IO 강제 스왑(`force_admin`), vendor opcode(`opcode_override`), data_len 불일치(`data_len_override`), nsid 오버라이드 등 원본 seed의 세부 파라미터가 replay 시 복원되지 않아 재현성이 낮았다.

#### 구현 — cmd 복원 우선순위

```
1. label 매칭 (c.name == hist_item['label'])
   ↓ 실패 시
2. opcode + cmd_type 조합 매칭
   (c.opcode == hist_opcode AND admin/io 일치)
   ↓ 실패 시
3. commands[0] fallback
```

#### 추가 복원 필드

| 필드 | 복원 방법 |
|------|-----------|
| `force_admin` | `passthru_type` 필드로 Admin↔IO 스왑 여부 판별 |
| `opcode_override` | `hist_opcode != cmd.opcode`면 override 적용 |
| `nsid_override` | key 존재 여부로 판별 (0도 유효한 nsid) |
| `data_len_override` | `hist_item['data_len']`으로 정확히 복원 (zero-length 포함) |

#### `record_history=False`

replay 실행 시 `_send_nvme_command(..., record_history=False)`를 사용해 `_cmd_history`가 replay 항목으로 오염되지 않도록 분리.

---

### [Fix] State-Replay EMA score + C2 reward

#### v7.2 문제

`_replay_state_sequence()`가 완료된 뒤 state 변화를 평가하지 않아 EMA score가 갱신되지 않고, C2 reward도 기록되지 않았다.

#### v7.3 수정

```
_replay_state_sequence() 진입 시
  ↓
_pre_snap = state_monitor.capture()      # replay 전 state 스냅샷

시퀀스 실행 (_account_command() 반복)
  └─ _replay_new_pcs 누적

replay 완료 후
  ↓
_post_snap = state_monitor.capture()     # replay 후 state 스냅샷
_rdelta = state_monitor.delta(_pre_snap, _post_snap)

EMA score 갱신:
  _state_score  = rdelta.score / seq_len
  _edge_score   = _replay_new_pcs / seq_len
  _replay_score = _state_score + _edge_score
  entry.score   = 0.8 × entry.score + 0.2 × _replay_score

C2 reward:
  entry.causes 버킷 중 하나라도 재현 → 1
  실패 / state 캡처 불가              → 0
  self._csfuzz_c2_rewards.append(result)
```

#### `seq_len` 기준

`seq_len = max(nvme_count, 1)` — `_cmd_history`의 `kind='pm'`/`'pcie_state'` 항목을 제외한 실제 NVMe 명령 수 기준. PM 항목은 replay에서 의도적으로 제외하므로 score 계산 분모에서도 제외.

---

### [Fix] CSFuzz m2 정규화 단위 명확화

v7.2에서 `m2 = m2_raw / max(avg_seq, 1.0)` 주석이 "per-NVMe-command 기준"으로만 설명되었으나, v7.3에서 "per-replay → per-command 단위 변환"으로 명확히 정의. `avg_seq`는 state corpus entry의 평균 시퀀스 길이(NVMe 명령 수)를 사용해 m2를 m1(per-command 단위)과 동일한 스케일로 변환 후 비교.

---

## v7.2 변경사항

### [Fix] DET_BUDGET(20%) 도입

```
배경: _det_queue가 있으면 random.random() 체크 없이 항상 det stage를 소비
      → Write seed가 new coverage를 내면 ~400회 Write 전용 실행 연속 발생
         havoc/random/admin/state 경로가 완전히 차단되는 다양성 편향

수정: if self._det_queue and random.random() < DET_BUDGET
      DET_BUDGET = 0.20 (전체 실행의 20%만 det stage 소비)
```

### [Fix] MOpt operator reward 누적 버그

```
배경: self._current_mutations = [] 가 _mutate() 이후에 위치
      → reward 계산 시점에 항상 빈 리스트 → MOpt weight 전혀 갱신 안 됨

수정: self._current_mutations = [] 를 루프 iteration 시작(is_det_stage 설정 전)으로 이동
```

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
30% 확률: state corpus 선택
  → _replay_state_sequence(): 저장된 100개 시퀀스 replay
  → replay 이후 suffix mutation 추가 실행

70% 확률: edge corpus 선택 (기존 경로)
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

### 적응형 버킷 (§III-B)

`StateMonitor`는 각 필드를 `log2(1 + |init_delta|) × weight` 기반 power-of-2 구간으로 버킷화. 초기 관측값(`init_value`)을 기준점으로 버킷 경계를 동적 결정.

---

## Power Management 설계

### POWER_COMBOS 구성

NVMe PS(0~4) × PCIe L-state(L0/L1/L1.2) × D-state(D0/D3hot) = 30가지 조합.

### PM 전환 흐름

```
[PM 로테이션 — 100회마다]
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

### v7.3 신규/변경 상수

| 상수 | 기본값 | 설명 |
|------|--------|------|
| `FUZZER_VERSION` | `'7.3.0'` | 버전 문자열 |
| `DET_BUDGET` | `0.20` | det stage가 전체 실행에서 차지할 최대 비율 |

### 주요 상수 (기존)

| 상수 | 기본값 | 설명 |
|------|--------|------|
| `PM_ROTATE_INTERVAL` | `100` | PM 전환 주기 (실행 횟수) |
| `PS_SETTLE_CAP_S` | `1.0` | NOPS settle 상한 (초) |
| `SCHEMA_MUT_PROB` | `0.30` | Schema Mutation 적용 확률 |
| `IO_ADMIN_RATIO` | `3` | I/O 커맨드 선택 가중치 |
| `DIAGNOSE_MAX` | `10000` | idle 수집 최대 샘플 수 |
| `DIAGNOSE_STABILITY` | `100` | idle 수렴 연속 횟수 |
| `RANDOM_GEN_RATIO` | `0.2` | 랜덤 생성 비율 |
| `ADMIN_SWAP_PROB` | `0.05` | Admin↔IO 교차 전송 확률 |
| `MAX_SAMPLES_PER_RUN` | `500` | 명령 1회당 최대 샘플 수 |

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
--all-commands           위험 명령어 포함 전체 활성화
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
output/pc_sampling_v7.3.0/
├── fuzzer_YYYYMMDD_HHMMSS.log
├── coverage.txt
├── corpus/
│   └── input_<cmd>_<opcode>_<md5>
├── state_corpus/                         # State-Aware Fuzzer (v7.0+)
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
| **v7.3** | `_account_command()` 헬퍼 도입 — NVMe 명령 회계를 단일 메서드로 통합. State-Replay cmd 복원 정확도 개선 (label→opcode+type→fallback 3단계). EMA score + C2 reward를 replay 후 state 재현 결과 기반으로 정확히 갱신. m2 정규화 단위 명확화 (per-replay → per-command 변환). |
| v7.2 | DET_BUDGET(20%) 도입 (det stage 다양성 편향 수정). MOpt operator reward 누적 버그 수정 (`_current_mutations = []` 이동). |
| v7.1 | `--allow-no-openocd --pm` 조합 PM-only 독립 검증 경로 추가. |
| v7.0 | State-Aware Fuzzer 도입: `NVMeStateMonitor`, `StateCorpusEntry`, CSFuzz 적응형 p 갱신, dual interesting(PC + state), state corpus replay. |
| v6.4 | PS3/PS4 강제 idle 슬롯 (1/6 확률, settle×2 대기) — NOPS 커버리지 확보. |
| v6.3 | JTAG 지원(BM9H1, 2코어), `--product` / `--interface` 옵션, JLink 덤프(OpenOCD shutdown 후), JLink PC 모니터링, defect PCSR 샘플링 1000회. |
| v6.2 | Rule-Based Schema Mutation (42커맨드/~150필드/8타입), IO_ADMIN_RATIO=3. |
| v6.0 | OpenOCD PCSR 비침습 샘플링, 3코어(Core0/1/2), PMU POR, 2단계 복구, hang 보존 분석. |
| v5.x | J-Link halt-sample-resume, MOpt, Power Combo(NVMe PS + PCIe L/D), Basic Block 커버리지, 시각화 그래프. |
