# PC Sampling SSD Firmware Fuzzer v7.5

OpenOCD PCSR(PC Sampling Register) 비침습 샘플링 + `nvme-cli` passthru 기반 Coverage-Guided + State-Aware Fuzzer.

v7.5 핵심: **SequenceSeed corpus** — builtin sequence를 N개 명령 단위로 corpus에 저장하고 단일 Seed와 동일한 cull/favored 규칙으로 관리. 기본 명령어(Read/Write/SetFeatures/GetFeatures)만으로도 시퀀스 작동.

---

## 목차

1. [아키텍처 개요](#아키텍처-개요)
2. [요구사항 / 빠른 시작](#요구사항--빠른-시작)
3. [v7.5 변경사항](#v75-변경사항)
4. [SequenceSeed corpus](#sequenceseed-corpus)
5. [Builtin sequence](#builtin-sequence)
6. [CSFuzz / State-Aware Fuzzer](#csfuzz--state-aware-fuzzer)
7. [Power Management](#power-management)
8. [JTAG 지원 (BM9H1)](#jtag-지원-bm9h1)
9. [Defect 처리](#defect-처리)
10. [주요 상수](#주요-상수)
11. [CLI 옵션 (19개)](#cli-옵션-19개)
12. [출력 디렉터리](#출력-디렉터리)
13. [버전 이력](#버전-이력)

---

## 아키텍처 개요

```
┌──────────────────────────────────────────────────────────────┐
│  Startup: PMU POR → OpenOCD → diagnose() → Calibration       │
└──────────────────────────────────────────────────────────────┘
┌── Main Loop ────────────────────────────────────────────────┐
│  ① PM 로테이션 (100회마다, seed 선택 전)                      │
│  ② 시드 선택                                                  │
│     [3a] corpus SequenceSeed continuation                    │
│     [3b] builtin sequence continuation                       │
│     [3c] 신규 builtin sequence 시작 (SEQ_PROB=0.05)          │
│     [그 외] CSFuzz p로 C1(edge) / C2(state) 분기             │
│  ③ 변이 (Phase 1/2/3 + Havoc/Splice/Schema/MOpt)            │
│  ④ nvme-cli passthru + PCSR 샘플링                          │
│  ⑤ _account_command()                                       │
│     ├ coverage 평가 + corpus 추가 (단일 Seed)               │
│     ├ _seq_sink 누적 (시퀀스 모드)                           │
│     └ 시퀀스 완료 → _finalize_seq_sink()                    │
│                     → SequenceSeed corpus 추가 + replay .sh │
└─────────────────────────────────────────────────────────────┘
[Defect] timeout/hang → PCSR stuck 분석 → JLink dump → UFAS dump → PC 모니터링
```

---

## 요구사항 / 빠른 시작

```
Python 3.8+, openocd 0.12.0+, nvme-cli, setpci, JLinkExe, J-Link V9/EDU, pmu_4_1.py
```

```bash
# PM9M1 (SWD, 3코어)
sudo python3 pc_sampling_fuzzer_v7.5.py --product PM9M1 --nvme /dev/nvme0

# BM9H1 (JTAG, 2코어)
sudo python3 pc_sampling_fuzzer_v7.5.py --product BM9H1 --nvme /dev/nvme0

# 위험 명령 포함 (FWDownload→FWCommit 시퀀스 활성)
sudo python3 pc_sampling_fuzzer_v7.5.py --product PM9M1 --nvme /dev/nvme0 --all-commands
```

주소 범위·출력 폴더 등 자주 변경하지 않는 값은 코드 상단 상수 또는 `FuzzConfig` 필드로 직접 수정.

---

## v7.5 변경사항

### SequenceSeed corpus 도입
builtin sequence 결과를 N개 명령 단위로 저장. `energy = MAX_ENERGY / N` 패널티로 단일 Seed와 per-exec 공정 경쟁. `_seq_sink`에 시퀀스 도중 누적 후 완료 시 일괄 저장 (개별 중복 저장 제거).

### Sequence ctx 파생 개선
Write를 먼저 mutation → 그 결과 CDW10/11/12/data에서 ctx 파생 → Compare/Read에만 적용. Write mutation 결과가 보존되고 후속 명령만 Write를 따라감.

### Cull 일관성 (2-pass favored)
- **Pass 1**: 단일 Seed로 PC → best(data 크기 기준) 매핑
- **Pass 2**: 미커버 PC만 SequenceSeed가 채움
- SequenceSeed가 단일 Seed와 같은 PC를 커버하면 **단일 Seed가 항상 favored**
- 일반 cull / hard limit / epoch reset 모두 SequenceSeed에 동일 적용
- `MAX_SEQUENCE_CORPUS=50` cap 정렬을 `(is_favored, new_pcs)`로 변경

### seq_corpus/ replay .sh
SequenceSeed의 각 명령을 nvme-cli 커맨드로 변환, `replay_seq_{found_at}.sh`로 저장. cull 시 고아 파일 자동 청소.

### BUILTIN_SEQUENCES 확장 (기본 모드 작동)
```python
BUILTIN_SEQUENCES = [
    ["Write", "Read"],              # 데이터 일관성 (기본 모드)
    ["Write", "Write"],             # overwrite 경로 (기본 모드)
    ["SetFeatures", "GetFeatures"], # feature config 회귀 (기본 모드)
    ["Write", "Compare"],           # --commands Compare 필요
    ["FWDownload", "FWCommit"],     # --all-commands 필요
]
```

`_CTX_SEQUENCES = {("Write","Compare"), ("Write","Read"), ("Write","Write")}` — ctx 공유 필요한 시퀀스.

### CLI 옵션 정리 (51 → 19개)
자주 변경하지 않는 옵션 32개를 CLI에서 제거하고 `FuzzConfig` 필드/상수로 유지. 필요 시 코드 직접 수정.

### JLink dump 토글
`--no-jlink-dump` 옵션 추가 — UFAS와 동일한 패턴.

### Mutation 버그 수정
- DSM NR=0xFF payload 불일치: payload=1 entry(언더플로) 케이스 수정
- Copy `_nr_mask` 0xFF→0xF (CDW12[11:8] = 4비트, NVMe spec 준수)
- DSM/Copy structured payload 재구성 후 `data_len_override` 잔존 리셋

---

## SequenceSeed corpus

### 데이터 구조

```python
@dataclass
class SequenceSeed:
    commands: List[Seed]           # 실행 순서대로 저장된 Seed 목록
    new_pcs: int = 0               # 시퀀스 전체에서 발견한 새 PC 수
    energy: float = 1.0            # MAX_ENERGY / N 패널티
    found_at: int = 0
    exec_count: int = 0
    is_favored: bool = False       # 2-pass favored 마킹 결과
    covered_pcs: Optional[set] = None
```

### _seq_sink 누적 → _finalize_seq_sink()

시퀀스 시작 시 `_seq_sink = {'commands': [], 'new_pcs': 0, 'covered_pcs': set(), 'interesting': False}` 초기화. 각 명령은 `_account_command()`에서 누적되며 개별 corpus 추가는 하지 않음. 시퀀스 완료 시 `interesting=True`이면 SequenceSeed 하나로 corpus 추가 + replay .sh 저장.

### Cull 규칙 (단일 Seed와 동일)

| 단계 | 규칙 |
|------|------|
| 일반 cull | `favored OR exec_count<2 OR found_at==0` 만 생존 — SequenceSeed도 동일 |
| Hard limit | `found_at==0 OR favored` 보호, 나머지 exec_count 내림차순 evict |
| MAX_SEQUENCE_CORPUS(50) | `(is_favored, new_pcs)` 내림차순 상위 50개 보존 |
| Epoch reset | `favored OR found_at==0` 만 생존 |

cull/evict된 SequenceSeed의 `seq_corpus/replay_seq_{found_at}.sh` 와 `replay_data_seq_{found_at}/` 폴더는 `_remove_seq_replay_artifacts()`가 함께 청소.

### Replay 흐름

```
corpus에서 SequenceSeed 선택
  ├─ SEQ_MAX_PER_100 초과? → 첫 명령만 단독 실행
  └─ replay 시작
       ├─ commands[0] = _mutate(stored_seed)           ← Write
       ├─ CTX_SEQUENCES이면 ctx 파생 → _pending_seq_ctx
       ├─ _pending_seq_seeds = commands[1:]
       └─ _seq_sink 초기화
            [다음 iteration: 3a continuation]
            ├─ _mutate(commands[1])                    ← Read/Compare/Write
            ├─ (ctx 있으면) _apply_seq_ctx()
            └─ 소진 시 _pending_seq_ctx = None
```

---

## Builtin sequence

### 게이팅
```python
_enabled_names = {c.name for c in self.commands}
_valid_seqs = [s for s in BUILTIN_SEQUENCES
               if all(n in _enabled_names for n in s)]
```

비활성 명령을 포함한 시퀀스는 자동 제외. FWDownload→FWCommit은 `--all-commands` 또는 `--commands FWDownload FWCommit` 필요.

### 발동 조건
모두 만족할 때 5% 확률로 시작:
- `SEQ_PROB=0.05` 확률 충족
- `_seq_cmds_in_window < SEQ_MAX_PER_100(=10)`
- det-stage / state-replay 미진행

### _apply_seq_ctx() 동작

```python
seed.cdw10 = slba & 0xFFFFFFFF
seed.cdw11 = (slba >> 32) & 0xFFFFFFFF
seed.cdw12 = (seed.cdw12 & ~0xFFFF) | (nlb & 0xFFFF)   # NLB만 덮어씀
seed.data  = ctx['data']
seed.data_len_override = len(ctx['data'])
# 시퀀스 명령은 정상 경로 — 변이 필드 초기화
seed.opcode_override = None
seed.force_admin     = None
seed.nsid_override   = None
```

CDW12 상위 비트(FUA, PRINFO 등)와 CDW13~15 mutation은 살아있음.

---

## CSFuzz / State-Aware Fuzzer

- **state_fields.py** — 관측 필드 정의 (퍼저 수정 없이 추가/삭제)
- **NVMeStateMonitor** — 100회마다 nvme smart-log / get-log delta 계산
- **StateCorpusEntry** — state 변화를 일으킨 최근 100개 명령 시퀀스 저장
- **dual interesting** — new PC → edge corpus (C1), new state → state corpus (C2)
- **p 갱신** (10000회마다):
  ```
  m1 = sum(C1_rewards) / len(C1_rewards)
  m2 = (sum(C2_rewards) / len(C2_rewards)) / avg_seq
  p  = clamp(p + (m2-m1)×CSFUZZ_DELTA_SCALE, P_MIN=0.05, P_MAX=0.60)
  ```

---

## Power Management

NVMe PS(0~4) × PCIe L-state(L0/L1/L1.2) × D-state(D0/D3hot) = 30 combo. 100회마다 seed 선택 전 PM 로테이션. PS3/PS4 강제 idle 슬롯(1/6 확률, NOPS 커버리지 확보).

APST 비활성화 권장 — 퍼저와 무관한 PS 전환을 막아 커버리지 오염 방지.

---

## JTAG 지원 (BM9H1)

```
JTAG IDCODE: 0x6BA00477 (irlen=4)
Core0 Debug Base: 0x80030000 → PCSR: 0x80030084
Core1 Debug Base: 0x80032000 → PCSR: 0x80032084
```

JTAG cfg는 `transport select jtag`을 `adapter driver`보다 앞에 배치. init 직후 DP CTRL/STAT=0x50000000, ABORT=0x1e로 sticky 클리어.

---

## Defect 처리

```
[timeout / hang]
  1. read_stuck_pcs(1000) — top_ratio≥70%=HANG, 40~70%=busy-wait, <40%=분산
  2. OpenOCD shutdown (J-Link USB 해제)
  3. JLink 메모리 덤프         ← --no-jlink-dump로 비활성화
  4. UFAS 펌웨어 덤프          ← --no-ufas로 비활성화
  5. JLink PC 모니터링 루프 (30초 간격, Ctrl+C 종료)
```

---

## 주요 상수

| 상수 | 값 | 설명 |
|------|-----|------|
| `FUZZER_VERSION` | `7.5.0` | 버전 |
| `SEQ_PROB` | `0.05` | builtin sequence 시작 확률 |
| `SEQ_MAX_PER_100` | `10` | 100-exec window당 sequence 명령 최대 |
| `MAX_SEQUENCE_CORPUS` | `50` | corpus 내 SequenceSeed 최대 |
| `LBA_PAIR_MUT_PROB` | `0.15` | 64-bit LBA pair mutation 확률 |
| `STRUCT_PAYLOAD_MUT_PROB` | `0.10` | DSM/Copy structured payload 확률 |
| `MDTS_CACHE_TTL` | `5000` | MDTS 캐시 갱신 주기 (exec) |
| `SCHEMA_MUT_PROB` | `0.30` | Schema Mutation 확률 |
| `DET_BUDGET` | `0.20` | det stage 최대 비율 |
| `IO_ADMIN_RATIO` | `3` | I/O 커맨드 가중치 |
| `PM_ROTATE_INTERVAL` | `100` | PM 전환 주기 |
| `MAX_SAMPLES_PER_RUN` | `500` | 명령 1회당 최대 샘플 수 |
| `CSFUZZ_P_MIN / P_MAX` | `0.05 / 0.60` | state corpus 선택 확률 범위 |

기타 상수는 코드 상단(파일 시작 ~400줄 부근)에서 직접 수정.

---

## CLI 옵션 (19개)

```
# 제품/타겟
--product {PM9M1,BM9H1}   interface/cfg 자동 설정
--interface {swd,jtag}    디버그 transport (--product 우선)
--nvme DEVICE             /dev/nvme0
--namespace N             namespace ID

# 명령어 선택
--commands NAME ...       활성화할 명령 (예: Read Write Compare)
--all-commands            위험 명령 포함 전체 활성화
--exclude-opcodes HEX     쉼표 구분 hex (예: "0xC1,0xC0")

# 커버리지
--resume-coverage FILE    이전 coverage.txt 경로

# FW Download/Commit
--fw-bin PATH             FWDownload용 펌웨어 바이너리
--fw-xfer BYTES           청크 크기 (기본 32768)
--fw-slot N               FWCommit 슬롯 (기본 1)

# Power Management
--pm                      PM 로테이션 활성화 (30 combo)
--allow-no-openocd        OpenOCD 없이 PM 독립 검증

# 토글
--no-por                  POR 건너뜀
--no-ufas                 UFAS 덤프 건너뜀
--no-jlink-dump           JLink 메모리 덤프 건너뜀
--no-state                State monitoring 비활성화
--prefill                 POR 전 드라이브 전체 쓰기 (GC/WL 트리거)
--prefill-bs BYTES        prefill dd 블록 크기
```

OpenOCD host/port, 샘플링 간격, 타임아웃, diagnose/calibration 파라미터, settle sweep, CLKREQ 핀, POR 보조 등은 CLI에서 제거 — 코드 상단 상수 또는 `FuzzConfig` 필드로 직접 수정.

---

## 출력 디렉터리

```
output/pc_sampling_v7.5.0/
├── fuzzer_YYYYMMDD_HHMMSS.log
├── coverage.txt
├── corpus/
│   └── input_<cmd>_<opcode>_<md5>
├── seq_corpus/                          # SequenceSeed replay
│   ├── replay_seq_<found_at>.sh
│   └── replay_data_seq_<found_at>/
├── state_corpus/                        # state-triggered 시퀀스
│   ├── replay_state_<found_at>.sh
│   └── replay_data_state_<found_at>/
├── crashes/
│   ├── crash_<cmd>_<opcode>_<md5>
│   ├── replay_<tag>.sh
│   └── replay_data_<tag>/
└── graphs/
    ├── command_comparison.png
    ├── mutation_chart.png
    ├── coverage_heatmap_1d.png
    ├── edge_heatmap_2d.png
    ├── coverage_growth.png              (* Ghidra 연동)
    └── firmware_map.png                 (* Ghidra 연동)
```

---

## 버전 이력

| 버전 | 주요 변경 |
|------|-----------|
| **v7.5** | SequenceSeed corpus + 2-pass favored cull 일관성. Sequence ctx를 Write mutation 결과에서 파생. seq_corpus/ replay .sh 자동 저장 + 고아 청소. BUILTIN_SEQUENCES에 기본 모드 시퀀스(Write→Read 등) 추가. `--no-jlink-dump` 추가. CLI 옵션 51→19. DSM/Copy NR 마스크 수정. |
| v7.4 | Phase 1 (NLB/MDTS data_len), Phase 2 (64-bit LBA, DSM/Copy structured), Phase 3 (builtin sequence). PM 로테이션을 seed 선택 전으로 이동. |
| v7.3 | `_account_command()` 헬퍼, State-Replay 복원 정확도, m2 정규화. |
| v7.2 | DET_BUDGET(20%), MOpt reward 누적 버그 수정. |
| v7.1 | `--allow-no-openocd --pm` PM 독립 검증 경로. |
| v7.0 | State-Aware Fuzzer (NVMeStateMonitor, StateCorpusEntry, dual interesting). |
| v6.4 | PS3/PS4 강제 idle 슬롯 — NOPS 커버리지 확보. |
| v6.3 | JTAG 지원(BM9H1), `--product` / `--interface` 옵션. |
| v6.2 | Rule-Based Schema Mutation (42cmd / ~150field / 8type). |
| v6.0 | OpenOCD PCSR 비침습 샘플링, 3코어, POR, 2단계 복구. |
| v5.x | J-Link halt-sample-resume, MOpt, Power Combo, BB 커버리지, 시각화. |
