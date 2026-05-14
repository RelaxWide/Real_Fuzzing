# PC Sampling SSD Firmware Fuzzer v7.5

OpenOCD PCSR(PC Sampling Register) 방식으로 커버리지를 수집하고, `nvme-cli` subprocess를 통해 NVMe 명령어를 SSD에 전달하는 Coverage-Guided + State-Aware Fuzzer.

v7.5의 핵심: **SequenceSeed corpus** — builtin sequence 실행 결과를 N개 명령어 단위로 corpus에 저장하고 energy 기반으로 재사용. Write→Compare ctx 파생 방식을 "fresh random 생성"에서 "Write mutation 결과 파생"으로 개선. seq_corpus/ replay .sh 자동 저장.

---

## 목차

1. [아키텍처 개요](#아키텍처-개요)
2. [요구사항](#요구사항)
3. [빠른 시작](#빠른-시작)
4. [v7.5 변경사항 상세](#v75-변경사항-상세)
5. [v7.4 변경사항](#v74-변경사항)
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
│                     PC Sampling Fuzzer v7.5                             │
│                                                                        │
│  ┌──────────┐    ┌──────────────────────────────────────────────────┐  │
│  │  Startup │    │                Main Fuzzing Loop                  │  │
│  │          │    │                                                  │  │
│  │ PMU POR  │    │  ① PM 로테이션 (100회마다, seed 선택 전)          │  │
│  │   ↓      │    │  ② 시드 선택                                     │  │
│  │ OpenOCD  │    │    ├─ [3a] corpus SequenceSeed continuation       │  │
│  │  연결    │    │    ├─ [3b] builtin sequence continuation          │  │
│  │   ↓      │    │    ├─ [3c] 신규 builtin sequence 시작 (SEQ_PROB)  │  │
│  │diagnose  │    │    └─ Power Schedule + CSFuzz (C1/C2 경로)        │  │
│  │idle_pcs  │    │       └─ corpus SequenceSeed replay 시작          │  │
│  │   ↓      │    │  ③ 변이 (_mutate)                                │  │
│  │Calibrat- │    │    ├─ Phase 1: NLB-relative / MDTS data_len      │  │
│  │  ion     │    │    ├─ Phase 2: 64-bit LBA pair                   │  │
│  │          │    │    ├─ Phase 2: DSM/Copy structured payload       │  │
│  │          │    │    └─ 기존: Det/Havoc/Splice/Schema              │  │
│  └──────────┘    │  ④ nvme-cli passthru → PCSR 샘플링               │  │
│                  │  ⑤ _account_command()                            │  │
│                  │   ├─ coverage 평가 + corpus 추가                  │  │
│                  │   ├─ _seq_sink 누적 (시퀀스 모드)                 │  │
│                  │   ├─ 시퀀스 완료 → _finalize_seq_sink()           │  │
│                  │   │   └─ SequenceSeed corpus 추가 + replay .sh   │  │
│                  │   └─ Stats / state / cull / graph 주기 처리      │  │
│                  └──────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

### 전체 실행 흐름

```
[시작]
  │
  ▼
PMU POR → OpenOCD 연결 → diagnose() → Calibration
  │
  ▼
┌─ Main Loop ──────────────────────────────────────────────────────┐
│  ① PM 로테이션 (100회마다)                                        │
│                                                                  │
│  ② 시드 선택 (Phase 3)                                           │
│    [3a] corpus SequenceSeed continuation (_pending_seq_seeds)    │
│         → _mutate(next_seed) → (ctx 있으면 _apply_seq_ctx)       │
│    [3b] builtin sequence continuation (_pending_sequence)        │
│         → _pick_seq_seed(cmd, ctx)                               │
│    [3c] 신규 builtin sequence 시작 (SEQ_PROB=0.05)               │
│         → _pick_seq_seed(Write/FWDownload, ctx=None)             │
│         → Write mutation 결과에서 ctx 파생 → _pending_seq_ctx    │
│                                                                  │
│    [corpus 선택]                                                  │
│      SequenceSeed → SEQ_MAX 체크 → replay 시작 or 단독 실행      │
│      일반 Seed    → _mutate()                                    │
│      corpus 없음  → 완전 랜덤 생성                               │
│                                                                  │
│  ③ 변이 (_mutate): Phase 1/2 + Havoc/Splice/Schema               │
│  ④ nvme-cli passthru 실행 + PCSR 샘플링                          │
│  ⑤ _account_command()                                            │
│     → _seq_sink 누적 → 시퀀스 완료 시 _finalize_seq_sink()       │
│        → SequenceSeed corpus 추가 + seq_corpus/ replay .sh 저장  │
└──────────────────────────────────────────────────────────────────┘
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
```

파일 구성:

```
PC_Sampling/
├── pc_sampling_fuzzer_v7.5.py          # 메인 퍼저
├── nvme_seeds.py                        # NVMe 명령 시드 템플릿
├── state_fields.py                      # 상태 필드 정의
├── pmu_4_1.py                           # PMU 보드 제어 (POR용)
├── r8_pcsr.cfg                          # OpenOCD 설정 — SWD (PM9M1)
└── r8_pcsr_jtag.cfg                     # OpenOCD 설정 — JTAG (BM9H1)
```

---

## 빠른 시작

### PM9M1 (SWD, 3코어)

```bash
sudo python3 pc_sampling_fuzzer_v7.5.py \
  --product PM9M1 \
  --nvme /dev/nvme0 \
  --addr-start 0xA4000 \
  --addr-end 0x3B7FFF \
  --output ./output/run_pm9m1
```

### BM9H1 (JTAG, 2코어)

```bash
sudo python3 pc_sampling_fuzzer_v7.5.py \
  --product BM9H1 \
  --nvme /dev/nvme0 \
  --addr-start 0x00000 \
  --addr-end 0x27FFF \
  --output ./output/run_bm9h1
```

### FWDownload→FWCommit 시퀀스 포함 (위험 명령어 활성화)

```bash
sudo python3 pc_sampling_fuzzer_v7.5.py \
  --product PM9M1 \
  --nvme /dev/nvme0 \
  --all-commands \
  --addr-start 0xA4000 --addr-end 0x3B7FFF \
  --output ./output/run_all_cmds
```

---

## v7.5 변경사항 상세

### 배경

v7.4에서 builtin sequence(Write→Compare 등)는 실행되더라도 결과가 corpus에 단일 Seed로만 저장됐다. 같은 시퀀스 조합이 반복적으로 커버리지를 냈던 경우에도 "시퀀스 단위"로 재사용하는 경로가 없었다.

v7.5는 시퀀스 실행 결과를 `SequenceSeed` 단위로 corpus에 저장하고, energy 기반 Power Schedule로 재사용한다. 또한 Write→Compare의 공유 컨텍스트 파생 방식을 올바르게 수정한다.

---

### SequenceSeed corpus

#### 데이터 구조

```python
@dataclass
class SequenceSeed:
    commands: List[Seed]      # 시퀀스 내 명령어 목록 (실행 순서)
    new_pcs: int = 0          # 시퀀스 전체에서 발견한 새 PC 수
    energy: float = 1.0       # base / len(commands) 패널티
    found_at: int = 0
    exec_count: int = 0
    is_favored: bool = False
    covered_pcs: Optional[set] = None
```

각 `commands[i]`는 실제 실행 당시의 CDW10/11/12/data/force_admin 등이 모두 저장된 `Seed` 객체다.

#### Energy 계산

```
energy = base_energy / len(commands)
```

N개 명령어 시퀀스는 단일 Seed 대비 `1/N` 에너지를 갖는다. per-execution 기준으로 단일 Seed와 공정하게 경쟁한다.

#### _seq_sink — 시퀀스 중 누적 버퍼

```python
_seq_sink = {
    'commands':    [],      # 실행된 Seed 목록 (순서대로 누적)
    'new_pcs':     0,       # 시퀀스 전체 누적 새 PC 수
    'covered_pcs': set(),   # 방문한 PC 주소 집합
    'interesting': False,   # 하나라도 새 PC를 낸 경우 True
}
```

시퀀스 시작 시 초기화 → 각 명령 실행 후 `_account_command()`에서 누적 → 시퀀스 완료 시 `_finalize_seq_sink()` 호출.

시퀀스 모드에서는 개별 Seed를 corpus에 추가하지 않는다. 시퀀스 완료 후 `SequenceSeed` 하나로만 저장한다.

#### _finalize_seq_sink()

```
_seq_sink['interesting'] == True
  → SequenceSeed 생성 → corpus 추가
  → _generate_seq_replay_sh() → seq_corpus/ 에 replay .sh 저장
  → log.warning("[+][SeqSeed] cmds=N  new_PC=M  corpus=K  exec=X")

_seq_sink['interesting'] == False
  → 저장 없이 _seq_sink = None 리셋
```

#### corpus SequenceSeed replay 흐름

```
[corpus에서 SequenceSeed 선택]
  │
  ├─ SEQ_MAX_PER_100 초과?
  │   └─ YES → 첫 명령만 단독 실행 (log.debug "[Seq/Corp] window 초과")
  │
  └─ NO → replay 시작 (log.debug "[Seq/Corp] replay 시작")
      │
      ├─ commands[0] = _mutate(stored_seed)   ← Write
      ├─ CTX_SEQUENCES이면 ctx 파생 (아래 참조)
      ├─ _pending_seq_seeds = commands[1:]
      └─ _seq_sink 초기화
           │
           [다음 iteration: 3a continuation]
           ├─ _mutate(commands[1])   ← Compare
           ├─ (ctx 있으면) _apply_seq_ctx()
           └─ _pending_seq_seeds 소진 시 _pending_seq_ctx = None
```

| 상수 | 값 | 설명 |
|------|---|------|
| `MAX_SEQUENCE_CORPUS` | `50` | corpus 내 SequenceSeed 최대 개수 |

---

### Write→Compare 공유 ctx 파생 개선

#### 기존 방식 (v7.4)

```
시퀀스 시작 시:
  fresh random SLBA/NLB/data 생성
  → Write와 Compare 양쪽에 _apply_seq_ctx() 강제 적용
  → Write의 mutation 결과 덮어씌워짐
```

#### 개선 방식 (v7.5)

```
시퀀스 시작 시:
  1. Write = _mutate(seed) or _pick_seq_seed(ctx=None)   ← mutation 완전히 살아있음
  2. ctx = {
       'slba': (mutated_write.cdw11 << 32) | mutated_write.cdw10,
       'nlb':  mutated_write.cdw12 & 0xFFFF,
       'data': mutated_write.data,
     }                                                   ← Write 결과에서 파생
  3. _pending_seq_ctx = ctx
  4. Compare continuation 시:
       compare = _mutate(seed)
       _apply_seq_ctx(compare, ctx)                      ← Compare만 ctx 적용
```

builtin sequence([3c])와 corpus SequenceSeed replay 양쪽 모두 동일한 방식 적용.

#### _apply_seq_ctx() 동작

```python
def _apply_seq_ctx(self, seed, ctx):
    seed.cdw10 = slba & 0xFFFFFFFF          # SLBA_LO
    seed.cdw11 = (slba >> 32) & 0xFFFFFFFF  # SLBA_HI
    seed.cdw12 = (seed.cdw12 & ~0xFFFF) | (nlb & 0xFFFF)  # NLB만 덮어씀
    seed.data  = ctx['data']
    seed.data_len_override = len(ctx['data'])
    # 시퀀스 명령은 정상 경로로 실행
    seed.opcode_override = None
    seed.force_admin     = None
    seed.nsid_override   = None
    return seed
```

Compare에 `opcode_override`/`force_admin`/`nsid_override` mutation이 발동해도 ctx 적용 시 초기화된다. CDW12 상위 비트(FUA, PRINFO 등), CDW13~15 mutation은 살아있다.

---

### seq_corpus/ replay .sh 저장

#### _generate_seq_replay_sh()

SequenceSeed의 각 명령을 `nvme-cli` 커맨드로 변환하여 `seq_corpus/replay_seq_{found_at}.sh`로 저장.

```
passthru_type 결정:
  seed.force_admin is not None
    → True:  admin-passthru (controller device)
    → False: io-passthru (namespace device: /dev/nvme0n1)
  else
    → cmd.cmd_type == ADMIN: admin-passthru
    → else: io-passthru

device 결정:
  admin-passthru → config.nvme_device (/dev/nvme0)
  io-passthru   → {nvme_device}n{namespace} (/dev/nvme0n1)
```

data_len 계산은 런타임 `_send_nvme_command()`와 동일한 로직 사용:
- `data_len_override` 있으면 우선 적용
- IO 명령(Write/Read/Compare 등): `(NLB+1) × LBA_SIZE`
- GetLogPage, SecurityReceive, GetLBAStatus: CDW/파라미터에서 계산
- 그 외 admin 고정 크기 명령: `_ADMIN_FIXED` 테이블 참조

---

### DSM/Copy 경계 케이스 수정

#### DatasetManagement NR 불일치 수정

```
[기존] mut_type=2: NR=0xFF 선언, payload = 257 entries(오버플로)
[수정] mut_type=2: NR=0xFF 선언, payload = 1 entry 16B (언더플로 불일치)
```

CDW10 NR 필드 마스크: `cdw10 & ~0xFF` (8비트)

#### Copy NR 마스크 수정

```
[기존] _nr_mask = 0xFF << 8   # CDW12[15:8] — 8비트 범위 오염
[수정] _nr_mask = 0xF << 8    # CDW12[11:8] — 4비트 (NVMe spec)
```

#### data_len_override 잔존 제거

DSM/Copy structured payload 재구성 후 이전 `data_len_override` 값이 남아 실제 전송 크기와 불일치하는 문제 수정:

```python
new_seed.data_len_override = None   # structured payload 재구성 후 리셋
```

---

### Stats 한 줄 개선

#### 변경 전 (v7.4)

```
[Stats] exec: 1,200 | corpus: 45 | pcs: 3,821 | samples: 12,345 | last_run: 5 | exec/s(avg): 12.3 | exec/s(win): 14.5
```

#### 변경 후 (v7.5)

```
[Stats] exec: 1,200 | corpus: 45(seq:3) | pcs: 3,821 | exec/s: 14.5 | seq_run: 120
```

| 필드 | 설명 |
|------|------|
| `corpus: N(seq:M)` | 전체 corpus 크기 + SequenceSeed 개수 |
| `exec/s` | 최근 100-exec window EPS (avg 제거) |
| `seq_run` | 누적 sequence 명령 발행 횟수 |
| 제거 | `samples`, `last_run`, `exec/s(avg)` |

---

### Sequence 로그

| 로그 | 레벨 | 시점 |
|------|------|------|
| `[Seq/Builtin] 시작: ('Write', 'Compare')` | debug | builtin sequence 시작 |
| `[Seq/Corp] replay 시작: cmds=... new_pcs=N` | debug | corpus SequenceSeed 선택 |
| `[Seq/Corp] continuation: cmd=Compare remaining=0` | debug | [3a] 다음 명령 처리 |
| `[Seq/Corp] window 초과 → 단독 실행: cmd=Write` | debug | SEQ_MAX 초과 fallback |
| `[+][Seq-Acc] cmd=Write +N PCs (seq_acc=M)` | info | 시퀀스 중 새 PC 발견 |
| `[+][SeqSeed] cmds=2 new_PC=N corpus=K exec=X` | warning | SequenceSeed corpus 저장 |
| `[SeqSeed] replay .sh 저장: .../replay_seq_N.sh` | info | replay .sh 저장 성공 |

---

## v7.4 변경사항

### [Phase 1] NLB-relative + MDTS boundary data_len

Write/Read/Compare 대상으로 CDW12 NLB 기반 `(NLB+1)×LBA_SIZE` 주변 경계 후보 + MDTS boundary 후보를 data_len mutation에 추가.

| 상수 | 값 | 설명 |
|------|---|------|
| `DATALEN_MUT_PROB` | 기존값 | data_len mutation 확률 |
| `MDTS_CACHE_TTL` | `5000` | MDTS 캐시 갱신 주기 |

통계 키: `datalen_nlb`, `datalen_mdts`

### [Phase 2] 64-bit LBA pair mutation

Read/Write/Compare/Verify/Copy 대상으로 cdw10+cdw11 쌍을 `nsze` 경계값 기반으로 변이.

| 상수 | 값 |
|------|---|
| `LBA_PAIR_MUT_PROB` | `0.15` |

통계 키: `lba_pair_64bit`

### [Phase 2] DSM/Copy structured payload

CDW(NR) + payload entry 수를 4가지 케이스(1 entry / max entry / 선언-실제 불일치 / 빈 payload)로 재구성.

| 상수 | 값 |
|------|---|
| `STRUCT_PAYLOAD_MUT_PROB` | `0.10` |

통계 키: `dsm_structured`, `copy_structured`

### [Phase 3] Builtin sequence mini-set

| 시퀀스 | 활성 조건 | 목적 |
|--------|-----------|------|
| `Write → Compare` | 기본 활성 | 데이터 정합성 검증 경로 탐색 |
| `FWDownload → FWCommit` | `--all-commands` 필요 | FW 에러 핸들링 경로 탐색 |

| 상수 | 값 |
|------|---|
| `SEQ_PROB` | `0.05` |
| `SEQ_MAX_PER_100` | `10` |

---

## v7.0 — State-Aware Fuzzer

### 설계 배경

PC sampling은 코드 경로를 추적하지만, SSD 내부 상태 변화(ECC 에러, 헬스 비트, 벤더 내부 카운터)를 일으키는 입력을 우선 탐색하지 못한다.

### 구성 요소

| 구성 요소 | 역할 |
|-----------|------|
| `state_fields.py` | 관측 필드 정의 |
| `NVMeStateMonitor` | 100회마다 `nvme smart-log` / `nvme get-log` 실행, delta 계산, 새 state 버킷 감지 |
| `StateCorpusEntry` | state 변화를 일으킨 최근 100개 명령 시퀀스 저장, replay .sh 자동 생성 |

### dual interesting 기준

```
new PC    → edge corpus 추가 (C1 경로)
new state → state corpus 추가 (C2 경로)
두 기준은 독립적으로 작동
```

### CSFuzz p 갱신 (10000회마다)

```
m1 = sum(C1_rewards) / len(C1_rewards)
m2 = (sum(C2_rewards) / len(C2_rewards)) / avg_seq
δ  = (m2 - m1) × CSFUZZ_DELTA_SCALE
p  = clamp(p + δ, P_MIN=0.05, P_MAX=0.60)
```

---

## 제품별 설정 (`--product`)

| 옵션 | 제품 | Interface | OpenOCD 설정 | 코어 수 |
|------|------|-----------|-------------|--------|
| `PM9M1` | Samsung PM9M1 | SWD | `r8_pcsr.cfg` | 3 |
| `BM9H1` | Samsung BM9H1 | JTAG | `r8_pcsr_jtag.cfg` | 2 |

---

## CSFuzz 적응형 corpus selection

CSFuzz §III-B/C/D 기반. edge coverage(C1)와 state diversity(C2) 중 더 유익한 경로를 동적으로 선택한다. 상세 내용은 v7.4 문서 참조.

---

## Power Management 설계

NVMe PS(0~4) × PCIe L-state(L0/L1/L1.2) × D-state(D0/D3hot) = 30가지 조합. 100회마다 seed 선택 전 PM 로테이션 실행. 상세 내용은 v7.4 문서 참조.

---

## JTAG 지원 (BM9H1)

```
JTAG IDCODE: 0x6BA00477  (irlen=4)
  Core0 Debug Base: 0x80030000  → PCSR: 0x80030084
  Core1 Debug Base: 0x80032000  → PCSR: 0x80032084
```

상세 내용은 v7.4 문서 참조.

---

## Defect 처리 흐름

```
[Defect 감지 — timeout or hang]
  1. read_stuck_pcs(1000) → HANG / busy-wait / 분산 분류
  2. OpenOCD shutdown
  3. JLink 메모리 덤프
  4. UFAS 덤프 (--enable-ufas 시)
  5. JLink PC 모니터링 루프
```

---

## JLink 기반 PC 모니터링

timeout crash 후 OpenOCD 종료 상태에서 JLinkExe로 PC를 주기적으로 읽는다. 30초 간격, Ctrl+C 종료.

---

## 코드 상단 상수 설정

### v7.5 신규 상수

| 상수 | 기본값 | 설명 |
|------|--------|------|
| `FUZZER_VERSION` | `'7.5.0'` | 버전 문자열 |
| `MAX_SEQUENCE_CORPUS` | `50` | corpus 내 SequenceSeed 최대 개수 |

### v7.4 주요 상수 (유지)

| 상수 | 기본값 | 설명 |
|------|--------|------|
| `LBA_PAIR_MUT_PROB` | `0.15` | 64-bit LBA pair mutation 확률 |
| `STRUCT_PAYLOAD_MUT_PROB` | `0.10` | DSM/Copy structured payload mutation 확률 |
| `SEQ_PROB` | `0.05` | builtin sequence 시작 확률 |
| `SEQ_MAX_PER_100` | `10` | 100-exec window당 sequence 명령 최대 개수 |
| `MDTS_CACHE_TTL` | `5000` | MDTS 캐시 갱신 주기 |

### 주요 상수 (기존)

| 상수 | 기본값 | 설명 |
|------|--------|------|
| `PM_ROTATE_INTERVAL` | `100` | PM 전환 주기 |
| `SCHEMA_MUT_PROB` | `0.30` | Schema Mutation 적용 확률 |
| `IO_ADMIN_RATIO` | `3` | I/O 커맨드 선택 가중치 |
| `RANDOM_GEN_RATIO` | `0.2` | 랜덤 생성 비율 |
| `ADMIN_SWAP_PROB` | `0.05` | Admin↔IO 교차 전송 확률 |
| `MAX_SAMPLES_PER_RUN` | `500` | 명령 1회당 최대 샘플 수 |

---

## CLI 옵션

```
# 제품/연결
--product PRODUCT        제품 자동 설정 (PM9M1 | BM9H1)
--interface swd|jtag     디버그 transport (기본: swd)
--openocd-binary PATH    OpenOCD 바이너리 경로
--openocd-config PATH    OpenOCD 설정 파일
--openocd-host HOST      OpenOCD telnet 호스트 (기본: 127.0.0.1)
--openocd-port PORT      OpenOCD telnet 포트 (기본: 4444)
--openocd-timeout SEC    OpenOCD 시작 대기 타임아웃

# NVMe 대상
--nvme DEVICE            NVMe 장치 경로 (기본: /dev/nvme0)
--namespace N            네임스페이스 ID (기본: 1)
--lba-size N             LBA 크기(바이트). 0=자동 감지

# 펌웨어 주소 범위
--addr-start HEX         펌웨어 .text 시작 주소
--addr-end HEX           펌웨어 .text 끝 주소
--pcsr-addrs A,B[,C]     PCSR 주소 오버라이드 (hex)

# 실행 제어
--output DIR             출력 디렉터리
--runtime SEC            총 실행 시간 (기본: 604800 = 1주)
--pm                     Power Combo 활성화
--no-por                 시작 시 POR 건너뜀
--no-state               State-Aware Fuzzer 비활성화
--allow-no-openocd       PM preflight 독립 검증용

# 명령어 제어
--commands CMD ...       활성화할 명령어 목록
--all-commands           위험 명령어 포함 전체 활성화
--exclude-opcodes A,B    제외할 opcode (hex)

# 퍼징 파라미터
--random-gen-ratio F     랜덤 생성 비율 (기본: 0.2)
--admin-swap-prob F      admin↔IO 교체 확률 (기본: 0.05)
--timeout GROUP MS       명령 그룹별 타임아웃 설정
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
transport select jtag
adapter driver jlink
adapter speed 4000
reset_config none
jtag newtap r8 cpu -irlen 4 -expected-id 0x6BA00477
dap create r8.dap -chain-position r8.cpu
target create r8.abp mem_ap -dap r8.dap -ap-num 0
target create r8.axi mem_ap -dap r8.dap -ap-num 1
init
r8.dap dpreg 4 0x50000000
after 100
r8.dap dpreg 0 0x1e
```

---

## 출력 디렉터리 구조

```
output/pc_sampling_v7.5.0/
├── fuzzer_YYYYMMDD_HHMMSS.log
├── coverage.txt
├── corpus/
│   └── input_<cmd>_<opcode>_<md5>
├── seq_corpus/                          # v7.5 신규
│   ├── replay_seq_<found_at>.sh
│   └── replay_data_seq_<found_at>/
│       └── data_NNN.bin
├── state_corpus/
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
    ├── coverage_growth.png              (* Ghidra 연동 시)
    └── firmware_map.png                 (* Ghidra 연동 시)
```

---

## 버전 이력 요약

| 버전 | 주요 변경 |
|------|-----------|
| **v7.5** | SequenceSeed corpus 도입 (N개 명령어 단위 저장, energy=base/N, MAX_SEQUENCE_CORPUS=50). Write→Compare ctx를 fresh random에서 Write mutation 결과 파생으로 변경 (builtin+corpus 양쪽). seq_corpus/ replay .sh 자동 저장. DSM NR 불일치 수정, Copy NR 마스크 4비트 수정, data_len_override 잔존 리셋. Stats 한 줄에 seq 정보 추가. |
| v7.4 | Phase 1: NLB-relative/MDTS boundary data_len. Phase 2: 64-bit LBA pair + DSM/Copy structured payload. Phase 3: Write→Compare/FWDownload→FWCommit builtin sequence. PM 로테이션을 seed 선택 전으로 이동. |
| v7.3 | `_account_command()` 헬퍼 도입. State-Replay cmd 복원 정확도 개선. EMA score + C2 reward를 replay 후 state 재현 기반으로 갱신. m2 정규화. |
| v7.2 | DET_BUDGET(20%) 도입. MOpt operator reward 누적 버그 수정. |
| v7.1 | `--allow-no-openocd --pm` 조합 PM-only 독립 검증 경로 추가. |
| v7.0 | State-Aware Fuzzer 도입: `NVMeStateMonitor`, `StateCorpusEntry`, CSFuzz 적응형 p 갱신, dual interesting(PC + state). |
| v6.4 | PS3/PS4 강제 idle 슬롯 — NOPS 커버리지 확보. |
| v6.3 | JTAG 지원(BM9H1), `--product`/`--interface` 옵션, JLink 덤프/PC 모니터링. |
| v6.2 | Rule-Based Schema Mutation (42커맨드/~150필드/8타입). |
| v6.0 | OpenOCD PCSR 비침습 샘플링, 3코어, PMU POR, hang 보존 분석. |
| v5.x | J-Link halt-sample-resume, MOpt, Power Combo, Basic Block 커버리지, 시각화. |
