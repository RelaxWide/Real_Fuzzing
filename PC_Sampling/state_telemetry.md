# State (Telemetry)-Aware Fuzzing

> 최종 갱신: v7.6 (state_fields.py 정리 — 55 → 25 필드)
> 도입: v7.0

## 개요

PC Sampling(PCSR) 기반 edge coverage에 더해 **NVMe 장치 상태(telemetry)** 를 두 번째 coverage 신호로 사용한다.

- **Edge corpus** (C1): 새 PC/BB를 발견한 명령 시퀀스
- **State corpus** (C2): 드라이브 내부 상태 변화를 일으킨 최근 100개 명령 시퀀스

두 corpus를 CSFuzz §III-C 방식으로 확률적으로 선택하며, state 변화를 일으킨 시퀀스를 재현(replay)해 같은 상태에서 퍼징을 계속한다.

---

## 아키텍처

```
                  ┌─────────────────────────────┐
                  │         NVMeFuzzer           │
                  │                             │
  100회마다 ──→   │  NVMeStateMonitor.capture() │
                  │    ├─ smart-log 파싱         │
                  │    ├─ get-log (vendor LID)   │
                  │    └─ security-send → recv   │
                  │                             │
                  │  delta(before, after)        │
                  │    └─ adaptive bucket 판정   │
                  │                             │
                  │  새 bucket? → StateCorpus    │
                  │    └─ _cmd_history 스냅샷    │
                  └─────────────────────────────┘

  corpus selection (매 iteration):
    p확률  → C1 (edge corpus)  → 일반 seed 선택 + 뮤테이션
    1-p확률 → C2 (state corpus) → 시퀀스 replay → seed 선택 + 뮤테이션
```

---

## 주요 클래스

### `NVMeStateMonitor`

100회마다 세 가지 소스에서 state 값을 수집한다.

| source | 명령 | 설명 |
|--------|------|------|
| `smart` | `nvme smart-log` | SMART/Health 텍스트 출력 파싱 |
| `vendor` | `nvme get-log --log-id=<LID>` | 벤더 로그 페이지 binary offset |
| `security_recv` | `nvme security-send` → `nvme security-recv` | Security Protocol 응답 텍스트 파싱 |

**초기화 시 동작**

- `source='security_recv'` 필드를 `(secp, spsp, nsid)` 키로 그룹화 → 그룹별 1회 Send→Recv 실행
- `_init_values`: 최초 관측값 등록 (CSFuzz §III-B adaptive partitioning 기준점)
- `_change_counts`: 필드별 변화 횟수 누적 (동적 weight 보정용)

**capture() 흐름**

```
1. smart-log 텍스트 파싱 → {field_name: int}
2. get-log (LID별 1회) binary → offset/length로 필드 추출
3. security-send (4B dummy) → security-recv 텍스트 파싱 → offset/length로 필드 추출
4. 최초 관측 필드 → _init_values 등록
```

**security-recv 응답 검증**

- `raw[0] == SPSP` (magic byte 체크)
- 실패 시 `첫 32B hex dump` 로그 출력 후 skip

---

### `NVMeStateDelta`

100회 window 전후의 state 차분.

| 필드 | 설명 |
|------|------|
| `changes` | `{field_name: after - before}` |
| `weights` | 동적 보정된 effective weight |
| `buckets` | CSFuzz §III-B adaptive bucket 목록 |
| `init_deltas` | `{field_name: current - init_value}` |

**score 공식**

```
score = Σ log2(1 + |init_delta|) × effective_weight
```

- raw delta 대신 `log2` 적용 → I/O 볼륨처럼 절대값이 큰 필드가 score를 독식하는 현상 방지
- `effective_weight = static_weight / log2(2 + change_count)` → 자주 바뀌는 필드 weight 자동 감소

**CSFuzz §III-B Adaptive Bucket**

초기값 `init_value` 기준 power-of-2 거리로 버킷화:

```
d = current - init_value
d = 0        → "{field}:=init"   (변화 없음, cov_map 등록 제외)
d = 1        → "{field}:+2^0"
d = 2..3     → "{field}:+2^1"
d = 4..7     → "{field}:+2^2"
d = -1       → "{field}:-2^0"
...
```

새 bucket이 발견될 때만 state corpus에 등록된다.

---

### `StateCorpusEntry`

state 변화를 일으킨 명령 시퀀스.

| 필드 | 설명 |
|------|------|
| `sequence` | `_cmd_history` 스냅샷 (최대 100개 명령) |
| `delta` | 발견 시점의 `NVMeStateDelta` |
| `score` | 발견 시점의 delta.score |
| `causes` | 새로 등록된 bucket 목록 (`=init` 제외) |
| `found_at` | 발견 시 execution 번호 |
| `exec_count` | replay 횟수 |
| `energy` | AFLfast 초기 에너지 (16.0) |

---

## State Corpus 관리

### cull (`_cull_state_corpus`)

- **중복 제거**: 동일 `causes` bucket 조합 중 score 높은 것만 유지
- **크기 제한**: 최대 50개, 초과 시 score 낮은 것 제거

### 선택 (`_select_state_entry_csfuzz`, CSFuzz §III-D 수식 6)

```
weight(entry) = term1 + term2

term1 = (1-α) / (min_fuzz × Σ(1/n_i))   # 덜 탐색된 bucket 우선
        → min_fuzz=0이면 (1-α) (최우선)

term2 = α × found_at / Σfound_at         # 최근 발견된 entry 우선

α = 0.5 (고정)
```

### Replay (`_replay_state_sequence`)

선택된 entry의 `sequence`를 순서대로 `_send_nvme_command`로 재실행해 드라이브 내부 상태를 재현한 뒤, 이어서 정상 seed 선택 + 뮤테이션을 실행한다.

- `[State-Replay] found_at=... seq=... score=...` 로그 출력
- timeout 발생 시 `False` 반환 → 해당 iteration skip
- `_cmd_history` / `executions` 는 수정하지 않음

---

## CSFuzz corpus selection 확률 p (`_update_csfuzz_p`)

1000회마다 C1/C2 보상을 비교해 p를 동적 조정한다 (CSFuzz §III-C 수식 4/5).

```
Δp = (a × m1/NC1 - b × m2/NC2) × (NC1 + NC2)
p  = clip(p + Δp, 0.1, 0.9)

m1, m2  : C1/C2의 평균 보상 (새 coverage 발견 여부)
NC1, NC2: corpus 크기
```

C1이 더 많은 보상을 내면 p 증가 (C1 선호), C2가 더 효과적이면 p 감소 (C2 선호).

---

## 관측 필드 (`state_fields.py`)

총 **25개 필드**, weight 총합 **100.5**.
- smart (LID 02h): **5**
- vendor (LID 01h + DFh): **4**
- security_recv: **16**

### v7.6 정리 원칙

| 기준 | 처리 |
|------|------|
| 다른 source가 같은 지표 추적 | 한 쪽만 유지 (df_* ↔ sec_* 중 sec_ 선호 — 단일 read로 다수 필드 묶음) |
| 위치/식별자 (state 측정 아님) | 제외 (`err_param_location`) |
| fuzz 실행 결과 단조증가 (활동 카운터) | 제외 (`*_written`, `host_active_idle`, `user_erase`, `host_flush`, `set_feature_sv1`, `pel_save`) |
| fuzzer가 직접 트리거 가능 (POR/PERST/PS 전환 등) | 제외 (`ctrl_reset`, `ftl_spor`, `shn`, `perst`, `nssr`, `flr`, `ps3/4`, `d3hot`, `short_power_on`, `pci_hotreset`) |
| fuzz 명령으로 발화 가능한 에러 | 가중치 하향 (`media_errors`, `num_err_log_entries`, `err_status_field`, `sec_uncorr_read_errors`, `sec_e2e_corrections`) |
| **NAND 마모/수명 (가장 직접적 신호)** | **가중치 전체 상향** |

### 카테고리별 weight 비중

| 카테고리 | 필드 수 | weight 합 | 비중 |
|---------|:---:|:---:|:---:|
| **NAND 마모/수명** (Sec 4c) | 8 | **49.0** | **49%** — 최우선 |
| 메모리 무결성 / 에러 (Sec 4a) | 6 | 28.0 | 28% |
| SMART | 5 | 11.0 | 11% |
| 인터페이스/마모 (DFh) | 3 | 9.0 | 9% |
| I/O 볼륨 (Sec 4e) | 2 | 2.5 | 2.5% |
| 에러 정보 (LID 01h) | 1 | 1.0 | 1% |

### 전체 필드 표

#### SMART (LID 02h) — 5개

| 필드 | weight | 설명 |
|------|:---:|------|
| `critical_warning` | 2.0 | 헬스 비트마스크 (spare/temp/reliability/ro/volatile) |
| `media_errors` | 2.0 | NAND ECC 비복구 (WriteUncorrectable로도 ++) |
| `num_err_log_entries` | 2.0 | 에러 로그 엔트리 수 — fuzz 에러마다 단조증가 |
| `percent_used` | 3.0 | 수명 소모율 (%) — 100 초과 가능 |
| `avail_spare` | 2.0 | 여유 스페어 블록 (%) — 감소 방향 주목 |

#### LID 01h Error Information — 1개

| 필드 | weight | 설명 |
|------|:---:|------|
| `err_status_field` | 1.0 | `[01h 0Ch]` 최신 에러 SCT/SC — fuzz 에러마다 변화 (noisy) |

#### Vendor DFh (Lenovo Drive Identification, 512B) — 3개

| 필드 | weight | 설명 |
|------|:---:|------|
| `df_crc_errors` | 4.0 | `[0xF0]` LCRC/ECRC 에러 — 인터페이스 무결성 |
| `df_max_pe_cycles` | 3.0 | `[0x119]` Max P/E Cycles — 느린 마모 |
| `df_avg_pe_cycles` | 2.0 | `[0x117]` Average P/E Cycles |

#### Security Receive — 메모리 무결성 / 에러 (Sec 4a, 6개)

`SECP=0xFE, SPSP=0x3D, NSID=1, size=4096` 1회 read에서 다수 필드 추출.

| 필드 | weight | 설명 |
|------|:---:|------|
| `sec_dram_parity_errors` | **10.0** | `[416h]` DRAM Parity — 메모리 corruption |
| `sec_sram_parity_errors` | **10.0** | `[418h]` SRAM Parity — 캐시/버퍼 무결성 |
| `sec_uncorr_read_errors` | 2.0 | `[400h]` Uncorrectable read — WriteUncorrectable로도 ++ |
| `sec_e2e_corrections` | 2.0 | `[408h]` End-to-End Correction |
| `sec_pcie_corr_errors` | 2.0 | `[212h]` PCIe Correctable — PM 전환 시 정상 발생 |
| `sec_soft_ecc_errors` | 2.0 | `[420h]` Soft ECC — read 부하 시 흔함 |

#### Security Receive — NAND 마모/수명 (Sec 4c, 8개) **★ 핵심**

| 필드 | weight | 설명 |
|------|:---:|------|
| `sec_patrol_relocated` | **10.0** | `[332h]` Read Patrol relocated — NAND 열화 직접 지표 |
| `sec_sys_wear_level` | 7.0 | `[239h]` System Area Wear Level |
| `sec_system_max_ec` | 7.0 | `[671h]` System Max EC |
| `sec_endurance_estimate` | 6.0 | `[252h]` Endurance Estimate (하위 64-bit) |
| `sec_read_reclaim` | 6.0 | `[324h]` Lifetime Read Reclaim — read 부하 자동 |
| `sec_free_blocks_pct` | 5.0 | `[242h]` % Free Blocks |
| `sec_wear_level_count` | 4.0 | `[234h]` Wear Level Count — write 부하 자동 |
| `sec_refresh_counts` | 4.0 | `[340h]` Refresh Counts — 백그라운드 자동 |

#### Security Receive — I/O 볼륨 / 활동 (Sec 4e, 2개)

| 필드 | weight | 설명 |
|------|:---:|------|
| `sec_slc_pct_used` | 1.0 | `[241h]` Static SLC Percentage Used |
| `sec_sys_data_pct_used` | 1.5 | `[240h]` System data % used |

### 제외된 30개 (참고)

| 그룹 | 사유 | 필드 |
|------|------|------|
| df_*↔sec_* 중복 | sec_ 통합 read 선호 | `df_dram_parity_errors`, `df_sram_parity_errors`, `df_grown_bad_blocks`, `df_patrol_relocated`, `df_slc_percent_used`, `df_nand_written`, `df_slc_written` |
| SMART↔sec_ 중복 | SMART 유지 | `sec_percent_used` |
| 위치/식별자 | state 측정 아님 | `err_param_location` |
| 활동 카운터 | fuzz 실행으로 단조증가 | `sec_nand_written`, `sec_slc_written`, `sec_host_active_idle`, `sec_user_erase_counts`, `sec_host_flush_cmds`, `sec_set_feature_sv1`, `sec_pel_save_count` |
| 리셋/이벤트 (4b 전체) | fuzzer POR/PERST 트리거 | `sec_ctrl_reset_count`, `sec_ftl_spor_count`, `sec_shn_count`, `sec_perst_count`, `sec_nssr_count`, `sec_flr_count` |
| PS/Power (4d 전체) | --pm fuzzer 트리거 | `sec_ps3_count`, `sec_ps4_count`, `sec_d3hot_count`, `sec_short_power_on`, `sec_pci_hotreset_count` |
| 신호 약함 | 의미 제한적 | `sec_bad_nand_blocks`, `sec_incomplete_shutdowns`, `sec_thermal_throttle` |

> 정적 weight는 초기 힌트값이며, 실제 effective weight는 관찰된 변화 빈도로 자동 보정된다 (아래 [동적 Weight 보정](#동적-weight-보정) 참조).

---

## 동적 Weight 보정

```
effective_weight(field) = static_weight / log2(2 + change_count)

change_count=0   → ÷ 1.00  (초기값 그대로)
change_count=10  → ÷ 3.58
change_count=100 → ÷ 6.67
change_count=1000→ ÷ 9.97
```

자주 변화하는 I/O 볼륨 필드는 시간이 지날수록 weight가 낮아지고,
거의 변화하지 않는 에러/리셋 필드는 높은 weight를 유지한다.

---

## 관련 로그

| 태그 | 의미 |
|------|------|
| `[State] capture 완료: 총 N개 필드 수집` | 100회마다 state 수집 완료 |
| `[State] init_value 등록: field=value` | 최초 관측값 등록 |
| `[State] sec-recv magic 불일치` | security-recv 응답 검증 실패 (첫 32B hex dump 포함) |
| `[+][State-Cov] [bucket, ...] score=X.X` | 새 state bucket 발견 → state corpus 등록 |
| `[+][State-Cov]   field: before → after (Δ±N)` | 변화된 필드 상세 |
| `[State-Replay] found_at=N seq=M score=X.X` | state 시퀀스 replay 실행 |
| `[State-Snap] ══ State Fields Snapshot ══` | 10000회마다 전체 필드 스냅샷 출력 |

---

## CLI 옵션

```
--no-state    State monitoring 비활성화 (기본: 활성화)
```

비활성화 시 v6.4와 동일하게 edge coverage(PC/BB)만 사용한다.

---

## 필드 추가 방법

`state_fields.py`만 수정하면 된다. 퍼저 본체는 수정 불필요.

```python
# SMART 필드 추가
{
    'name':   'my_field',
    'source': 'smart',
    'key':    'nvme_cli_key_name',   # nvme smart-log 텍스트 출력의 키
    'weight': 5.0,
    'desc':   '설명',
},

# Vendor log 필드 추가
{
    'name':    'my_vendor_field',
    'source':  'vendor',
    'lid':     0xCA,
    'log_len': 512,
    'offset':  0x10,
    'length':  4,
    'endian':  'little',
    'weight':  3.0,
    'desc':    '설명',
},

# Security Receive 필드 추가
{
    'name':   'my_sec_field',
    'source': 'security_recv',
    'secp':   0xFE,
    'spsp':   0x3D,
    'nsid':   1,
    'size':   4096,
    'offset': 128,
    'length': 8,
    'endian': 'little',
    'weight': 5.0,
    'desc':   '설명',
},
```
