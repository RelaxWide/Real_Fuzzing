# v10 — BM9K1 (RISC-V) 커버리지 + 디렉토리 정리

## Context

v9.8은 ARM 제품(PM9M1/BM9H1/P9)에서 **stripped 펌웨어를 Ghidra로 분석**한 BB/함수 목록에
**DBGPCSR 폴링 샘플**을 매핑해 커버리지를 만든다.

신규 제품 **BM9K1**(SiFive E76, RISC-V 4코어)은 세 가지가 다르다:

1. **심볼 있는 ELF 4개**(HCORE/CMCore/Fcore/QCore) → 주소가 아니라 **함수 이름 단위**
   커버리지가 가능하고 정합성을 기계 검증할 수 있다. (실측: offset=0, addr2line 100% 매칭)
2. **코어 4개 × 독립 주소공간** → flat `Set[int]` 커버리지는 주소가 겹치면 오염된다.
3. **전송로**: pylink + Secure JTAG 인증 + SBA. 인증은 **전원 사이클마다** 재수행.
   비침습 PC 소스는 실측으로 찾은 per-core 레지스터(`TE + 0x1000×core + 0x17C`, bit0=valid).

동시에 **디렉토리가 정리되지 않았다**: 퍼저 6버전 4.7MB가 평면 배치, 문서 11개·보조도구 7개가
코드와 섞여 있고, 제품별 자산(`.cfg`/`.ini`/`basic_blocks_*.txt`)은 배치 규약이 없다.
BM9K1은 4코어 × 3종 = **12개 파일**이 추가되므로 지금 구조로는 더 나빠진다.

**목표**: v9.8의 검증된 퍼징 루프(변이/POR 복구/안전가드/replay)는 재사용하고
**커버리지 서브시스템 교체 + 디렉토리 전면 정리**.

**제약**: 소스 없음 → 함수/모듈 단위까지. 기밀 SoC 주소는 `risc-v/sjtag_addrs.json`에만
(콘솔 출력 금지). **코드 오버레이 추후 도입 예정.**

---

## 1. 디렉토리 정리 (전면) — 파일별 감사 결과

**이동 안전성의 유일한 기준: 퍼저가 import 하는가.** 실측 확인:
- **진짜 import는 `nvme_seeds.py` 하나뿐** (`from nvme_seeds import SEED_TEMPLATES`, line 83)
- `coverage_growth_plot.py` / `ghidra_export.py` / `jlink_reg_diag.py` 는 **주석·도움말 문자열에서
  이름만 언급** → 이동해도 안 깨짐
- `rag/`, `risc-v/` 는 import 경로 → 유지

### 파일별 판정

| 파일 | 크기 | 판정 | 근거 |
|---|---|---|---|
| `pc_sampling_fuzzer_v9.8.py` | 864K | **유지** (→v10) | 현행 |
| `pc_sampling_fuzzer_v9.3~9.7.py` | **4.0M** | → `archive/` | 구버전 5개 |
| `pc_sampling_fuzzer_v9.4~9.7.md` | 45K | → `archive/` | 구버전 릴리스노트 |
| `pc_sampling_fuzzer_v9.8.md` | 3K | → `docs/` | 현행 노트 |
| `fuzzer_config.json` | 40K | **유지** | 기본 탐색 위치 |
| `nvme_seeds.py` | 25K | **유지** | ★유일한 실제 import |
| `riscv_cov.py` | — | **신규·최상위** | 퍼저가 import |
| `coverage_growth_plot.py` | 9K | → `tools/` | 언급만 |
| `ghidra_export.py` | 4K | → `tools/` | 언급만. §2에서 확장 |
| `jlink_reg_diag.py` | 7K | → `tools/` | 언급만 |
| `halt_loop_stress.py` | 13K | → `tools/` | 독립 실행 |
| `kernel_sweep.py` | 17K | → `tools/` | 독립 실행 |
| `pcie_link_probe.py` | 9K | → `tools/` | `halt_loop_stress` 가 참조 → **같이** 이동하면 상대참조 유지 |
| `install_fuzzer_deps.sh` | 10K | → `tools/` | 설치 스크립트 |
| `r8_pcsr_jtag.cfg` | 645B | → `products/BM9H1/` | 제품 자산 |
| 문서 6종(HANDOFF/ROADMAP/RUNBOOK/PPT/paper/LLM_strategies) | 90K | → `docs/` | |
| `DebugPackage/` | 12K | → **`dump/`** | RDDump 파서 |
| `backup/` | **18M** (97개) | → `archive/backup/` | 과거 핸드오프·스크립트 |
| `__pycache__/` | **2.4M** | **삭제** + `.gitignore` | 재생성됨 |

정리 대상 합계 **약 24MB**가 최상위에서 빠진다.

### 목표 구조

```
PC_Sampling/
  pc_sampling_fuzzer_v10.py     fuzzer_config.json
  nvme_seeds.py                 riscv_cov.py        # ★ import 되는 것만 최상위
  rag/   risc-v/                                    # import 경로 → 유지
  products/                                         # 제품별 자산
    PM9M1/  PM9M1_LNB/  PM9M1_HP/  BM9H1/  P7/  P9/
        basic_blocks.txt  functions.txt  <openocd>.cfg  <ufas>.ini
    BM9K1/  basic_blocks_core0..3.txt  functions_core0..3.txt
            callgraph_core0..3.txt     symbols.json
  dump/                                             # ★ 덤프 도구 + 산출물
    ufas                        SnapShot/PM9M1_A815.ini
    Debug_Tool_v1.0.0.2         run_smi_mem_dump_JLINK_USB.sh
    DebugPackage/smi_mem_parsing/{customer_parsing_dump.sh,.py}
  tools/   docs/   archive/   output/
```

### `dump/` — 코드 변경 0

config `paths` 의 값들은 **script_dir 기준으로 해석**된다
(`ufas_path = os.path.join(script_dir, UFAS_BINARY)`, line 11475). 따라서 **값 앞에 `dump/` 만
붙이면 끝**이다:
```json
"ufas_binary":      "dump/ufas",
"debug_tool_binary":"dump/Debug_Tool_v1.0.0.2",
"jlink_dump_script":"dump/run_smi_mem_dump_JLINK_USB.sh",
"debug_package_dir":"dump/DebugPackage/smi_mem_parsing",
"pmu_script":       "dump/pmu_4_1.py"          # PMU 도 외부 실행 파일이라 같이
```
> 이 5개 파일은 현재 리포에 없다(퍼즈 호스트에만 존재). 실기에서 `dump/` 로 옮기고 config만 갱신.

**단, 덤프 *산출물* 은 코드 변경이 필요하다.** 지금 JLink 덤프 결과를
`_find_latest_jlink_dump(script_dir, …)`(정의 11165 / 호출 11218)로 **script_dir에서 찾는다**
= `.bin` 이 최상위에 쌓인다. UFAS 산출물(`<date>_UFAS_Dump.bin`)도 마찬가지.
→ 탐색·출력 기준 디렉토리를 `dump/` 로 바꾼다(2곳). 이러면 `dump/` 가 **도구 홈이자 착지점**이 된다.

### `products/` — 경로 해석 헬퍼 하나

```python
def product_asset(product, name):     # products/<P>/<name>, 없으면 구경로 폴백
```
적용(패턴 동일): `_load_static_analysis`(**8175-8176**, bb/func), `openocd_config`(**~15950**),
`ufas_ini`(**~16038**). 구경로 폴백을 남겨 **이관 중에도 기존 제품이 동작**한다.
config의 `bb_file`/`func_file` 은 legacy 키로 강등(있으면 존중).

**이득**: 제품 폴더 안 파일명이 **고정**(`basic_blocks.txt`)되어 `_PM9M1` 접미사 관리와
`ghidra_export.py` 후 **수동 rename 이 사라진다**.

---

## 2. BB / 함수 / 콜그래프 추출 — Ghidra 확정

실측 결과 **`objdump: can't disassemble for architecture UNKNOWN`** — BFD가 파일은 열지만
(`elf32-little`) RISC-V 디스어셈블러가 없다. (addr2line이 동작한 건 DWARF/symtab만 읽기 때문.)
→ **BB 추출은 Ghidra**. 자체 디코더는 인코딩 버그 위험 대비 이득이 없어 채택하지 않는다.

**기존 `tools/ghidra_export.py`를 확장**한다 (신규 파일 없음):
1. **제품/코어 인자**를 받아 `products/<P>/basic_blocks_core<N>.txt` 등으로 직접 출력
   (하드코딩 `OUTPUT_DIR`과 수동 rename 제거)
2. **`callgraph_core<N>.txt` 추가** — `fn.getCalledFunctions(monitor)`로 `caller_entry callee_entry`.
   §6의 frontier 함수(가장 값진 신규 LLM 신호)가 여기서 나온다. Ghidra API 5줄 수준이나
   **첫 실행 시 실제 산출 여부를 확인할 것**.
3. `symbols.json`(코어→ELF→exec범위, 빌드ID, 추출 시각) 출력 → 퍼징 시작 시
   **stale 심볼 불일치 감지**.
4. ELF 입력이므로 기존의 phantom-BB 필터는 사실상 무해(섹션·심볼이 있어 오탐이 거의 없음).

출력 형식은 기존과 **바이트 동일**(`0xSTART 0xEND`, `0xENTRY <십진 size> <name>`)하게 유지해
파서를 건드리지 않는다. 함수 크기는 Ghidra 값을 그대로 쓴다(런타임 정합성은 §4 게이트가 담당).

---

## 3. Per-core 커버리지 (+ 오버레이 확장 대비)

**키**: `pack(core, bank, addr)` — 패킹 int.
```
key = (core << 44) | (bank << 32) | addr        # bank=0 이 현재 기본값
```
- **오버레이 대비**: 오버레이가 들어오면 같은 주소에 다른 코드가 올라간다. 지금 `bank`를
  **예약만** 해두면 나중에 뱅크 레지스터를 샘플과 함께 읽는 훅만 추가하면 된다.
  키 구조를 나중에 바꾸면 저장된 커버리지·코퍼스가 **전부 무효화**되므로 지금 잡는다.
- core=0,bank=0이면 기존 BB 주소와 값이 동일 → 기존 데이터와 비교 가능.
- int인 이유: 이 키가 `Seed.covered_pcs`(1169) → `_cull_corpus`의 `pc_best: dict`(7127-7141)
  → `set.update()`로 흐르는데 전부 int 가정과 호환.

**변경 지점** — 핫루프는 건드리지 않는다:
| 위치 | 변경 |
|---|---|
| `_sampling_worker` **2792** | `self._reset_window_extra()` 훅 추가(기본 no-op) |
| `_sampling_worker` **2886** | **그대로.** `SJTAGPCSampler._read_all_pcs`가 `_win_by_core`를 자체 적재하고 튜플도 반환 → 상속된 saturation/idle/raw 로직 무수정 동작 |
| `_account_command` **6644-6667** | 인라인 bisect를 `self.cov.account(sampler.window_by_core())`로 교체. `_update_static_coverage`(8243)의 중복 bisect도 흡수(현재 트레이스를 2번 훑음) |
| `_snapshot_chart_data` **12865** | `'cov': self.cov.snapshot()` 추가. `_CHART_SNAPSHOT_ATTRS`에 **객체를 넣지 않는다** — `_snap_copy`는 dict/set/list만 이해 |
| `_render_charts_from_snapshot` **15733** | `inst.cov = CoverageModel.from_snapshot(snap['cov'])` |
| `_sa_*` 뷰 | `CoverageModel`이 union 뷰를 노출 → **기존 차트 6종 무수정 동작** |
| `_update_static_coverage` **8253-8281** | Thumb 자동감지를 `arch != 'riscv'`로 게이트(RISC-V는 bit0=0이라 로그 노이즈만 생김) |

**"interesting" 정책**: `(core,bank,bb)` 키라 union-new가 곧 코어별 신규성이다. 기본 **union**
(§4의 셔플 버스트로 모든 코어가 매 윈도우 샘플되므로 비교 가능). `new_by_core`를 별도 집계해
저duty 코어의 노이즈를 관측하고, `interesting_policy: "union"|"primary"` 로 전환 가능.

**형식 호환**: `coverage.txt`(union raw PC) 유지 → `--resume-coverage` 그대로.
`coverage_by_core.txt` 신규. `_sa_cov_history`에 5번째 원소 `{core:(bb%,func%)}` **추가**
(차트는 `h[0]`~`h[3]`만 인덱싱 → 양방향 호환). `coverage_growth.jsonl`에 `bb_pct_by_core` 추가.

---

## 4. 샘플러 `SJTAGPCSampler` (`riscv_cov.py`)

`class SJTAGPCSampler(OpenOCDPCSampler)` — `JLinkHaltSampler`(3115)와 같은 전략: worker /
`diagnose` / `stop_sampling` / `evaluate_coverage`를 상속, 링크 계층과 `_read_all_pcs`만 교체,
telnet 계열 no-op. **모듈 레벨에서 pylink를 import하지 않는다**(`connect()` 안에서 지연 import)
→ 커버리지 모델을 하드웨어 없이 테스트 가능.

### 4코어 읽기 — 비용
"동시"는 어느 쪽도 아니다. v9.8의 OpenOCD 3코어 읽기도 **telnet 왕복 1회**였을 뿐 내부는
3번의 개별 DAP 트랜잭션이었다. USB 왕복 기준:

| 경로 | 왕복 |
|---|---|
| 순진한 `_sba_read` | ~20 (4×`mem_read32`, 각 5 AP op) |
| **핀 고정 동일코어 읽기** | **1** (SBCS/SBADDR0 1회 세팅 + TAR을 SBDATA0 고정 → DRW 반복) |
| 코어 전환 | ~5-8 |

→ 샘플당 라운드로빈은 최악. **버스트**가 정답(셋업을 버스트 길이에 분할상환).

### 버스트 스케줄 — 순서를 고정하지 않는다 ★
고정 순서(항상 core0이 윈도우 앞, core3이 뒤)는 **계통 편향**을 만든다. 명령 처리에는
단계(파싱→DMA→완료)가 있어 코어마다 특정 단계만 관측하게 된다. 매 윈도우:
1. 가중치를 **버스트 개수**로 환산 (예 HCORE 3 : 나머지 1 → `[0,0,0,1,2,3]`)
2. **셔플** (예 `[2,0,1,0,3,0]`)
3. 버스트 경계에 **지터**(±20%) — 주기적 펌웨어 루프와의 aliasing 방지

가중치(=관측량)와 순서(=편향)를 분리한다. `primary_core`(NVMe 핸들러)는 **실측으로 확정**한다 —
이름만으로는 알 수 없다.

### 필터
1. **`bit0 == 1`** (하드웨어 valid 플래그) 2. `pc = value & ~1`
3. **`elf_map.Ranges` 코어별 exec 범위 화이트리스트**(bisect, 테스트 완료)
4. `>= 0xF0000000` 가드(halt 상태 쓰레기값)

프로파일 `fw_addr_start/end`는 4개 ELF exec 범위의 **합집합**으로 두어 상속된 worker 필터를
관대한 상위집합으로 만들고, 정밀 필터는 `_read_all_pcs`에 둔다.
`_read_fail_needs_recovery()`는 **transport 실패일 때만 True** — valid=0은 코어가 잠깐 무효
상태인 것이지 링크 장애가 아니다(잘못하면 재연결 루프).

### 인증 — 켜질 때 자동
- `_power_cycle_ssd()`(4698) 성공 시 `power_epoch += 1`.
- `connect()`/`_reconnect()`는 항상 `ensure_auth(epoch)`:
  1. **probe-first** — SJTAG state를 read-only로 읽어 `AUTH_PASS`가 살아있고 epoch이 같으면
     **skip**(인증 카운터 소모 회피)
  2. 아니면 **고정 sudoers 래퍼**(`risc-v/run_sjtag_auth.sh`)를 subprocess 호출 —
     기존 `run_sjtag_trace{arm,delta}.sh` 선례. wine·root·기밀 JSON을 프로세스 밖에 두고,
     서명도구가 죽어도 퍼저가 안 죽는다. rc ∈ {0,10,11} 성공(`run_debug.sh:41-46`)
  3. `Link.open()`은 **2회 시도**(README: 첫 connect는 실패, 2회차에 붙음)
- POR이든 repro든 켜질 때 자동 인증되므로 별도 처리 불필요.
- connect 말미에 코어별 ~200 free-run 샘플 → `elf_map.check_gate(threshold=95%)`.
  **실패 시 해당 코어 심볼화를 끄고 제안 offset을 로그**(조용히 틀린 커버리지 금지).

### capability 플래그 — `isinstance` 제거
v9.8엔 `isinstance(self.sampler, JLinkHaltSampler)` 9곳 + `sampler_type` 문자열 비교에
**halt 전용 동작**이 묶여 있고, 이런 플래그는 **전혀 없다**. `NullSampler`(사실상의 계약 베이스)에
클래스 상수로 기본값 선언 후 override:

| 플래그 | 기본 | JLinkHalt | SJTAG | 걸린 동작 |
|---|---|---|---|---|
| `INVASIVE` | False | True | **False** | 펌웨어시간 워치독(`halt_freeze_accum`) — 10797, 14576. **비침습인데 적용하면 실제 hang을 가린다** |
| `REPORTS_HALT_STATS` | False | True | False | halt 실패율·health check — 6983, 7000 |
| `USES_JLINK_USB` | False | True | **True** | 덤프 전 USB 해제·복구 안내 — 12443, 12670, 12717, 15613 |
| `RECONNECT_ON_FW_COMMIT` | False | True | **True** | FWCommit 후 재연결 — 10853 |
| `SUPPORTS_CONCURRENT_SAMPLING` | True | False | **True** | prefill 동시 샘플링 — 4584 |
| `LINK_LABEL` | `[OpenOCD]` | `[J-Link]` | `[SJTAG]` | 로그 — 15255 |

플래그 값이 **현재 동작을 그대로 재현**하므로 이 리팩터는 RISC-V 코드 없이 먼저 랜딩·회귀검증할 수 있다.

### 제품 프로파일 (`products.BM9K1`)
`interface`/`enable_ufas`/`enable_jlink_dump`는 bare-index라 필수.
`sampler_type:"sjtag"`, `arch:"riscv"`, `riscv:{cores:[{id,name,elf,offset}],
sample_plan:{weights,burst_len,jitter_pct,shuffle:true}, interesting_policy, gate_threshold,
auth_wrapper, addr2line}`. `openocd_config`/`tcl_prefix`/`pcsr_addrs`/`power_*` 생략(`.get` 가드).
**PCSR 주소는 config에 쓰지 않는다** — `sjtag_addrs.json`의 `trace.te_base` + `pc_sample_off`.
→ BM9K1에서 **v10은 root로 실행**된다(기밀 JSON이 root-lock).

---

## 5. 산출물 (소스 없음 → 함수/모듈 단위)

유지: `coverage.txt`, `ledger/`, `corpus/`, `crashes/`+`replay_*.sh`, 기존 PNG 6종.

신규: `report.html`(자체완결 — 코어별 요약, **함수 커버리지 표**, 모듈 롤업, 미도달 Top-N,
frontier, 명령→함수 귀속), `function_coverage.csv`, `module_coverage.csv`(`STT_FILE` 심볼로
오브젝트 단위 롤업 — 소스·DWARF 없이도 "모듈 커버리지"), `coverage_by_core.txt`,
`firmware_map.png` 코어별 4패널.

**렌더 격리 준수**: `os.fork()`가 호스트를 재부팅시킨 이력이 있어 차트는 별도 인터프리터에서
그린다. HTML/CSV 생성기는 **matplotlib을 import하지 않고** `_render_charts_from_snapshot`(15713)
에서 **차트보다 먼저** 호출 → matplotlib SIGSEGV(12826-12831)에도 가장 값진 산출물은 살아남는다.

---

## 6. LLM 프롬프트

주입 지점은 `_llm_coverage_context()`(5181) 하나. 파싱/브리지는 **무수정**(순수 추가 텍스트).

1. **`_AUTONAME_KW` 비활성화**(제품별 플래그). `(default|thunk|switch)`가 **진짜 심볼도 먹는다**
   (주석 232가 이미 경고: `set_default_mode`). `_AUTONAME_RE`(FUN_/sub_)는 유지.
2. **코어 라벨**: `- nvme_admin_get_log (core=HCORE, size=812, NEVER entered)`
3. **frontier 함수(최대 신규 신호)**: 콜그래프로 *커버된 함수가 직접 호출하는 미도달 함수*를
   호출자 수 순으로. "가장 큰 미도달"보다 **실행 가능**하다 — 이미 도달한 지점에서 한 걸음이므로.
4. **명령→함수 귀속**: `cmd_pcs[cmd]`(6697)는 이미 명령별 PC를 모으나 함수 환산이 없다.
   `_llm_grounding_block()`(5294)에 추가. **배경 차감 필수** — idle/dispatch 함수는 모든 명령에
   나타나 신호를 덮으므로 80% 이상 명령에 등장하는 함수와 `idle_pcs` 유래 함수를 뺀다.
5. 예산: `RAG_BRIDGE_TIMEOUT`(180s)/`RAG_CALL_TIMEOUT`(150s) → 기존 상한 유지 + frontier 별도 상한.

---

## 7. 구현 순서

**Phase 0 — 실측(하드웨어 불필요)**: `readelf -lW` 4개 → **exec 범위 겹침 여부**,
`readelf -sW` → STT_FUNC 수·**STT_FILE 유무**(모듈 롤업 가능성). Ghidra에 ELF 1개 시범 import.

**Phase 1 — 디렉토리 정리**: `products/`·`dump/`·`tools/`·`docs/`·`archive/` 생성 + 이관
(§1 감사표대로), `__pycache__` 삭제 + `.gitignore`.
코드 작업은 둘뿐 — ① `product_asset()` 헬퍼(구경로 폴백) ② 덤프 **산출물** 탐색/출력 기준을
`dump/` 로(11165/11218). 덤프 **도구** 경로는 config 값에 `dump/` 접두어만 붙이면 되고 코드 무변경.
**검증: 기존 제품이 v9.8에서 그대로 뜨는지 + 크래시 1건 강제해 UFAS/JLink 덤프 경로 확인.**

**Phase 2 — `tools/ghidra_export.py` 확장**: 제품/코어 인자, `products/` 직접 출력,
`callgraph_core<N>.txt`, `symbols.json`. 4개 ELF로 실행해 BB/함수 수·주소범위 sanity.

**Phase 3 — `riscv_cov.py` 커버리지 모델(오프라인 단위테스트)**: per-core bisect, 키 팩/언팩
(bank 예약), 두 정책, `snapshot()/from_snapshot()` 왕복, **기존 PM9M1 `coverage.txt` 재생 시
v9.8과 동일한 BB/func 수**(회귀 오라클).

**Phase 4 — v10 포크 + capability 리팩터(오프라인)**: 플래그 9곳 치환, `'sjtag'` 분기,
BM9K1 프로파일, `_account_command` 교체. **회귀: PM9M1/P9를 `--no-jlink`로 수백 execs 돌려
v9.8과 로그·산출물 diff.**

**Phase 5 — 리포트(오프라인)**: 합성 스냅샷으로 `--render-charts` 직접 실행,
matplotlib 강제 실패시켜도 HTML/CSV가 나오는지.

**Phase 6 — 하드웨어 벤치(퍼징 없음)**: 인증→링크→4코어 probe→free-run. 측정: 핀 고정
샘플레이트, 버스트 스케줄별 레이트, invalid/SBA 에러율, `check_gate` 코어별 %, 인증 지연,
**명령당 코어별 unique-PC 수확 → primary 코어 확정**, 30분 소크.

**Phase 7 — 루프 투입(POR off)** → **Phase 8 — POR on(20회 재인증)** → **Phase 9 — LLM/리포트 마감**

---

## 8. 리스크 / 먼저 확인할 것

| 리스크 | 대응 |
|---|---|
| **인증 카운터/락아웃** — 캠페인당 POR 수십 회 × 인증. 하드웨어가 시도를 세면 **자기 디버그 접근을 스스로 막을 수 있다** | Phase 8 전 SoC 담당 확인. 설계상 probe-first로 불필요한 인증 회피 |
| **호스트 안정성** — `os.fork()` 재부팅, always-on 샘플링 freeze 이력. kHz 폴링은 그 부류 부하 | Phase 6 30분 소크 필수. `sample_interval_us`를 0이 아니라 200-500µs로 시작 |
| **`+0x17C`의 정체** — last-branch-target 래치일 가능성 | 코어 핀 고정 → `halt_checked` → `read_pc`와 대조. 래치여도 BB 귀속은 유효하나 분포가 edge 편향 |
| **Ghidra RISC-V BB 품질 / 콜그래프 API** | Phase 2에서 BB 수·범위를 `.text`와 대조, `getCalledFunctions` 산출 확인 |
| **코어 간 주소 겹침** | Phase 0에서 확인(이미 per-core 설계라 안전, 리포트 단순화 여지만 결정) |
| **primary 코어 미상** | Phase 6에서 명령당 수확량으로 실측 |
| **디렉토리 이관이 기존 제품 회귀** | 구경로 폴백 유지 + Phase 1 검증 |
| **capability 리팩터가 ARM 제품 회귀** | 플래그 기본값이 현 동작 재현. Phase 4에서 v9.8과 diff |
| **`read_stuck_pcs` 튜플 길이 가변** | 진단 경로는 레이트 무관 → **전 코어 라운드로빈 강제**해 항상 4-튜플 |
| **오버레이 도입 시 키 무효화** | `bank` 필드 지금 예약(§3) |

---

## 9. 검증

- **오프라인**: `python3 -m unittest` — 기존 `test_elf_map`(18개) + 신규 `test_riscv_cov`.
- **정합성 게이트**: `elf_map.check_gate(관측 PC, 코어 ELF) ≥ 95%` 통과해야 심볼화 허용.
- **회귀(최대 위험)**: PM9M1/P9가 v10 + 새 디렉토리에서 v9.8과 동일 동작.
- **하드웨어**: Phase 6 벤치 수치 → Phase 7 짧은 세션에서 코어별 커버리지 단조 증가 확인.
