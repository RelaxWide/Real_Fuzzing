# risc-v/ — BM9K1(SiFive SF-E76) 디버그 연결 · SJTAG 인증 · PCSR 도구

BM9K1 컨트롤러(SiFive E76, 4코어: HCORE / CMCore / Fcore / QCore)에 **cJTAG + Secure
JTAG 인증**으로 들어가 **코어를 멈추지 않고 PC 를 샘플링**하기 위한 저수준 모듈과 도구다.
퍼저(`../pc_sampling_fuzzer_v10.3.py` 의 `RiscvPcsrSampler`)가 이 폴더를 import 해서 쓴다.

작성 기준 2026-09-28. 전체 설계는 [`../docs/V10_BM9K1_PLAN.md`](../docs/V10_BM9K1_PLAN.md),
실행 준비 자산 규격은 [`../docs/BM9K1_ASSETS.md`](../docs/BM9K1_ASSETS.md).

---

## 1. 한눈에

```
J-Link ──cJTAG──► ARM DP ──► APB-AP ──► SJTAG 블록 (PKC 인증 → AUTH_PASS)
                               └──► RISC-V DM(DMI) ──► SBA(System Bus Access)
                                                         └──► 코어별 PC 샘플 레지스터(PCSR 등가) 폴링
```

| 단계 | 담당 파일 | 비고 |
|---|---|---|
| J-Link 연결·cJTAG 초기화·DAP 전원 | `sfe76_link.py`, `dap_access.py` | checked API 만 노출 |
| SJTAG 인증(challenge-response) | `sjtag_unlock.py` | **전원 사이클마다 다시** 해야 한다 |
| SBA 로 PCSR 폴링 | `sjtag_unlock.py` (`sba_pin` / `sba_read_pinned` / `sba_unpin`) | 퍼저 경로 |
| 세션 붕괴 복구 | `sjtag_unlock.py` (`reopen_session`) | close+open+prepare 전체 재생성만 회복 |
| 관측 PC ↔ ELF 정합성 게이트 | `elf_map.py` | 임계(기본 95%) 미만이면 심볼화 거부 |
| 코어별 커버리지 모델 | `../riscv_cov.py` (폴더 밖) | `PcsrSession` 이 이 폴더 모듈을 감싼다 |

**방향 전환 기록:** 2026-08 에는 N-Trace(온칩 트레이스 버퍼 덤프 → Nexus 디코드)가 유일한
비침습 경로라고 결론냈으나, 이후 **코어별 PC 샘플 레지스터가 실측으로 발견**되어 PCSR
폴링으로 바뀌었다. 4코어 모두 ELF 와 offset=0 으로 100% 매칭된다. N-Trace 관련 기능
(`--trace-*`)과 `TRACE_COVERAGE_PLAN.md` 는 기술 자료로만 남아 있다.

---

## 2. 주소 단일 출처 원칙

**SoC 실주소·오프셋·상태 비트는 `sjtag_addrs.json` 한 파일에만 있다.** `.py` / `.sh` /
`.template` / 이 README 는 JSON 필드명만 가리킨다.

- 목적: 사내 LLM 컨텍스트에서 `sjtag_addrs.json` **한 파일만 빼면** 주소가 노출되지 않는다.
  git 에는 올라가 있다(리포 접근권자에게는 공개 허용).
- `sjtag_addrs.example.json` 은 같은 구조의 placeholder 판이다. 새 환경은 이걸 복사해 채운다.
- 생성물 `sf_e76.JLinkScript`(실주소가 채워진 것)는 `.gitignore` 대상이다.
- `check_bm9k1_setup.py` 는 값을 찍지 않고 '채워짐/비어있음'과 개수만 보고한다 —
  결과를 그대로 공유해도 안전하다.

### `sjtag_addrs.json` 구조

| 키 | 내용 | 누가 읽나 |
|---|---|---|
| `ap_map`, `core_base_main`, `core_base_ncore`, `chain_tap_id`, `apbap3_idr_expect`, `dead_fingerprints` | DAP/AP 토폴로지와 식별값 | `sfe76_link`, `sjtag_unlock` |
| `sjtag_offsets.*` | SJTAG 레지스터 블록 오프셋(HW 버전·상태·chip ID·request/challenge/response·dbg_control) | `sjtag_unlock` |
| `sjtag_state_bits.*` | `auth_pass`·`soft_lock`·`request_ready`·`response_ready` 등 상태 비트 | `sjtag_unlock` |
| `runtime.sjtag_base` / `sign_tool` / `tool_prefix` / `word_order` | 실행 환경값(SJTAG 블록 주소, 서명 도구 경로, `wine`, 워드 순서) | `sjtag_unlock`, `run_debug.sh` |
| `trace.*` | N-Trace 인코더·funnel·sink 주소, `mem_type` | `--trace-*` 모드(기술 자료용) |
| `pcsr.offset` / `core_stride` / `valid_bit` | 코어별 PC 샘플 레지스터 위치 규칙 | 퍼저 |
| `pcsr.cores[]` | `{id, name, elf, load_offset}` — **ELF 경로 포함이라 기밀** | 퍼저(`RiscvPcsrSampler.connect`) |

`pcsr.cores[].elf` 의 상대경로는 퍼저 디렉터리 → `risc-v/` → `products/BM9K1/` → cwd 순으로
찾는다(`RiscvPcsrSampler._resolve_elf`).

---

## 3. 파일별 설명

### 파이썬 모듈

| 파일 | 줄 | 역할 |
|---|---|---|
| `sfe76_link.py` | 678 | **연결 계층의 정식 모듈.** pylink 로 cJTAG 연결, DAP 전원, AP 맵, JSON 로더(`RISCV_ADDRS`, `ADDRS_REAL`). pylink 의 `halt()`/`restart()` 는 실패해도 `False` 만 돌려주므로 **반환값 + 사후 상태를 모두 확인하는 API**(`connect_checked` / `halt_checked` / `read_pc` / `resume_checked`)만 노출한다. raw `jl.halt()` 를 직접 부르지 말 것 — 멈춘 코어를 성공으로 오인하거나 resume 실패로 SSD 가 hang 된다 |
| `dap_access.py` | 141 | ADIv6 DP/AP 원시 접근(`Dap`, MEM-AP read/write). CoreSight **표준** 인덱스·오프셋만 담고 SoC 주소는 없다 |
| `sjtag_unlock.py` | 2,095 | **메인 도구.** T32 `clavis.cmm` 의 SJTAG PKC(ECDSA P-521) 인증을 J-Link 로 옮긴 것 + 진단 + RISC-V DM 접근 + SBA + 트레이스 + JLinkScript 생성. 퍼저가 쓰는 SBA 핫루프(`sba_pin` / `sba_read_pinned` / `sba_unpin`)와 세션 재생성(`reopen_session`)도 여기 있다. **기본은 읽기 전용** — `--execute` 를 줘야 인증(쓰기)을 한다 |
| `elf_map.py` | 323 | ELF 실행영역 정합성 게이트 + 심볼화. `readelf -lW` 로 실행 세그먼트를 읽어 관측 PC 가 그 범위에 드는 비율을 계산하고, 임계 미만이면 **심볼화를 거부**하고 offset 후보를 제안한다. 런타임 주소가 ELF vaddr 과 어긋나도 addr2line 은 그럴듯한 이름을 내므로, 조용히 틀린 커버리지를 막는 장치다 |

### 셸 스크립트

| 파일 | 역할 |
|---|---|
| `run_debug.sh` | **원스텝 오케스트레이터.** ① `sjtag_unlock.py --execute`(인증) → ② `--gen-jlinkscript`(JLinkScript 생성) → ③ `JLinkExe -autoconnect 1`. 환경변수 `WINEPREFIX`(기본 `/root/.wine32`), `JLINK`(`JLinkExe`/`JLinkGDBServer`), `JLINK_SCRIPT`, `NO_AUTH=1`(이미 인증됨) |
| `run_sjtag_tracearm.sh` | N-Trace 측정 Phase 0 — 코어 하나의 트레이스 인코더를 무침습(StallEna=0)으로 켜고 버퍼·Wptr 기준선을 기록. sudoers NOPASSWD 용 고정 커맨드 |
| `run_sjtag_tracedelta.sh` | 위 arm 이후 생성된 트레이스 바이트 수/overflow 를 보고. 명령 1개당 캡처가 가능한지 판정용 |

### 설정·템플릿·문서

| 파일 | 역할 |
|---|---|
| `sjtag_addrs.json` | 실주소 단일 출처(§2) |
| `sjtag_addrs.example.json` | 같은 구조의 placeholder 판 |
| `sf_e76.JLinkScript.template` | JLinkScript 템플릿. `SetcJTAGInitMode=1`(SiFive short-form), `CORESIGHT_AddAP`/`SetCoreBaseAddr`(DM 위치), N-Trace 설정 |
| `sf_e76.JLinkScript` | 템플릿에 실주소를 채운 **생성물**(`.gitignore`). `run_debug.sh` 가 매번 다시 만든다 |
| `TRACE_COVERAGE_PLAN.md` | N-Trace 커버리지 계획(2026-08). 핵심 결론이 반증돼 **기술 자료로만** 유효 |

---

## 4. 퍼저가 이 폴더를 쓰는 방식

1. `RiscvPcsrSampler.connect()` 가 `riscv_cov.PcsrSession` 을 연다. 세션은 이 폴더의
   `sjtag_unlock` 을 import 해 **cJTAG warmup → 디버그 전원 → SJTAG 인증 → DM 활성**을 수행한다.
2. `pcsr.cores` 를 읽어 코어별로 `pin()`(해당 코어 PCSR 에 SBA FIFO 셋업 1회. 코어 전환 시 이전
   FIFO 를 끄고 busy 완료를 확인 — 실패하면 fail-closed)을 하고, 실패한 코어는 샘플링에서 뺀다.
3. `elf_map.check_gate()` 로 코어별 관측 PC 의 ELF 정합성을 검사하고, 통과한 코어만
   `elf_map.Ranges` 로 실행영역 필터를 건다.
4. 샘플링 워커가 코어별로 `sba_read_pinned()` 버스트를 돌린다(가중치·지터·seed 는
   `fuzzer_config.json` 의 `riscv.sample_plan`). seed 는 로그에 남는다 — 재현하려면 설정에 넣는다.
5. 링크가 죽으면 `_reinit_target()`(1회 재수립) → `_reconnect()`(settle + backoff 로 최대 N회).
   전원 사이클 뒤에는 이 과정에서 **SJTAG 인증을 다시** 한다.

**동작이 확인된 폴링 형태는 하나뿐이다** — SBA FIFO 모드 **셋업 1회 + DRW 반복**. 루프 안에
sbcs 확인·clear_sticky·지연을 넣으면 실패율이 폭증한다(I/O 부하 중 실측).
**세션 붕괴**(수만~십수만 샘플 지점에서 전 코어 무효, 자가 회복 없음)는 `reopen_session()` 의
전체 재생성으로만 회복된다.

---

## 5. 실행법

### 사전 1회 — `sjtag_addrs.json` 채우기

`runtime.sjtag_base`, `runtime.sign_tool`(서명 .exe 경로)을 실기값으로 채운다.
`tool_prefix`(=`wine`)·`word_order`·`ap_map`·`pcsr` 등은 제품 기준값이 이미 들어 있다.

서명 도구는 Windows 실행파일(PE32)이라 root 용 32비트 wine prefix 가 필요하다
(`wine32 wine64` 설치 + `/root/.wine32`). 공개키는 `-s3 -f5`(정적 34워드), 서명은
`-s1 -f5 <challenge>`(세션마다 다른 34워드)로 받는다.

### 사람이 디버거로 붙을 때

```bash
sudo ./run_debug.sh              # 인증 → JLinkScript 생성 → JLinkExe 접속
NO_AUTH=1 sudo ./run_debug.sh    # 같은 전원 사이클에서 이미 인증했을 때
```

### 점검 도구 (폴더 밖 `../tools/`)

```bash
sudo python3 tools/check_bm9k1_setup.py     # 자산·설정 누락 점검(값은 안 찍음)
sudo python3 tools/check_bm9k1_connect.py   # 퍼저 없이 import → 인증 → SBA → PCSR 단계별 격리 시험
```

### `sjtag_unlock.py` 모드

base/tool/word-order 를 안 주면 JSON `runtime` 에서 읽는다. `--power both` 를 권장한다.

| 분류 | 옵션 | 내용 |
|---|---|---|
| 인증 | `--execute` | SJTAG PKC 인증(쓰기). 없으면 read-only probe. 성공하면 DM 활성·스캔까지. rc 0/10/11 = AUTH_PASS(DM 검증 수준 차이) |
| | `--word-order`, `--tool`, `--tool-prefix`, `--base`, `--timeout` | 인증 파라미터 override |
| 링크 진단 (읽기) | `--diag` | DAP 전원 req/ack + AP IDR 스윕 + sticky |
| | `--read-burst N [--burst-delay MS]` | request 워드 반복 읽기로 transport 안정성 판별 |
| | `--scan [--scan-window --scan-step]` | SJTAG 오프셋 live/dead 분류 |
| | `--rom-scan` | CoreSight ROM 테이블을 걸어 메모리맵 PC 샘플 컴포넌트(EDPCSR/PMPCSR) 후보 탐색 |
| | `--analyze-pubkey` | 서명도구 공개키가 정적인지·워드 순서 후보(오프라인) |
| DM | `--dm-scan [--dm-window]`, `--dm-activate`, `--dm-halt` | dmstatus 실측 / dmactive=1 / halt → misa(abstract 실패 시 progbuf) → resume |
| PC | `--pc-probe N` | 실행 중 abstract `dpc` 를 N회 읽어 비침습 PC 샘플링 가능 여부 판정(E76 은 cmderr=2 로 불가 — PCSR 폴링으로 간 이유) |
| 트레이스 | `--trace-status`, `--trace-dump [PATH]`, `--trace-arm`, `--trace-delta`, `--trace-core N` | N-Trace(기술 자료용) |
| 생성 | `--gen-jlinkscript [PATH]` | JSON 값으로 `sf_e76.JLinkScript` 생성(오프라인) |
| 연결 | `--power` | DAP 전원 도메인(`both` 권장) |
| | `--tif-init on/off` | cJTAG TIF 초기화(기본 on). off 는 이미 활성화된 링크 재사용 실험용 |
| | `--tap-script on/off` | 수동 TAP 체인 선언(기본 off = CMM 방식) |

### `elf_map.py` (단독 실행)

```bash
python3 elf_map.py --elf core.elf --pcs pcs.txt [--offset 0x0] [--threshold 95.0] [--top 20] [--force]
```

---

## 6. 기술 노트 — 막혔다 풀린 것

- **콜드 DP warmup**: cJTAG 활성 직후 DP 가 미동기라 첫 전원 요청이 안 먹는다(CTRL/STAT=0).
  `prepare_session` 이 DP SELECT/DPIDR priming + 요청 재기입으로 warmup 을 내장한다.
- **transport 견고성**: 일시적 STICKYERR 을 rd/w/poll 에서 clear + 재시도로 자가 복구한다.
  없으면 34워드 주입 중 끊긴다.
- **DM 접근**: DM 은 별도 AP 의 memory-mapped 레지스터. `dmactive=1` 로 깨워야 dmstatus 가
  유효하다. CSR 은 abstract 직접 접근이 안 돼(cmderr=2) **progbuf 경유**로 읽는다.
- **JLinkExe 접속**: `SetcJTAGInitMode=1` 이 없으면 TAP 스캔이 실패해 'Failed to identify'.
- **SBA**: 트레이스·PCSR 레지스터는 MEM-AP 로 안 닿고 **DM 의 SBA 로만** 접근된다
  (T32 `SB:`, J-Link MemType=2).
- **인증 수명**: challenge-response nonce 가 세션/전원 단위라 **전원 사이클마다 재인증**.
  퍼저의 `_reconnect` 가 전원 이벤트 뒤 이를 수행한다.
- **POR ↔ JTAG 커넥터**: JTAG 을 꽂은 채 POR 하면 ROM 부팅으로 빠지던 하드웨어 문제
  (커넥터 GND 핀이 부팅 스트랩 핀을 접지)는 2026-09-28 기준 **해결됨**. 재발하면 하드웨어부터 본다.

---

## 7. 커버리지 자산 (Ghidra 산출물)

`../riscv_cov.py` 가 코어별로 다음을 읽는다(위치는 `products/BM9K1/`, 사내 관리 — 리포에 없음).

```
basic_blocks_core<X>.txt   0xSTART 0xEND        (END = 마지막 바이트 + 1)
functions_core<X>.txt      0xENTRY <size> <name>
callgraph_core<X>.txt      0xCALLER 0xCALLEE
symbols.json               ELF 해시·exec 범위·개수(자가 검증)
```

생성은 Ghidra headless 로 `../tools/ghidra_export.py`(Jython 스크립트)를 코어별 ELF 에
돌린다. 코드 오버레이가 있는 코어는 `FW_{label}Core_overlay_map.json` 을 함께 준다
(`{label}` 은 코어 이름으로 자동 치환). 과거 README 에 있던 래퍼 `run_ghidra_export.sh` 는
리포에 없다 — 사내 호스트에만 있다.

---

## 8. 테스트

이 폴더의 단위 테스트(`test_sjtag_unlock.py`, `test_pcsr_fastpath.py`, `test_elf_map.py`)는
커밋 `f532202`(v10.0 정리)에서 제거됐다. 현재 이 경로를 덮는 시험은 퍼저 쪽에 있다.

```bash
python3 -m unittest discover -s PC_Sampling/tests -p 'test_v10_2_pcsr_response.py'
python3 -m unittest discover -s PC_Sampling/tests -p 'test_v10_1_sampler_recovery.py'
```

샘플러 클래스(`RiscvPcsrSampler` 등)는 `tests/fixtures/v10_2_device_ast.json` 의 AST 해시로
동결돼 있다 — 의도한 변경이 아니면 해시가 달라지는 순간 시험이 깨진다.

## 9. 관련 자료 (로컬 `G:\RISC-V`)

- SEGGER: `UM08001_J-Link_J-Trace.pdf`, `J-Link_command_strings.md`(RISCV_Set*/SBA),
  `J-Link_cJTAG_specifics.md`
- `RISC-V_N-Trace_Specification.pdf`, `SiFive_Trace_and_Debug.md`, `Arm_CoreSight_SoC-400.md`
- T32 원본(사용자 제공): `clavis.cmm`(인증), `ViewNexusTracedump.cmm`, `NexusTracedatadump.cmm`
