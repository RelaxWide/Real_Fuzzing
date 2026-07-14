# SESSION HANDOFF — v8.8 (P9 halt 샘플러 집중 세션)

> 이 파일이 **유일한 핸드오프/브링업 문서**다. 구 `SESSION_HANDOFF_v8.3.md`,
> `P9_BRINGUP.md`, `backup/SESSION_HANDOFF_v7.8.md` 는 이 세션에서 삭제하고
> 필요한 사실을 여기로 통합했다.

---

## 0. 현재 상태 한 줄

- **최신 = `pc_sampling_fuzzer_v8.8.py`** (`FUZZER_VERSION="8.8.0"`). **v9.0(.py/.md)은 삭제됨**
  (v8.8 버전문자열만 바꾼 복사본이었고 RAG 통합은 코드로 구현된 적 없음).
- 설정은 `fuzzer_config.json` (버전 비종속 공유). 시드 `nvme_seeds.py`(import 하드 의존).
- 이번 세션은 대부분 **P9(Cortex-R5, J-Link halt 샘플러)** 관련.

---

## 1. P9 하드웨어 사실 (확정 — 구 P9_BRINGUP 통합)

- **제품**: P9 = Cortex-R5 단일코어, SWD, J-Link(pylink) **halt 샘플러**(`sampler_type='jlink_halt'`).
- **디버그 구성**: SW-DP `0x6BA02477`, AP[0]=APB-AP 단일, ROMTbl `0x80020000`→**R5 debug base `0x80030000`**.
- **비침습(PCSR) PC 샘플링은 하드웨어상 불가 — 3계층 실측 확정**:
  - `DBGPCSR(0x80030084)` = 0 (PC Sample Register 무효)
  - `DBGAUTHSTATUS(0x80030fb8)` = **0xF0** → SNID(secure non-invasive)=`11`(활성). 즉 **인증 잠금 아님**
    (제조사가 막은 게 아님). NSNID/NSID=00 은 R5 가 TrustZone 없어서.
  - `DBGDEVID(0x80030fc8)` = 0 → PCSample 필드=0 → **PC Sample 확장 자체가 미탑재**.
  - 결론: DBGPCSR 은 HW 에 없음 → OpenOCD/J-Link/인증 무엇으로도 비침습 불가. ETM 은 트레이스 핀 없음.
  - **따라서 halt→register_read(R15)→Go 가 P9 의 유일한 PC 수집법** (SID=11 이라 invasive halt 는 지원·활성).
- **fw .text 범위(coverage 필터)**: `0x0 ~ 0x9cffff` (Ghidra 확정).
- 진단 도구: `backup/p9_core_probe.py` — DBGDIDR/DBGPCSR + **DBGAUTHSTATUS 디코드**(이번 세션 추가).
  memory_read32 은 코어 AXI 를 읽어 디버그 레지스터 접근 실패 → **OpenOCD 로 `r5.abp mdw 0x800300xx`**
  가 확실(APB-AP + `r5.dap dpreg 4 0x50000000` 로 디버그 전원 ON). 상세는 아래 5장.

## 2. P9 현재 설정값 (fuzzer_config.json / products.P9)

| 키 | 값 | 비고 |
|----|----|------|
| sampler_type | `jlink_halt` | pylink 직접 halt |
| jlink_speed | **2000** kHz | 4000→2000 하향(halt 성공률↑) |
| go_settle_ms | 50 | resume→다음 halt 최소 실행시간 |
| pc_reg_index | null | connect 시 자동 탐지 |
| por_remove_bdf | **`0000:00:01.1`** | POR PCIe remove 대상 = topology 최상단(이 시스템). device 자동탐지 아님 |
| nvme_timeouts | command/flush/selftest/verify=**40000**, format=310000, aer=610000 | 기존 30s + **halt 오버헤드 마진 +10s** |
| enable_debug_tool_dump | **true** | crash dump = `./Debug_Tool_v1.0.0.2 RDDump <device>` (UFAS 대체) |
| enable_ufas / enable_jlink_dump | false / false | P9 는 UFAS·JLink dump 미사용 |
| fw_addr_start/end | 0x0 / 0x9cffff | coverage 주소필터 |
| state_fields | p9 | LID 0xDF 제외판 |
| (globals) power.por_boot_wait | **30.0** | POR 후 device 재검출 대기 8→30s |

---

## 3. 이번 세션에서 한 일 (커밋 순, 최신 위)

**코드 리뷰(초반)**: 620KB 단일 파일 영역별 검토 → 확정 버그 6건 수정(차트 `NUM_MUTATION_OPS`
스냅샷 누락 / APST·KeepAlive get-feature 파싱이 Feature ID 를 잡던 것 / crash 파일명 충돌(빈 data
md5 상수) / seq replay nsid(needs_namespace=false → 0) / `_splice` override 손실). 상세는
`pc_sampling_fuzzer_v8.8.md`.

**공통/구조**:
- v9.0(.py/.md) 삭제, `rag/export_cmd_schemas.py`·README 참조를 v8.8 로 수정.
- 미사용 파일 `state_fields.py`(정의는 config 로 이전됨)·`r5_pcsr.cfg`(orphan) → `backup/`.
- POR 후 device 미검출 시 대기 30s + **abort**(시작 경로 `run()` 에서 `_por_pcie_rescan()` 반환 검사).

**P9 crash dump**: `_run_debug_tool_dump()` 신규 — `./Debug_Tool_v1.0.0.2 RDDump <ctrl device>`.
device 는 `_ctrl_device()` 로 상황별 자동. `--no-debug-tool-dump`. P9 는 JLink dump 로직 원래 안 탐.

**P9 POR**: `_por_remove_target()` — `por_remove_bdf` 있으면 그 BDF, 없으면 EP 자동탐지. remove/rescan
단계 로깅 추가. boot sweep 전샘플 halt 실패 시 "코어 미실행(POR 의심)" ERROR 진단.

**P9 halt 노이즈 — 핵심 작업 (아래 4장 참고)**:
- jlink_speed 2000, nvme_timeouts +10s 마진.
- **halt 모드 재구성**: DAP 연결 ≠ 코어 실행. → **device 가 `nvme id-ctrl` 에 응답(코어 실행)한 뒤
  connect**, **boot sweep 생략**(코어 미실행 상태 halt spam 방지). 비침습 PCSR(PM9M1/BM9H1)은 기존대로.
- **"CPU is not halted" 실제 제거**: `_read_all_pcs` 가 halt 실패해도 항상 `JLINKARM_Go` 를 불러서
  = 실행 중 코어에 resume → DLL 이 이 메시지를 찍던 것. → **halt 성공 시에만 Go**.
- **"CPU could not be halted" 급감**: 코어가 WFI 일 때 halt 시도가 timeout. → 연속 실패 시 **지수
  backoff**(50→…→1000ms)로 halt 시도(=메시지) 자체를 줄임. 성공 시 즉시 리셋. PCSR 무영향.
- 실패 후 복구 시 `[Sampler] PC 읽기 정상 재개 ...` 로그(커버리지 지속 확인). 연속실패 로그 라벨
  `[OpenOCD] PCSR read` → `[Sampler] PC read`.
- (중간에 넣었다 뺀 것): DLL stderr fd-2 억제는 "감추기"라 사용자 요청으로 제거 — 근본 수정으로 대체.

GitHub: `RelaxWide/Real_Fuzzing` (branch main). 커밋 `40d8893` 이 세션 마지막.

---

## 4. P9 halt 실패 메시지 — 이해와 현재 상태 (중요)

- **원인**: SSD 컨트롤러 R5 는 I/O-bound — 명령 처리 중에도 CPU 는 대부분 **WFI(NAND/DMA 대기, 클럭
  게이팅)**. SWD halt 는 코어 클럭이 돌아야 되므로 WFI 구간에 halt 시도가 걸리면 실패("could not be
  halted"). **NVMe 명령이 잘 되는 것과 무관** — CPU 는 그 사이 자고 있음.
- **두 메시지 구분**:
  - "CPU **is not** halted" = 안 멈춘 코어에 Go/read → **제거됨**(halt 성공 시에만 Go).
  - "CPU **could not be** halted" = JLINKARM_Halt 자체 timeout(코어 WFI). **backoff 로 빈도 급감**.
    완전 제거는 불가(WFI 는 정상 동작) → 아래 6장 DBGDSCR 사전확인이 유일한 근본책.
- **`[Sampler] PC read 연속 N회 실패 — 이 윈도우 샘플링 중단`(구 `[OpenOCD] PCSR read ...`)은 영구
  중단 아님** — `start_sampling` 이 `stop_event.clear()` 후 다음 명령에서 재시작(코드 확인). 코어가
  깨면 다시 샘플. **미해결 관찰 이슈**: 사용자가 "중간부터 이 로그가 계속" 보고 → (A)WFI 많은 구간
  (coverage 는 계속 증가, 양성) vs (B)코어가 그 지점부터 지속 halt 불가(coverage flatline, 실제 문제)
  를 구분해야 함. **확인 필요**: 그 로그 이후 coverage 증가 여부 / 같은 시점 NVMe timeout 여부 / --pm
  여부 / 직전 명령·PM 이벤트. (사용자는 backoff 이전 옛 코드 로그를 보고 있었을 가능성 — pull 후 재현 권장.)

---

## 5. P9 디버그 레지스터 읽기 (OpenOCD 일회성 — 검증됨)

pylink `memory_read32` 은 디버그 레지스터(APB-AP)에 못 닿음(코어 AXI 읽음). 일회성 진단은 OpenOCD:
```bash
sudo openocd -f backup/r5_pcsr.cfg \
  -c "r5.dap dpreg 4 0x50000000" \        # 디버그 전원(CDBGPWRUP) ON — 필수
  -c "r5.abp mdw 0x80030000" \            # DBGDIDR (0x77040013 정상)
  -c "r5.abp mdw 0x80030fb8" \            # DBGAUTHSTATUS (0xF0)
  -c "r5.abp mdw 0x80030088" \            # DBGDSCR (코어 상태 — 6장용)
  -c "r5.abp mdw 0x80030084" -c "shutdown"  # DBGPCSR
```
(`backup/r5_pcsr.cfg` 는 APB mem_ap `r5.abp` 를 만들어 둠. J-Link 는 퍼저 종료 상태여야 함.)

---

## 6. 미해결 / 다음 작업 후보

- **[관찰] "연속 N회 실패" 원인 확정** — 위 4장 (A)/(B) 판별. (B)면 무엇이 코어를 재웠는지(특히 --pm).
- **[근본책] DBGDSCR 사전확인** — halt 전에 코어 상태(DBGDSCR, 0x80030088)를 읽어 **실행 중일 때만
  halt** → "could not be halted" 를 진짜 0 에 가깝게. 단 APB-AP 디버그 레지스터 read 를 pylink 에서
  되게 해야 함(memory_read32 불가 → coresight_read/DP 전원 시퀀스, HW 에서 iteration 필요). OpenOCD
  경로(5장)는 됨을 확인.
- **[안전] P9 `--pm` 위험** — CLKREQ# 핀 토글(S2, `_pm_perturb_clkreq`)이 L1.2 지원 여부를 **가드하지
  않음**. P9 는 L1.2 미지원인데 CLKREQ# deassert 시 ref clock 제거 → **PCIe 링크 드롭 가능**. L1.2/L1SS
  config write 는 가드됨(skip). → **P9 는 --pm 미사용 권장**, 또는 P9 전용으로 CLKREQ#/L1.2 퍼터베이션
  끄는 게이트 추가 필요(현재 P9 profile 에 PM 제한 키 없음). NVMe PS(PS3/PS4) 는 --pm 없이도 fuzz 됨.
  (참고: P9 는 NVMe power state 만 지원, PCIe PM(L1.2 등) 미지원. PS3 ENLAT20/EXLAT3ms, PS4 30/80ms —
  이 latency 는 40s timeout 대비 무시 가능 → timeout 추가 상향 불필요.)
- **[코드리뷰 보류]** — energy 스케줄 포화, MOpt 크레딧 순서, 변이 필드폭 overflow 붕괴, CSFuzz-p
  bang-bang. 동작/알고리즘 변경이라 의도 확인 후 진행(상세 `pc_sampling_fuzzer_v8.8.md`).
- **[RAG]** `rag/`(스키마 추출·검증·PDF 분할)은 스캐폴딩만 동작. end-to-end 미구현 → 실제 major 때.

---

## 7. 실행

```bash
sudo python3 pc_sampling_fuzzer_v8.8.py --product P9 --nvme /dev/nvme0n1
# 전제: pip3 install pylink-square. Debug_Tool_v1.0.0.2 를 이 폴더에 두면 crash dump 활성(없으면 skip).
# P9 에서 --pm 은 위 6장 위험으로 당분간 미사용 권장.
```
정상 시작 로그 순서(P9): `[POR] 침습 halt 샘플러 — id-ctrl 응답 확인 후 connect` → `[POR] PCIe rescan
시작` → `[J-Link] 연결 성공` → (샘플링). PM9M1/BM9H1 은 PCSR 경로라 기존과 동일.
