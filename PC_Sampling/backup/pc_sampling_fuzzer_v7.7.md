# PC Sampling SSD Firmware Fuzzer v7.7

OpenOCD PCSR(PC Sampling Register) 비침습 샘플링 + `nvme-cli` passthru 기반 Coverage-Guided + State-Aware Fuzzer.

v7.7 핵심: **PM Robustness Perturbation (S1+S2)** — 기존 PM rotation slot 에 PCIe config bit / CLKREQ# timing perturbation 통합. `--pm` 옵션 활성 시 자동 사용 (별도 옵션 없음). 모든 입력은 host OS/BIOS 정상 발행 또는 hardware glitch level 범위 한정 → vendor 클레임 가능한 결함 신호 도출. 변경된 PM 상태는 다음 rotation 까지 유지 → PM × fuzz 상호작용 평가.

v7.6 시각화 / v7.5 SequenceSeed corpus / ctx 모드(full / lba_nlb) / 2-pass favored cull 그대로 유지.

---

## 목차

1. [아키텍처 개요](#아키텍처-개요)
2. [요구사항 / 빠른 시작](#요구사항--빠른-시작)
3. [v7.7 변경사항](#v77-변경사항)
4. [v7.6 변경사항](#v76-변경사항)
5. [v7.5 변경사항](#v75-변경사항)
6. [시드 (Seed)](#시드-seed)
7. [SequenceSeed corpus](#sequenceseed-corpus)
8. [Builtin sequence](#builtin-sequence)
9. [Mutation 전략](#mutation-전략)
10. [CSFuzz / State-Aware Fuzzer](#csfuzz--state-aware-fuzzer)
11. [Power Management](#power-management)
12. [PM Robustness Perturbation (v7.7)](#pm-robustness-perturbation-v77)
13. [JTAG 지원 (BM9H1)](#jtag-지원-bm9h1)
14. [Defect 처리](#defect-처리)
15. [주요 상수](#주요-상수)
16. [CLI 옵션](#cli-옵션)
17. [출력 디렉터리](#출력-디렉터리)
18. [버전 이력](#버전-이력)

---

## 아키텍처 개요

```
┌──────────────────────────────────────────────────────────────┐
│  Startup: PMU POR → OpenOCD → APST/KA disable                │
│         → diagnose() (idle universe)                         │
│         → PM Preflight (PowerCombo 30 + S1/S2 17, --pm 시)   │
│         → Calibration                                        │
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
sudo python3 pc_sampling_fuzzer_v7.6.py --product PM9M1 --nvme /dev/nvme0

# BM9H1 (JTAG, 2코어)
sudo python3 pc_sampling_fuzzer_v7.6.py --product BM9H1 --nvme /dev/nvme0

# 위험 명령 포함 (FWDownload→FWCommit 시퀀스 활성)
sudo python3 pc_sampling_fuzzer_v7.6.py --product PM9M1 --nvme /dev/nvme0 --all-commands
```

주소 범위·출력 폴더 등 자주 변경하지 않는 값은 코드 상단 상수 또는 `FuzzConfig` 필드로 직접 수정.

---

## v7.7 변경사항

### S1 + S2 PM Robustness Perturbation 도입

기존 PM rotation slot (POWER_COMBO + forced_idle) 에 PCIe config bit / CLKREQ# timing perturbation 슬롯 추가. 별도 클래스/옵션 없이 기존 `_pm_rotate` 분기 확장만으로 통합. **`--pm` 활성 시 자동 동작**.

#### Slot 분기 (`--pm` 활성 시)

| 비율 | Slot | 설명 |
|------|------|------|
| 60% | POWER_COMBO 30종 | 기존 — PS × L × D 조합 |
| 10% | forced_idle PS3/PS4 | 기존 — NOPS 진입 슬롯 |
| 20% | **PCIe config bit perturb** | S1 — 13개 비트 중 1개 random 변경, **다음 rotation 까지 유지** |
| 10% | **CLKREQ# timing perturb** | S2 — 4 mode random (missed_wake / extended_wait / short_pulse / rapid_toggle) |

`--pm` 미사용 시 PM rotation 자체 비활성 (회귀 없음).

#### S1 — PCIe Config Bit 대상 (13개)

| 위치 | 비트 | 설명 |
|------|------|------|
| LNKCTL [2] | `rcb` | Read Completion Boundary 64↔128B |
| LNKCTL [7] | `extended_sync` | sync ordered set 강제 |
| LNKCTL [8] | `enable_clock_pm` | Clock PM 활성 |
| LNKCTL [9] | `hw_autonomous_width` | HW Autonomous Width Disable |
| DEVCTL2 [9:8] | `ido` | ID-based Ordering Req/Cpl |
| DEVCTL2 [10] | `ltr_enable` | LTR Mechanism Enable |
| DEVCTL2 [14:13] | `obff_enable` | OBFF Enable (0/1/2/3) |
| PMCSR [1:0] | `pmcsr_d1_d2_forced` | **일회성** — D1/D2 진입 후 50ms → D0 자동 복귀 |
| PMCSR [3] | `no_soft_reset` | D3→D0 reset 수반 정책 |
| PMCSR [8] | `pme_en` | PME 활성화 |
| L1SS Ctl1 [3:0] | `l1ss_enable` | L1.1/L1.2 PCI-PM/ASPM enable mask |
| L1SS Ctl1 [15:8] | `ltr_l1_2_threshold` | L1.2 entry 임계값 |
| L1SS Ctl1 [31:29] | `ltr_l1_2_scale` | threshold scale (1ns/μs/ms/s) |

**의도적 제외** (host PCIe controller / kernel timeout 로직 영향):
- DEVCTL2 [3:0] Completion Timeout Range
- DEVCTL2 [4] CTO Disable
- L1SS Ctl1 [7:5] Common Mode Restore Time (큰 값 시 wake 매우 느림)
- LNKCTL [4/5/6/12] LD/RL/CCC/DRS (링크 끊김 또는 reset trigger)
- LNKCTL [1:0] ASPM Control (기존 POWER_COMBO 가 이미 사용)

#### S2 — CLKREQ# Timing 모드 (4개, 매번 random 선택)

| Mode | 동작 | 모방 환경 |
|------|------|---------|
| `missed_wake` | L1.2 진입 + 50~500ms 지연 후 wake | hot-plug 시퀀스 |
| `extended_wait` | 정상 L1.2 entry + T_POWER_ON ±50% timing | BIOS 설정 변경 |
| `short_pulse` | 10~100μs 단발 pulse | hardware glitch (cheap PCIe slot) |
| `rapid_toggle` | 10ms 내 3~8회 toggle | cheap chipset glitch |

#### 변경 상태 유지 정책

- PCIe config bit 변경 후 **복원 안 함** — 다음 rotation 까지 유지
- 다음 rotation 에서 새 perturbation 또는 POWER_COMBO 가 덮어씀
- POWER_COMBO 가 명시 설정하는 영역(PS/L-state/D-state)은 자동 reset, 그 외 비트는 잔류 (realistic — 실제 OS 도 일부만 변경)
- D1/D2 forced 는 일회성: D1/D2 진입 → 50ms → D0 복귀 시 **`setpci_write` 반환값 + readback 검증**. restore 실패 시 warning 로그 + False 반환 (host-side restore 실패가 firmware 결함으로 attribution 되는 오염 차단)
- CLKREQ# perturb 는 일회성 timing 이벤트 (모든 mode 가 assert state 로 종료)

#### 결함 판정

별도 sanity check 없음. 시그널:

| 관찰 | 해석 |
|------|------|
| PM rotation 직후 100 exec 안 명령 timeout | 직전 PM event 가 원인 후보 |
| state telemetry 4a/4c 그룹 비정상 변동 | PM event 부수 효과 |
| 일관된 latency 증가 | 약한 PM 결함 신호 |

`_cmd_history` 가 PM event (`kind: pcie_pm_bit` / `kind: clkreq`) 자동 기록 → crash 시 `_generate_replay_sh()` 가 setpci write-with-mask / PMU GPIO 토글 시퀀스 (4 mode 별 정확 reproduction) 으로 변환 → **완전 재현 가능**. state corpus / seq corpus replay 도 동일 경로 사용.

#### Preflight 검증

`--pm` 활성 시 fuzzing 시작 전 두 단계 PM preflight 수행:

| 단계 | 검증 항목 | 메서드 |
|------|----------|--------|
| 1단계 | POWER_COMBO 30종 (PS × L × D) | `_pm_preflight_check()` — 기존 |
| 2단계 (v7.7) | S1 PCIe bit 13개 + S2 CLKREQ# 4 mode = **17 perturbation** | `_pm_preflight_s1_s2()` — 신규 |

각 항목 1회씩 결정적으로 적용 → `nvme id-ctrl` 5초 응답 확인 → 원복 (S1 normal 12개는 `(orig & mask, mask)` 으로 perturbed bit 만 복원, 다른 비트 보존). 실패해도 fuzzing 계속 (식별만, abort X).

**OK 의미**: setpci write 성공 + controller hang 안 됨. Data corruption / latency 증가 / 내부 state 정합성은 검증 안 함 (본격 fuzz 의 state telemetry + crash detection 영역).

**Init 순서 보정**: idle PC universe 수집(`sampler.diagnose()`)은 PM preflight **앞**에서 수행. PM preflight ~50회 전환 직후엔 firmware cleanup/wake handler PC 가 idle universe 에 오염될 위험 → POR + APST/Keep-Alive disable 직후의 가장 깨끗한 baseline 사용.

#### CLI

별도 옵션 없음. **`--pm` 활성 시 자동 동작**.

#### Validity

모든 input 이 host OS/BIOS 정상 발행 가능 (spec-valid) 또는 hardware glitch level 로 실제 발생 가능 (spec-violating-but-environmental) 범위 한정 → **vendor 가 "비현실적 입력" 으로 거부 불가**.

가정 환경:
- consumer (일반 OS desktop/laptop)
- server/datacenter (SMI, hypervisor, VM passthrough)
- embedded/자동차 (hardware glitch level)

### v7.7 후속 정리

#### forced_idle slot — APST 자율 진입으로 변경

기존: `SetFeatures FID=0x02 cdw11=4` 강제 PS=4 → settle 2초 × 2회 = 4초 대기. 일부 SSD 가 강제 PS=4 만으로는 NAND deep sleep 까지 도달하지 못함 + 실제 OS 동작과 다른 경로.

신규: PM rotation 의 forced_idle slot 동안만 APST 짧은 ITPT 로 활성화 → 디바이스 자율 PS0 → PS3 → PS4 전환. 슬롯 종료 시 다시 disable → 다른 슬롯 (POWER_COMBO/pcie_bit/clkreq) 의 manual PM 제어와 충돌 X.

| 단계 | 시간 | 동작 |
|------|------|------|
| 1 | t=0 | `_apst_enable_short_itpt(500, 2000)` — APST table 설정 |
| 2 | t=0.5s | device 자율 PS0 → PS3 진입 |
| 3 | t=2.5s | device 자율 PS3 → PS4 진입 |
| 4 | t=3.5s | sampling stop + `_apst_disable()` |

APST table (256B): Entry[0]=(ITPS=3, ITPT=500ms), Entry[3]=(ITPS=4, ITPT=2000ms). 나머지 entry/upper 32-bit reserved=0.

#### Replay 산출물 self-contained

| 항목 | 변경 |
|------|------|
| crash_<ts>/ 폴더 통합 | `_handle_timeout_crash` 시작 시 미리 생성하여 replay_<tag>.sh + replay_data_<tag>/ + dump + log + dmesg 모두 동일 폴더에. 통째로 다른 머신에 옮겨도 동작. |
| `--input-file` 상대경로 | `cd "${SCRIPT_DIR}"` 헤더 + `./replay_data_<tag>/data_NNN.bin` — 어디서 실행해도 동작 |
| dump 파일명 시분초 | `%Y%m%d_%H%M%S` — 동일 일자 다중 crash 시 덮어쓰기 방지. JLink dump 는 `DUMP_TIMESTAMP` env var + argv `$1` 로 shell 에 전달. |
| crash JSON 정리 | raw fuzz_data binary + .dmesg.txt 제거. `.json` 만 유지 (seed CDW + stuck PC top5 + dmesg 필드). 명령 데이터는 `replay_data_<tag>/data_NNN.bin` 에 이미 포함. |
| PM 복구 replay 순서 | `_pm_d3_safe_restore` 가 `_pm_set_state(0)` 호출 직전에 `pcie_state(L0+D0)` entry 를 `_cmd_history` 에 기록 → replay 가 setpci L0+D0 → SetFeatures PS0 순서로 정확히 재생 (이전엔 D3hot 상태에서 PS0 시도 → hang) |
| device path 정규화 | replay 출력 직전 `/dev/nvme0n1n1` 같은 중복 `nN` 접미사 제거 (`_normalize_nvme_path`) |
| replay 분기 확장 | `_generate_replay_sh` 에 `pcie_pm_bit` (setpci) / `clkreq` (PMU 4 mode 시퀀스) 분기 추가 — PM perturbation 발생 시점도 완전 재현 가능 |

#### Device 호환성

| 항목 | 변경 |
|------|------|
| WSL2 / namespace-only 환경 | `/dev/nvme0` controller char device 없으면 `/dev/nvme0n*` glob 으로 namespace block device 검색 → 최저 ns id 사용. `_io_device()` 헬퍼가 admin/io 모두 동일 경로 사용. |
| `--nvme /dev/nvme0nN` 명시 | path 에서 namespace 번호 추출 → `config.nvme_namespace` 자동 보정 (mismatch 시 `EINVAL` 방지) |
| nvme-cli 구버전 | `-o json` → `--output-format=json` 으로 변경. JSON 자체 미지원 환경에선 text 출력 파싱 fallback (`_parse_nvme_text`) — 모든 `id-ctrl`/`id-ns` 호출이 `_nvme_id_dict()` 헬퍼 통과 |

#### Logging / 진단

| 항목 | 변경 |
|------|------|
| FileHandler encoding | 명시적 `encoding='utf-8'` — sudo / C locale 환경에서 μ/✓/→/한글 깨짐 방지 |
| stderr 인코딩 | `sys.stderr.reconfigure(encoding='utf-8', errors='replace')` (Python 3.7+; 실패 시 silent skip) |
| Device Information 출력 | idle universe 수집 완료 직후 `_log_device_info()` 호출 — Model/Serial/Firmware/Vendor ID/IEEE OUI/NVMe spec/Namespaces/MDTS + Namespace size/LBA size/사용량 + PCIe BDF/Root Port/ASPM cap 한 박스에 표시 |
| nvme-cli 실패 진단 | id-ctrl/id-ns 실패 시 stderr 메시지 + 실제 cmd 전체 + stdout 일부 출력 — 권한/구버전/옵션 인식 실패 원인 즉시 판별 |

---

## v7.6 변경사항

### `coverage_growth.png` 발전

이전(v7.5): BB%/Func% 단일 곡선.

신규:
- **Plateau 음영** — `window = 전체 길이의 5%` 동안 BB% 증가가 0.5% 미만이면 노란 음영으로 표시. 포화 시점을 한눈에 확인.
- **마일스톤 annotation** — 25/50/75/90% BB 도달 시점에 수직 점선 + 도달 시간 라벨.
- **하단 패널: BB velocity bar** — 각 window의 ΔBB%(%/window)를 막대로 표시. 진행 속도 추세 확인.
- 최종 값 annotation 굵게 강조.

### `firmware_map.png` 발전

이전(v7.5): 이진 색상 (covered / not), 최대 400개 표시.

신규:
- **BB-coverage 그라데이션** — 함수별 BB 커버율(0~100%)을 5단계 그라데이션으로 표시 (어두운 보라 → 주황 → 노랑 → 연초록 → 밝은 초록). 부분 커버 함수가 한눈에 보임.
- **전체 함수 표시** — MAX_FUNCS=400 cap 제거. 함수 수에 따라 자동 cols/rows 조정 (treemap 스타일).
- **Top-N 라벨** — 가장 큰 미진입 함수 5개(빨강) + 가장 큰 부분 커버 함수 5개(주황) 이름 표시.
- **그라데이션 colorbar** + **BB-weighted 평균** 부제목 추가.

### `csfuzz_dynamics.png` 신규

CSFuzz §III-C/D의 적응형 corpus selection 동역학을 3-panel로 시각화:

```
Panel 1: p 값 추이 (P_MIN/P_MAX guideline)
Panel 2: NC1 (edge corpus) vs NC2 (state corpus) 크기 변화
Panel 3: m1 vs m2 reward (per-command 정규화 후 비교)
```

데이터 수집: `_update_csfuzz_p()` 호출마다 `_csfuzz_history`에 `(exec, p, m1, m2_norm, NC1, NC2)` 누적. `--no-state` 시 생성 안 함.

### per-command CFG 제거

`{cmd}_cfg.dot/.png` 생성 코드 제거. edge 수가 늘어나면 sfdp 레이아웃으로 떨어져도 가독성 떨어지고, 대체 시각화(heatmap)가 이미 존재해서 가치 낮음.

### v7.6 후속 정리

- **command_comparison.png** — opcode mutation으로 생성된 `unknown_op0x..` 라벨이 차트를 노이즈로 채우는 문제 해결. `_tracking_label` 형식을 `unknown_{admin|io}_op0x{XX}` 로 변경 후 차트에서 `unknown(admin)` / `unknown(io)` 두 버킷으로 합산. 종료 summary 텍스트에 **Top-5 unknown opcode** 별도 출력 (hit count 내림차순) — 차트는 깔끔하고 디테일은 텍스트로 보존.
- **coverage_growth.png** — 하단 panel y축 라벨을 모호한 `BB ΔΔ%/window` 에서 `New BB % per window` 로 변경, subtitle `Coverage velocity — new BB % discovered per window (0 = saturated)` 추가 (영어, 폰트 호환성).
- **heatmap 정리** — `edge_heatmap_2d.png` 제거 (PC 샘플링에서는 진짜 edge가 아니라 sample 인접이라 노이즈). per-command 1D heatmap strip도 제거. **`coverage_heatmap_1d.png`는 global 1개 strip만 유지**하되 가장 hit이 많은 top-3 bin 주소를 hot spot 라벨로 표시.
- **uncovered_funcs.png 제거** — firmware_map의 Top-N 라벨 + BB-coverage 그라데이션이 같은 정보를 더 효율적으로 보여줌. 우선순위 분석은 종료 summary 텍스트에 **Top-20 not-entered + Top-20 partially-covered** 함수 목록(주소·크기·BB% 포함)으로 출력.
- **firmware_map BB-weighted 평균 정확화** — 함수별 % 단순 평균이 아니라 `Σ covered_bbs / Σ total_bbs` 가중 평균.
- **JLink shutdown 분리** — `_shutdown_openocd_for_jlink()` 헬퍼 + `_handle_timeout_crash`에서 항상 호출. `--no-jlink-dump` 사용 시에도 후속 JLink PC 모니터링이 J-Link USB에 정상 접근 가능.
- **JLink/MONITOR 터미널 로그 표시** — `_FuzzingTerminalFilter._ALLOW` 정규식에 `[JLINK]`, `[JLINK DUMP]`, `[MONITOR]` prefix 추가. 이전엔 파일 로그에만 기록돼 dump 진행 상황이나 PC 모니터링 출력이 터미널에 안 찍히던 문제 수정.
- **차트 한글 텍스트 제거 + 폰트 fallback 안전화** — matplotlib 기본 폰트(`DejaVu Sans`)에 한글 글리프가 없어 `Glyph N missing from current font` 경고와 글자 깨짐 발생. 모든 차트 렌더링 텍스트를 ASCII로 통일. 추가로 `_setup_matplotlib_chart_env()` 헬퍼 신설 — `font.family = DejaVu Sans` 고정 + `Glyph missing` 경고 패턴 ignore. 5개 차트 생성 사이트가 모두 이 헬퍼를 호출. 우발적 한글 텍스트가 들어가도 fallback 폰트 시도 없이 안전한 ASCII 렌더링.
- firmware_map Top-N 라벨에서 ⬛/⬜ unicode 제거 (matplotlib 기본 폰트에 없어 Glyph missing 경고).

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
    ["Write", "Write"],             # 동일 LBA overwrite (기본 모드, 데이터 분리)
    ["Write", "Compare"],           # --commands Compare 필요
    ["FWDownload", "FWCommit"],     # --all-commands 필요
]
```

`_CTX_SEQUENCES` (dict — 모드 매핑):

| 시퀀스 | 모드 | 동작 |
|--------|------|------|
| `("Write","Compare")` | `full` | SLBA + NLB + **data** 모두 공유 — Compare가 Write 결과 검증 |
| `("Write","Read")` | `full` | SLBA + NLB + **data** 모두 공유 — Read가 동일 LBA 회수 |
| `("Write","Write")` | `lba_nlb` | SLBA + NLB만 공유, data는 독립 mutation — overwrite 경로 탐색 |

### CLI 옵션 정리 (51 → 19개)
자주 변경하지 않는 옵션 32개를 CLI에서 제거하고 `FuzzConfig` 필드/상수로 유지. 필요 시 코드 직접 수정.

### JLink dump 토글
`--no-jlink-dump` 옵션 추가 — UFAS와 동일한 패턴.

### Mutation 버그 수정
- DSM NR=0xFF payload 불일치: payload=1 entry(언더플로) 케이스 수정
- Copy `_nr_mask` 0xFF→0xF (CDW12[11:8] = 4비트, NVMe spec 준수)
- DSM/Copy structured payload 재구성 후 `data_len_override` 잔존 리셋

---

## 시드 (Seed)

### Seed dataclass (단일 명령)

```python
@dataclass
class Seed:
    data: bytes                          # host buffer / payload
    cmd: NVMeCommand                     # name, opcode, type(Admin/IO), needs_data, weight
    cdw2: int = 0;  cdw3: int = 0        # NVMe CDW2/3 (metadata pointer 등)
    cdw10..cdw15: int = 0                # 명령별 파라미터 6×32-bit
    # override 필드 — None이면 명령어 기본 동작
    opcode_override:   Optional[int]  = None   # opcode 강제
    nsid_override:     Optional[int]  = None   # NSID 강제
    force_admin:       Optional[bool] = None   # True=admin-passthru, False=io-passthru
    data_len_override: Optional[int]  = None   # 전송 크기 declared 강제
    # corpus 운영 metadata
    exec_count: int = 0;  found_at: int = 0;  new_pcs: int = 0
    energy: float = 1.0;  is_favored: bool = False
    covered_pcs: Optional[set] = None    # 이 시드 실행 시 방문한 PC/BB 집합
    is_calibrated: bool = False;  stability: float = 1.0
    stable_pcs: Optional[set] = None     # calibration 과반 PC
    det_done: bool = False               # deterministic stage 소비 완료
```

각 필드의 mutation 처리는 [Mutation 전략](#mutation-전략) 참조.

### 초기 시드 소스: `nvme_seeds.py`

명령어별 정상 CDW 조합 목록이 정의된 사전 (`SEED_TEMPLATES: Dict[cmd_name, List[dict]]`).
시드 추가/수정은 이 파일만 편집하면 됨 — 퍼저 코드 수정 불필요.

**예시** (`Identify`):

```python
"Identify": [
    # CNS=0x01 (Controller): NSID는 Reserved → nsid_override=0
    dict(cdw10=0x0001, nsid_override=0),
    dict(cdw10=0x0000),
    dict(cdw10=0x0002, nsid_override=0),
    ...
    # CNTID 필드 포함 (CNS=0x06/0x07에서 특정 컨트롤러 조회)
    dict(cdw10=(0x0001 << 16) | 0x0006, nsid_override=0),
    # 미지원 CNS — 에러 경로 탐색
    dict(cdw10=0x00FF, nsid_override=0),
],
```

각 dict는 그대로 `Seed(**)` 키워드 인자로 사용 (`data`, `cdw2/3/10~15`, `nsid_override` 등).

| 명령 | 시드 수 | 비고 |
|------|--------|------|
| Identify | ~14 | CNS 값별 + CNTID + 미지원 CNS |
| GetLogPage | ~26 | LID 0x01~0x13 + vendor 0x70~0xFF + LPOL offset |
| GetFeatures / SetFeatures | 각 ~20 | FID별 + SEL (current/default/saved/supported) |
| Read / Write | ~10 | NLB·FUA·PRINFO·PRCHK 조합 |
| Compare / Verify / WriteZeroes / Flush / DSM / Copy | 각 다수 | NVMe spec 기반 정상 조합 |
| FWDownload | 1 (또는 청크별) | `--fw-bin` 명시 시 실제 바이너리 청크화 |
| FWCommit | 4 | slot × action (CA=0/1/2/3) |

총 **42 commands × 평균 10 시드 ≈ 400+ 초기 시드** (활성 명령 수에 비례).

### 시드 생성 흐름 (`_generate_default_seeds`)

```
for cmd in self.commands:            # 활성 명령어만
    if cmd in {"FormatNVM","Sanitize"}: skip            # 파괴 명령 제외
    if cmd == "FWDownload":
        if --fw-bin 지정 + 파일 존재:
            바이너리를 fw_xfer(32KB) 청크로 분할
            chunk_seed = Seed(data=chunk, cdw10=NUMD, cdw11=OFST)
            self._fw_chunks 에 모든 청크 보관
            corpus 에는 첫 청크만 (대표 시드)
        else:
            32KB zero 더미 시드 1개
    if cmd == "FWCommit":
        cdw10 = (slot << 3) | CA  (CA=1: replace+activate-on-reset)
    else:
        for tmpl in SEED_TEMPLATES[cmd.name]:
            seed = Seed(data=tmpl['data'], cdw2..15=tmpl[...],
                        nsid_override=tmpl.get('nsid_override'),
                        found_at=0)
            seeds.append(seed)

# I/O 우선 정렬: Write → Read → 나머지
return write_seeds + read_seeds + others
```

`found_at=0` 인 초기 시드는 cull / epoch reset에서 **무조건 보호**됨 (favored 여부 무관).

### Calibration (`_calibrate_seed`)

각 초기 시드를 `--calibration-runs` (기본 3회) 만큼 미리 실행하여:
- PC 안정성 측정 — 과반수 실행에 등장한 PC를 `stable_pcs`로 분류
- `covered_pcs = all_seen_pcs` 설정 → 2-pass favored 마킹 즉시 참여 가능
- `global_coverage` 에 합산 → 첫 mutation부터 새 PC 판정 정확

Calibration 중 timeout/error 발생 시 즉시 중단 + crash 처리.

### 시드 vs SequenceSeed

| 구분 | Seed | SequenceSeed |
|------|------|--------------|
| 단위 | 단일 NVMe 명령 1회 | N개 명령 시퀀스 (Write→Read 등) |
| 저장 시점 | new PC 발견 시 즉시 | 시퀀스 완료 + 누적 interesting 시 |
| 위치 | `corpus/input_<cmd>_<opcode>_<md5>` | `seq_corpus/replay_seq_<found_at>.sh` |
| Energy | `MAX_ENERGY` 기반 | `MAX_ENERGY / N` (per-exec 공정 경쟁) |
| Cull | `unfavored + exec≥2 + found_at>0` → 제거 | 동일 규칙 + 50개 hard cap (favored 우선) |
| 변형 단위 | `_mutate(seed)` 단일 명령 변형 | 각 commands[i] 를 개별 `_mutate` + ctx 공유 |

상세 SequenceSeed 운영은 [SequenceSeed corpus](#sequenceseed-corpus) 참조.

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
if ctx.get('data') is not None:        # full 모드
    seed.data = ctx['data']
    seed.data_len_override = len(ctx['data'])
# lba_nlb 모드: seed.data 와 data_len_override 는 mutation 결과 그대로 유지
# 시퀀스 명령은 정상 경로 — 변이 필드 초기화
seed.opcode_override = None
seed.force_admin     = None
seed.nsid_override   = None
```

CDW12 상위 비트(FUA, PRINFO 등)와 CDW13~15 mutation은 살아있음.

`lba_nlb` 모드에서 두 번째 명령의 `data_len_override` mutation이 ctx의 NLB와 불일치하면 declared/actual size mismatch가 발생 — **의도된 경계 fuzzing** (FTL의 size 검증 경로 탐색).

---

## Mutation 전략

v7.6에서 사용되는 모든 mutation 대상·방법·확률 정리.

### NVMe CLI 명령 매핑 (어디를 변형하는가)

각 Seed는 최종적으로 `nvme {admin|io}-passthru` CLI로 변환되어 SSD에 전송됨. Seed 필드 ↔ CLI 플래그 매핑:

```bash
nvme {admin-passthru | io-passthru} {device}        # ← seed.force_admin / cmd.cmd_type
  --opcode={hex}                                    # ← seed.opcode_override or cmd.opcode
  --namespace-id={hex}                              # ← seed.nsid_override or default(1)
  --cdw2={hex}  --cdw3={hex}                        # ← seed.cdw2 / cdw3
  --cdw10={hex} --cdw11={hex} --cdw12={hex}         # ← seed.cdw10 / 11 / 12
  --cdw13={hex} --cdw14={hex} --cdw15={hex}         # ← seed.cdw13 / 14 / 15
  --data-len={bytes}                                # ← seed.data_len_override or NLB-derived
  --input-file={path}  -w                           # ← seed.data (write 명령)
  --read                                            # ← read 명령
  --timeout={ms}                                    # ← config 기반
```

#### 매핑 표 — 어떤 mutation이 어떤 플래그를 바꾸는가

| CLI 플래그 | Seed 필드 | 변형 단계 (적용 확률) |
|-----------|----------|--------------------|
| `admin-passthru` ↔ `io-passthru` | `force_admin` | `[3] admin↔io swap` (5%) — passthru type 강제 교차 |
| device path (`/dev/nvme0` vs `/dev/nvme0n1`) | `force_admin` 파생 | admin → controller char dev / IO → namespace block dev |
| `--opcode` | `opcode_override` (없으면 `cmd.opcode`) | `[1] opcode_override` (10%) — vendor 0xC0~0xFF / 완전 random / bit flip / 타 명령 opcode |
| `--namespace-id` | `nsid_override` (없으면 `config.nvme_namespace`) | `[2] nsid_override` (10%) — 0x00 / 0xFFFFFFFF / 0xFFFFFFFE / 비존재 NS / random |
| `--cdw2`, `--cdw3` | `cdw2`, `cdw3` | havoc CDW (30%) + schema (30%) |
| `--cdw10` | `cdw10` | 동일 + Phase 2 LBA pair (cdw10 lower) + Phase 2 DSM NR (cdw10[7:0]) + Phase 2 Copy dest SLBA |
| `--cdw11` | `cdw11` | 동일 + LBA pair (cdw11 upper) |
| `--cdw12` | `cdw12` | 동일 + Phase 1 NLB-relative (cdw12[15:0]) + Phase 2 Copy NR (cdw12[11:8]) |
| `--cdw13`, `--cdw14`, `--cdw15` | `cdw13/14/15` | 동일 (대부분 reserved=0) |
| `--data-len` | `data_len_override` (없으면 NLB·cmd 추론) | `[4] data_len_override` (8%) — NLB-relative / MDTS boundary / static |
| `--input-file` 내용 | `data` (bytes) | Havoc 16 op (`_mutate_bytes`) + Splice + Phase 2 DSM/Copy payload 재구성 |
| `--timeout` | (config) | timeout group별 고정 + PS_ENTRY_EXIT_MARGIN_MS=105ms 가산 |

#### 예시 — `Identify` (CNS=0x01) seed가 어떻게 변형되는가

**초기 시드** (`nvme_seeds.py`):
```python
dict(cdw10=0x0001, nsid_override=0)
```
→ Seed 객체: `cmd=Identify`, `cdw10=0x0001`, `nsid_override=0`, `data=b''`

**`_mutate()` 후 (예시 변형)**:
- `cdw10 = 0x00010003` (schema mutation으로 CNTID=0x0001 추가)
- `nsid_override = 0xFFFFFFFF` (`[2]` nsid mutation, broadcast)
- `opcode_override = 0xC3` (`[1]` opcode mutation, vendor-specific)
- `force_admin = False` (`[3]` admin→io swap)

**최종 CLI**:
```bash
nvme io-passthru /dev/nvme0n1 \
  --opcode=0xc3 \              # opcode_override
  --namespace-id=0xffffffff \  # nsid_override
  --cdw2=0x0 --cdw3=0x0 \
  --cdw10=0x10003 \            # CNS + CNTID
  --cdw11=0x0 --cdw12=0x0 --cdw13=0x0 --cdw14=0x0 --cdw15=0x0 \
  --timeout=8000
```

→ Admin 명령 Identify가 IO passthru로 vendor opcode를 달고 전송됨 → dispatch table / nsid validation / opcode validation 경로 동시 탐색.

#### 예시 — `Write` (4KB) seed가 어떻게 변형되는가

**초기 시드**:
```python
dict(data=os.urandom(4096), cdw10=0, cdw11=0, cdw12=7)   # SLBA=0, NLB=7 (8 LBA = 4096B)
```

**`_mutate()` 후 (예시)**:
- `data` ← `_mutate_bytes(data)` (havoc 2~128 ops 적용 후)
- `cdw10=0xFFFFFFFF`, `cdw11=0x1` (`[6]` LBA pair → `slba=0x100000000`)
- `cdw12 = (cdw12 & ~0xFFFF) | 0x0F` (havoc CDW 또는 schema에서 NLB=15 = 16 LBA = 8KB)
- `data_len_override = 4097` (`[4]` NLB-relative → expected+1 boundary)

**최종 CLI**:
```bash
nvme io-passthru /dev/nvme0n1 \
  --opcode=0x01 \
  --namespace-id=0x1 \
  --cdw10=0xffffffff --cdw11=0x1 \   # SLBA = 0x100000000
  --cdw12=0xf \                       # NLB = 15 (8KB transfer 선언)
  --data-len=4097 \                   # 실제는 4097B 만 전송 (mismatch)
  --input-file=/tmp/.nvme_input.bin -w \
  --timeout=8000
```

→ NLB(8KB)와 data-len(4097B)의 declared/actual size mismatch + LBA 64-bit 경계 + 이상한 PRINFO 플래그 등이 한 번에 적용된 fuzz 명령.

---

### Mutation 대상 (Seed 필드별)

| 필드 | 타입 | 의미 | 변형 방법 |
|------|------|------|----------|
| `seed.data` | `bytes` | host buffer / payload | havoc 16 op (`_mutate_bytes`) + splice |
| `seed.cdw2`, `cdw3` | `uint32` | metadata pointer 등 | CDW mutation (random op 6종) |
| `seed.cdw10` ~ `cdw15` | `uint32 × 6` | 명령별 파라미터 (SLBA/NLB/FID/CNS 등) | CDW + schema (필드 단위) + Phase 1/2 |
| `seed.opcode_override` | `uint8 \| None` | opcode 강제 (디스패치 테이블 탐색) | `_mutate` `[1]` |
| `seed.nsid_override` | `uint32 \| None` | NSID 강제 (오류 핸들링 경로) | `_mutate` `[2]` |
| `seed.force_admin` | `bool \| None` | passthru 타입 강제 (admin↔io 교차) | `_mutate` `[3]` |
| `seed.data_len_override` | `int \| None` | 전송 크기 declared 강제 (NLB/cmd 추론 무시) | `_mutate` `[4]`, Phase 1 NLB/MDTS |

### Pipeline (`_mutate(seed)` 적용 순서)

```
1. Splice (15%)              — 다른 corpus Seed와 임의 split 지점 합성
2. Havoc (_mutate_bytes)     — 2^(1~7) = 2~128회 스택 mutation, MOpt 16 op
3. CDW 필드 변형 (30%)        — 1~3개 cdw 필드 무작위 선택, _mutate_cdw 적용
4. 확장 mutation 7개 (각 독립 확률, 누적 적용 가능):
   [1] opcode_override        OPCODE_MUT_PROB        = 10%
   [2] nsid_override          NSID_MUT_PROB          = 10%
   [3] admin↔io swap          ADMIN_SWAP_PROB        =  5%
   [4] data_len_override      DATALEN_MUT_PROB       =  8%   (NLB/MDTS boundary 우선)
   [5] schema-guided CDW      SCHEMA_MUT_PROB        = 30%
   [6] 64-bit LBA pair        LBA_PAIR_MUT_PROB      = 15%   (Read/Write/Compare/Verify/Copy)
   [7] DSM/Copy structured    STRUCT_PAYLOAD_MUT_PROB= 10%   (DSM/Copy 한정)
```

### Havoc operators (16개, MOpt 선택)

| # | Operator | 동작 | 제약 |
|---|----------|------|------|
| 0 | `bitflip1` | 1 byte의 1 bit XOR | — |
| 1 | `int8` | 1 byte에 interesting_8 대입 | — |
| 2 | `int16` | 2 byte에 interesting_8/16 대입 (LE/BE 50:50) | len≥2 |
| 3 | `int32` | 4 byte에 interesting_8/16/32 대입 (LE/BE) | len≥4 |
| 4 | `arith8` | 1 byte ± `random(1, 35)` | — |
| 5 | `arith16` | 2 byte ± delta (LE/BE) | len≥2 |
| 6 | `arith32` | 4 byte ± delta (LE/BE) | len≥4 |
| 7 | `randbyte` | 1 byte 완전 랜덤 | — |
| 8 | `byteswap` | 2 byte 위치 교환 | len≥2 |
| 9 | `delete` | 1~len/4 byte 삭제 | len>1 |
| 10 | `insert` | 1~min(128, len/4) byte 삽입 (clone/random 50:50) | — |
| 11 | `overwrite` | 1~min(128, len/4) byte 덮어쓰기 (clone/random) | len≥2 |
| 12 | `splice` | 다른 corpus Seed와 chunk 교차 | corpus≥2, len≥4 |
| 13 | `shuffle` | 2~16 byte 범위 in-place 셔플 | len≥2 |
| 14 | `blockfill` | 1~32 byte를 `0x00`/`0xFF`/`0x41`/`0x20`/random 으로 채움 | — |
| 15 | `asciiint` | 8 byte에 ASCII 숫자 (`-1`, `0x7FFFFFFF` 등) 삽입 | len≥8 |

**AFL++ Interesting 상수**:
- `INT_8`  = `[-128, -1, 0, 1, 16, 32, 64, 100, 127]`
- `INT_16` = `[-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767]`
- `INT_32` = `[-2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647]`
- `ARITH_MAX` = `35`

### MOpt (Mutation Operator Pilot)

- **Pilot 단계** (5000 iter): 16 operator 균등 확률
- **Core 단계** (50000 iter): `finds[i]/uses[i]` 비율로 정규화된 가중치 적용
- 사이클: `pilot → core → 통계 리셋 → pilot ...`
- 최소 확률 `0.01 / 16` 보장 (operator 완전 0 방지)

### `_mutate_cdw(value)` — CDW 32-bit 변형 (6종 중 1개)

- bitflip 1~4 bits
- arith ±1~35
- random interesting (`INT_8` ∪ `INT_16` ∪ `INT_32`)
- 완전 random 32-bit
- byte-level (32비트 중 랜덤 1 byte만 교체)
- endian swap (32-bit 또는 16-bit halves)

### Deterministic stage (`DET_BUDGET = 20%`)

새 coverage 발견 시드만 `_det_queue`에 등록. iteration의 20%에서 generator 1개씩 소비.

| Phase | 동작 | 대상 | 발화 수 (per seed) |
|-------|------|------|------------------|
| 1 | Walking bitflip | cdw10~cdw15 (cdw13~15는 0이면 skip) | 최대 32 × 6 = 192 |
| 2 | Arith ±1~10 | 동일 | 20 × 6 = 120 |
| 3 | Interesting 32-bit (8개 값) | 동일 | 8 × 6 = 48 |
| 4 | Byte-position interesting 8-bit | 4 byte × `INT_8` 9개 | 36 × 6 = 216 |

DET_BUDGET 도입 전엔 det queue 우선 소비로 단일 명령 ~400회 전용 실행이 연속 발생하던 다양성 편향 문제를 해결.

### Schema-guided CDW mutation (`SCHEMA_MUT_PROB = 30%`)

각 명령의 `CMD_SCHEMAS` 사전에서 CDW 필드 무작위 선택. 8가지 FieldType별 generation:

| FieldType | 후보 |
|-----------|------|
| `ENUM` | valid list ∪ (옵션) reserved 범위 random ∪ vendor 범위 random |
| `LBA` | `0, 1, nsze-2, nsze-1, nsze, nsze+1, 0xFFFF, 0xFFFFFFFF, random(0, nsze)` |
| `LBA_CNT` | `0, 1, 7, 0xFF, 0xFFFF, 0xFFFFFFFF, random(0, 0xFFFF)` |
| `FLAGS` | valid list 또는 비트 너비 mask 안에서 random |
| `SIZE_DW` | `0, 1, 0x7F, 0xFF, 0x3FF, 0x7FF, 0xFFFF, random` |
| `OFFSET_DW` | `0, 1, 0x100, 0x1000, 0xFFFF, 0xFFFFFFFF, random(0, 0xFFFFFF)` |
| `SLOT` | `0, 1, max_val, max_val+1, random` |
| `OPAQUE` | 비트 너비 mask 안에서 `_mutate_cdw(0)` |

42 commands × ~150 fields 정의 (`CMD_SCHEMAS`).

### Phase 1 — `data_len_override` (NLB/MDTS boundary, 8%)

Write/Read/Compare 한정. 다음 후보 풀에서 random.choice 후 `mutation_stats["datalen_nlb"]` / `datalen_mdts` 출처별 집계:

| 출처 | 후보 |
|------|------|
| **NLB-relative** | `expected = (NLB+1) × LBA_size`, `[expected-1, expected, expected+1, expected+PAGE_SIZE]` |
| **MDTS boundary** | `max_bytes = (1 << mdts) × PAGE_SIZE`, `[max-1, max, max+1]` (mdts > 0 시) |
| **Static fallback** | `[0, 4, 64, 512, 4096, 8192, 65536, random(1, 2MB)]` |

캐시: `_get_mdts()`는 `nvme id-ctrl`에서 5000 exec마다 갱신.

### Phase 2 — 64-bit LBA pair (15%)

대상: Read / Write / Compare / Verify / Copy. cdw10+cdw11을 64-bit SLBA 단일 단위로 변이.

```
SLBA 후보: 0, 1, nsze-2, nsze-1, nsze, nsze+1,
           0xFFFFFFFF, 0x100000000 (cdw10=0, cdw11=1 — high dword 경로),
           random(0, nsze)

cdw10 = slba & 0xFFFFFFFF
cdw11 = (slba >> 32) & 0xFFFFFFFF
```

캐시: `_get_nsze()`는 `nvme id-ns`에서 5000 exec마다 갱신.

### Phase 2 — DSM / Copy structured payload (10%)

`CDW` 선언과 payload 크기가 연동되는 두 명령에 한해, 4가지 경계 케이스로 재구성. `data_len_override`는 이때 None으로 리셋되어 mutation 잔존 mismatch 제거.

#### DatasetManagement (`CDW10[7:0] = NR`, payload = `(NR+1) × 16B` range entry)

| mut_type | NR (declared) | payload | 의도 |
|---|---|---|---|
| 0 | 0 | 1 entry (16B) | 정상 단일 |
| 1 | 255 | 256 entries (4096B) | 최대 정상 |
| 2 | 255 (declared) | 1 entry (16B) | declared/actual mismatch (underflow) |
| 3 | 0 | empty (`b''`) | NR=0 + zero payload |

각 entry: `Context Attrs(4B) + LBA Count(4B) + SLBA(8B)`, LBA Count/SLBA는 nsze 경계 후보.

#### Copy (`CDW12[11:8] = NR` 4-bit, `CDW10/11 = dest SLBA`, payload = `(NR+1) × 32B` source range)

| mut_type | NR | payload | dest SLBA |
|---|---|---|---|
| 0 | 0 | 1 entry (32B) | 경계값 |
| 1 | 3 | 4 entries (128B) | 경계값 |
| 2 | 3 (declared) | 1 entry (32B) | declared mismatch |
| 3 | 0 | empty | 경계값 |

각 entry: `SLBA(8) + NLB(2) + RSVD(2) + EILBRT(4) + ELBATM(2) + ELBAT(2) + RSVD(12) = 32B`.

### Phase 3 — Sequence (5%, max 10/100-window)

상세는 [Builtin sequence](#builtin-sequence) 참조. 요약:

| 시퀀스 | ctx 모드 | 의미 |
|--------|---------|------|
| `Write → Read` | `full` | Read가 Write 결과 LBA/data 회수 |
| `Write → Write` | `lba_nlb` | 동일 LBA 다른 data overwrite (FTL 매핑) |
| `Write → Compare` | `full` | data 일관성 검증 (Compare 필요) |
| `FWDownload → FWCommit` | — | FW 에러 핸들링 (`--all-commands` 필요) |

### 입력 소스 (mutation 발화 전 단계, 시드 선택 순위)

| 소스 | 빈도 | 설명 |
|------|------|------|
| `[3a]` corpus SequenceSeed continuation | 시퀀스 진행 중 | 이전 iteration 시작된 시퀀스 다음 명령 |
| `[3b]` builtin sequence continuation | 시퀀스 진행 중 | 이전 iteration 시작된 builtin 다음 명령 |
| `[3c]` 신규 builtin sequence | `SEQ_PROB = 5%` | 새 시퀀스 시작 |
| CSFuzz C2 state replay | `p` 확률 | `state_corpus`의 100-명령 시퀀스 전체 replay |
| 일반 corpus mutation | `1 - random_gen_ratio = 80%` | `_select_seed()` 가중치 + `_mutate()` |
| 완전 랜덤 생성 | `random_gen_ratio = 20%` | `os.urandom(64~512)` + 랜덤 명령 |

### 통계 키 (`mutation_stats`)

| 키 | 의미 |
|----|------|
| `corpus_mutated` | corpus seed mutation 횟수 |
| `random_gen` | 완전 랜덤 생성 횟수 |
| `opcode_override` | opcode mutation 적용 |
| `nsid_override` | NSID mutation 적용 |
| `force_admin_swap` | admin↔io swap |
| `data_len_override` | data_len mutation |
| `datalen_nlb` / `datalen_mdts` | data_len 출처별 |
| `schema_field` | schema-guided field |
| `lba_pair_64bit` | 64-bit LBA pair |
| `dsm_structured` / `copy_structured` | structured payload |
| `seq_builtin` | sequence 모드로 발행된 명령 누적 |

종료 summary 텍스트 + `mutation_chart.png` (3 subplot: MOpt efficiency / uses+finds / source 분포) 에서 시각화.

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
output/pc_sampling_v7.7.0/
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
    ├── command_comparison.png           (v7.6 unknown 버킷팅)
    ├── mutation_chart.png
    ├── coverage_heatmap_1d.png          (v7.6 global only + hot-spot 라벨)
    ├── coverage_growth.png              (* Ghidra 연동, v7.6 velocity+plateau+milestone)
    ├── firmware_map.png                 (* Ghidra 연동, v7.6 BB-gradient+전체 함수+Top-N)
    └── csfuzz_dynamics.png              (v7.6 신규, state 활성 시)
```

v7.6에서 제거된 산출물:
- `{cmd}_cfg.dot/.png` — edge 많아지면 가독성 낮음
- `edge_heatmap_2d.png` — PC 샘플링에서는 진짜 edge가 아니라 노이즈
- `uncovered_funcs.png` — firmware_map + 종료 summary 텍스트로 대체

---

## 버전 이력

| 버전 | 주요 변경 |
|------|-----------|
| **v7.7** | S1+S2 PM Robustness Perturbation 도입. 기존 PM rotation slot 에 PCIe config 13 비트 perturb (LNKCTL/DEVCTL2/PMCSR/L1SS, 변경 유지) + CLKREQ# 4 mode (missed_wake / extended_wait / short_pulse / rapid_toggle) 통합. PMCSR D1/D2 일회성 forced (50ms→D0 + readback 검증). **`--pm` 옵션 활성 시 자동 동작** (별도 옵션 없음). Completion Timeout / Common Mode Restore 등 host timeout 로직 영향 비트 제외 — vendor 클레임 가능 영역만. S1/S2 preflight 추가. forced_idle slot 을 APST 자율 PS3→PS4 진입 방식으로 전환 (짧은 ITPT로 OS 동작 모사 + 다른 슬롯과 충돌 X). `_generate_replay_sh()` 가 `pcie_pm_bit`/`clkreq`/`pcie_state(restore)` event 까지 setpci+PMU+SetFeatures 시퀀스로 정확히 재생. D3 복구 시 L0+D0 setpci 가 PS0 SetFeatures 보다 먼저 기록되도록 순서 보정. Init: idle universe 수집을 PM preflight 앞으로 이동. Crash artifact: replay/dump/log/dmesg 모두 `crash_<ts>/` 단일 폴더, 상대경로 `--input-file` 로 통째로 옮기기 가능, 시분초 timestamp. Device 호환: WSL2/namespace-only 환경 자동 fallback + `nvme_namespace` path 기반 보정, nvme-cli 구버전 text 출력 파싱 fallback, idle 직후 Device Information 박스 (Model/Serial/FW/PCIe BDF/ASPM/Namespace size) 출력, UTF-8 logging encoding 명시. |
| v7.6 | 시각화 개선: coverage_growth(velocity bar + plateau + milestone), firmware_map(BB gradient + 전체 함수 treemap + Top-N 라벨), csfuzz_dynamics 신규(3-panel p/corpus/m1m2). per-command CFG 생성 제거. |
| v7.5 | SequenceSeed corpus + 2-pass favored cull 일관성. Sequence ctx를 Write mutation 결과에서 파생 + `full`/`lba_nlb` 두 모드 지원 (Write→Write는 data 분리). seq_corpus/ replay .sh 자동 저장 + 고아 청소. BUILTIN_SEQUENCES에 기본 모드 시퀀스(Write→Read, Write→Write) 추가. SequenceSeed window 초과 fallback에서 exec_count 보정. `--no-jlink-dump` 추가. CLI 옵션 51→19. DSM/Copy NR 마스크 수정. |
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
