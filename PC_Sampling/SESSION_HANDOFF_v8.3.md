# 세션 핸드오프 — v8.3 현재 구현 상태 (2026-06-09)

다음 세션 컨텍스트 복원용. 이 파일 + `git log --oneline -20` + 최근 commit diff 만 보면
즉시 작업 가능. v7.8 이전 내용은 `SESSION_HANDOFF_v7.8.md` 참조.

---

## 작업 대상

- **저장소**: `/home/ssd/gdbfuzz/` (branch `main`, GitHub `RelaxWide/Real_Fuzzing`)
- **현재 최신 본체**: `PC_Sampling/pc_sampling_fuzzer_v8.3.py` (FUZZER_VERSION="8.3.0")
- **버전당 파일 1개** 패턴: 버전업 시 `.py`/`.md` 를 새 이름으로 복사.
- **⚠️ 공유 파일(버전 안 붙음 — 복사 금지, 모든 버전이 공유)**:
  - `fuzzer_config.json` — v8.3 신규. 모든 사용자 설정값.
  - `state_fields.py` — **v8.3 부터 deprecated**(v8.3 은 import 안 함, JSON 으로 이전). v8.2 이하만 사용.
  - `nvme_seeds.py` — NVMe 시드 템플릿.

---

## 지원 제품 (3종)

| 제품 | interface | core | coverage 샘플러 | state 세트 | UFAS/JLink dump |
|------|-----------|------|-----------------|-----------|------|
| **PM9M1** | SWD | 3 (R8) | OpenOCD PCSR (비침습) | r8 (25필드) | ✅ / ✅ |
| **BM9H1** | JTAG | 2 (R8) | OpenOCD PCSR (비침습) | r8 (25필드) | ✅ / ✅ |
| **P9** | SWD | R5 단일 | **J-Link halt (pylink)** | p9 (22필드) | ❌ / ❌ |

```bash
sudo python3 pc_sampling_fuzzer_v8.3.py --product PM9M1 --nvme /dev/nvme0n1
sudo python3 pc_sampling_fuzzer_v8.3.py --product P9    --nvme /dev/nvme0n1   # pylink 필요
# 설정 변경은 코드 아닌 fuzzer_config.json 편집. --config PATH 로 교체 가능.
```

---

## v8.3 핵심 1: 모든 사용자 설정을 `fuzzer_config.json` 으로 외부화

### 동작 원리 (코드 변경 최소화)
- import 시점에 `load_user_config(_early_config_path())` 로 JSON 로드 → `_cfg_hexnorm()` 이
  `"0x.."` 문자열을 int 로 변환.
- `_CFG['globals']`/`['paths']`/... 를 **기존과 같은 이름의 모듈 전역**(FW_ADDR_START,
  NVME_TIMEOUTS, PRODUCT_PROFILES, mutation 확률, ...)에 주입. FuzzConfig 정의 **이전**에 실행되어
  dataclass 기본값(`= SAMPLE_INTERVAL_US` 등)이 자동으로 JSON 값을 픽업 → 나머지 코드 무수정.
- **우선순위**: JSON 기본값 → 제품 profile override → CLI 인자 override(최우선).
- **누락 시**: 명확한 fatal 에러(`[FATAL] 설정 파일이 없습니다`). `--config` 는 import 시점
  `_early_config_path()` 가 argparse 보다 먼저 sys.argv 에서 추출.

### JSON 섹션 구조
`globals`(FW주소·OpenOCD/JLink·PCSR·DPIDR·NVMe device) · `paths`(fw_bin·pmu_script·ufas_binary·
jlink_dump_script·debug_package_dir·parser_script·engine_errint_logs) · `timeouts`(global 기본) ·
`sampling` · `diagnose_idle_calibration` · `fuzzing` · `mutation` · `power` · `visualization` ·
`runtime_hw`(clkreq 핀/전압·fw_xfer/slot·prefill_bs·boot_sweep·settle_sweep·nvme_lba_size) ·
`state_fields`(r8/p9 세트) · `products`(PM9M1/BM9H1/P9) · `strategy`(blocked_admin_opcodes·
builtin_sequences·pcie_pm_fuzz_targets·clkreq_fuzz_modes).

### 코드 유지(외부화 제외 — 설정 아님)
`OUTPUT_DIR`(버전 종속 f-string), `CMD_SCHEMAS`/`NVME_COMMANDS`(명령·필드 구조 정의),
`POWER_COMBOS`(range 생성식), 파생/런타임(`_PAGE_SIZE`/`_FW_BIN_PATH`/`_PMU_SCRIPT`/`_OPCODE_TO_NAME`/
`PRODUCT_CONFIGS`/`_NVME_NS_SUFFIX_RE`).

### 메서드 본문에 박혀 있던 경로 → 명명 상수 승격 후 JSON 주입
`UFAS_BINARY`/`JLINK_DUMP_SCRIPT`/`DEBUG_PACKAGE_DIR`/`PARSER_SCRIPT_SH`/`PARSER_SCRIPT_PY`/
`ENGINE_ERRINT_LOGS` (paths 섹션). FuzzConfig 묻힌 기본값(`BOOT_SWEEP_S`/`CLKREQ_*`/`FW_XFER_SIZE`/
`FW_SLOT`/`PREFILL_BS`/`SETTLE_SWEEP*`/`NVME_LBA_SIZE`/`PM_TEST_CYCLES`)도 상수 승격 후 JSON.

### 동작 보존 검증 방법 (재현 가능)
v8.2(하드코딩) vs v8.3(JSON) 의 81 상수 + PRODUCT_PROFILES + 72 FuzzConfig 필드를 importlib 로
양쪽 로드해 1:1 비교 → 일치(출력 폴더 버전문자열만 차이, 의도적). 새 검증 필요 시 동일 패턴 사용:
```python
import importlib.util, sys
def load(n,p):
    s=importlib.util.spec_from_file_location(n,p); m=importlib.util.module_from_spec(s)
    sys.modules[n]=m; s.loader.exec_module(m); return m
```
(주의: importlib 로 합성 모듈명 로드 시 dataclass `__module__` 이슈 → `sys.modules[n]=m` 선등록 필수.)

---

## v8.3 핵심 2: 제품별 State 관측 필드 (JSON `state_fields`)

- `fuzzer_config.json` `state_fields` 에 **세트별** 정의: `r8`(PM9M1/BM9H1, 25필드, = 옛
  state_fields.py STATE_FIELDS 와 동일) / `p9`(P9, 22필드 = r8 에서 **LID 0xDF `df_*` 3개 제외**).
  제외된 것: `df_crc_errors`/`df_max_pe_cycles`/`df_avg_pe_cycles`(P9 에 LID 0xDF 페이지 없음).
- **P9 유지**: LID 02h(SMART 5필드)·LID 01h(`err_status_field`)·SecRecv(SECP=0xFE/SPSP=0x3D sec_* 다수).
- 제품의 `state_fields` 키가 세트명을 가리킴(PM9M1/BM9H1→`r8`, P9→`p9`). main() 에서
  `STATE_FIELD_SETS[setname]` 해석 → `config.state_fields` 로 주입.
- `NVMeStateMonitor(device, config.state_fields)` + `_log_state_snapshot()` 이 `self.config.state_fields`
  사용(모듈 전역 STATE_FIELDS import 제거). → P9 는 LID 0xDF get-log 를 **안 함**(검증: P9 monitor
  `_vendor_lids=[(1,64)]`, PM9M1 `[(1,64),(223,512)]`).
- 이 state 관측 명령(SMART/get-log/SecRecv)은 PM9M1 과 동일하게 P9 에서도 수행됨(state_enabled 기본 True).

### 주기적 전체 State 출력 + 터미널 (PM9M1·P9 공통)
- 10000 exec 마다 `_log_smart()` + `_log_state_snapshot()` 호출(`run()` 내 `executions % 10000 == 0`).
- `_log_state_snapshot()` 은 모든 state 필드(smart/vendor LID/SecRecv) **명령 수행 + 값 전체** 를
  `log.warning("[State-Snap] ...")` 로 출력.
- v8.3: 터미널 필터 `_FuzzingTerminalFilter._ALLOW` 에 `[State-Snap]`/`[SMART]` 추가 → **터미널에도**
  표시(콘솔 핸들러 레벨 WARNING, snapshot 이 warning 이라 통과).

---

## v8.3 핵심 3: 제품별 timeout override

- `globals` 의 `timeouts` 는 기본값. 각 제품 `nvme_timeouts`(+선택 `nvme_passthru_timeout_ms`/
  `nvme_kernel_timeout_sec`)가 그 위를 덮어씀. main(): `{**NVME_TIMEOUTS, **product.nvme_timeouts}`,
  passthru/kernel 은 `_profile.get(..., GLOBAL)`. FuzzConfig 에 passthru/kernel 도 전달.
- **PM9M1/BM9H1**: 현재 global 값으로 시드(불변). command8000/format120000/flush2000/verify20000 등.
- **P9** (`products.P9.nvme_timeouts`): 예외 빼고 전부 **30s** — command/flush/selftest_short/
  selftest_ext/verify=30000, **format=300000(300s)**, **aer=600000(600s)**. 미지정 그룹은 command(30s) 폴백.

---

## P9 전용 J-Link halt 샘플러 (v8.1, 현재 유지)

- P9 는 **DBGPCSR 미구현**(비침습 불가) → `sampler_type='jlink_halt'` → `JLinkHaltSampler`
  (`OpenOCDPCSampler` 상속). OpenOCD telnet halt(v8.0)의 소켓 desync(빈 reg pc→resume 누락→R5 wedge)
  문제를 pylink in-process `halt → register_read(PC) → JLINKARM_Go()` 블로킹 API 로 대체.
- 핵심: `_jlink_lock`(스레드 직렬화), `restart()` 절대 금지(CPU 리셋 — `JLINKARM_Go()` 만),
  halted() 폴링 ~50ms 상한, PC reg index 자동 탐지(`--pc-reg-index` override).
- OpenOCD 전용 메서드(`_telnet_cmd`/`_open_telnet`/...) no-op override. USB 충돌 가드:
  `_shutdown_openocd_for_jlink` early-return, 크래시 모니터는 `read_stuck_pcs` 경유.
- `pip3 install pylink-square` 필요(import 가드 — 미설치 호스트는 P9 선택 시에만 영향).
- 평가환경 bring-up: `P9_BRINGUP.md` (PC reg index 확인, halt vs NVMe timeout `--go-settle`,
  BB/func 파일 `basic_blocks_P9.txt`/`functions_P9.txt` 배치).

---

## 최근 버그픽스

### APST/KeepAlive set-feature → 컨트롤러 char device (386b10d)
- **증상**: APST set-feature 가 nvme0n1 이 아닌 디바이스에서 실패.
- **원인**: APST(0x0C)/KeepAlive(0x0F)는 컨트롤러 스코프인데 namespace 경로로 보내면 nvme-cli 가
  NSID 를 실어 보냄 → 일부 펌웨어(P9 등)가 NSID≠0 거부.
- **수정**: 신규 `_ctrl_device()` — nvme_device 에서 컨트롤러 char device 유도
  (`/dev/nvme0n1`→`/dev/nvme0`, 없으면 namespace 폴백). 5개 사이트(`_apst_disable`/`_apst_enable_short_itpt`/
  `_apst_restore`/`_keepalive_disable`/`_keepalive_restore`) 적용.

### UFAS bus hex→decimal (5ec8534, v8.0)
- `_get_nvme_pcie_bus()` 가 sysfs/lspci hex bus("81")를 ufas 에 그대로 넘겨 실패 → `int(x,16)` decimal 변환.

### 가성 불량 방지 (79155d9, v8.0)
- `BLOCKED_ADMIN_OPCODES={0x00,01,04,05,0C,7C}` admin-passthru 전송 차단(kernel I/O 큐 깨짐 방지).

---

## 최근 커밋 (시간 역순)
```
386b10d fix(v8.3): APST/KeepAlive set-feature → 컨트롤러 char device (NSID 의존 실패 수정)
46c92c8 feat(v8.3): 제품별 state 필드(JSON) + 주기적 전체 state 터미널 출력 + P9 timeout
46ae7d1 feat(v8.3): 제품별 nvme_timeouts override
f8ed4c5 feat(v8.3): 모든 사용자 설정값·경로를 fuzzer_config.json 으로 외부화
dfc222d chore(v8.2): P9 profile 정리 — J-Link halt 미사용 키 제거 + .get 관용화
9729fb3 feat(v8.1): P9 전용 J-Link(pylink) halt 샘플러
```

---

## 알려진 미완 / 주의사항

- **`aer`(600s) 미배선**: P9 nvme_timeouts 에 `aer:600000` 넣었으나, Async Event Request(admin
  0x0C)는 `BLOCKED_ADMIN_OPCODES` 로 전송 차단 + NVME_COMMANDS 에 AER 명령 없음 → `aer` 그룹을
  실제 쓰는 명령이 없음. JSON 값은 준비됨, 적용하려면 AER 명령에 `timeout_group="aer"` 배선 필요.
- **`state_fields.py` deprecated**: v8.3 은 미사용(JSON 으로 이전). v8.2 이하 호환 위해 파일은 유지.
  상단에 deprecation 주석 추가 검토했으나 미적용 — 필요 시 추가(데이터 안 건드리면 옛 버전 안 깨짐).
- **dev 샌드박스에 NVMe 장치 없음**: 이 개발 머신엔 `/dev/nvme*` 없어 import/문법/등가 검증만 가능.
  실제 fuzzing/하드웨어 동작은 평가 환경에서 사용자가 확인.
- **P9 bring-up 미완**: PC reg index 실측, halt vs NVMe timeout 튜닝, BB/func 파일 배치 (`P9_BRINGUP.md`).
- **`r5_pcsr.cfg`**: P9 가 OpenOCD 미사용이라 코드 미참조(파일은 수동 진단용으로 유지).
- **`OpenOCDHaltSampler`**: `--sampler halt` 로만 선택 가능한 범용 fallback(기본 쓰는 제품 없음).

---

## 협업 규칙 (유지)
- 답변 짧게, diff 가 말하게. 추측보다 실제 파일 확인. commit+push 는 사용자 워크플로(매번).
- 동작 보존이 최우선 — 변경 시 v8.2 등가 검증 같은 안전망 사용.
- 설정/경로/상수/state필드/timeout 변경은 **코드 아닌 `fuzzer_config.json` 편집**.

## 다음 세션 시작 절차
1. `cat PC_Sampling/SESSION_HANDOFF_v8.3.md` (이 파일)
2. `git log --oneline -15`
3. `cat PC_Sampling/fuzzer_config.json` (현재 설정 상태)
4. 최신 본체: `PC_Sampling/pc_sampling_fuzzer_v8.3.py`
