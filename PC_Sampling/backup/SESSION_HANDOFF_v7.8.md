# v7.8 세션 핸드오프 — 2026-05-29

다음 세션에서 컨텍스트 복원용 요약. 이 파일 + `git log --oneline -20` + 최근 commit
diff 만 보면 즉시 작업 가능.

---

## 작업 대상

- **저장소**: `/home/ssd/gdbfuzz/` (branch `main`, GitHub `RelaxWide/Real_Fuzzing`)
- **핵심 파일**:
  - `PC_Sampling/pc_sampling_fuzzer_v7.8.py` (~10,600줄, FUZZER_VERSION="7.8.0")
  - `PC_Sampling/pc_sampling_fuzzer_v7.8.md` (사용법, ~55KB)
  - `PC_Sampling/DebugPackage/smi_mem_parsing/customer_parsing_dump.sh` (vendor parser Linux wrapper)
- **베이스**: v7.7 복사 → v7.8 신규 기능 추가

---

## v7.8 주요 신규 기능 (구현 완료)

### 1. `--unsupported-skip` — EngineErrInt 자동 검출 + 복구
- timeout 발생 → JLink dump → vendor parser (`customer_parsing_dump.sh`) 실행
- 결과 폴더의 `g16arEventLog.txt` / `g16arEventLog2.txt` 에서 `EngineErrInt` **count delta** 검출
  (NAND 영구 로그 false positive 방지 위해 baseline count 추적: `self._engineerrint_baseline`)
- 검출 시: UFAS dump / artifact 수집 **skip** + power cycle 후 메인 루프 **계속**
- 미검출 시: 기존 timeout crash 흐름 (UFAS + break)
- `crashes/crash_<ts>/SKIPPED.marker` 작성
- stats: `unsupported_skipped` 카운터

### 2. `--no-jlink` — J-Link 없이 NVMe-only fuzz
- `NullSampler` 클래스 추가 (coverage 0, OpenOCD 없음)
- PM perturbation 만 검증하고 싶을 때 사용

### 3. 복구 sequence (`_recover_after_unsupported_skip`)
```
SIGKILL nvme-cli → PMU OFF → 방전 → PCIe remove (driver unbind)
  → PMU ON → boot wait (max(boot_sweep_s, 5s)) → rescan retry → 재초기화
```
- 시행착오로 정착된 순서. PCIe remove 필수 (안 하면 wedged driver state 에 새 device
  붙어 id-ctrl 단계에서 admin queue hang)
- nvme_core admin/io_timeout 은 **손대지 않음** — 짧게 잡으면 recovery 후 id-ctrl
  polling 까지 그 값에 갇혀 boot 안 끝나서 실패함

---

## 최근 7개 commit (시간순 역순)

```
0bf3d7f docs(v7.8): top docstring + 코드 내 긴 주석 정리
62d160d fix(v7.8): _probe_device 에서 nvme id-ctrl 제거 — 좀비 subprocess FD 점유 차단
be3c9c3 fix(v7.8): _shutdown_openocd_for_jlink — 멱등 flag 제거, 매번 alive 체크
a28e1fe docs(v7.8): docstring 압축 + md 사용법 섹션 처음 사용자용 확장
cc4dd5f docs(v7.8): docstring + md 갱신 — recovery / EngineErrInt / probe 진단 반영
8da3013 fix(v7.8): _por_pcie_rescan — v7.7 의 단순 hammer 방식으로 회귀 + retry 유지
58b788f fix(v7.8): _por_pcie_rescan — char + namespace device 둘 다 생성 대기
```

---

## 최근 해결한 버그 — 재발 가능성 있는 것들

### A. 두번째 J-Link dump 실패 (commit be3c9c3)
- **증상**: `--unsupported-skip` 모드에서 첫번째 timeout 의 J-Link dump 는 성공, 두번째는
  "J-Link is already open" 으로 실패
- **원인**: `_shutdown_openocd_for_jlink` 의 `_openocd_shutdown_done` idempotent flag 가
  recovery 의 `_reconnect()` 후에도 reset 되지 않아 두번째 호출에서 shutdown 자체를 skip
- **수정**: flag 제거. 매번 `sampler._openocd_alive()` 로 실제 상태 체크

### B. JLink/UFAS dump 후 manual `echo 1 > .../remove` hang (commit 62d160d)
- **증상**: v7.7 에선 정상이던 사용자 수동 PCIe remove 가 v7.8 에서 hang. lspci 엔 device
  보임
- **원인**: v7.8 신규 `_probe_device` 가 `nvme id-ctrl` 을 daemon thread + subprocess 로
  던졌는데, device hung 상태일 때 subprocess 가 D-state 좀비로 잔류하면서 kernel nvme
  FD 점유 → 후속 PCIe remove 가 그 FD ioctl 끝나기를 기다리며 영구 block
- **수정**: `_probe_device` 를 sysfs read only 로 변경. nvme id-ctrl 호출 부 통째 제거.
  잃는 진단 정보: `id-ctrl=OK/FAIL/NO_RESPONSE` 라인만. `dev/bdf/link` 는 유지

### C. PCIe remove 한참 wedged 상태로 잡혀 id-ctrl hang
- **원인**: PMU off → remove 없이 PMU on → rescan 하면 driver state 가 wedged 인 채로
  새 device 붙음 → admin queue wedged → id-ctrl hang
- **해결**: remove 단계 필수 — PMU off (link down + AER) 후 remove (driver unbind) 후
  PMU on (fresh bind)

### D. customer_parsing_dump.py 가 Linux 에서 동작 불가
- 원래 Windows 전용 (bundled Python + `..\python\python.exe`). `module.share` import,
  `intelhex` 패키지, `\\*.bin` glob 등 Windows 특화
- **해결**: `customer_parsing_dump.sh` wrapper. cwd 설정 + PYTHONPATH 에 DebugPackage/
  와 bundled site-packages 추가 + 시스템 python3 사용
- 분석 폴더명: `<dump.bin>_customer_analysis` (확장자 포함). 후보 6개 탐색 (stem×name × 3 location)

---

## 알려진 다음 작업 / 미해결

### 사용자 확인 대기
- 이번 commit (62d160d, 0bf3d7f) 들이 다음 fuzzer 실행에서 잘 동작하는지 검증 필요
  - `--unsupported-skip` 모드 두번째 dump 정상?
  - manual `echo 1 > /sys/.../remove` 즉시 통과?
- 회귀 가능성 — `_probe_device` 가 sysfs only 로 변하면서 `id-ctrl=NO_RESPONSE` 진단 정보가
  사라짐. 그 정보가 필요한 상황이 생기면 별도 함수 (`_probe_nvme_id_ctrl_oneshot`) 를
  만들고, recovery 가 성공한 직후처럼 device 가 healthy 일 것이 확실한 경우에만 호출

### 미완성 로드맵 (memory/roadmap_todo.md 에 보존, 파일에선 제거함)
- Phase 1: PC 필터 범위 multi-range 진단, BB coverage 정확도 검증
- Phase 2: --prefill 강화, state_fields.py 추가 지표
- Phase 3: ScenarioSeed, POR 직후 boot_sweep injection
- Phase 4: TransactionSeed, 시퀀스 자체 mutation (insert/delete/swap)
- Phase 5: 안전한 추가 명령 활성화

---

## 사용자 협업 규칙 (배운 것)

- **답변 짧게** — 코드 변경 후 변경점 한두 문장 + diff 가 말하게. 장황한 요약 금지
- **추측보다 확인** — "v7.7 에서 어땠는지" 묻거나 사용자가 직접 비교 요청하면 실제 v7.7
  파일 (`/home/ssd/gdbfuzz/PC_Sampling/pc_sampling_fuzzer_v7.7.py`) 읽어서 확인할 것
- **destructive 동작 / git push** 은 매번 commit + push 하는 게 사용자 워크플로 (별도 확인 불필요)
- **docstring**: 한 줄 요약 + 필요시 짧은 줄 몇 개. 디테일은 md 로
- **md**: 사용법 + 트러블슈팅 표 + 디렉토리 구조도까지 (처음 사용자 기준)

---

## 디렉토리 구조 (참고)

```
/home/ssd/gdbfuzz/
├── PC_Sampling/
│   ├── pc_sampling_fuzzer_v7.8.py        ← 작업 파일
│   ├── pc_sampling_fuzzer_v7.8.md         ← 사용법
│   ├── pc_sampling_fuzzer_v7.7.py         ← 비교용 베이스라인
│   ├── pc_sampling_fuzzer_v7.7.md
│   ├── pmu_4_1.py                          ← PMU GPIO 제어 (PowerOff/On)
│   ├── ufas                                ← UFAS 펌웨어 덤프 바이너리
│   ├── DebugPackage/
│   │   ├── smi_mem_parsing/
│   │   │   ├── customer_parsing_dump.py   ← vendor 제공 parser
│   │   │   └── customer_parsing_dump.sh   ← 우리가 만든 Linux wrapper
│   │   ├── module/                          ← parser 의존 모듈 (PYTHONPATH 대상)
│   │   ├── python/Lib/site-packages/       ← bundled pure-Python 패키지 (intelhex 등)
│   │   └── SnapShot/SnapShot.csv
│   ├── SESSION_HANDOFF_v7.8.md             ← 이 파일
│   └── ...
└── (작업 디렉토리 루트)
```

---

## 다음 세션 시작 시 권장 절차

1. `cat PC_Sampling/SESSION_HANDOFF_v7.8.md` (이 파일)
2. `git log --oneline -10`
3. `git status` — 미커밋 변경 확인
4. 마지막 3개 commit diff 확인: `git show 0bf3d7f`, `git show 62d160d`, `git show be3c9c3`
5. 사용자 추가 요청 받으면 그대로 진행
