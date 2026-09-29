# v11 예외 주입 / 사전시험

2026-09-23. BM9K1·PM9M1 계열부터 여러 제품에 적용할 구조.
**구현·자동시험과 실기 통과는 별개다. 이 환경에서 NVMe/PMU 조작은 하지 않았다.**

## 개발·회귀 검사 기준 (2026-09-29)

앞으로 기능 추가와 수정은 **v11에만 적용**한다. v10.3은 안정된 이전 버전으로 보존하며,
v11과의 차이 고정 검사나 v10.3에서 v11을 생성하는 절차는 사용하지 않는다.
v10.3에 남은 비활성 예외 hook도 이번 변경에서 정리하지 않는다.

공통 회귀 테스트의 `FUZZER_FILE`은 v11이다. 과거 버전 이름이 붙은 테스트도 실행·소스
검사 대상은 v11로 전환했다. 장치 경로 AST 동결 검사는 v10.2/v10.3을 유지하면서
v11의 전송 함수와 샘플러 클래스까지 검사한다. v11 override는 기존에 검토된 v10.3
해시를 그대로 사용했으며 현재 코드에서 해시를 새로 생성하지 않았다. 향후 의도적인
장치 경로 변경은 해당 경로를 검토한 뒤 v11 전용 amendment와 override로 기록한다.

## 규격 확인과 Ubuntu 적용

읽은 원본: `G:\NVMe_Spec\PCIe_Express_5.0.pdf`
이 환경 경로: `/mnt/g/NVMe_Spec/PCIe_Express_5.0.pdf` (1299페이지).
PCI Express Base Specification Revision 5.0 Version 1.0의 다음 부분을 확인했다.

| 근거 | 구현에 적용한 의미 |
|---|---|
| §4.2.4.9, pp.309–310 | Fundamental reset과 프로토콜 hot reset을 구분 |
| §6.6.1, p.552 | Warm은 주전원 재인가 없는 Fundamental reset. 발생 수단은 플랫폼별이며 REFCLK OFF/ON을 필수 순서로 규정하지 않음 |
| §6.6.1, pp.553–554 | Conventional reset 뒤 링크/설정 접근 준비 시간이 필요. SBR은 hot reset을 발생시킴 |
| §6.6.1, p.554 | Tperst, Tpvperl, Tfail, Tperst-clk 수치는 플랫폼/폼팩터에서 정의해야 함 |
| §6.6.2, pp.554–557 | FLR은 선택 지원, 함수 단위이며 링크 상태를 리셋하지 않음. 미완료 트랜잭션/재초기화를 고려해야 함 |

다른 환경의 `pcireset(1) → pciRefClk(0) → pciRefClk(1) → pcireset(0)`을
Ubuntu 공통 API로 번역하지 않는다. 함수의 1/0을 물리 GPIO 전압으로 추정하지 않는다.
우리 WARM 경로는 **주전원 유지 + GPIO7 PERST Low/High**다. 독립 REFCLK gating은
확인된 플랫폼 API가 없어 `UNCONFIGURED`로 보고한다. CLKREQ(GPIO1)도 대체 수단으로
쓰지 않는다. 별도 REFCLK 토글은 현재 플랫폼에서 구현됐다고 주장하지 않는다.

FLR/hot reset은 kernel `reset_method`를 각각 `flr`/`bus` 하나로 지정하고 `reset`을
실행한 뒤 원래 설정으로 복원한다. 다른 방식으로 자동 fallback하지 않는다.
Linux NVMe 드라이버의 reset_prepare/reset_done은 I/O 정리와 재초기화를 수행하므로,
이를 갑작스러운 전기적 단절이나 SSD 내부 명령 처리 중 주입으로 단정하지 않는다.
실제 기록은 `host_process_alive_only`다.

## 파일 구성

| 파일 | 역할 |
|---|---|
| `pc_sampling_fuzzer_v11.py` | 독립 퍼징 엔진·CLI. 명령 생성·전송·가드·샘플링·LLM·PM·예외 주입·사전시험·불량 보존·복구·종료 처리 포함. v10.3 파일을 로드하지 않는다 |
| `tests/test_v11_*.py` | 예외 제어·실제 v11 전송·복구·독립 실행 회귀 테스트 |

MRO는 `NVMeFuzzer → ExceptionFuzzerMixin → LearningMixin → _V101Fuzzer`다.
`_V101Fuzzer`는 v11 파일 내부에 포함된 엔진이다. v10.3에서 검증된 가드·LLM·PM 구현을
v11에 포함했으며, v10.3 파일을 수정해도 v11에 자동 반영되지 않는다.
`strategy.blocked_cdw_rules`(0xC0+CDW12=0x2 차단), `excluded_opcodes`,
`blocked_admin_opcodes`와 기존 LLM 프롬프트 필터·task 회전판을 유지한다.
예외 mixin은 v11 내부 전송 구현에 `super()`로 위임해 동일한 가드를 통과한다.

배포 시 `pc_sampling_fuzzer_v11.py`와 기존 공통 모듈·설정·제품 자산을 함께 둔다.
예외 제어와 capability 조회도 v11 파일에 포함되므로 별도 예외 모듈은 필요 없다. **`pc_sampling_fuzzer_v10.3.py` 및 다른 구버전 퍼저 파일은 필요 없다.**

## 설정 표면 — `exceptions` 절

```jsonc
"exceptions": {
  "enabled": false,              // 배포 기본. v10.3 진입점은 이 절을 아예 안 본다
  "min_interval_minutes": 5,     // 이전 이벤트 **완료** 후 다음까지의 하한
  "initial_delay_minutes": 5,    // 사전시험 종료 뒤부터 계산
  "trigger_delay_ms": 0,         // 명령 시작 후 예약 지연
  "cleanup_timeout_sec": 10,     // 공급 ON/release 복원 동작 예산
  "resume_timeout_sec": 30,      // RDY 확인 후 NVMe 환경 재설정/검증 예산
  "recovery_observation_commands": 1, // 재개 직후 이벤트에 귀속할 명령 수
  "recovery_observation_sec": 0,  // 추가 시간 구간(둘 중 하나라도 남으면 별도 귀속)
  "seed": 0,                     // 선택 RNG. 전역 random 을 쓰지 않는다
  "preflight": { "enabled": true, "attempts_per_kind": 1 },   // 1..10
  "adapters": { },               // 사용자 정의 action (아래)
  "restore_actions": [ ],        // 종료/중단 시 되돌릴 action 이름들
  "profiles": [ ]                // prefix → body × repeat → suffix
}
```

### action — 내장 9종

`controller_reset`, `nssr`, `flr`, `hot_reset`, `pci_remove`, `pci_rescan`,
`power_off`, `power_on`, `wait`.

각 action 은 **effect** 를 갖는다(`none` / `power_off` / `power_on` / `assert` / `deassert`).
effect 가 공급 상태 추적의 근거이고, 복원 정책(“이미 ON 인 장치를 OFF→ON 으로 돌리지
않는다”)이 이 값으로 판정된다.

### adapters — PMU 같은 외부 제어를 action 으로 등록

PMU 호출은 코드에 박혀 있지 않다. `adapters` 로 등록한다.

```jsonc
"adapters": {
  "perst_assert": {
    "argv": ["python3", "{pmu_script}", "16", "1", "7", "3300"],
    "effect": "assert",
    "readback": { "argv": ["python3", "{pmu_script}", "20", "1", "7"], "expected": 0 }
  }
}
```

- `argv` 는 **배열만** — 셸을 거치지 않는다
- 치환은 `{device}` 와 `{pmu_script}` **둘뿐**이다. 다른 `{}` 는 기동 시 거부한다
  (임의 format 식을 받지 않는다)
- 내장 이름과 겹치면 거부(`reserved adapter`)
- `readback.expected` 는 0/1. 파싱 실패나 모순된 응답을 성공으로 보지 않는다
- `effect` 를 안 주면 `none`

### profile — 단계와 시간

```jsonc
{ "name": "warm_reset_perst",
  "prefix": [], "body": [ {"action": "perst_assert", "hold_sec": 0.1}, ... ],
  "repeat": 1, "suffix": [],
  "timeout_sec": 30,
  "ready_timeout_sec": 30 }       // 또는 ready_timeout_ref: "power.por_boot_wait"
```

- `repeat` 는 1..10000, 전체 단계 수(`len(prefix) + len(body)*repeat + len(suffix)`)는 10000 이하
- `hold_sec` 대신 **`hold_ref`**, `ready_timeout_sec` 대신 **`ready_timeout_ref`** 로
  기존 JSON 경로(`power.por_boot_wait` 등)를 **참조**할 수 있다. 숫자를 두 군데 복사하면
  갈라지기 때문이다
- 모든 profile 은 장치를 건드리기 **전에** 컴파일·검증한다

## 실행

```bash
cd PC_Sampling
sudo python3 pc_sampling_fuzzer_v11.py --config fuzzer_config.json --product BM9K1 --nvme /dev/nvme0
```

기존 실행 옵션은 그대로 사용한다. PM9M1 계열도 기존 `--product` 값을 유지한다.
JSON `exceptions.enabled=true`로 켠다. 배포 기본은 false.
v10.3 진입점은 exceptions를 사용하지 않는다. v11 출력은 `output/pc_sampling_v11.0.0`.

기존 calibration 이후 fuzz_start에서 장치 식별 → 사전시험 → 통과 목록 확정 → 퍼징.
설정의 profiles에 나열된 종류만 사전시험하고 실제 주입 후보로 삼는다.

```json
"preflight": {"enabled": true, "attempts_per_kind": 1}
```

- 지원/환경 조회 뒤 명령 사이에서 profile을 실제 실행한다.
- 동일 serial+BDF, live 장치 인식, CSTS.RDY=1/CFS=0, Identify 응답 및 serial,
  샘플러 재연결을 확인해야 PASS다.
- `UNSUPPORTED`: capability 또는 정확한 kernel reset 경로 없음. 제외하고 계속.
- `UNCONFIGURED`: PMU 스크립트/플랫폼 제어 정보 없음. 제외하고 계속.
- `FAIL_PRESERVED`: 실제 시도 중 오류·RDY 초과·장치 변경·프로브 최종 실패.
  미지원으로 숨기지 않고 현상 보존·덤프 후 캠페인 중단.
- active 사전시험을 명시적으로 끄면 capability만 확인하고 UNVERIFIED로 표시한다.
  PASS로 표시하지 않는다. 기본값은 active 사전시험 활성이다.
- 모두 제외되면 일반 퍼징은 계속하지만 예외 주입은 예약하지 않는다.
- 이전 실행의 PASS를 다른 제품/커널/펌웨어에 재사용하지 않는다.

## 기본 제공 profile

| 이름 | 동작 / 지원 판단 |
|---|---|
| controller_reset | `nvme reset`, RDY/정상 재개 확인 |
| nssr | CAP.NSSRS 확인, 현재 호스트에서 같은 subsystem NQN에 컨트롤러 하나만 보이는 경우 `nvme subsystem-reset` |
| flr | sysfs reset_method에 정확히 flr이 있을 때 실행 |
| hot_reset | 정확히 bus 방식이 있고 같은 부모 버스 범위에 DUT 외 PCI 기능이 없을 때 실행 |
| warm_reset_perst | PERST assert → host remove → release → 기존 rescan 대기 → rescan. 주전원/REFCLK 조작 없음 |
| sudden_por | 전원 OFF → host remove → 기존 OFF 대기 → ON → 기존 rescan 대기 → rescan |
| normal_por | host orderly remove → OFF → 기존 OFF 대기 → ON → 기존 rescan 대기 → rescan |

Normal POR의 의미는 **Linux 드라이버 orderly removal 이후 전원 차단**이다.
별도 MMIO SHN/SHST 관측 시험이나 제품별 전기적 shutdown 인증과 동일시하지 않는다.
NSSR의 NQN 범위 검사는 보수적이므로 placeholder NQN이 중복되면 실행을 제외할 수 있다.
Hot reset도 여러 DUT/기능으로 영향을 넓히지 않는다. PCI remove/rescan을 reset 자체로
이름 붙이지 않으며 실제 PMU/PCI reset 동작과 host 재인식을 별도 단계로 기록한다.

## PMU 확정 정보

사용자가 제공한 API:
- 4 SetPowerOnAll: 3.3V/12V 전원만 공급. PERST/REFCLK를 바꾸지 않음.
- 7 SetPowerOffAll.
- 15 SetGpioHigh(devIdx,pinNo,level), 16 SetGpioLow(devIdx,pinNo,level).
- 17 SetGpioToggle(devIdx,pinNo).
- 18 SetGpioMcToggle(devIdx,pinNo,lowTime,highTime,cycle).
- 20 GetGpio(devIdx,pinNo).
- devIdx=1, PERST pinNo=7, 기본 level=3300. CLKREQ의 기존 pinNo는 1.

PERST assert: `python3 pmu_4_1.py 16 1 7 3300`
PERST release: `python3 pmu_4_1.py 15 1 7 3300`
Readback: `python3 pmu_4_1.py 20 1 7`
`[GetGpio][OK]D1] 0/1` 형식을 파싱해 실제 읽은 디지털 값과 비교한다.
파싱 실패/모순된 응답을 성공으로 보지 않는다. 해제 readback 실패는 assert 잔류 가능성을
유지하므로 cleanup이 release를 재시도한다.

전원 OFF/ON argv는 기존 시작 POR 호출과 동일하다. ON voltage는 기존
`runtime_hw.clkreq_voltage_mv` 값을 재사용하며 이름만으로 GPIO 제어라고 해석하지 않는다.
전원 ON 성공만으로 PERST가 풀렸다고 처리하지 않는다.

18번 McToggle은 단위·동기/비동기 완료·종료 핀 상태가 아직 미확인이다. 임의로 시간을
변환해 보내지 않는다. 현재 반복은 명시적 Low/High 단계로 실행하며 subprocess 지연 때문에
마이크로초 펄스 정확도를 주장하지 않는다. 이 점은 기능 미지원과 별개의 정밀도 한계다.

## 부분 반복 / 시간 기준

profile은 `prefix → body × repeat → suffix`다. 앞뒤 절차는 한 번씩, body만 반복한다.
각 step은 `action`, `hold_sec` 또는 기존 JSON을 참조하는 `hold_ref`를 받는다.
반복/전체 단계 수와 시간 예산을 검증한다. 다른 이벤트와 중첩하지 않는다.

- 최소 간격: `min_interval_minutes`. 이전 이벤트 완료 후 다음 이벤트까지의 하한.
- 최초 지연: `initial_delay_minutes`. fuzz_start 사전시험 종료 뒤 계산.
- 명령 시작 후 예약 지연: `trigger_delay_ms`. 완료된 대상에 늦게 주입하지 않음.
- POR 재개 기준: **기존 `power.por_boot_wait` 직접 참조**. 별도 Normal/Sudden 숫자 복사 없음.
- OFF/재검색 대기: 기존 `power.por_poweroff_wait` / `power.por_rescan_delay` 직접 참조.
- ON/reset/release 시작부터 RDY 예산을 센다. 뒤따르는 hold/rescan도 같은 예산을 사용한다.
- 의도적으로 다음 OFF/assert 단계로 들어간 반복에서는 다음 ON/release부터 새 재개 창을 센다.
- Warm 기본 assert 유지 0.1초는 조절 가능한 시험값이며 PCIe Base가 규정한 공통 최소값이라고
  주장하지 않는다. 폼팩터/보드 전기 타이밍 적합성은 별도 실측 대상이다.

## 기존 퍼저 / 장애 보존

명령 종류별 추가 제외 없음. 기존 CLI 선택/사용자 전송 가드는 유지한다.
PM 전환 중에는 주입하지 않는다. 대상 명령은 **`RC_EXCEPTION = -1011`** 로 분리해
성공/일반 실패 학습에서 제외하며 자동 재시도 없이 다음 시퀀스/IO 단계로 진행한다.
setup을 몰래 다시 실행하거나 남은 시퀀스를 취소하지 않는다. 중단된 setup을 성공한 것으로
학습하지 않는다. 후속 일반 명령의 기존 timeout 검사는 복원한다.

장치 RDY가 확인되기 전에는 프로브 복구로 재개 성공을 만들지 않는다.
장치 이상이면 추가 POR/reset 없이 증거 수집/덤프/중단한다.
Known OFF/assert 상태에서는 전원 ON → PERST release만 시도한다. 이미 ON인 장치를
OFF→ON으로 돌리지 않는다. Ctrl+C도 같은 공급 유지 정책을 사용한다.
PMU helper가 아직 살아 있어 후속 OFF가 발생할 수 있으면 상충하는 복원 명령을 병렬로
보내지 않는다. 잔존 PID/복원 불가를 기록한다. 호스트/보드가 응답하지 않는 상황까지
복원을 보장한다고 주장하지 않는다.

PCI remove/rescan으로 nvmeN이 바뀌면 원래 serial+BDF로 재탐색하고 퍼저 경로를 갱신한다.
원래 ioctl이 RDY 이후에도 남아 있으면 새 명령을 누적하지 않고 중단한다.
일반 sequence replay가 reset을 재현하지 못하므로 예외가 개입한 새 시퀀스를 리셋 없는
replay로 corpus에 추가하지 않는다. 단계별 결과는 이벤트 로그에 남긴다.
데이터 손실/영속성 oracle 및 reset-aware 자동 replay는 이번 구현 범위가 아니다.

## 로그 / 검증

`exceptions.jsonl`: 지원 근거, 사전시험 결과, profile/반복, 실제 명령·시간·GPIO 값,
RDY 관측, 원본 중단 명령 결과, 이어진 명령, 실패 증거 위치.
터미널/텍스트 로그: `[Exception]`.
장애 시 `crashes/exception_*/exception.json`, 기존 context/dmesg 및 제품 설정에 따른 JLink/UFAS/Debug Tool 산출물.

자동시험: `tests/test_v11_exceptions.py`, `tests/test_v11_preflight.py`.
가짜 sysfs/PMU/프로세스로 capability, scope, profile, readback, 예산, 사전시험 PASS 선별,
실제 시도 실패 보존, 전송 hook, 시퀀스 계속 실행, 다음 watchdog 복원을 검사한다.
실기 결과는 자동시험 결과와 분리한다. 각 제품의 실제 지원은 시작 시 사전시험 결과로 판단한다.

Linux 구현 참고(6.8):
- https://github.com/torvalds/linux/blob/v6.8/drivers/pci/pci-sysfs.c
- https://github.com/torvalds/linux/blob/v6.8/drivers/pci/pci.c
- https://github.com/torvalds/linux/blob/v6.8/drivers/nvme/host/pci.c

### 이어받는 사람에게 — 2026-09-23 현재 상태

이 세션은 **멈춘 상태**이고 아래 파일은 아직 커밋되지 않았다:
`pc_sampling_fuzzer_v11.py`, `exception_control.py`, `exception_probe.py`,
`tests/test_v11_exceptions.py`, `tests/test_v11_preflight.py`,
그리고 `fuzzer_config.json` 의 `exceptions` 절과 `pc_sampling_fuzzer_v10.3.py` 의
v11 훅(`_ENTRY_VERSION`, `[Exception]` 로그 필터, post-Popen hook).

**⚠ 재개 전에 두 가지를 반드시 처리한다.**

**① `git pull --rebase`.** 같은 리포에서 다른 세션이 v10.3 작업을 `origin/main` 에
올렸다(0xC0 차단, LLM task 회전판 수정, 프롬프트 후보 필터, timeout 400초). 로컬
`main` ref 는 뒤처져 있다 — 그 위에 그냥 커밋하면 push 가 non-fast-forward 로 거절된다.

**② AST 동결 override 를 다시 계산한다.** `tests/fixtures/v10_2_device_ast.json` 의
`_V101Fuzzer._send_nvme_command` override 가 **두 번 갈라졌다**:

| 값 | 무엇을 담았나 |
|---|---|
| `98799edc…` | 작업 트리 — v11 post-Popen hook **만** |
| `abbb7724…` | `origin/main` — 0xC0 CDW 가드 **만** |

둘 다 들어간 상태의 해시는 **아직 계산된 적이 없다.** rebase 뒤 실제 파일로 다시 구해
override 를 갱신하고, amendment 에 두 변경을 모두 적는다. 작업 트리의 amendment 기록
(v11 hook)은 그대로 살려 두고 `origin/main` 의 것(0xC0)과 **합친다** — 어느 한쪽을
덮으면 검토 이력이 사라진다.

해시 계산 규칙은 `tests/test_v10_2_learning.py` 의 `normalize()` 가 정본이다
(빈 `type_params` 무시 → canonical JSON → sha256). 그 함수를 그대로 써서 구한다.

### ⚠ 2026-09-23 이후 — 다른 세션의 v10.3 수정 (io_patterns 성과표)

v10.3 운용 중 발견된 문제로, v11 과 **같은 작업 트리**에서 v10.3 을 고쳤다. 설명은
`RUNBOOK_v10.3.md` §6-9.

**`origin/main` 에 `5234cc5` 로 push 완료.** v11 hunk 는 하나도 들어가지 않았다(같은 파일의
v11 hook 10개 hunk 는 제외하고 io 성과표 hunk 6개만 담아, `origin/main` 위 임시 worktree 에서
전체 시험 342개 통과 확인 후 커밋). 로컬 `main` ref 는 **건드리지 않았다** — 여전히 `80d01ce`.

작업 트리는 이미 `5234cc5` 내용 + v11 변경이다. 그래서 `git pull --rebase` 는 dirty tree 로
거절된다. 작업 트리를 건드리지 않고 기준만 옮기려면:

```bash
git fetch && git reset --mixed origin/main   # 파일은 그대로, HEAD·index 만 이동
git status                                   # v11 변경만 남아야 정상
```

그 뒤 `git status` 에 v11 파일·hook·`exceptions` 설정·AST fixture 외의 것이 보이면 멈추고 확인할 것.

| 파일 | 변경 |
|---|---|
| `pc_sampling_fuzzer_v10.3.py` | 모듈 상수 `IO_WL_PARAM_PATTERNS` 추가 · `__init__` 에 `_wl_pattern_stats`/`_wl_burst_seq` · `_llm_workload_feedback` 재작성 · `_wl_record_pattern`/`_llm_workload_table` 신규 · `_llm_build_request` 의 io_patterns 프롬프트 · `_run_llm_workload_burst` 에 cov/cmds 기록 |
| `tests/test_v10_3_io_table.py` | 신규 8건 |
| `docs/RUNBOOK_v10.3.md` | §6-9, §7 한 줄 |

v11 에 미치는 영향:

- **AST 동결 무관.** `_send_nvme_command`·샘플러 클래스를 건드리지 않았다. override 해시 재계산 불필요
- mixin 이 override 하는 메서드와 겹치지 않는다(`_llm_backend_meta` 등 그대로)
- 버스트 명령도 `_send_nvme_command` 를 지나므로 예외 주입 대상이다. 주입된 명령은 mixin 의
  `_account_command` 가 `executions` 를 올리므로 성과표의 `cmds` 에는 **포함**되고 `cov` 에는
  안 들어간다 → 주입이 잦으면 그 패턴의 `cov/1k` 가 약간 낮게 보인다. 필요하면 v11 쪽에서
  `exception_interrupted` 만큼 빼는 보정을 검토할 것
- 전체 unittest 393개 통과(v11 51개 포함, 신규 8개 추가분)

### ⚠ 2026-09-28 — 다른 세션의 v10.3 수정 (crash 덤프 수집)

**`origin/main` 에 `c9088da` 로 push 완료**(v11 hunk 10개 제외, 덤프 hunk 11개만. 임시
worktree 에서 전체 358개 통과 확인). 로컬 `main` ref 는 여전히 건드리지 않았다 — 위
`git reset --mixed origin/main` 절차가 그대로 유효하다.

`RUNBOOK_v10.3.md` §6-10. v11 에 **유리한** 변경이다 — `_exception_capture` 가 부르는
`_run_ufas_dump(dest_dir=dest)` 가 이제 스스로 덤프 산출물과 도구 로그를 `exception_<ts>/`
로 복사한다(예전엔 UFAS 가 경로를 무시하면 `dump/` 에만 남았다). v11 코드 수정 불필요.

- `_run_jlink_dump`/`_run_ufas_dump`/`_run_debug_tool_dump` 는 얇은 래퍼가 되었고 본문은
  `*_body` 로 옮겼다. 시그니처는 호환(`dest_dir` 선택 인자 추가). `test_v11_exceptions.py`
  처럼 `_run_ufas_dump` 를 Mock 으로 바꾸는 시험은 영향 없음
- `_spawn_dump_logged` 는 래퍼 안에서 호출되면 로그를 `dest_dir` 에 쓴다
- AST 동결 경로(`_send_nvme_command`, 샘플러) 무관
- 래퍼는 도구 출력(`UFAS_*.log`)을 끝나면 텍스트 로그에 되읽어 남긴다(앞/뒤 1,000줄)
- 산출물은 폴더 구조를 보존해 복사한다(`dump/SnapShot/a.bin` → `exception_<ts>/SnapShot/a.bin`)
- 전체 unittest 409개 통과(작업 트리 기준, v11 포함)

### 2026-09-28 — 다른 세션의 문서 갱신 (`eafe02c`, push 완료)

문서만 바뀌었다(코드 변경 없음): `docs/RUNBOOK_v10.3.md`, `docs/pc_sampling_fuzzer_v10.3.md`,
`risc-v/README.md`(재작성), `rag/README.md`(신규). 작업 트리 파일과 내용이 같으므로
`git reset --mixed origin/main` 뒤에는 변경으로 보이지 않는다. v10.3 정본 문서에는 v11 을
"확장점" 한 줄로만 적었다 — v11 커밋 때 그 절에 hook 목록을 보태면 된다.

### ⚠ 2026-09-29 — 다른 세션의 v10.3 수정 (LLM 지시 준수 3건, `d9cb5d1` push 완료)

`RUNBOOK_v10.3.md` §6-11. 독립화 시점의 LLM 변경을 v11 엔진에도 포함했다. 이후 변경은 버전별로 명시적으로 반영해야 한다.
v11 hunk 13개는 제외하고 이 변경 hunk 16개만 담았다(임시 worktree 에서 377개 통과 확인). 로컬 `main` ref 는 그대로 — `git reset --mixed origin/main` 절차 유효.

- `pc_sampling_fuzzer_v10.3.py`: `RAG_FOCUS_COMMANDS`/`RAG_FOCUS_POOL`, `_llm_pairs_hook`/
  `_LLM_DUP_KEY`, `_llm_extract_json`(중복 키 감지), `_llm_make_seed`(중복 키 후보 검증),
  `_llm_cmd_yield`/`_llm_focus_pick`/`_llm_focus_block`/`_llm_focus_account` 신규,
  `_llm_build_request` 의 new_group_seeds·sequences·io_patterns 프롬프트, `_llm_apply_result`
  집계, `_llm_make_workload_desc`, `[LLM/task]` 표기, `__init__` 두 필드
- `tests/test_v10_3_llm_prompt_fixes.py` 신규 19건(외부 리뷰 3건 반영 포함)
- AST 동결 경로(`_send_nvme_command`, 샘플러) 무관. v11 mixin 이 override 하는 메서드와 겹치지 않음
- `_llm_make_seed` 가 중복 키 해소 시 `_llm_repair_note` 를 부른다 — v11 쪽 시험이 이를 Mock 으로
  막아 두었으면 영향 없음
- 작업 트리 전체 unittest 464개 통과

### 2026-09-23 검증 기록

- 전체 unittest 364개 통과 (약 44초).
- 이후 pending PCI remove가 공급 복원을 막지 않도록 PMU 제어 helper만 구분하는
  보완 시험 추가. v11 관련 51개 시험 재실행 통과.
- v10.3/v11 --help, Python 구문 검사, git diff --check 통과.
- JSON을 실제 compile_profiles에 넣어 7개 profile과 기존 30초 재개 기준 참조 확인.
- 사용자 작업 트리의 CDW 조합 차단 변경 유지. 해당 loop만 제거한 AST가 이전
  v11-hook 해시와 동일함을 확인하고, 가드 시험과 함께 fixture 변경 이유를 기록했다.
- 그 뒤 0xC0 차단이 `origin/main` 에 커밋되며 override 가 `abbb7724…` 로 바뀌었다.
  작업 트리의 `98799edc…` 와 **합쳐야 한다** — 위 ② 참조.
- 작업 트리 기준 전체 unittest **385개** 통과(v11 51개 = exceptions 32 + preflight 19 포함).
  `origin/main` 만으로는 334개(v11 파일 없음).
- 실제 DUT/PMU 실기 지원 여부와 성공률은 이 자동시험으로 확정하지 않는다.


### 2026-09-28 리뷰 6건 반영

리뷰 원문은 대화로 전달됐으며, 아래는 코드 대조 후 적용한 수정 기록이다.

| 번호 / 심각도 | 문제 | 수정 |
|---|---|---|
| 1 / 높음 | account를 거치지 않는 calibration 및 FW 청크에서 주입 플래그가 다음 timeout/정상 결과를 가림 | 매 전송 시작에 플래그 초기화, 회계는 해당 반환 코드가 RC_EXCEPTION인지로만 판정. Calibration 중단 회차는 안정성·커버리지·보상에서 제외하고 실행 수/중단 수만 기록. FWDownload는 중단 청크에서 나머지 청크 전송을 멈추고 해당 청크로 회계 |
| 2 / 중간 | 예외용 stop hook이 실제 worker를 정리하지 않음 | stop_sampling 및 _stop_worker 호출 후 관측 큐와 current_trace 비움. 기존 자동 복구는 호출하지 않음 |
| 3 / 중간 | 보존 종료가 sampler.close를 건너뜀 | 보존 종료도 기존 sampler.close로 세션 해제. 추가 timeout PC 모니터 및 APST/keepalive/timeout 복원은 보존 실패 경로에서 계속 생략 |
| 4 / 중간 | active preflight Ctrl+C가 캠페인 finally 밖에서 발생 | fuzz_start 사전시험과 learning save를 메인 try 내부로 이동. 사용자 중단도 통계/커버리지 저장·샘플러 close를 거침. 사전시험 중단의 장치 복원 금지는 아래 후속 수정 참조 |
| 5 / 중간 | PMU argv 문자열 비교로는 다른 하드웨어 adapter의 잔존 프로세스를 놓침 | 실행 시 supply_control을 명시. 전원 및 모든 사용자 adapter/readback을 복원 경합 대상으로 추적. PCI remove 등은 별도 분류해 공급 복원을 불필요하게 막지 않음 |
| 6 / 낮음 | rescan 이후 state monitor가 이전 nvmeN을 사용 | resume 시 config와 NVMeStateMonitor._device를 함께 갱신 |

회귀 시험은 실제 전송의 미회계 주입 → 다음 timeout, calibration의 주입 → timeout,
실제 FW 청크 루프의 조기 종료, worker/관측 정리, 실제 run의 try/finally에서 사전시험
Ctrl+C 및 보존 종료, gpioset/긴 인자 adapter timeout 경합, telemetry 경로 갱신을 검사한다.
종료/FW 시험은 장치 준비 절차를 실행하지 않도록 실제 메서드의 해당 AST 블록을 추출해
실행하며, 전송·calibration 시험은 실제 메서드를 사용한다. 하드웨어 조작은 mock 처리한다.

이 수정은 실기 통과 기록이 아니다. exceptions.enabled 기본값 false는 유지한다.

검증: v11 59개(회귀 8개 추가), 전체 unittest 417개 통과(46.175초).
Python 구문 검사 및 git diff --check 통과. 기존 전송/샘플러 AST 보호 시험도 통과했으며,
이번 수정으로 fixture 해시는 변경하지 않았다. 실장치·PMU 조작과 커밋은 하지 않았다.


### 2026-09-28 후속 리뷰 2건

- **중간 — 사전시험 Ctrl+C 보존 누락:** `_learning_baseline('fuzz_start')`의
  KeyboardInterrupt 처리에서 `_exception_preserve`와 `_timeout_crash`를 먼저 설정한다.
  공급 ON/release의 제한된 복원만 시도하며, 실행 중인 제어 helper와의 경합 차단은 유지한다.
  이후 캠페인 finally는 통계·커버리지 저장과 sampler.close를 수행하되 SMART 조회,
  APST/keepalive 명령 및 커널 timeout 복원을 실행하지 않는다.
- **낮음 — 샘플러 정지 후 주입 기회 상실:** before() 이후 명령이 끝난 경우를
  명시적인 missed_window 결과로 전달한다. 실제 명령 반환 코드·완료 상태는 유지하지만
  잘린 관측은 coverage_unobserved로 분리하며 커버리지 평가·학습 보상에 사용하지 않는다.
  명령별 통계에는 실행 수·원래 rc·coverage_unobserved를 기록한다. Calibration의 해당
  관측도 안정성 계산에서 제외하고, FW 청크는 해당 청크에서 회계하여 플래그 유실을 막는다.
  다음 전송은 플래그를 초기화한다. before() 이전에 완료한 명령은 기존 정상 관측을 유지한다.

추가 회귀 시험: 실제 사전시험 interrupt handler에서 캠페인 finally까지의 보존 상태 전달,
SMART/설정 복원 금지 및 close/save 유지, 실제 전송의 두 missed-window 시점 구분,
불완전 관측의 unobservable 학습 기록 및 다음 정상 관측 복원, calibration 안정성 제외.
기존 FW 청크 시험도 관측 중단 조건을 함께 검사하도록 확장했다.

검증: 회귀 시험 4개 추가 및 기존 FW 청크/주입 시점 시험 확장.
전체 unittest **421개 통과**(44.430초, v11 관련 63개 포함).
Python 구문 검사·git diff --check 통과. 실장치·PMU 조작 및 커밋 없음.
이전 종료 시험은 보존 플래그를 미리 설정한 상태만 검사했으므로, 이번에는 실제
사전시험 interrupt handler가 플래그를 설정해 finally까지 전달하는 경로를 추가했다.


### 2026-09-28 목적 대조 후 필수 보강 (1·2·3번)

**정상 재개 환경:** RDY와 원래 identity를 확인한 뒤 갱신된 장치 경로를 사용한다.
PM 기능을 사용하는 캠페인은 PCIe 정보를 다시 탐지하고 L0/D0를 설정·확인한다.
이어 Identify serial 및 APSTA/KAS를 새로 읽어 지원되는 APST/KATO를 0으로 맞추고,
Power Management feature의 PS를 0으로 맞춘다. 모든 feature는 현재 값을 읽고 필요할 때만
설정한 뒤 다시 읽어 검증한다. 최초 저장값이 0이어도 현재 값을 다시 확인하며,
기존 종료 복원용 `_orig_*` 값은 덮어쓰지 않는다. 미지원은 Identify의 명시적 근거가
있을 때만 건너뛴다. 통신·파싱·readback 실패는 보존·중단이며 경고 후 진행하지 않는다.
NVMe 환경 복원은 별도 `resume_timeout_sec` 예산으로 제한하고 기존 RDY 예산을 늘리지 않는다.
확인 후 PM 추적값을 갱신하고 샘플러를 연결한다. 시퀀스 setup을 재실행하지 않는다.
불량 보존 상태에서는 이 환경 복원 명령을 실행하지 않는다.

**제품별 덤프:** 공급이 ON/deassert이고 잔존 공급 제어 helper가 없을 때 제품 설정의
`enable_jlink_dump`, `enable_ufas`, `enable_debug_tool_dump`를 따른다.
JLink → UFAS → Debug Tool 순서로 같은 exception 폴더를 전달한다. JLink 전에
OpenOCD 점유를 해제하고, Debug Tool 전에 필요한 JLink 세션을 닫는다.
각 단계의 예외는 기록하고 다음 덤프를 시도한다. 기존 timeout handler의 unsupported/POR
복구 분기는 호출하지 않는다. 도구 부재 등으로 실제 덤프가 생성되지 않을 수 있으며
`dump_returned`는 함수 반환 기록이지 덤프 성공 보증이 아니다.

**재개 후 관측 분리:** 기본은 다음 실제 전송 1건을 이벤트 관측으로 분리한다.
`recovery_observation_commands`와 `recovery_observation_sec` 중 하나라도 남아 있으면
해당 관측의 PC/코어 관측을 `recovery_observation` 이벤트와 원래 이벤트 ID에 기록한다.
이를 일반 seed의 커버리지·학습 보상·corpus 추가에 사용하지 않는다. 실행 결과는
기존 `coverage_unobserved` 회계로 남기며, timeout/error 처리와 덤프는 계속 유효하다.
가드로 차단된 전송은 명령 수 예산을 소비하지 않는다. Calibration에도 관측 제외가
적용되고 FW 청크 묶음은 해당 회계 경계에서 멈춘다. 주입된 시퀀스의 후속 관측도
일반 보상에서 제외하며, 재개 관측이 포함된 시퀀스는 일반 corpus로 등록하지 않는다.

기본 1건은 최소한의 관측 경계일 뿐 펌웨어 초기화가 끝났다는 보증이 아니다.
실기 관측으로 구간을 조정해야 한다. reset-aware replay, QD>1, SMART 자동 판정,
자동 seed/가중 선택, 보드별 PMU 설정 확장은 이번 변경에 포함하지 않았다.

검증: `test_v11_resume.py` 회귀 17개 추가. v11 관련 **80개**, 전체 unittest
**438개 통과**(47.814초). Python 구문 검사와 git diff --check 통과.
실장치·PMU 조작 및 커밋은 하지 않았다.


## 2026-09-29 최종 리뷰 반영

- 재개 시 PCIe 정보를 재탐지해도 캠페인 시작 시 저장한 `_orig_aspm_policy`를
  보존한다. 재탐지 실패 경로에도 같은 정책을 적용한다.
- 명령 회계와 calibration 종료 시 interrupted/truncated/recovery 플래그를 정리해
  다음 PM 전용 관측으로 상태가 새지 않게 한다. 보존 플래그와 복구 관측 예산은 유지한다.
- 가드가 `RC_SKIP`으로 차단한 명령은 복구 관측으로 기록하지 않고 예산도 소비하지 않는다.
- 해당 회귀 테스트 7개를 추가했다(v11 테스트 총 87개). 실장치 검증은 미실시이며
  배포 설정의 `exceptions.enabled=false`는 유지한다.

게시 전 검증: 원격 `d9cb5d1`에 v11을 합친 작업 공간에서 전체 unittest **464개 통과**
(46.630초). Python 구문 검사와 `git diff --check` 통과.


## 2026-09-29 독립 버전으로 전환

v11 진입점에서 v10.3 파일을 runpy로 실행하던 구조를 제거했다. v11 파일이 전체 엔진을
포함하고 `NVMeFuzzer(ExceptionFuzzerMixin, LearningMixin, _V101Fuzzer)`로 직접 구성된다.
버전은 `11.0.0`으로 고정하며 차트 자식 프로세스도 v11 파일을 다시 실행한다.
예외 제어·학습·제품 모듈 등 공통 의존성은 유지하지만 구버전 퍼저 파일은 필요 없다.

검증: 구버전 퍼저 파일을 모두 제외한 임시 배포 폴더에서 `--help`, 엔진 생성,
예외 주입 비활성/활성 초기화와 실제 전송 가드의 `RC_SKIP` 반환을 확인했다.
v11 전송·calibration·종료·복구 테스트는 v11 모듈을 직접 검사한다. 엔진의 함수·클래스
67개는 기존 검증된 구현과 AST 동등함을 확인했다(새 클래스 구성과 버전 상수 제외).

독립화 후 전체 unittest **465개 통과**(46.613초). Python 구문 검사와
`git diff --check` 통과. 실장치 검증은 미실시.


## 2026-09-29 예외 모듈 통합

`exception_control.py`와 `exception_probe.py`의 구현을 v11 파일 내부로 옮기고
별도 파일은 삭제했다. 예외 제어·조회 함수를 v11 엔진과 한 파일에서 관리한다.
기존 공통 학습/RAG/제품 모듈의 구조는 유지한다. v11 회귀 테스트와 patch 대상은
통합된 모듈을 가리키며, 배포 테스트는 구버전과 예외 모듈 두 파일이 모두 없는
환경에서 실행한다. 위의 분리 배포 설명은 이전 변경 이력이다.

통합 후 전체 unittest **465개 통과**(51.934초). 기존 엔진과 예외 구현의 함수·클래스
82개는 AST 동등함을 확인했다. Python 구문 검사와 `git diff --check` 통과.

2026-09-29 개발 기준 전환 검증: 공통 회귀 테스트를 v11 대상으로 실행해
**465개 통과**(47.910초). v11 전송 함수에 메모리상 변조를 주면 AST 동결 검사가
실패함을 별도로 확인했다. v10.3/v11 제품 코드 변경 없음.


## 사전시험 실패 로그 판독 (2026-09-29)

일반 로그에도 profile 시작, 단계 시작/완료, 실행 argv, RDY 대기 시작·상태 변화·실패를
출력한다. `capture`는 active가 해제된 뒤에도 마지막 실패 이벤트 ID/profile/stage를 유지한다.
`preflight ... PASS`는 해당 profile 성공을 뜻하며 뒤 profile까지 성공했다는 의미가 아니다.
실패 종료는 `preflight failed; campaign stopped`로 표시한다.

`ready_timeout`의 `gate`와 마지막 관측을 확인한다:
- `sysfs_unreadable`: DUT의 sysfs 정보를 읽지 못함(`sysfs_error`).
- `driver_not_live`: Linux 컨트롤러 state가 live가 아님(`state`).
- `device_node_missing`: 장치 노드가 없음(`device`, `node_exists`).
- `show_regs_failed`: show-regs 실패(`show_regs_rc`, `stderr`).
- `controller_rdy`: CSTS의 RDY/CFS 확인 단계(`csts`, `rdy`, `cfs`).

`ready_timeout`만으로 펌웨어 hang이라고 단정하지 않는다. `exceptions.jsonl`의 마지막
`preflight_start`, `step_start`, `action_command`, `helper`, `ready_probe`, `preflight_failure`와
덤프 폴더의 `exception.json`을 함께 확인한다. 추가 POR/reset이나 대기 예산 변경은 없다.

진단 회귀 3개 추가(네 가지 RDY 대기 원인, 종료 후 이벤트 연결, helper 실행 전 argv 기록).
전체 **468개 통과**(50.360초), `git diff --check` 통과. 실장치 확인은 미실시.

## 사람이 읽는 로그 형식 (2026-09-29)

사전시험·주입 로그를 `--pm` preflight 와 같은 형식으로 바꿨다. **`exceptions.jsonl` 은 그대로**
(기계용 원본, 모든 필드)이고, 텍스트 로그·터미널에는 값만 정돈해 찍는다 — JSON 덤프·중괄호·
따옴표를 내보내지 않는다.

```
============================================================
[Exception-Preflight] 예외 profile 사전 검증 시작 (7개)
  DUT: S97TNE0L900259 @ 0000:02:00.0 (/dev/nvme0)
============================================================
  [기준] 시작 전 장치 준비 확인
    [ready]   0.1s  준비 완료 — driver=live CSTS=0x00000001 RDY=1 CFS=0
  [1/7] controller_reset   지원: 가능
    [step 1/1] controller_reset : nvme reset /dev/nvme0
      완료 (0.1s)
    [ready]   0.8s  준비 완료 — driver=live CSTS=0x00000001 RDY=1 CFS=0
    [check] Identify serial 일치 (S97TNE0L900259)
    [check] 환경 복원·샘플러 재연결 OK
    → PASS  (2.3s)
  [2/7] nssr               지원: 가능
    [step 1/1] nssr : nvme subsystem-reset /dev/nvme0
      완료 (0.1s)
    [ready]   0.0s  driver=resetting (live 아님)
    [ready]  30.0s  한도 초과 — driver=resetting (live 아님)
    → FAIL — 현상 보존  (30.1s)
      원인: 준비 시간 초과(30s): driver=resetting (live 아님) [gate=driver_not_live]
============================================================
[Exception-Preflight] 결과 요약
  Profile            결과          시간  사유
  controller_reset   PASS          2.3s  RDY·identity·Identify·환경 복원·샘플러 확인
  nssr               FAIL         30.1s  준비 시간 초과(30s): driver=resetting …
  flr                미실행              앞 profile 실패로 중단
[Exception-Preflight] 통과 1/2 — 실패로 캠페인 중단 (복구 POR/리셋 없음, 현상 보존)
============================================================
[Exception] 증거 폴더: output/pc_sampling_v11.0.0/crashes/exception_…
[Exception] 캠페인 중단 — 복구 POR/리셋 없이 현상 보존
[Exception]   원인: 준비 시간 초과(30s): …
```

- 단계 줄은 **명령을 실행하기 전에** 찍는다 — helper 가 멈춰도 무엇을 실행 중인지 보인다
- python `-c` 도우미는 뜻으로 바꿔 보인다(`sysfs PCI reset (reset_method=flr) …`, `echo 1 > …/remove`)
- `[ready]` 는 **상태가 바뀔 때만** 한 줄, 경과 시간과 함께. `gate` 코드는 실패 사유 끝에 남긴다
- 사전시험은 터미널 필터 이전이라 들여쓰기 줄, 캠페인 중 주입은 모든 줄에 `[Exception]`
  (`exception-000001 controller_reset 주입 — 명령 Write 실행 중` → 단계 → `재개 OK`)
- 실패 사유(`ExceptionFailure`)도 사람용 문장으로 바꿨다. 원본 관측값은 `exceptions.jsonl` 의
  `ready_timeout` 행에 그대로 있다
- 요약표는 한글 표시 폭 기준으로 정렬한다

위 `사전시험 실패 로그 판독` 절의 `preflight failed; campaign stopped` 문구는 `통과 N/M — 실패로
캠페인 중단` 으로 바뀌었다.
