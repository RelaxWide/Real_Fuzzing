# RISC-V 신제품 브링업 — v10.0 조사 노트

> 살아있는 문서. 사실이 확인될 때마다 갱신한다.
> 표기: **✅ 확정**(실측/원자료) / **❓ 추론**(검증 필요) / **⬜ 미확인**

**목표:** 신제품(RISC-V 기반)에 퍼저를 올린다. 기존 `pc_sampling_fuzzer_v9.7.py` 의
**샘플러 층만 교체**하는 것이 v10.0 의 범위다(NVMe·코퍼스·LLM·replay 등은 주소 무관 → 그대로).

---

## 1. 확정된 사실

### 1.1 코어

| 항목 | 값 | 출처 |
|---|---|---|
| **✅ 코어** | **`SF-E76` = SiFive E76** | T32 `SYStem.CPU` |
| ✅ 코어 개수 | **5개** — `hcore`, `CMCore`, `Fcore0`, `QCore`, `Ncore` | T32 스크립트 |
| ❓ 하트 개수 | 코어당 1하트면 5하트 | 확인 필요 |

> **SF-E76 이 밝혀진 게 큰 수확이다.** 미지의 커스텀 코어가 아니라 **문서가 공개된 SiFive 표준 코어**다.
> RISC-V Debug Spec 을 표준대로 구현했을 가능성이 높고, OpenOCD/J-Link 도 SiFive 를 안다.

### 1.2 디버그 포트 — **cJTAG**

| 항목 | 값 |
|---|---|
| **✅ 포트 타입** | **cJTAG (IEEE 1149.7, 2선)** — `SYStem.CONFIG.DEBUGPORTTYPE CJTAG` |
| ✅ cJTAG 플래그 | `NOKEEPER USEOAC` |
| ✅ JTAG 클럭 | **USB 연결 시 10MHz** / Ethernet 시 5MHz |
| ✅ TAP 체인 | `IRPRE/IRPOST/DRPRE/DRPOST` **없음** → 단일 TAP 으로 보임 |

**→ 4선 JTAG 로는 절대 안 붙는다.** J-Link 4선 시도가 `all ones` 로 실패한 원인이 이것으로 확정.
cJTAG 는 TDI/TDO 배선이 없어 TDO 가 풀업으로 계속 1 이다.

`USEOAC` = OAC(Online Activation Code) 방식으로 2선 모드 진입. `NOKEEPER` = 타깃이 keeper 미구현.
**디버거가 이 활성화 방식을 정확히 맞춰야** 한다 — "cJTAG 지원"만으로는 부족할 수 있다.

### 1.3 접근 토폴로지 — **ARM DAP 경유** ★ 예상과 다름

표준 RISC-V DTM(`dtmcs`/`dmi` JTAG DR)이 **아니다.** ARM CoreSight ADI 를 전송로로 쓴다.

```
cJTAG(2선) → ARM DP → AP(여러 개) → APB 버스 → RISC-V Debug Module / 코어 디버그
```

**✅ AP 목록** (T32 `SYStem.CONFIG.*.Base`, 전부 `DP:` 공간)

| AP | T32 Base | ❓ 추론 AP 번호 |
|---|---|---|
| APBAP1 | `DP:0x10000` | 1 |
| APBAP2 | `DP:0x20000` | 2 |
| AXIAP1 | `DP:0x30000` | 3 |
| AHBAP1 | `DP:0x40000` | 4 |
| APBAP3 | `DP:0x50000` | 5 |
| APBAP4 | `DP:0x60000` | 6 |

> **❓ 추론:** `DP:0xN0000` 의 상위 니블이 곧 **APSEL(AP 번호)** 로 보인다(0x10000→1, 0x20000→2 …).
> 맞으면 OpenOCD `-ap-num N` 에 1:1 대응된다. **검증 필요.**

**✅ 코어 디버그 base** (`SYStem.CONFIG.COREDEBUG.Base`, APB 공간 — 코어마다 다름)

| 코어 | Base |
|---|---|
| hcore / CMCore / Fcore0 / QCore | **`APB:0x81480000`** |
| **Ncore** | **`APB:0x81481000`** |

> ✅ 확인 완료(오타였음). **4KB(0x1000) 간격** = CoreSight 컴포넌트 표준 배치와 일치.
> ⬜ 다만 4개 코어가 **같은 base** 를 공유하는 점은 여전히 확인 필요 —
> T32 가 코어별 인스턴스로 뜨며 각자 다른 값을 주입받는 구조일 가능성.

### 1.4 기타

| 항목 | 값 |
|---|---|
| ✅ `SYStem.Mode` | `up`/`down`/`prepare` 만 사용. **`Attach` 없음** |
| ✅ `SYStem.Up` | 1회, `ERROR.RESet` 직후 |
| ✅ `Data.Set` | 다수 — 대부분 **코어 halt 관련**으로 보임 |
| ✅ 멀티 인스턴스 | `INTERCOM.execute Localhost:&port` — T32 인스턴스 간 통신 = 코어별 인스턴스 |
| ⬜ 파일명 `Init_**FPGA**_RISCV.cmm` | **FPGA 프로토타입용인지 양산칩용인지 미확인** |

---

## ★★★ 2026-08-07 — **J-Link connect 성공**

```
SetcJTAGInitMode = 0
set_tif(7)            # cJTAG
set_speed(10000)
CORESIGHT_AddAP = Index=0 Type=APB-AP Addr=0x10000
CORESIGHT_AddAP = Index=1 Type=APB-AP Addr=0x20000
CORESIGHT_AddAP = Index=2 Type=AXI-AP Addr=0x30000
CORESIGHT_AddAP = Index=3 Type=AHB-AP Addr=0x40000
CORESIGHT_AddAP = Index=4 Type=APB-AP Addr=0x50000
CORESIGHT_AddAP = Index=5 Type=APB-AP Addr=0x60000
CORESIGHT_SetIndexAPBAPToUse = 0        # APBAP1 @0x10000
CORESIGHT_SetCoreBaseAddr    = 0x81481000
connect('RISC-V')
```

**이게 v10.0 의 최대 관문이었다.**

### ★★ 첫 `connect()` 는 구조적으로 실패한다 (통제 실험으로 확정)

같은 주소를 두 번 시도하는 통제 실험으로 **위치 vs 주소** 교락을 풀었다:

| 실험 | 결과 |
|---|---|
| `0x81481000` 단독 | 1회차 실패 |
| **`0x81480000` → `0x81480000`** | **1회차 실패, 2회차 성공** |
| `0x81481000` → `0x81480000` | 1회차 실패, 2회차 성공 |

**같은 주소인데 1회차만 실패한다** → 주소 문제가 아니라 **순서 문제**다.

- 첫 `connect()` 는 `Error while halting CPU / Specific core setup failed` 로
  실패하며 **예열 역할**을 한다
- 두 CoreBase 모두 **J-Link connect 후보로 통과**: `0x81480000`(4코어 공유) / `0x81481000`(Ncore)
  ⚠ "접근 가능" 이 아니다 — DM register/hart/PC/halt 미검증. 다른 AP·선택 메커니즘을 아직 배제하지 말 것
- APB Index 0(APBAP1)로 둘 다 connect 후보 통과. 다만 **다른 AP·선택 메커니즘을
  배제하지는 않는다** — 코어 귀속이 확정되기 전까지는 열어둔다
- **핸들을 close 하면 예열이 사라진다.** 하나의 핸들로 반복해야 한다

> **폐기:** "`0x81480000`(hcore 계열)은 연결 실패" 라는 앞선 결론은 **틀렸다.**
> 그 주소가 항상 첫 자리에 있었던 탓이고, 순서를 통제하니 정상 연결된다.

→ **T32 가 `SYStem.Up` 을 재시도 루프로 감싼 이유가 이것이다.** 불안정해서가 아니라
  첫 시도가 구조적으로 실패하기 때문. (이 해석을 두 번 뒤집은 끝에 확정)

→ **샘플러도 connect 를 2회 이상 시도해야 한다.**

#### ✅ 메커니즘 분리 완료 — **실패한 connect 자체가 초기화한다**

`isolate_warmup.py` A/B/C 를 여러 번 반복한 결과:

| 실험 | 결과 | 배제 |
|---|---|---|
| **A** setup 1회 → connect 2회 | **2회차 성공** | — |
| B setup 2회 → connect 1회 | 실패 | setup 이중 적용 아님 |
| C setup → sleep → connect | 실패 | readiness 지연 아님 |

**설정을 두 번 넣어도, 기다려도 안 된다. connect 시도 자체가 있어야 한다.**
→ "레지스터를 써야 하는 일"이 빠진 것이고, 유력 후보는 **ARM DAP 디버그 도메인 전원**이다
  (`CTRL/STAT ← 0x50000000` → `0xF0000000` ACK. pylink 프로브에서 이미 실측).

J-Link 의 connect 도 결국 이걸 하지만 **같은 connect 안의 CPU setup 단계보다 늦게**
하는 것으로 보인다. 그래서 1차는 실패하고 2차가 붙는다.

→ 시도한 해법: `InitTarget()` 에서 전원을 미리 올린다 (`SF_E76_config.JLinkScript`).
  **결과: 실패 — 전원 ACK 안 뜸.** `InitTarget()` 안의 `JLINK_CORESIGHT_*` 호출이
  동작하지 않는다. `SF_E76_addap.JLinkScript` 에서 전부 `0x80000000` 이 나왔던 것과
  같은 현상으로, **현재 사용한 JLinkScript 훅과 호출 순서에서는** `JLINK_CORESIGHT_*` 접근이 동작하지 않았다
  (훅 시점·DLL 버전·선행 초기화 조건 문제일 수 있어 일반화 금지.
   `ConfigTargetSettings()` 의 command string 설정과 `InitTarget()` 의 저수준 API 실패는
   서로 다른 경로이므로 한 결론으로 합치지 않는다).

→ **bounded retry 는 임시 workaround 로만 쓴다. 원인 규명은 계속한다.**

  재시도로 붙는 것은 정상이 아니고, 이 프로젝트에선 특히 위험하다 —
  **퍼저는 POR 복구·크래시 후 수백 번 재연결**한다. 매번 첫 시도가 실패하는 걸
  전제로 두면 운영 리스크이고, J-Link 펌웨어/소프트웨어가 바뀌면 깨질 수 있다.

  임시 정책 규칙 (feedback.md §8.5):

  | 규칙 | 이유 |
  |---|---|
  | 재시도 상한(3회) | 무한 재시도 금지 |
  | 1회차 실패를 로그·카운터로 남김 | 숨기면 진짜 고장을 못 본다 |
  | **한 handle = 한 설정** | 조합을 섞으면 거짓 성공/전체 실패 (실측 2회) |
  | **best-effort resume 보장** | ★ halt 로 남으면 SSD 컨트롤러가 멈춘다 |

#### ★ 유력 가설 — RISC-V DM 의 `dmactive`

RISC-V Debug Spec 상 **`dmcontrol.dmactive` 를 1 로 쓴 뒤 되읽어 1이 될 때까지
기다려야** DM 이 리셋에서 깨어난다. J-Link 이 `dmactive=1` 을 쓰고 **기다리지 않고
바로 `haltreq`** 를 하면 정확히 관측된 에러가 난다:

```
Error while halting CPU  ->  Specific core setup failed
```

2차 connect 때는 이미 `dmactive=1` 이라 성공한다.

**이 가설이 A/B/C 를 전부 설명한다:**

| 실험 | 결과 | dmactive 로 설명 |
|---|---|---|
| B setup 2회 | 실패 | setup 은 DM 을 안 건드린다 |
| C sleep | 실패 | **레지스터를 써야** 하는 일이라 시간으론 안 됨 |
| A connect 2회 | 성공 | 1차가 `dmactive=1` 을 쓴다 |

#### 남은 실험 — `diagnose_connect.py`

| | 실험 | 성공 시 의미 |
|---|---|---|
| **D** | 성공 후 close/reopen → **1회** connect | 성공 = 상태가 **타깃**에 남음(dmactive 지지). 퍼저는 세션당 1회만 예열하면 됨 |
| **E** | 장치명 후보별 1회 connect | 성공 = 제네릭 `RISC-V` 프로파일이 원인. **가장 깨끗한 해결** |
| **F** | `RISCV_SetHartSel` 을 connect 前에 | 성공 = 기본 하트가 halt 불가였던 것 |

**D 가 특히 실용적으로 중요하다** — 재연결마다 예열이 필요한지, 전원 사이클당 1회면
되는지가 갈린다. 퍼저 운영 설계가 여기서 달라진다.

#### ⬜ 미확인 — JLinkScript 의 첫 connect 는 성공했나?

`SF_E76_config.JLinkScript` 실행 시 **전원 ACK 는 안 떴다.** 그러나
**`connect()` 자체의 성공 여부는 확인되지 않았다.** ACK 와 무관하게 첫 connect 가
붙었다면 `ConfigTargetSettings()` 의 AP map 선언만으로 해결된 것이므로 반드시 확인할 것.
  (feedback.md §2.1 이 `InitTarget()` 의 용도로 '전원' 을 명시했는데,
   내가 "T32 에 커스텀 시퀀스 없음" 을 이유로 비워둔 것이 놓친 지점이었다 —
   이건 벤더 커스텀이 아니라 ARM DAP 표준 절차다)

#### 근본 해법 후보 — `ConfigTargetSettings()`

pylink `exec_command()` 는 `connect()` **직전**에 설정을 넣는데, SEGGER 정식 절차는
**`ConfigTargetSettings()` 훅**이다. 이 훅은 **CPU 자동검출보다 앞서** 호출되므로
cold session 의 첫 connect 를 성공시킬 수 있다.
→ `SF_E76_config.JLinkScript` (기존 `SF_E76_addap.JLinkScript` 는 `InitTarget()` 을
  써서 시점이 늦었다 — 그게 첫 connect 실패의 원인으로 의심된다)

#### ⚠ 원칙 — 하나의 handle 에 여러 조합을 섞지 말 것

스윕이 두 번 실패한 이유가 이것이다:
- 핸들 재사용 → 한 번 연결되면 이후가 전부 거짓 성공(23/24)
- 조합마다 close → 필요한 초기화까지 사라져 전부 실패

**한 handle = 한 설정.** 조합을 바꾸려면 세션을 새로 시작한다.

#### ⚠ 코어 귀속은 아직 미확정

`connect()` 성공이 **어느 코어에 붙었는지**를 말해주지 않는다.
`0x81480000` 이 hcore/CMCore/Fcore0/QCore 중 무엇인지는
halt → PC 읽기 → hart 비교로 확인해야 한다.

### 폐기된 가정

- ~~`0x81480000 + 0xFF0` 에서 CoreSight `CIDR0 = 0x0D` 를 확인한다~~
  → DMI aperture 라면 CoreSight ID 레지스터가 없다. **판정 기준이 틀렸었다.**
- ~~APSEL 번호로 AP 를 지정한다~~
  → `CORESIGHT_AddAP` 의 `Index` 는 **J-Link 내부 AP 맵 번호**이고
    실제 위치는 `Addr`. T32 의 `DP:0xN0000` 은 주소였다.

---

## ★★ 2026-08-07 — 원인 규명 (SEGGER 공식 문서)

SEGGER KB **"J-Link RISC-V"** 가 우리 토폴로지를 그대로 문서화하고 있다:

> 지원 토폴로지: `JTAG/SWD → SWJ-DP → APB-AP → DMI registers`
> **"there is no ROM table scan available for RISC-V"**
> **"J-Link cannot auto-detect the AP location or DMI register positioning in hybrid designs"**

**→ J-Link 은 이 구성을 자동 검출할 수 없다. 반드시 수동으로 알려줘야 한다.**

지금까지 APSEL 스윕·ADIv6 주소·AddAP 가 전부 실패한 이유가 이것이다.
**우리 코드 문제가 아니라, 애초에 자동 검출이 불가능한 구성**이었다.

### 필요한 설정 (J-Link Command Strings)

| 명령 | 뜻 |
|---|---|
| `CORESIGHT_AddAP = Index=<i> Type=<T> Addr=<base>` | AP 등록. **Index 는 J-Link 내부 번호이지 하드웨어 APSEL 이 아니다.** `Addr` 이 실제 CoreSight 주소 → T32 의 `DP:0x10000` 과 대응 |
| `CORESIGHT_SetIndexAPBAPToUse = <i>` | DMI 가 붙은 APB-AP 지정 |
| `CORESIGHT_SetCoreBaseAddr = <addr>` | **AP 주소공간 내 DMI 레지스터 위치** → T32 `COREDEBUG.Base` |
| `SetcJTAGInitMode = <0\|1\|2>` | cJTAG 활성화 시퀀스 변형 (0=LONG 기본, 1=SHORT, 2=WILIOT) |
| `RISCV_SetHartSel = <n>` | 멀티하트 선택 (코어 5개) |
| `RISCV_SetTEBaseAddr = <addr> [APIndex=..]` | **RISC-V 트레이스 인코더** — 나중에 쓸 것 |

pylink 는 `exec_command()` 로 이 문자열들을 그대로 낼 수 있다.
(DLL 심볼 `AddAP` 가 없었던 것과 별개 경로다.)

**★ `SetcJTAGInitMode`** — T32 의 `CJTAGFLAGS NOKEEPER USEOAC` 와 대응될 수 있는
활성화 시퀀스 선택지. J-Link 기본(LONG)이 안 맞을 가능성이 있어 0/1/2 전부 시도한다.

**★ `RISCV_SetTEBaseAddr` 의 존재 = J-Link 이 RISC-V 트레이스를 지원한다는 뜻.**
halt 샘플러가 돌기 시작한 뒤 트레이스 트랙을 열 때 결정적 단서.

→ 실행: `connect_sfe76.py`

---

## 2. 지금까지의 실측

### ★ 2026-08-07 — DP 접근 성공

```
성공 조합: TIF=7, perform_tif_init=True, connect() 선행(실패해도 무방)
  DPIDR     = 0x6BA0009D     ← 유효. PARTNO 0xBA00 = ARM DAP
  CTRL/STAT = 0xF0000000     ← CSYSPWRUPACK|CDBGPWRUPACK
```

**ARM DAP 토폴로지 실측 확정. 디버그 전원 인가 성공.**

주의: `connect('RISC-V')` 는 `Error while halting CPU / Specific core setup failed`
로 **실패**하지만, 그 시도가 뭔가를 초기화하므로 **호출은 해야 한다**(무시하고 진행).

**남은 문제:** APSEL 0~7 열거가 전부 `0x00000000`.
→ T32 의 `APBAP1.Base DP:0x10000` 을 글자 그대로 **AP 주소**로 읽으면
   **ADIv6**(APSEL 폐지, 주소 기반 AP 지정)이라는 뜻이 된다. 그렇다면 APSEL
   순회는 원리적으로 아무것도 못 찾는 게 맞다. → 주소 방식으로 재시도 중.

### J-Link 전기적 상태 — **정상**
```
VTref   = 1.793V        ← 타깃 급전 정상 (1.8V 계열)
ITarget = 0mA           ← 정상 (타깃 자체 전원)
TCK/TDI/TDO/TMS/TRES/TRST = 모두 1   ← 유휴 풀업, 정상
```

### OpenOCD 4선 JTAG 스캔 — **실패 (원인 규명됨)**
```
JTAG scan chain interrogation failed: all ones
probe.tap: IR capture error; saw 0x1f not 0x01
```
→ **cJTAG 이므로 당연한 실패.** IRLEN 스윕은 무의미(IDCODE 스캔은 IR 을 안 씀).

환경: OpenOCD **0.12.0** (RISC-V 지원 포함 버전)

### OpenOCD J-Link 드라이버 — **cJTAG 미지원 (확정)**

`openocd -c "adapter driver jlink" -c "help jlink"` 전체 명령 목록에 **cJTAG/1149.7 관련이 없다.**

```
jlink config … / emucom / freemem / hwstatus / jtag [2|3] / targetpower / usb<0-3>
```

> ⚠ **`jlink jtag [2|3]` 은 cJTAG 가 아니다** — OpenOCD↔J-Link 펌웨어 간
> **JTAG 명령 프로토콜 버전**(JTAG2/JTAG3) 선택이다. 혼동 주의.

**→ OpenOCD + J-Link 경로는 막혔다.** 아래 선택지로 이동.

### J-Link 펌웨어 — **cJTAG 지원 확인 ✅**

```
J-Link> si cJTAG
Selecting cJTAG as current target interface.
```
펌웨어: **V13, compiled Dec 18 2025** (최신). → **경로 A 유효.**

### 보드 배선 — **TDI/TDO 존재 ✅**

10핀 커넥터 설계에 **TDO/TDI 가 배선돼 있다.** → 4선 레거시 JTAG 가 **물리적으로 가능**.

> ### ★ 핵심 추론 — 4선 실패의 진짜 이유
>
> **IEEE 1149.7 장치는 전원 인가 시 4선(레거시) 모드로 시작하고, 활성화 시퀀스를 받아야
> 2선 모드로 전환된다.** 즉 **T32 가 이미 칩을 2선 모드로 바꿔놓은 상태**에서 4선으로
> 접근해 TDO 가 안 나왔을 가능성이 높다.
>
> **→ 타깃 전원을 껐다 켜면 4선 모드로 복귀한다.** 단, 그 뒤 **T32 를 띄우기 전에
> J-Link 이 먼저** 붙어야 한다.

---

## 3. 열린 질문 — 우선순위 순

| # | 질문 | 확인 방법 | 왜 중요 |
|---|---|---|---|
| ~~1~~ | ~~J-Link cJTAG 지원~~ | — | **확정: 지원함** (`si cJTAG` 수락, FW V13) |
| ~~1b~~ | ~~TDI/TDO 배선~~ | — | **확정: 배선 있음** (10핀 설계) |
| **A** | **전원 사이클 후 4선이 붙나?** | 전원 OFF→ON → **T32 띄우기 전에** OpenOCD 4선 스캔 | ★ 되면 가장 편한 경로. OpenOCD 그대로 |
| **B** | J-Link cJTAG 실제 연결 | `si cJTAG` → `speed 1000` → `connect` | A 가 안 될 때 |
| **C** | 10핀 핀아웃이 J-Link ARM 규격과 같나 | 회로도 대조 (2=TMS, 4=TCK, 6=TDO, 8=TDI, 10=nRESET) | 커스텀이면 4선 불가 |
| ~~2~~ | ~~OpenOCD jlink cJTAG~~ | — | **확정: 미지원** (§2) |
| ~~3~~ | ~~코어 base 주소~~ | — | **확정: `0x81480000` / `0x81481000`** (§1.3) |
| 4 | RISC-V **DM base** 주소 (APB 상 위치) | T32 스크립트 재검색 | halt/PC 읽기의 핵심 |
| 5 | `SYStem.Up` 이전 커스텀 초기화 시퀀스 | CMM 에서 `SYStem.Up` 위쪽 `Data.Set` | 디버그 도메인 전원/언락 — 조용한 실패 원인 1순위 |
| 6 | 하트 개수 / 코어↔하트 매핑 | DM `dmstatus` 또는 SiFive 문서 | 샘플러가 복수 PC 를 읽어야 함 |
| 7 | `Init_FPGA_RISCV.cmm` 이 실사용인가, FPGA 전용인가 | `.bat` → `DO` 체인 추적 | 잘못된 참조면 전부 무의미 |
| 8 | 펌웨어 `.text` 범위 / ITCM / **오버레이 사용 여부** | 벤더 자료 | 커버리지 필터 + 오버레이 문제 |

---

### 경로 선택지 (1번 결과에 따라)

| # | 경로 | 조건 |
|---|---|---|
| A | **pylink/JLinkExe 직접** (OpenOCD 우회) | J-Link 펌웨어가 cJTAG 지원 시. v9.x `JLinkHaltSampler` 가 이미 pylink 직접 방식이라 자연스러움 |
| B | **4선 레거시 JTAG** | 보드에 TDI/TDO 배선 존재 시. **가장 편한 경로** — OpenOCD 그대로 |
| C | SiFive / riscv-collab **OpenOCD 포크** | SiFive 보드가 cJTAG 를 쓰므로 지원 가능성 |
| D | **cJTAG 지원 프로브 조달** | A~C 전부 불가 시. **리드타임 고려해 판단을 앞당길 것** |
| E | Lauterbach 유지 | 이미 붙지만 퍼저 자동화 연동이 번거로움 |

---

## 4. ★ 재검토 필요 — Nexus 트레이스

앞서 "STM 을 대체하는 Nexus Trace Feature" 를 보고 **관계없다고 접었는데, 다시 봐야 한다.**

**SiFive 의 트레이스(Insight)는 Nexus 기반이고 Program Trace(분기 트레이스)를 포함한다.**
코어가 SF-E76 으로 확인된 이상, 그 Nexus 블록이 **명령 트레이스일 가능성이 높다.**

확인할 것:
- Nexus **Class 등급** (2 이상이면 Program Trace 포함)
- `Program Trace` / `Branch Trace` / `DBM` / `IBM` 언급
- **싱크가 온칩 버퍼인가** (→ JTAG 로 드레인 가능 = J-Link 로 가능)

되면 **halt 없는 완전 커버리지** — 이 프로젝트 최대 약점 두 개(부분맹 커버리지, halt 유발
호스트 프리즈)가 한 번에 해소된다. 다만 **크리티컬 패스에 두지 말 것**(§5 참조).

---

## 5. 다음 단계

> **이 문서는 조사 이력이다.** 지금 실행할 명령과 판정 기준은 `README.md` 를 볼 것.

### 완료 (역사)

| | 내용 |
|---|---|
| ~~전원 사이클 후 4선 JTAG 스캔~~ | 폐기 — cJTAG 확정 |
| ~~J-Link cJTAG connect~~ | ✅ 완료 |
| ~~핀아웃 확인~~ | ✅ TDI/TDO 배선 확인 |
| ~~DM base / `SYStem.Up` 전 시퀀스 추출~~ | ✅ 커스텀 시퀀스 없음 확인, DM base 확보 |
| ~~AP 스윕~~ | ✅ APBAP1 로 충분 |

### 지금

**`verify_halt_pc.py` 로 halt → PC → resume 을 안전하게 검증한다.**
먼저 **Ncore(`0x81481000`)** 로 — 단일 하트로 **추정**되어 변수가 적을 것으로 보인다
(하트 수는 아직 확인 전이다).
이게 안 되면 멀티코어 스윕이나 샘플러 통합으로 넘어가지 않는다.

### 그다음

1. 첫 connect 실패 원인 (`diagnose_connect.py` D/E/F)
2. `0x81480000` 네 코어 귀속 — PC fingerprint 로. **PC 가 읽힌다고 코어 이름을
   붙이지 말 것.** 최소 두 개의 독립 fingerprint 가 일치할 때만 확정.
3. 내구성 — halt/read/resume 1,000회, close/reopen 반복, POR 복구 반복,
   NVMe I/O 동시 수행 시 timeout/hang 영향

---

## 6. 재사용 자산

**기존 ARM 설정이 골격 그대로 맞는다** — DAP + mem_ap 구조가 동일하기 때문:

```tcl
# r8_pcsr_jtag.cfg (기존 ARM) — RISC-V 도 같은 뼈대
dap create X.dap -chain-position X.cpu
target create X.abp mem_ap -dap X.dap -ap-num 0    ← APBAP 번호로 교체
X.dap dpreg 4 0x50000000    # CSYSPWRUPREQ|CDBGPWRUPREQ (디버그 전원)
X.dap dpreg 0 0x1e          # sticky error 클리어
```

⚠ **주의:** `dmcontrol 0x10`, `dmstatus 0x11` 등은 **DMI register address** 이지
APB byte offset 이 아니다. `CORESIGHT_SetCoreBaseAddr` 가 가리키는 벤더 DMI aperture 의
레이아웃과 J-Link 의 변환 방식을 확인하지 않은 채 `base + 0x10` 식으로 읽고 쓰면
**엉뚱한 장치를 건드릴 수 있다.** 직접 접근은 벤더/T32 자료로 레이아웃을 확보한 뒤에만. `target create ... riscv`(표준 DTM 전제)는 안 맞을 수 있다.

**포팅 가능한 기존 도구:**
| 도구 | 용도 |
|---|---|
| `jlink_reg_diag.py` | PC 레지스터 인덱스 탐색 (ARM 때 만든 것, 그대로 재사용) |
| `halt_loop_stress.py` | **halt 가 PCIe 를 멈추는지 조기 검증** — 신제품에서 재발하는지 반드시 볼 것 |
| `ghidra_export.py` | Ghidra RISC-V 로 BB 추출. thumb 마스킹은 코드가 자동 판별하므로 무변경 |

---

## 7. 아키텍처 결정 (잠정)

| 단계 | 내용 | 상태 |
|---|---|---|
| **0a** | connect (G1) | ⚠️ **부분** — bounded retry 로만. 원인 미규명 |
| **0b** | halt + PC + resume (G2~G4) | ⬜ ← 지금 여기. `verify_halt_pc.py` |
| 1 | 임의 주소 메모리 read/write | |
| 2 | System Bus Access (halt 없는 메모리 접근) | 오버레이 탐지에도 필요 |
| 3 | 트레이스 유닛 레지스터 맵 확보 | |
| 4 | 드레인 + Nexus 디코더 → **트레이스 커버리지** | 병행 트랙 |

**0단계만 되면 퍼저는 돈다.** 트레이스는 성공하면 halt 를 대체하고, 실패해도 v10.0 은 이미 동작.
