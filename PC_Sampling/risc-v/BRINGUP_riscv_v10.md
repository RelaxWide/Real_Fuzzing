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

## ★★★ 2026-08-08 — **J-Link connect 성공**

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

### ★ 주목 — CoreBase 가 `0x81481000` 이다

`0x81480000` 이 아니라 **`0x81481000`** 에서 붙었다. T32 에서 이 주소는 `Ncore` 로
보였는데, RISC-V behind DAP 에서 `CORESIGHT_SetCoreBaseAddr` 은
**"AP 주소공간 내 DMI 레지스터 위치"** 이므로 **"코어별 base" 라는 내 해석 자체가
틀렸을 가능성**이 높다(feedback.md §2.4 가 지적한 그대로).

→ 코어가 5개이므로 **어느 코어/하트에 붙은 것인지, 나머지는 어떻게 접근하는지**가
   다음 확인 사항. `RISCV_SetHartSel` 로 열거한다.

### 폐기된 가정

- ~~`0x81480000 + 0xFF0` 에서 CoreSight `CIDR0 = 0x0D` 를 확인한다~~
  → DMI aperture 라면 CoreSight ID 레지스터가 없다. **판정 기준이 틀렸었다.**
- ~~APSEL 번호로 AP 를 지정한다~~
  → `CORESIGHT_AddAP` 의 `Index` 는 **J-Link 내부 AP 맵 번호**이고
    실제 위치는 `Addr`. T32 의 `DP:0xN0000` 은 주소였다.

---

## ★★ 2026-08-08 — 원인 규명 (SEGGER 공식 문서)

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

### 즉시 (오늘)
1. **실험 A — 전원 사이클 후 4선 스캔** (§3-A). 순서가 핵심: 전원 ON 직후 **J-Link 이 먼저**
2. 실패 시 **실험 B — J-Link cJTAG connect** (§3-B)
3. 10핀 핀아웃 대조 (§3-C)
4. `.bat` → `DO` 체인으로 `Init_FPGA_RISCV.cmm` 실사용 여부 확인

### 그다음
3. T32 에서 **DM base 주소**와 **`SYStem.Up` 이전 시퀀스** 추출
4. OpenOCD cfg 작성 — 기존 `r8_pcsr_jtag.cfg` 골격 재사용 (아래)
5. `dmstatus` 읽어 Spec 버전·인증 상태·하트 수 확인

### 병행 (크리티컬 패스 아님)
6. Nexus 트레이스 Class/싱크 조사 (§4)

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

RISC-V DM 레지스터(`dmcontrol` 0x10 / `dmstatus` 0x11 / `command` 0x17 / `data0` 0x04)를
**APB 주소로 접근**하는 방식이 된다. `target create ... riscv`(표준 DTM 전제)는 안 맞을 수 있다.

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
| **0a** | **connect** | ✅ **완료** (2026-08-08) |
| **0b** | halt + `dpc` 읽기 + resume → **halt 샘플러** | ← 지금 여기. `verify_halt_pc.py` |
| 1 | 임의 주소 메모리 read/write | |
| 2 | System Bus Access (halt 없는 메모리 접근) | 오버레이 탐지에도 필요 |
| 3 | 트레이스 유닛 레지스터 맵 확보 | |
| 4 | 드레인 + Nexus 디코더 → **트레이스 커버리지** | 병행 트랙 |

**0단계만 되면 퍼저는 돈다.** 트레이스는 성공하면 halt 를 대체하고, 실패해도 v10.0 은 이미 동작.
