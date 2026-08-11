# 질문서 — SF-E76 RISC-V DM 에 J-Link 으로 도달하지 못한다

> 실측만 적었다. 추정은 "추정" 이라고 표시했다.
>
> ⚠ **이 문서는 계획이 아니라 보조 채널이다.** 벤더는 T32 관련만 답할 수 있고,
> **J-Link 스크립트는 우리가 만든다**(`try_jlinkscript.py` / `SF_E76_riscv.JLinkScript`).
> 그러니 §5 에서는 **"J-Link 를 어떻게 설정하나" 를 묻지 말고, T32 가 이미
> 알고 있는 사실**만 받아온다:
> `APBACCESSPORT` 값 · `COREDEBUG.Base` 의 의미(DMI aperture 인가 컴포넌트 base 인가)
> · `SYStem.UP` 전 unlock/`Data.Set` 시퀀스 유무 · 퓨즈/패스워드 여부 · 펌웨어 ELF.

---

## 1. 구성

| | |
|---|---|
| 타깃 | SiFive **SF-E76** 기반 커스텀 SSD 컨트롤러 (Arty 보드 아님) |
| 프로브 | **J-Link Plus**, **하드웨어 V13.00**, 소프트웨어 **V9.66** |
| 인터페이스 | **cJTAG** (`SetcJTAGInitMode=0`, TIF=7), **10 MHz** |
| 호스트 | Linux, pylink-square 2.0.0 |
| 목표 | 펌웨어 코드 커버리지를 **트레이스 기반**으로 수집. halt 는 하지 않는다 |

**T32(TRACE32)로는 이 제품에서 코드 커버리지 수집이 실제로 동작한다.**
T32 하드웨어가 벤치에 없어 교차검증은 불가하고, T32 스크립트만 갖고 있다.

## 2. 동작하는 것 (전부 실측)

**2.1 cJTAG / DP**
```
DPIDR = 0x11013913
   VERSION  = 3      → DPv3 / ADIv6 / CoreSight SoC-600
   DESIGNER = 0x489  → SiFive
```
JTAG TAP 은 IRLen=4 인 CoreSight DAP TAP.

**2.2 DAP 전원 — 디버그·시스템 둘 다 ACK**
```
CTRL/STAT 에 0x50000000 (CDBGPWRUPREQ|CSYSPWRUPREQ) 기입
→ CDBGPWRUPACK=1, CSYSPWRUPACK=1  확인
```

**2.3 AP 6개 전부 실재 — IDR 실측이 T32 선언과 6/6 일치**

| T32 `SYStem.CONFIG` | AP 주소 | IDR | CLASS | TYPE |
|---|---|---|---|---|
| `APBAP1.Base DP:0x10000` APB-AP | `0x10000` | `0x09130006` | 8 MEM-AP | 6 = APB4/5 |
| `APBAP2.Base DP:0x20000` APB-AP | `0x20000` | `0x09130006` | 8 MEM-AP | 6 = APB4/5 |
| `AXIAP1.Base DP:0x30000` AXI-AP | `0x30000` | `0x09130004` | 8 MEM-AP | **4 = AXI3/4** |
| `AHBAP1.Base DP:0x40000` AHB-AP | `0x40000` | `0x09130001` | 8 MEM-AP | **1 = AHB3** |
| `APBAP3.Base DP:0x50000` APB-AP | `0x50000` | `0x09130006` | 8 MEM-AP | 6 = APB4/5 |
| `APBAP4.Base DP:0x60000` APB-AP | `0x60000` | `0x09130006` | 8 MEM-AP | 6 = APB4/5 |

전 AP `DESIGNER=0x489`(SiFive). **AP 레지스터 읽기·쓰기 동작하고, DP SELECT 로
AP 전환도 된다**(6개가 서로 다른 IDR 을 준다).

## 3. 막힌 곳 — 딱 하나

```
Timeout waiting for debug module to become active     (dmcontrol.dmactive 안 올라옴)
```

시도한 것과 결과:

| 시도 | 결과 |
|---|---|
| `CORESIGHT_AddAP`(6개) + `SetIndexAPBAPToUse=0` + `SetCoreBaseAddr=0x81480000` | dmactive 타임아웃 |
| `SetCoreBaseAddr` = `0x81480000` / `0x81481000` × APB-AP 인덱스 일부 | 전부 실패 (**전수 스윕은 아직 미실행**) |
| 장치명 `E76` / `E76-MC` / `RISC-V` (AP 맵 수동지정 없이) | `Could not find supported CPU` |
| 장치명 `E76ARTY` | `Target is not connected` |
| MEM-AP 로 `0x81480000` 직접 읽기 (TAR/DRW) | **6개 AP 전부 무응답 상수** (`0xEAFFFFFE`/`0xEAFFFFFC`/`0`) |
| MEM-AP 로 AP 주소공간 `0x0` 읽기 | ★ `APBAP1=0x81480003`, `APBAP2=0x81481003` (ROM 엔트리) |
| MEM-AP 로 트레이스 블록 `0xFD......` 읽기 | 전 AP 무응답 상수 — **MEM-AP 로는 안 보인다** |
| 주소 디코드 폭 확인 (wrap 탐지, `2^12`~`2^31`) | **wrap 없음** — aliasing 아님 |
| 디버그 전원 사이클 (`CDBGPWRUPREQ` OFF → 500ms → ON) | 값 변화 없음 |
| AP `BASE`(0xDF8) → ROM 테이블 | SEGGER 문서상 **RISC-V 는 ROM 스캔 미지원** |
| `JLinkScriptFile` 경로 | cJTAG 스캔이 깨짐 (`IRPrint=0x..0000`) |

`0x81480000` 의 출처는 T32 스크립트뿐이다:
```
&core_base = APB:0x81480000
INTERCOM.execute ... sys.config.coredebug.base &core_base
```
→ **T32 의 APB 버스 주소**이지, J-Link 이 요구하는 *"address in AP address space"*
와 같다는 보장이 없다. (SEGGER 예제는 `SetCoreBaseAddr = 0x0`)

## 3.5 ★ 결정적 관측 — MEM-AP 읽기가 `0x0`/`0x4` 에서만 동작한다

APBAP1 으로 여러 주소를 32비트 읽은 결과입니다.

| 주소 | 값 |
|---|---|
| `0x00000000` | `0x81480003` |
| `0x00000004` | `0x00000000` |
| `0x00100000`, `0xFD000000`, `0xFD180000`, `0x81480000` … | 전부 `0x00000001` |
| `0x0021BFFC`, `0xFD18001C`, `0x81480044`, `0x81480FFC` | 전부 `0xEAFFFFFE` |

**`0x0` 과 `0x4` 만 서로 다른 값을 주고, 나머지는 주소가 아니라 32바이트 정렬
여부만 보고 두 상수 중 하나로 떨어집니다.** TAR 되읽기는 항상 일치하고,
`CSW.DeviceEn=1`, DP 전원 ACK 도 정상입니다. wrap 탐지로 주소 디코드 폭도
확인했는데 `2^12`~`2^31` 어디서도 wrap 이 없어 aliasing 도 아닙니다.

> **질문:** 이 상태를 어떻게 해석해야 합니까? MEM-AP 는 열거되고 CSW/TAR 도
> 정상 동작하는데 **DRW 만 실제 버스 응답을 못 받는 것**으로 보입니다.
> `Prot`/`Type`/`SDeviceEn` 조합, 또는 별도의 인에이블이 필요합니까?

## 4. SEGGER 지원에 보낼 질문

> **Setup.** SiFive SF-E76 based custom SoC. J-Link Plus, software V9.66, cJTAG
> at 10 MHz. RISC-V is behind a CoreSight DAP (ADIv6 / SoC-600,
> `DPIDR = 0x11013913`, DESIGNER 0x489 SiFive).
>
> **What already works.** cJTAG activation and DP communication are fine.
> DAP power-up succeeds — both `CDBGPWRUPACK` and `CSYSPWRUPACK` are set.
> We declared six APs with `CORESIGHT_AddAP` at DP addresses
> `0x10000/0x20000/0x30000/0x40000/0x50000/0x60000` and verified by reading each
> AP's IDR directly (via DP SELECT + AP register access):
> `0x09130006 / 0x09130006 / 0x09130004 / 0x09130001 / 0x09130006 / 0x09130006`.
> All are MEM-APs (CLASS 8) and their TYPE fields match the declared
> APB/AXI/AHB types exactly, so the AP map and addresses are correct.
>
> **The problem.** `JLINKARM_Connect()` fails with
> *"Timeout waiting for debug module to become active"*. We tried several
> `CORESIGHT_SetIndexAPBAPToUse` / `CORESIGHT_SetCoreBaseAddr` combinations
> without success (an exhaustive sweep is still in progress).
> Selecting device `E76` / `E76-MC` without a manual AP map gives
> *"Could not find supported CPU"*.
>
> **Questions.**
> 1. For "RISC-V behind a CoreSight DAP", is `CORESIGHT_SetCoreBaseAddr` the
>    **offset inside the selected AP's address space**, or an address on the
>    APB bus as seen by the SoC? Our value comes from a TRACE32 script that uses
>    `SYStem.CONFIG.COREDEBUG.Base APB:0x81480000`.
> 2. `CORESIGHT_AddAP` is documented as `Addr=` in the Command Strings page but
>    as `BaseAddr=` in the J-Link RISC-V page. **Which is correct in V9.66, and
>    is an unknown parameter silently ignored?**
> 3. Is there a way to make the DLL log the DMI transactions it attempts, so we
>    can see which address it is driving? (`EnableRemarks`, verbose log level?)
> 4. Is cJTAG + RISC-V-behind-DAP a supported combination in V9.66?
> 5. ★ **The one that matters.** Steady-state cJTAG communication **works** —
>    with `JLINKARM_CORESIGHT_Configure("...IRLenDevice=4;PerformTIFInit=0;")`
>    we read `DPIDR = 0x11013913` and all six AP IDR registers, and their TYPE
>    fields match the TRACE32-declared AP types 6/6 (APB→6, AXI→4, AHB→1).
>    **That is real data; the board and the link are alive.**
>
>    But J-Link's own **TIF init / JTAG chain detection** reads
>    `Id: 0x00000001, IRLen: 04` and then assumes a RISC-V JTAG-DTM, and
>    `target_connected()` is never true. In other words **only the
>    activation / scan phase fails, not communication itself.**
>
>    We have tried every knob we could find for that phase:
>    `SetcJTAGInitMode` 0/1/2, speeds 10 MHz / 4 MHz / 1 MHz / 500 kHz,
>    declaring the TAP via `JLINK_JTAG_SetDeviceId()` with
>    `JTAG_AllowTAPReset = 0` in `InitTarget()`, and 4-wire JTAG
>    (`TIF=JTAG` produces no chain at all).
>
>    **How can we make J-Link skip or replace its chain-detection scan and use
>    a manually declared chain, given that steady-state access already works?**
>
> 6. **KEEPER logic.** TRACE32 connects to this target using
>    `SYStem.CONFIG.CJTAGFLAGS NOKEEPER USEOAC`, i.e. the SoC has **no KEEPER
>    logic**. Your cJTAG page says a workaround exists but *"if a specific
>    J-Link hardware version comes with this workaround can be checked via the
>    model overview page"*.
>    **Does our J-Link Plus (hardware version <채워넣기>, firmware <채워넣기>)
>    include the no-KEEPER workaround?**
>    Symptoms match a floating TMSC exactly: JTAG chain detection reports
>    `Id: 0x00000001, IRLen: 04`, results differ between identical runs, and
>    at <= 500 kHz no scan happens at all. `SetcJTAGInitMode` 0/1/2 make no
>    difference. 4-wire JTAG (TIF=JTAG) produces no chain at all.
>
> A J-Link log file of the failing connect is attached.

**첨부할 것:** `JLinkExe` 를 `-log jlink.log` 로 돌린 로그와
`SetLogVerbose = 1` / `EnableRemarks` 를 켠 출력.

## 5. 벤더/설계팀(또는 T32 스크립트 작성자)에 보낼 질문

> 1. ★ **핵심 질문.** MEM-AP 주소공간 `0x0` 을 읽으면 이렇게 나옵니다:
>    ```
>    APBAP1(DP:0x10000) @0x0 = 0x81480003
>    APBAP2(DP:0x20000) @0x0 = 0x81481003
>    ```
>    CoreSight ROM 엔트리 인코딩(bit0=present, bit1=32bit, 상위20비트=오프셋)이고,
>    가리키는 `0x81480000` / `0x81481000` 이 T32 의 `COREDEBUG.Base` 와 정확히
>    일치합니다. **그런데 그 `0x81480000` 은 어느 MEM-AP 로도 읽히지 않습니다**
>    (CIDR3 자리에 `0xEAFFFFFE` 같은 무응답 상수만 나옵니다).
>
>    → 이 주소는 **AP 주소공간 기준입니까, 아니면 SoC 의 APB 버스 주소입니까?**
>      AP 주소공간 기준으로 DMI 레지스터에 닿으려면 어느 AP 의 **어느 오프셋**을
>      써야 합니까? (`CORESIGHT_SetCoreBaseAddr` 에 넣을 값입니다)
> 2. DMI 레지스터가 그 창 안에서 어떤 간격으로 매핑됩니까?
>    (`dmcontrol`=DMI 0x10 이 `base+0x40` 인지, 즉 `dmi_addr << 2` 인지)
> 3. DM 이 두 개(`0x81480000`, `0x81481000`)로 보이는데, **각각 어느 AP 뒤**입니까?
> 4. DM 에 **별도의 전원/클럭 인에이블**이 필요합니까?
>    (ARM DAP 의 `CDBGPWRUPREQ` 와 별개로)
> 5. ★ **디버그 접근 제어가 걸려 있습니까?** SiFive Insight 문서의
>    *"Multilayered Debug Access Control — fused permanent disable pins,
>    32-bit password barriers, or public-key cryptographic authentication"* 말입니다.
>    - 이 양산/평가 파트에 **퓨즈나 패스워드가 설정되어 있습니까?**
>    - 있다면 **해제 절차와 값**은 무엇입니까?
>    - T32 는 그 해제를 **어디서** 합니까? (우리가 받은 스크립트에는 없습니다)
>    - 증상: DP·DAP 전원·AP 열거·AP 레지스터 읽기는 전부 정상인데
>      **메모리 트랜잭션이 전 AP·전 주소에서 실패**하고 `dmactive` 가 안 올라옵니다.
> 5b. 트레이스 블록(`0xFD000000`, `0xFD180000`)은 **SBA 전용**입니까,
>    아니면 **AXI-AP 로도 접근 가능**합니까? (SBA 는 DM 을 거치므로 우리가 막힙니다)
> 5c. 그 버스 도메인에 **별도 클럭/전원 인에이블**이 필요합니까?
> 6. T32 가 `SYStem.Option.DAPSYSPWRUPREQ OFF` 로 설정된 이유가 있습니까?
> 6b. 이 칩의 Nexus 는 **legacy SiFive Insight Nexus** 입니까, 아니면
>    **비준된 N-Trace 1.0** 입니까? (T32 는 `NEXUS.Type SiFive`, sink 오프셋이
>    `+0x1C/+0x20/+0x24` 로 비준본과 다릅니다)
> 6c. sink 의 **wrap / overflow 정책**은? stop-on-wrap 이 있습니까?
>    TE 의 overflow/stall 상태 비트는 어디서 읽습니까?
> 7. **트레이스 인에이블 설정**은 어느 스크립트에 있습니까?
>    (`NexusTracedatadump.cmm` 에는 **끄는 것만** 있습니다. TE 켜기,
>    `TECTRL` 비트 정의, BTM/HTM 선택, 주소 범위 필터, sync 주기)
> 8. **펌웨어 이미지와 심볼(ELF)** — 트레이스 디코더의 하드 의존성입니다.

## 6. 이후 계획 (답을 받으면)

1~3번 답 → `CORESIGHT_SetIndexAPBAPToUse` / `SetCoreBaseAddr` 확정 → DM 도달
→ SBA(`sbcs`) 확인 → 트레이스 레지스터(`0xFD000000` TE / `0xFD180000` ETB)
접근 → 명령당 버퍼 드레인 → Nexus 디코드 → 기존 퍼저의 커버리지 계층에 연결.

7~8번은 그 다음 단계(디코더)의 선행 조건이라 **지금 같이 물어두는 게 좋다.**
