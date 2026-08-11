# SF-E76 브링업 — 현황 (자립 문서)

> 2026-08-11. **이 문서 하나로 이어받을 수 있게 쓴다.**
> 상세 이력 `BRINGUP_riscv_v10.md` / 외부 검토 `feedback.md` / 실행법 `README.md`

---

## 0. 목표

**J-Link Plus + cJTAG 로 SF-E76 SSD 펌웨어의 코드 커버리지를 트레이스 기반으로 추출.**
halt/PC 샘플링은 **안 한다**(T32 도 그 방식이 아님이 확인됨).

기존 `pc_sampling_fuzzer_v9.7.py` 의 NVMe·코퍼스·변이·LLM·replay·POR 는 전부 재사용.
새로 만들 것은 **커버리지 수집 계층**뿐.

---

## 1. 확정된 사실

### 1.1 연결 (실측)

```
인터페이스   cJTAG, TIF=7, 10MHz     ← 1000kHz 로 낮추면 활성화 자체가 실패
DPIDR        0x11013913
               DESIGNER = 0x489  = SiFive
               VERSION  = 3      = DPv3  → ADIv6 / CoreSight SoC-600
               ⇒ AP 를 APSEL 이 아니라 **주소**로 지정한다
J-Link       Plus, FW V13 / 소프트웨어 **V9.66** (V9.12 → 업그레이드 완료)
```

**동작하는 설정 (pylink + exec_command, connect 前 주입):**
```
SetcJTAGInitMode = 0
set_tif(7) / set_speed(10000)
CORESIGHT_AddAP = Index=0 Type=APB-AP Addr=0x10000     # APBAP1
CORESIGHT_AddAP = Index=1 Type=APB-AP Addr=0x20000     # APBAP2
CORESIGHT_AddAP = Index=2 Type=AXI-AP Addr=0x30000     # AXIAP1
CORESIGHT_AddAP = Index=3 Type=AHB-AP Addr=0x40000     # AHBAP1
CORESIGHT_AddAP = Index=4 Type=APB-AP Addr=0x50000     # APBAP3
CORESIGHT_AddAP = Index=5 Type=APB-AP Addr=0x60000     # APBAP4
CORESIGHT_SetIndexAPBAPToUse = 0
CORESIGHT_SetCoreBaseAddr    = 0x81480000   # 또는 0x81481000
connect('RISC-V')
```
> AP 주소는 T32 `SYStem.CONFIG.APBAP1.Base DP:0x10000` 등에서 옴.
> `CORESIGHT_AddAP` 의 `Index` 는 **J-Link 내부 맵 번호**이지 APSEL 이 아니다.

**JLinkScriptFile 경로는 폐기** — cJTAG 스캔을 깨뜨린다(`IRPrint=0x..0000`).

### 1.2 코어 / DM / hart  ← `attach.cmm` 로 **확정** (2026-08-10)

| 코어 | T32 `CORE <core>. <chip>.` | DM (`COREDEBUG.Base`) | **hart** | 코드 영역 |
|---|---|---|---|---|
| hcore | `1. 1.` | `0x81480000` | **0** | `0x0 ~ 0x21BFFF` |
| CMCore | `2. 1.` | `0x81480000` | **1** | 〃 |
| FCore | `3. 1.` | `0x81480000` | **2** | 〃 |
| QCore | `4. 1.` | `0x81480000` | **3** | 〃 |
| Ncore | `1. 2.` | `0x81481000` | **0** | **제외** — 별도 코드/메모리 |

근거: `SYS.CONFIG HARTINDEX 0. 1. 2. 3.` + `SYS.CONFIG CoreNumber 4.`
→ **DM 하나에 하트 4개.** Ncore 만 chip 2 = 별도 DM 의 hart 0.

**얻은 것 3가지:**
1. **hart 를 넘겨짚지 않아도 된다.** 0~3 이 전부고, `hcore = hart 0`.
2. **DM 은 하나만 쓰면 된다** → SEGGER 의 "Multiple DM not supported" 한계에 안 걸린다.
   Ncore 는 코드 맵에서도 제외돼 있으니 커버리지 대상이 아니다.
3. `&core_base=**APB:**0x81480000` — CoreBase 가 **APB 주소공간** 값임이 명시됐다.
   ⚠ 다만 `APB:` 는 **주소 클래스만** 알려준다. APB-AP 가 **4개**인데
   **어느 것인지는 모른다** — `APBAP1(index 0)` 확정이 아니다.
   T32 의 `SYStem.CONFIG.APBACCESSPORT` 를 찾아야 확정된다 (`T32_SEARCH.md` ①).

**DMI aperture 추론 (약함, 미검증):** 두 DM base 간격이 `0x1000` = 4KB
⚠ 4KB 는 **단순 컴포넌트 예약 크기**일 수도 있다. `<<2` 매핑의 근거로는 약하다.
아래는 **후보**일 뿐이며 벤더 확인 전에 확정으로 쓰지 말 것.

= DMI 주소 1024개 × 4바이트 ⇒ **APB 주소 = CoreBase + (dmi_addr << 2)**
`dmcontrol(0x10)` → `0x81480040`, `dmstatus(0x11)` → `0x81480044`, `sbcs(0x38)` → `0x814800E0`
(`sfe76_link.DMI_STRIDE_SHIFT` / `probe_dm.py --shifts 2`)

코드 영역 근거: `MAP.BOnchip 0x0++0x21BFFF` (쓰기 불가 영역 선언).
→ **커버리지 필터 · 디코더 디스어셈블리 범위 · Ghidra 로딩 base 로 그대로 쓴다.**

### 1.2b ★★ T32 의 접근 정책 (`attach.cmm`) — 우리 블로커의 정답 후보

```
sys.memaccess SB            메모리 접근은 System Bus(SBA)로
sys.cpuaccess DENIED        ★ CPU 를 통한 접근 금지 = halt 기반 접근을 아예 안 씀
sys.option resetmode.ndmrst 리셋은 핀이 아니라 ndmreset
sys.m prepare               ★ SYStem.Mode Prepare — 코어를 건드리지 않고 DP 만 세움

IF (HCORE)                          ← 마스터 세션 하나만 전원을 요청
    sys.CONFIG.Slave off
    SYStem.Option.DAPSYSPWRUPREQ OFF   ★★ CSYSPWRUPREQ 를 **안 쓴다**
    SYStem.Option.DAPDBGPWRUPREQ ON    ★★ CDBGPWRUPREQ 만 쓴다
    SYStem.Mode Prepare
    SYStem.DOWN → WAIT 500ms → SYStem.UP    ★ 신규 확인
ELSE
    sys.CONFIG.Slave on                 ← HCore 가 초기화한 DAP/DM 에 attach
```

★ **`SYStem.DOWN` → 500ms 대기 → `SYStem.UP`** 이 HCore 시퀀스에 있다.
우리는 이 **DOWN + 대기**를 한 번도 해본 적이 없다. 다만 `SYStem.UP` 의
SF-E76 전용 내부 동작은 **TRACE32 CPU 드라이버 안**이라 CMM 을 더 읽어도
안 나올 수 있다 — 그래서 CMM 전수 조사는 **여기서 종료**한다.

`cpuaccess DENIED` + `memaccess SB` + `sys.m prepare` 는 **§1.3 의 무-halt 커버리지 수집과
완전히 일치**한다 — 계획의 전제가 또 한 번 독립적으로 확인됐다.

**그리고 `DAPSYSPWRUPREQ OFF` 가 핵심이다.** 기본값이 ON 인 옵션을 굳이 OFF 로
적어 뒀다는 건 **켜면 안 되기 때문**이다. J-Link 은 기본적으로 `CDBGPWRUPREQ` 와
`CSYSPWRUPREQ` 를 **둘 다 요청하고 둘 다 ACK 될 때까지 기다린다.**
이 칩이 `CSYSPWRUPACK` 을 안 준다면 → 그대로 **`Failed to power-up DAP`** 다.

### 1.2c ★★★ 트레이스 토폴로지 확정 (`ViewNexusTracedump.cmm` 실물)

```
SYStem.CONFIG.NEXUS.Type SiFive                       ; NTRACE
SYStem.CONFIG.NEXUS.Base SB:0xFD000000 SB:0xFD001000
                         SB:0xFD002000 SB:0xFD003000  ; TraceEncoders ← **4개**
SYStem.CONFIG.RVFUNNEL1.Base SB:0xFD180000
SYStem.CONFIG.RVFUNNEL1.SourcePortNumber percore
SYStem.CONFIG.RVFUNNEL.TraceSource NEXUS.0 0 NEXUS.1 1 NEXUS.2 2 NEXUS.3 3
SYStem.CONFIG.RVSRAMTRACEsink1.Base SB:0xFD180000
SYStem.CONFIG.RVSRAMTraceSink1.TraceSource RVFUNNEL1
la.import.etb *   /   la.list
```

**얻은 것:**

| | |
|---|---|
| **TE 가 코어마다 하나씩 4개** | `0xFD000000/1000/2000/3000` — 간격 `0x1000` |
| **NEXUS.n ↔ hart n** | `hcore=hart0` → **TE = `0xFD000000`** (§1.2 의 hart 표와 일치) |
| **Funnel** | `0xFD180000`, 포트번호 = 코어 인덱스 |
| **Sink 는 ARM ETB 가 아니라 RISC-V *SRAM trace sink*** | 주소가 funnel 과 **같다** (`0xFD180000`) |
| **접근 클래스가 전부 `SB:`** | = System Bus = **RISC-V SBA** (DM 의 일부) |

**★ J-Link 명령이 1:1로 대응한다** — 이 구조를 그대로 옮길 수 있다:
```
RISCV_UseNexusLegacyMode = 1          ★ 아래 이유로 **필수 후보**
RISCV_SetHartSel      = 0
RISCV_SetTEBaseAddr   = 0xFD000000   MemTypeToUse=2(SBA)   ← hart 별
RISCV_SetTFBaseAddr   = 0xFD180000   MemTypeToUse=2
RISCV_SetSRAMBaseAddr = 0xFD180000   MemTypeToUse=2
```

### ⚠ legacy SiFive Nexus ≠ ratified N-Trace 1.0

`NEXUS.Type **SiFive**` 는 비준된 N-Trace 1.0 이 아니라 **legacy SiFive Insight
Nexus** 일 가능성이 높다. SEGGER 도 E-Series 용으로 별도 명령을 둔다:
`RISCV_UseNexusLegacyMode = 1`.

**레지스터 오프셋이 다르다** — 이게 실무적으로 치명적이다:

| | T32 legacy 스크립트(실물) | Ratified TCI 1.0 |
|---|---|---|
| write ptr | **`+0x1C`** | `+0x20` |
| read ptr | **`+0x20`** | `+0x28` |
| data | **`+0x24`** | `+0x40` |

→ **`RISC-V_Trace_Control_Interface.pdf` 는 개념 참고용이다.** 이 칩의 실제
레지스터 맵과 디코더를 그대로 설명한다고 보면 안 된다. **T32 스크립트의
오프셋이 정답**이고, 디코더도 legacy Nexus 기준으로 만들어야 한다.

→ 설계 불확실성이 **줄었을 뿐** 사라지지 않았다. legacy/ratified 구분과
버퍼 wrap·overflow 처리가 남아 있다.

### 1.2c-1 ★★ 이것이 여는 우회로

트레이스 블록은 `SB:` = **SBA** 로 접근한다. SBA 는 **DM 의 일부**라 우리가 막힌
지점에 걸린다. **그런데 AXI-AP 는 시스템 메모리로 가는 독립 경로다.**
같은 버스 주소 `0xFD000000` 을 **AXI-AP 로 읽을 수 있으면 DM 이 아예 필요 없다.**

- AP 레지스터 접근은 **이미 동작 확인됨**(IDR 6/6, TAR 되읽기)
- 이전 `probe_trace_regs.py` 의 실패는 priming 버그와 AP 미확인 상태에서의 측정
  → **증거로서 무효.** 다시 재야 한다.

### 1.2d ★★★ AP 맵 확정 — IDR 실측 (2026-08-10)

| T32 선언 | IDR | CLASS | TYPE | 판정 |
|---|---|---|---|---|
| APBAP1 `@0x10000` APB-AP | `0x09130006` | 8 MEM-AP | 6 = APB4/5 | ✅ |
| APBAP2 `@0x20000` APB-AP | `0x09130006` | 8 MEM-AP | 6 = APB4/5 | ✅ |
| AXIAP1 `@0x30000` AXI-AP | `0x09130004` | 8 MEM-AP | **4 = AXI3/4** | ✅ |
| AHBAP1 `@0x40000` AHB-AP | `0x09130001` | 8 MEM-AP | **1 = AHB3** | ✅ |
| APBAP3 `@0x50000` APB-AP | `0x09130006` | 8 MEM-AP | 6 = APB4/5 | ✅ |
| APBAP4 `@0x60000` APB-AP | `0x09130006` | 8 MEM-AP | 6 = APB4/5 | ✅ |

**전 AP DESIGNER = `0x489` = SiFive — DPIDR 의 DESIGNER 와 동일.**

**이건 우연일 수 없다.** IDR 의 TYPE 은 우리가 넣은 적 없는 값인데
**T32 선언과 6개 전부 일치**한다(APB→6, AXI→4, AHB→1). stale 값이나 착시라면
AXI 자리에서 4가, AHB 자리에서 1이 나올 이유가 없다. 따라서:

1. **AP 주소(`0x10000`~`0x60000`)가 맞다.** ADIv6 주소 지정 해석이 옳았다.
2. **`SELECT` 가 AP 를 실제로 전환한다.** 6개가 서로 다른 값을 준다.
3. **6개 AP 가 전부 실재한다.** 브링업 내내 미확인이던 항목이 닫혔다.
4. **AP 접근 경로가 완전히 살아 있다.** DP → SELECT → AP 읽기가 동작한다.

> `0x80000000` 이 간헐적으로 뒤쪽 AP 에 붙는 건 **J-Link API 에러 센티널**이지
> 값이 아니다. 재시도로 사라진다. `is_error()` 로 걸러 실재 집계에서 뺐다.

### 1.3 ★ T32 커버리지 메커니즘 (`NexusTracedatadump.cmm` 실물)

```
TE control        ESB:0xFD000000     bit1 = enable
TF control /
ETB base          ESB:0xFD180000     ← 둘이 같은 주소
  +0x1C  write ptr   (bit0 = wrap 플래그)
  +0x20  read ptr
  +0x24  data        (읽을 때마다 자동 증가)
버퍼              32KB (0x7FFF)
출력              Data.SAVE.Binary → .bin  (원시 Nexus 바이트)
```

**절차:** TE disable → TF disable → write ptr 로 wrap 판정 → read ptr 설정
→ data 반복 읽기 → 파일 저장. **halt 가 어디에도 없다.**

**`ESB:` 가 세 가지를 확정한다** (TRACE32: `E`=실행 중 접근, `SB`=System Bus/SBA):
1. **SBA 가 이 칩에 구현돼 있다** (SiFive Insight 에서는 optional)
2. **커버리지 수집에 halt 불필요** — 계획의 핵심 전제 확인
3. ★ **DM 은 정상 동작한다.** SBA 는 DM 의 일부다 →
   **우리 `dmactive` 실패는 칩 한계가 아니라 우리 설정 문제**

**J-Link 의 N-Trace 지원이 없어도 된다** — 스크립트는 순수 레지스터 read/write 다.
필요한 건 "그 주소에 32비트 접근" 하나뿐.

### 1.4 퍼저 구조 (여기서 정해짐)

```
TE enable → NVMe 명령 1개 실행 → TE disable → 버퍼 드레인 → 디코드 → 그 명령의 커버리지
```
**halt 가 없어 ARM 제품의 호스트 프리즈 문제가 원천적으로 없다** — 이건 확정.

⚠ **"명령당 32KB 면 충분" 과 "완전한 분기 트레이스" 는 미검증이다.**
버퍼가 wrap 하면 **오래된 트레이스가 사라지고**, FIFO overflow 시 N-Trace
Error Message 가 난다. 즉 **부분맹이 사라진다는 보장이 없다** — 형태가 달라질 뿐.
→ 캡처마다 **wrap 여부 / TE overflow·stall 비트 / sink flush 완료 /
실제 바이트 수 / hart 식별 / 시작·종료 시점**을 반드시 기록해야 한다.
버퍼 크기 충분 여부는 **짧은 workload 실측 후** 결정한다.

### 1.5 J-Link 버전 의존성 (문서 확인)

`RISCV_Set*BaseAddr` 의 `MemTypeToUse`: **0=Core / 1=DMI / 2=SBA**
- **DMI 접근 V9.56+**, **SBA 접근 V9.62+**
- V9.12 에서는 Core access(=halt 필요)뿐이었다 → **V9.66 으로 해소됨**

---

## 2. 현재 블로커

```
Timeout waiting for debug module to become active     ← dmcontrol.dmactive 안 올라옴
Failed to power-up DAP                                ← 그 위 계층에서 이미 실패 가능
```

DMI 위치까지는 인식(DPIDR / AP map / CoreBase). **DM 이 active 로 응답하지 않는다.**

### 가설과 상태

| | 가설 | 상태 |
|---|---|---|
| **G** | **connect 자체가 불안정 — 설정을 고정해도 결과가 갈린다** | ★★ **확정.** 단발 성공률 6/12 (아래) |
| ~~E~~ | ~~AP 6개 등록이 J-Link 열거를 깨뜨림~~ | **반증됨.** 1개 3/6 = 6개 3/6 |
| ~~F~~ | ~~`CSYSPWRUPREQ` 를 이 칩이 ACK 안 함~~ | **반증됨.** `CSYSPWRUPACK` 이 실제로 떴다 |
| A | 디버그 접근 제어(secure JTAG) 잠금 | **약해짐.** 전 AP `DeviceEn=1` = 트랜잭션 발행은 가능. ⚠ 단 `DeviceEn=1` 이 '잠금 아님' 을 뜻하진 **않는다**(주소별 firewall / Secure 제한 / SDeviceEn / Prot) |
| **B** | **DM 주소 `0x81480000` 이 틀렸거나 다른 AP 뒤에 있다** | ★★ **최유력으로 승격.** AP 는 6개 다 실재·접근 가능한데 이 주소만 안 읽힌다 |
| C | DM 전원/클럭 게이팅 | 미검증 — 전원 ACK 가 뜬 조건에서 DM 을 다시 봐야 한다 |
| D | 잘못된 DM | **해소.** hart 0~3 이 전부 `0x81480000`, Ncore 는 대상 아님 |

### ★ `probe_dap.py` 결과 (2026-08-10)

**1차 — 조합 스윕 (`(0,F) (1,F) (6,F) (1,T) (6,T)`)**
```
CDBGPWRUPACK 뜬 조합 : [(1, True)]
CSYSPWRUPACK 뜬 조합 : [(1, True)]
```

**2차 — 순서 통제 (`--ap-count-test --reps 3`, connect 단발)**
```
시행순서:  1  2  3  4  5  6  7  8  9 10 11 12
AP 개수 :  1  6  6  1  1  6  6  1  1  6  6  1
결과    :  O  X  O  X  O  O  O  X  O  X  X  X

AP 1개 : 3/6      AP 6개 : 3/6
```

**여기서 확정된 것 (좋은 소식과 나쁜 소식이 하나씩)**

1. **✅ G0 통과 — DAP 전원은 인가된다. 디버그·시스템 둘 다 ACK.**
   `Failed to power-up DAP` 는 칩의 한계가 아니다.
2. **가설 F 반증.** `CSYSPWRUPACK` 이 실제로 떴다. T32 의 `DAPSYSPWRUPREQ OFF` 는
   전원 능력 문제가 아니라 멀티세션 `Slave` 정책 때문으로 보인다.
   → JLinkScript 로 전원 요청을 끄려던 계획 폐기.
3. **가설 E 반증.** 1개와 6개의 성공률이 **정확히 같다**(3/6). AP 6개는 무해하다.
   1차의 `[(1, True)]` 는 **순서 교락에 의한 착시**였다 — 통제 실험이 잡아냈다.
4. **`connect` 없이는 ACK 가 하나도 없었다.** cJTAG 활성화가 `connect` 안에서
   일어난다는 뜻 → **DP 계층을 connect 이전에 손보는 접근은 성립하지 않는다.**
5. ★ **가설 G — 내부 대조가 결정적이다.**
   같은 설정(AP 1개)이 시행 1·5·9 에서 **3/3 성공**, 시행 4·8·12 에서 **0/3 실패**.
   **설정을 고정했는데 결과가 갈린다** ⇒ 원인은 설정이 아니라 **연결의 상태 의존성**.

> 이것이 예전부터 "첫 connect 는 실패한다" 로 관찰되던 현상의 정체다.
> 이제 **DP 전원 계층에서 측정된 수치**(단발 6/12)로 잡혔다.
> ⚠ `probe_dap` 의 connect 는 **단발**이었다. 실사용 경로(`connect_checked`)는
> 원래 3회 재시도한다 — 재시도로 덮이는지가 다음 질문이다.

### 시험 결과 (2026-08-10)

```
probe_dm.py          DM aperture 직접 읽기 → 전부 실패
                     (connect 실패 시 memory_read32 가 안 되므로 예상 범위)
probe_trace_regs.py  [A] connect+memory_read32, [B] CoreSight AP 직접 → 모두 실패
                     E76 device 지정 시: connect 1차 "Could not find supported CPU",
                     2차 성공, 그래도 [A][B] 실패
```

> ⚠ **`[B]` 실패는 증거가 약하다.** CoreSight AP 직접 접근은 **우리 코드로 한 번도
> 성공한 적이 없다**(예전에도 전부 `0x80000000`/0). "트레이스 블록이 MEM-AP 에 없다"
> 인지 "우리 코드가 원래 안 된다" 인지 **구분되지 않는다.**

---

## 2.5 ★ secure JTAG 가설 재검토 (2026-08-10, 문서 재독)

**SiFive 공식 문서에 이 기능이 실제로 있다** (`SiFive_Trace_and_Debug.md`):

> **Multilayered Debug Access Control**: Enforces strict TAP security through
> **fused permanent disable pins**, **32-bit password barriers**, or
> **public-key cryptographic authentication**.

세 방식을 증상과 대조하면:

| 방식 | 우리 증상과 맞나 |
|---|---|
| 퓨즈 영구 비활성 | **배제.** TAP 자체가 죽는다 — 우리는 DPIDR 을 읽는다 |
| **32비트 패스워드 / PKI** | **가능.** DM 을 잠그면 `dmactive` 실패가 그대로 설명된다 |
| AP 버스 포트 게이팅 | **가장 잘 맞는다** — AP 는 열거되는데 메모리만 전부 실패 |

**증상 프로파일이 정확히 "인증 게이트" 모양이다:**
```
DP 통신 ✅   DAP 전원 ✅   AP 열거·IDR ✅   AP 레지스터 읽기 ✅
────────────────────────────────────────────────────────
메모리 트랜잭션 ❌ (전 AP, 전 주소)      DM dmactive ❌
```
**"디버그 하드웨어는 다 보이는데 아무것도 못 만진다"** — 잠금의 전형이다.

### ⚠ 그전에 — 도구가 측정을 스스로 막고 있었다 (2026-08-11)

`Could not find supported CPU` 로 **전 세션이 무효 처리**돼 AP 측정이 아예
돌지 않았다. 원인은 우리 코드의 전제다:

```
connect_checked()  →  connect 실패 = 세션 무효 = 측정 건너뜀
```

**틀렸다.** DP/AP 레지스터를 직접 두드리는 데 필요한 건 **DAP 전원**뿐이다.
`connect(device)` 는 그 위에서 **CPU 를 식별**하려는 단계이고,
`Could not find supported CPU` 는 **CPU 계층의 실패**지 DAP 계층의 실패가 아니다.
실제로 브링업 초기의 DPIDR 도 **connect 가 실패한 세션에서** 읽었다.

pylink 로 확인:
```
coresight_configure  → @open_required        (connect 불필요)
coresight_read/write → @coresight_configuration_required  (connect 불필요)
```
**raw DAP 경로는 원래 connect 없이 열려 있다.**

→ `Link.open_dap()` 신설. connect 는 **best-effort**(cJTAG 활성화·전원 시퀀스를
위해 시도만)하고, 세션 유효성은 **DAP 전원 ACK 로만** 판정한다.
`dap_power()` 도 ACK 가 없으면 **직접 `CTRL/STAT=0x50000000` 을 써서 요청**한다 —
connect 가 실패한 세션에서는 J-Link 이 그 단계를 안 했을 수 있다.

### 이걸 가르는 단 하나의 측정: `CSW.DeviceEn`

MEM-AP `CSW`(AP+0xD00)의 **bit6 `DeviceEn`** 은 그 AP 의 **버스 포트가 켜져
있는지**를 하드웨어가 알려주는 읽기 전용 비트다. bit23 `SDeviceEn`(SPIDEN)은
보안 접근 허용 여부다.

| DeviceEn | 결론 |
|---|---|
| **0 (전 AP)** | ★ 버스 포트가 **하드웨어로 꺼져 있다.** 소프트웨어로 못 연다 → **잠금이거나 버스 미전원.** 우리 코드로 할 게 없다 |
| **1** | 포트는 열려 있다 → **잠금이 아니다.** 실패는 주소/코드 문제 |

**우리는 `mem_read32` 안에서 CSW 를 읽고도 값을 버려 왔다.** 브링업 내내
가장 결정적인 비트를 안 본 셈이다. 이제 열거 단계에서 `CSW`/`CFG` 를
디코드해 찍는다.

### 덤으로 정정된 것

이전 로그의 `RISC-V debug: 0.11, AddrBits: 0` 은 J-Link 이 이 TAP 을
**직접 RISC-V DTM 으로 오인**했을 때 나온 값이다. `AddrBits=0` 은 DMI 주소
비트가 없다는 뜻이라 애초에 정상 DTM 이 아니다.
→ **이 칩의 디버그 스펙 버전이 0.11 이라는 근거로 쓰면 안 된다.**

### 그리고 SEGGER 문서가 확인해 주는 것

> Memory access: via **System Bus Access (SBA)** / via **progbuf (CPU)** / via **abstract command**

셋 다 **DM 을 거친다.** 즉 **J-Link 의 RISC-V 메모리 접근은 AXI-AP 를 쓰지 않는다.**
AXI-AP 우회가 된다 해도 J-Link 의 정규 경로로는 못 쓰고, **raw AP 접근으로
트레이스 레지스터를 직접 두드리는 방식**으로만 쓸 수 있다.

## 3. 도구

| 파일 | 목적 | 상태 |
|---|---|---|
| `sfe76_link.py` | **연결 계층 정식 모듈.** `open_dap`(전원만 요구) / `dap_power` / `connect_checked` / `halt_checked` | 사용 중 |
| **`probe_ap_raw.py`** | **DP→AP 직접.** IDR·**CSW.DeviceEn**·TAR 되읽기·임의주소(`--addrs trace`) | ← **다음 실행** |
| `find_dm.py` | DM 위치 탐색. `--devices`(배제됨) / `--sweep`(문법×AP×CoreBase 48조합) | `--sweep` 미실행 |
| `probe_dap.py` | DP 계층 — DPIDR / 전원 ACK / AP 개수 비교 | 역할 완료 (G0 통과) |
| `probe_trace_regs.py` | 트레이스 레지스터에 MEM-AP 로 닿는지 | 결과 **무효** (§6) |
| `probe_dm.py` | ~~DM aperture 읽기~~ | **설계 결함(순환).** `probe_ap_raw` 로 대체 |
| `verify_halt_pc.py` | halt/PC/resume (**보조 트랙**) | halt 실패로 막힘 |
| `diagnose_connect.py` / `find_haltable.py` | 연결 원인 분리 (프로세스 격리) | 보조 |
| **`ASK.md`** | **벤더/SEGGER 질문서.** 그대로 잘라 보내면 됨 | ← **P0 와 동시 발송 권장** |
| **`T32_SEARCH.md`** | T32 스크립트에서 찾을 것 우선순위 | 진행 중 |
| `backup/` | 역할 끝난 도구 + 각각이 밝혀낸 것 | 참고 |

**종료 코드:** 0 정상 / 2 connect / 3 halt / 4 PC / **5 resume 실패(보드 복구 필요)** / 6 불충분

---

## 3.5 ★ 불안정한 연결 위에서 결과를 판단하는 법

**증상:** 같은 명령을 돌릴 때마다 결과가 다르다.
**원인:** 가설 G — connect 가 상태 의존적으로 실패한다(단발 6/12).
**결론: 1회 실행의 성패는 증거가 아니다.** 판단 방식을 바꿔야 한다.

### 원칙 1 — "실패" 와 "무효" 를 분리한다  ← 가장 중요

세션이 제대로 안 섰는데 잰 값은 **측정 실패가 아니라 무효**다. 둘을 섞으면
노이즈를 데이터로 오독한다. 지금까지 이걸 안 나눠서 **가설 E·F 를 둘 다
잘못 세웠다.**

그래서 `connect_checked(require_power=True)` 가 기본이 됐다:
`connect()` 가 예외 없이 끝나도 **`CDBGPWRUPACK` 이 없으면 그 시도는 실패**로
치고 다시 붙는다. 이 게이트를 통과한 세션 안에서 잰 값만 집계한다.

### 원칙 2 — 독립 세션 반복 + 일치만 인정

`--sessions N` 으로 붙었다 떼며 N 회 반복하고, **모든 유효 세션에서 같게 나온
값만** 실측으로 인정한다. 세션마다 달라지는 값은 노이즈다.
유효 세션이 3회 미만이면 **결론을 내지 않는다.**

### 원칙 3 — 성공률 비교는 n 이 작으면 하지 않는다

한 팔에 6회로 50% 와 70% 를 구분할 수 없다. 두 설정의 성공률을 비교해서
결론내려면 팔당 **30회 이상**이 필요하다. 그럴 바엔 **원칙 1 로 노이즈를
제거하는 게 싸고 정확하다.**

> 실제로 이 함정에 세 번 당했다: `0x81480000` 이 안 된다(순서 문제였음),
> AP 1개만 된다(가설 E, 순서 문제였음), 그리고 그 이전의 핸들 재사용 23/24.
> `backup/README.md` 함정 #2 와 같은 뿌리다.

### 원칙 4 — 퍼저에는 이 불안정성이 문제가 안 된다

퍼저는 **세션을 한 번 열고 몇 시간 쓴다.** 재시도로 유효 세션 하나만 확보하면
된다. 지금 시끄러운 이유는 **도구가 12번 붙었다 떼기 때문**이다.
연결 안정성의 근본 원인 규명은 **블로커가 아니다** — 뒤로 미룬다.

---

## 4. ⚠ 지켜야 할 원칙

1. **한 handle = 한 설정.** 조합을 섞으면 (a) 한 번 붙은 뒤 전부 거짓 성공(24개 중 23개)
   또는 (b) 조합마다 close 하면 전부 실패. **둘 다 실측으로 겪었다.**
2. **`connect()` 는 상태 의존적으로 실패한다** — 단발 성공률 **6/12** 로 측정됨(2026-08-10).
   같은 설정이 시행 위치에 따라 3/3 · 0/3 으로 갈린다. bounded retry 3회는 **임시 우회**.
   ⇒ **성공/실패 1회로 결론내지 말 것.** 어떤 비교든 반복 + 순서 통제가 필수다.
3. **halt 후 반드시 resume + 확인.** 단, **halt 가 애초에 실패했으면 resume 실패는 거짓 경보**다
   (`restart()` 는 halt 상태가 아니면 no-op 으로 False 반환).
4. **APB 메모리 접근 ≠ RISC-V DMI 레지스터 접근.** `dmcontrol 0x10` 은 DMI 주소이지
   byte offset 이 아니다. aperture 레이아웃 확보 전 `base+0x10` 식 접근 금지.
5. `connect()` 무예외 종료 ≠ 성공. **트랙별 실제 산출물**(halted 상태 / bitmap 변화 /
   raw trace)로 판정한다.

---

## 5. 폐기된 결론 (반복 금지)

| 한때 결론 | 실제 |
|---|---|
| `0x81480000` 은 연결 실패 | 틀림 — 항상 첫 자리였을 뿐. **순서 문제** |
| T32 재시도 루프 = 연결 불안정 | 틀림 — 첫 connect 가 구조적으로 실패하는 것 |
| 두 DM 모두 접근 가능 | 과함 — connect 후보 통과일 뿐 |
| resume 실패 → 보드 복구 필요 | 거짓 경보 — halt 가 안 돼 멈춘 적이 없었다 |
| halt/PC/resume 이 v10.0 착수 조건 | 틀림 — **T32 커버리지는 halt 방식이 아니다** |
| JLinkScript 경로는 **불가능** | **틀림 — 사용법 오류였다.** ① `InitTarget()` 은 JTAG 체인과 전역 `CPU` 를 수동 지정해야 하는데 안 했다 → 스캔 깨짐 ② `JLINK_CORESIGHT_Configure()` 를 먼저 안 불러서 나머지가 전부 `0x80000000` ③ `PerformTIFInit=0` 으로 cJTAG 를 지킬 수 있다. **P1 에서 부활** |
| DPIDR = `0x6BA0009D` | 구버전/깨진 경로의 값. **실제는 `0x11013913`** |
| AP 6개 등록이 방해 (가설 E) | **틀림** — 순서 통제하니 1개 3/6 = 6개 3/6. **또 순서 교락이었다** |
| `CSYSPWRUPACK` 을 칩이 안 준다 (가설 F) | **틀림** — 실제로 떴다. `attach.cmm` 의 `DAPSYSPWRUPREQ OFF` 는 `Slave` 정책 |

---

## 6. 시험 이력 — 무엇이 닫혔고 무엇이 무효인가

> **결과를 "실패" 로만 적지 않는다.** 닫힌 것 / 반증된 것 / **증거로서 무효인 것**을
> 구분한다. 무효를 실패로 세다가 가설 E·F 를 둘 다 잘못 세웠다.

| 시험 | 결과 | 지위 |
|---|---|---|
| cJTAG / DPIDR | `0x11013913` | ✅ **확정** |
| DAP 전원 | CDBG·CSYS **둘 다 ACK** | ✅ **확정** (§2) |
| AP 6개 IDR | T32 선언과 **6/6 일치** | ✅ **확정** (§1.2d) |
| AP 레지스터 R/W | 동작 (TAR 되읽기) | ✅ **확정** |
| AP 등록 개수 1 vs 6 | 3/6 = 3/6 | ✅ **가설 E 반증** |
| `CSYSPWRUPACK` 미반환 | ACK 실제로 뜸 | ✅ **가설 F 반증** |
| `probe_dm.py` DM 읽기 | 전부 실패 | ⛔ **무효** — `memory_read32` 는 CPU 컨텍스트 경유 = 순환 |
| ROM 테이블 워크 | "테이블 없음" | ⛔ **무효** — SEGGER: RISC-V 는 ROM 스캔 **미지원** |
| `probe_trace_regs.py` `[B]` | 실패 | ⛔ **무효** — priming 버그 + AP 미확인 상태 |
| 트레이스 주소(`0xFD......`) 읽기 | 전 AP 실패, TAR 불일치 | ⛔ **무효** — CSW 검증 누락 버그로 AP 를 우리가 망가뜨림 |
| `find_dm --devices` | `Could not find supported CPU` | ✅ **배제** — 커스텀 SoC 라 J-Link 내장 E76 스크립트가 맞을 리 없다 |
| `find_dm --sweep` | **미실행** | ⬜ |
| **`CSW.DeviceEn`** | **전 AP `[True,True,True]`** | ✅ **트랜잭션 발행 가능** (잠금 반증은 **아님**) |
| 주소 읽기 (`--addrs trace`) | 엄격 기준 재판정 | ✅ **AP 별로 갈림** (§ROM 발견) |
| AP 주소공간 `0x0` | `APBAP1=0x81480003`, `APBAP2=0x81481003` | ✅ **ROM 엔트리 = DM 위치 확인** |
| 트레이스 블록 `0xFD......` | 전 AP 고정 상수 | ⛔ **MEM-AP 로 안 보임** → 경로 B 닫힘 |
| **DM 컴포넌트 `0x81480000`** | **전 AP 무응답 상수** | ❌ **미도달** (아래) |
| AP alias 검사 | 미실시 | ⬜ |
| **AP 주소공간 지도(`--map`)** | **미실시** | ⬜ ← **여기가 다음** |

### 남은 단 하나의 증상

```
DP ✅   DAP 전원 ✅   AP 열거·IDR ✅   AP 레지스터 R/W ✅
──────────────────────────────────────────────────────
메모리 트랜잭션 ❌ (전 AP·전 주소)        DM dmactive ❌
```

---

## 6.1 다음 할 일

### ★★★ 2026-08-11 — ROM 테이블 발견. DM 위치가 실측으로 확인됐다

**AP 주소공간 `0x0` 을 읽은 값:**

| AP | `@0x0` | 해석 | `@0x4` |
|---|---|---|---|
| **APBAP1** | **`0x81480003`** | present=1, 32bit=1, **컴포넌트 `0x81480000`** | `0x00000000` (종료) |
| **APBAP2** | **`0x81481003`** | present=1, 32bit=1, **컴포넌트 `0x81481000`** | `0x00000000` (종료) |
| APBAP3 | `0x00040700` | present=0 → ROM 엔트리 아님 | `0x00000010` |

**이건 CoreSight ROM 테이블 엔트리 인코딩 그대로다** (`bit0`=present,
`bit1`=32비트 포맷, 상위 20비트=컴포넌트 오프셋). 그리고 가리키는 주소가
**T32 의 `COREDEBUG.Base` 두 개와 정확히 일치**한다:

```
APBAP1 → 0x81480000   = hcore / CMCore / FCore / QCore 의 DM (hart 0~3)
APBAP2 → 0x81481000   = Ncore 의 DM
```

**우연일 수 없다.** 두 AP 가 같은 주소 `0x0` 을 읽는데 **서로 다른 값**이 나오고,
그 차가 정확히 `0x1000` 이며, 둘 다 T32 가 선언한 DM base 와 일치한다.
(펌웨어 메모리를 읽는 것이었다면 두 AP 가 같은 값을 줬어야 한다.)

**확정되는 것:**
1. **APB-AP 각각의 주소공간 `0x0` 에 ROM 테이블이 있다.**
2. **`APBAP1`(index 0)이 메인 DM 을 본다** ← `T32_SEARCH.md` ① 의 `ACCESSPORT`
   질문이 **실측으로 답해졌다.** APB-AP 4개 중 어느 것인지 몰랐던 게 풀렸다.
3. **DM 은 그 AP 주소공간의 `0x81480000`.** `SetCoreBaseAddr` 값 자체는 맞았다.

### ⚠ 그런데 트레이스 우회(경로 B)는 나빠졌다

`0xFD......` 주소는 **어느 AP 에서도 고정 상수만** 나왔다:

| AP | 트레이스 주소들의 값 |
|---|---|
| APBAP1 | 전부 `0x00000001` (일부 `0xEAFFFFFE`) |
| APBAP2 | 전부 `0xEAFFFFFE` |
| APBAP3 | 전부 `0x00040700` |
| AXIAP1 / AHBAP1 / APBAP4 | 고유값 1종 = 아무것도 못 읽음 |

**주소마다 값이 달라야 진짜인데, 전부 같다.** `0xEAFFFFFE` / `0x00000001` /
`0x00040700` 은 **버스 미디코드 기본값**으로 보인다.

★ **이 결과는 T32 성공과 모순되지 않는다.** T32 의 실제 경로는 raw APB-AP
직접 읽기가 아니라 **RISC-V DM 의 SBA**다(`SB:`/`ESB:`). 트레이스 블록이
MEM-AP 로 안 보이는 건 **원래 그런 것**이고, 애초에 그렇게 접근한 적이 없다.
→ **경로 B(DM 우회)는 닫혔다. DM 을 살리는 것이 유일한 길이다.**

> 이 세 상수는 앞으로 **"읽은 값이 아님"** 의 지문으로 쓴다.

### (참고) 이전 판단 — 왜 아직 결론이 아니었나

```
CSW.DeviceEn        전 AP [True, True, True]
주소 읽기           전 AP 가 0xFD000000/1000/2000/3000, 0xFD180000/1C/20 **전부 '닿음'**
```

**`DeviceEn=1`** → 그 MEM-AP 가 **지금 트랜잭션을 낼 수 있다**는 것까지만 말한다.
⚠ **'잠금 아님' 의 증명이 아니다.** DeviceEn=1 이어도 주소별 firewall,
Secure 접근 제한, `SDeviceEn`, `Prot`/`Type` 설정 때문에 실패할 수 있고,
DeviceEn=0 의 원인도 인증뿐 아니라 전원·클럭·reset·integration 신호일 수 있다.

**그리고 "전부 닿음" 은 아직 성공이 아니다.** 이전 판정 기준이
`값 != 0xFFFFFFFF` 였다 — **전 주소가 `0x00000000` 이어도 전부 성공으로 찍힌다.**
6개 AP 가 7개 주소를 **똑같이** 읽었다는 결과 자체가 그 증상일 수 있다:

- 진짜로 같은 버스를 보고 있거나
- **AP 들이 alias 이거나**
- **전부 미디코드 기본값(고정 패턴)을 읽고 있거나**

→ 판정 로직을 다시 짰다(아래 P0). **값의 다양성**이 이 셋을 가른다.

### ❌ 2026-08-11 — ROM 이 가리킨 곳이 **안 읽힌다**

```
v=2026-08-11.5  valid=3/3          (probe_ap_raw --addrs dm --brief)
APBAP1 FFC=EAFFFFFE 044=EAFFFFFE 011=00000000
APBAP2 FFC=EAFFFFFE 044=EAFFFFFE 011=00000000
AXIAP1 FFC=00000000 044=00000000 011=00000000
AHBAP1 FFC=EAFFFFFC 044=EAFFFFFC 011=EAFFFFFC
APBAP3 FFC=00000000 044=00000000 011=00000000
APBAP4 FFC=EAFFFFFE 044=EAFFFFFE 011=00000000
VERDICT: 미도달
```

**전부 "읽은 값 아님" 지문**(`0xEAFFFFFE` / `0xEAFFFFFC` / `0x00000000`)이다.
CIDR 서명(`0xB1`)도 없고 `dmstatus` 후보도 유효하지 않다.

> 부수 정정: `stride 1` 후보 `0x81480011` 은 **4바이트 정렬이 아니다.**
> 32비트 레지스터에 stride 1 은 애초에 성립하지 않는다 — 후보에서 제외.

**모순처럼 보이는 상태:**
```
AP 주소공간 0x0 을 읽으면 → 0x81480003 (ROM 엔트리, DM 을 가리킴)
그런데 0x81480000 을 읽으면 → 무응답
```
가장 그럴듯한 해석: **ROM 엔트리의 주소가 AP 주소공간 기준이 아니다.**
CoreSight ROM 엔트리는 원래 *ROM 베이스로부터의 상대 오프셋*인데,
여기서는 값이 곧 T32 의 `APB:` 버스 주소와 같다. 즉 **그 주소는 SoC 의 APB
버스 주소이고, MEM-AP 창으로는 거기까지 닿지 않는 것**으로 보인다.
→ 이건 우리가 더 추측해서 좁힐 문제가 아니다 (`ASK.md` §5-1).

### ⛔ `--map` 은 다음 단계로 쓰지 않는다 (feedback 2026-08-11 §6)

만들어는 뒀지만 **P0 에서 내린다.** 이유가 셋이다:
- 성긴 간격이라 **좁은 컴포넌트를 사이로 놓친다**
- **고정 기본 응답을 live 로 오판**한다 (우리가 이미 겪은 실수)
- **읽기 부작용이 있는 MMIO** 를 건드릴 수 있다 ← 실기에서 위험하다

### ❌❌ 2026-08-11 — 두 가설 모두 반증. **raw DAP 경로는 소진됐다**

```
v=2026-08-11.8  valid=3/3
APBAP1 ref0=['81480003'] width=[None,None,None]
APBAP2 ref0=['81481003'] width=[None,None,None]
APBAP1 pwr before=00000001 after=00000001 ack=True changed=False
APBAP2 pwr before=EAFFFFFE after=EAFFFFFE ack=True changed=False
VERDICT: NO_ALIAS_APBAP1 NO_ALIAS_APBAP2
```

- **[A] aliasing 아님** — `2^12`~`2^31` 어디서도 wrap 이 없다. AP 는 32비트를 다 디코드한다.
- **[B] 전원 사이클도 아님** — `DOWN→500ms→UP` 후 값이 그대로다.

### ★ 그런데 값을 모아보니 결정적인 패턴이 있다

| 주소 | 값 | low5 | 32B 정렬 |
|---|---|---|---|
| `0x00000000` | **`0x81480003`** | 0x00 | O |
| `0x00000004` | **`0x00000000`** | 0x04 | X |
| `0x00100000` / `0xFD000000` / `0xFD180000` / `0x81480000` … | `0x00000001` | 0x00 | O |
| `0x0021BFFC` / `0xFD18001C` / `0x81480044` / `0x81480FFC` | `0xEAFFFFFE` | — | X |

**오직 `0x0` 과 `0x4` 만 서로 다른 실제 값을 준다.** 그 밖의 모든 주소는
**주소가 아니라 정렬만 보고** 두 상수 중 하나로 떨어진다
(32바이트 정렬 → `0x00000001`, 아니면 → `0xEAFFFFFE`).

⇒ **우리 MEM-AP 메모리 트랜잭션은 사실상 성립하지 않는다.**
`0x0`/`0x4` 는 실제 레지스터를 읽은 것이고, 나머지는 전부 응답이 아니다.
feedback 의 판정 어휘로는 **`MEM_AP_TRANSFER_BROKEN`** 에 해당한다.
→ **raw DAP 로 DM 을 찾겠다는 접근은 여기서 종료한다.**

> `0x81480003` / `0x81481003` 이 DM base 와 일치하는 것은 여전히 사실이지만,
> 그것이 ROM 테이블인지는 **확정하지 못했다**(`ROM_ENTRY_LIKE_NOT_CONFIRMED`).

### ★★★ 2026-08-11 — 진짜 블로커를 찾았다: **cJTAG 활성화 시퀀스**

E76 으로 connect 했을 때 **J-Link 자신의 로그**:
```
JTAG chain detection found 1 devices: #0 Id: 0x00000001, IRLen: 04
Unknown device, Assuming RISC-V TAP with JTAG-DTM setup
DTM architecture: RISC-V JTAG-DTM version: 0.11, AddrBits: 0, DataBits: 34
Error while reading <dmcontrol> debug register
Connect failed
```

**`Id: 0x00000001` 은 IDCODE 가 아니다** (bit0 만 1인 빈 값).
그래서 J-Link 이 TAPId 를 못 알아보고, SEGGER 의 TAP 선택 규칙에서

> IRLen=4 이고 TAPId 가 **알려진 CoreSight DAP TAP** → RISC-V behind DAP 로 간주
> 알려진 TAPId 가 없고 TAP 이 하나뿐이면 → 그냥 그것을 쓴다

**두 번째로 떨어져 RISC-V JTAG-DTM 으로 오인**한다.
⇒ 우리가 준 `CORESIGHT_*` 설정은 **애초에 쓰이지 않는다.**
**`CoreBase` 를 뭘로 바꿔도 결과가 같았던 이유가 이것이다.** `AddrBits: 0` 도
정상 DTM 이 아니라는 신호다.

### 그리고 답이 문서에 있었다

```
SetcJTAGInitMode
  0 = Long-form activation, JScan0 boot + OScan1 enter   (기본값)
  1 = Short-form activation, OScan1 boot
      → 원문: "**Needed for e.g. SiFive or RISC-V targets**"
  2 = Wiliot 전용
```

**우리는 브링업 내내 `0` 을 썼다.** SiFive 타깃에 필요한 건 `1` 이다.

우리가 직접 한 DP 읽기(`DPIDR=0x11013913`)는 됐는데 J-Link 의 스캔은 깨진 것도
설명된다 — 우리 경로는 `perform_tif_init=False` 로 **재초기화를 건너뛰었다.**

> `device` 도 **`E76`** 이어야 한다. `RISC-V` 로는 connect 자체가 제대로 안 된다.
> ⚠ 내 도구들은 기본값이 `RISC-V` 였다 — `try_jlinkscript.py` 의 24/24 는
> **틀린 device + 틀린 cJTAG 모드**에서 나온 것이라 **전부 무의미하다.**

**⇒ `sfe76_link`: `CJTAG_MODE 0 → 1`, `DEVICE 'RISC-V' → 'E76'` (API_LEVEL 4)**

### ★★ 2026-08-11 — **TAP 오인이 사라졌다.** 체인 수동 선언이 먹었다

```
1차 (모드만 훑음)      유효IDCODE=0/9    DTM오인아님=0/9
2차 (TAP ID 선언 추가) 유효IDCODE=24/90  DTM오인아님=78/90  connect=71/90
                       init스크립트실행=72/90     VERDICT: IDCODE_OK
```

**`24 = 4(선언한 ID) × 2(모드) × 3(속도) × 1(device)`** 로 딱 떨어진다.

> ⚠ **"유효 IDCODE" 자체는 증거가 약하다** — 우리가 선언한 값을 J-Link 이
> 되돌려준 것일 수 있다. **의미 있는 신호는 `DTM오인아님 0/9 → 78/90`** 이다.
> 동작이 실제로 바뀌었다.

**확정:** TAP 자동 검출이 `Id=0x00000001` 을 읽어 실패했고, 그래서 SEGGER 규칙
*"IRLen=4 + 알려진 CoreSight DAP TAP → RISC-V behind DAP"* 를 못 타고
**JTAG-DTM 으로 오인**했다. `JLINK_JTAG_SetDeviceId()` 로 **선언하니 그 오인이 사라졌다.**
지금까지 `CORESIGHT_*` 설정이 전부 무시된 이유가 이것이다.

### ★★★ 2026-08-11 — **설정이 드디어 결과를 바꾼다.** `CoreBase=0x0`

```
script실행=16/16   connect성공=2/16   DM살아있음=0
connect 된 조합: ('BaseAddr', AP=0, '0x0')  ('BaseAddr', AP=1, '0x0')
VERDICT: CONNECT_ONLY
```

| | 이전(TAP 선언 없음) | 지금(TAP 선언 있음) |
|---|---|---|
| connect | **24/24** — CoreBase 무관 | **2/16** — `CoreBase=0x0` 일 때만 |

**설정이 실제로 적용되고 있다.** TAP 선언이 그 문을 열었다.
그리고 **`0x81480000` 은 전부 실패, `0x0` 만 성공** —
SEGGER 예제값이 맞았고, **`0x81480000` 은 AP 주소공간 값이 아니다.**
(T32 의 `APB:` 버스 주소일 뿐이라는 해석이 실측으로 뒷받침됐다.)

이제 남은 건 **connect 는 되는데 `halted()` 가 예외**라는 것 하나다.

### ⚠ 그런데 **같은 조합이 실행마다 결과가 다르다**

```
1회차  AP=0 hart=0 connect=0 / hart=2,3 connect=1, halted=ERR "Target is not connected."
2회차  AP=0 hart=0,1 이 connect=1 로 바뀜
공통    halted / core_id 는 항상 None 아니면 ERR
```

**그러면 지금 데이터는 신호가 아니라 잡음이다** — §3.5 원칙 3 그대로다.
`try_jlinkscript` 는 조합당 1회만 재고 반복도 유효성 게이트도 없었다.
**우리가 세운 원칙을 우리 도구가 안 지켰다.**

### ★ 그리고 `"Target is not connected"` 가 결정적이다

`connect()` 가 예외 없이 끝났는데 그 직후 호출이 이 예외를 던진다.
pylink 의 `halted()` 는 **`@connection_required`** 라서
**`jl.connected()` 가 `False` 면** 이 문구를 던진다.

⇒ **connect 직후 세션이 죽는다.** DM 문제 이전에 **연결 유지**가 안 되는 것이다.
지금까지 "connect 성공" 을 세어 온 게 전부 이 위에서 이뤄졌다.

### ❌ 정정 — `SESSION_ALIVE_NO_DM` 은 **잘못된 판정이었다**

게이트를 잘못 걸었다. pylink 정의:

```python
connected()        = opened() and JLINKARM_EMU_IsConnected()
                     → **J-Link 프로브(USB)가 꽂혔는가.** 타깃과 무관하다
target_connected() = connected() and JLINKARM_IsConnected()
                     → **타깃에 붙었는가.** 이게 우리가 원하는 것
```
그리고 pylink 의 `@connection_required` 는
```python
if not self.target_connected(): raise JLinkException('Target is not connected.')
```
⇒ `halted()` 가 그 예외를 던졌다는 건 **`target_connected()` 가 `False`** 라는 뜻이다.

**`connected` 로 게이트하면 USB 만 확인하는 셈이라 늘 통과한다.**
그래서 `SESSION_ALIVE_NO_DM` 이 나왔고, "연결 유지 계층 통과" 도 **틀렸다.**
오류 문구가 `None` 과 `ERR Target is not connected.` 둘뿐이었던 게 그 증거다 —
유효하다고 센 세션에서조차 타깃에 안 붙어 있었다.

**⇒ 게이트를 `target_connected` 로 정정했다.** 이전 두 판정(`SESSION_ALIVE_NO_DM`,
그 위의 계층 통과 주장)은 **철회한다.**

> 이 프로젝트의 반복 패턴이다: **오라클을 먼저 검증하지 않으면 측정이 전부 무효가 된다.**
> `require_power`, `script_ran`, 그리고 이번 `target_connected` — 세 번째다.

### ❌❌ `TARGET_NEVER_CONNECTED` — **connect 기반 결과는 전부 무효다**

`target_connected()` 가 **한 번도 True 가 아니었다.** J-Link 은 타깃에 붙은 적이 없다.

**무효 (connect 성공을 전제로 한 것 전부):**
`try_jlinkscript` 24/24 · `CoreBase=0x0` 만 통과 · `focus` 의 hart 비교 ·
`find_dm --devices` · "connect 성공 N개" 집계 전부

**여전히 유효 (connect 없이 raw DP/AP 로 잰 것):**
pylink 에서 `coresight_configure`=`@open_required`,
`coresight_read/write`=`@coresight_configuration_required` — **셋 다
`target_connected` 를 요구하지 않는다.** 그래서 아래는 살아남는다:
- `DPIDR=0x11013913` (SiFive, DPv3/ADIv6)
- DAP 전원 `CDBGPWRUPACK`+`CSYSPWRUPACK` 둘 다
- **AP 6개 IDR 이 T32 선언과 6/6 일치**
- `CSW.DeviceEn=1`, AP 레지스터 R/W
- MEM-AP 읽기는 `0x0`/`0x4` 에서만 (나머지는 정렬만 보는 상수)
- `AP@0x0 = 0x81480003 / 0x81481003`

### ★ 그리고 진짜 소득 — **문제 계층이 확정됐다**

```
J-Link 자신의 JTAG 스캔이 Id=0x00000001 (쓰레기 IDCODE) 을 읽는다
```
⇒ **DM 설정 문제가 아니라 JTAG/cJTAG 신호 계층 문제다.**
그동안 DM·CoreBase·AP 를 훑은 건 **한 계층 위에서 헛짚은 것**이다.
우리 raw DP 접근만 동작했던 이유도 이제 맞아떨어진다 —
`perform_tif_init=False` 로 **재초기화를 건너뛰었기 때문**이다.

### ★★★ 2026-08-11 — 원인은 **설정이 아니라 cJTAG KEEPER 로직**일 가능성이 크다

```
tif=0 (4선 JTAG)  모든 속도  Id=-  target=0      ← 스캔 자체가 안 잡힌다
tif=7 (cJTAG)     10M/4M     Id=0x00000001 target=0
tif=7 (cJTAG)     1M/500k    Id=-  target=0
VERDICT: NO_SIGNAL
```

**SEGGER cJTAG 문서가 이 증상을 그대로 설명한다:**

> cJTAG 스펙은 타깃이 TCKC 상승엣지에 TMSC 를 놓아주도록 요구하고, 그동안
> 라인을 유지하는 **KEEPER 로직**을 두도록 규정한다.
> 그런데 *"some devices (**especially in the RISC-V segment**) have a buggy
> KEEPER logic or no KEEPER logic at all"* → **TMSC 가 뜬다(floating)** →
> *"can cause the target to detect escape sequences where there are none"*
>
> J-Link 에는 우회가 있지만 *"**if a specific J-Link hardware version comes
> with this workaround, can be checked via the model overview page**"*
> — **하드웨어 버전에 따라 있거나 없다.**
>
> 그리고 *"the workaround requires cJTAG speeds > 500 kHz ... J-Link ignores
> speed settings < 500 kHz"* — **저속에서 스캔이 아예 없던 것과 맞는다.**

**★ 결정적 정황: T32 는 이 타깃에 `CJTAGFLAGS NOKEEPER USEOAC` 로 붙는다.**
`NOKEEPER` = **이 칩에 KEEPER 로직이 없다**는 뜻이고, T32 에는 그 전용 플래그가 있다.

우리 증상 셋이 전부 floating TMSC 의 전형이다:
- `Id=0x00000001` (읽은 데이터가 사실상 0)
- **실행마다 결과가 바뀐다**
- 500 kHz 이하에서 스캔 자체가 사라진다

⇒ **설정 문제가 아닐 수 있다.** 그동안 DM·CoreBase·AP·TAP ID 를 훑은 것이
성과가 없던 이유도 이걸로 설명된다 — **한참 아래 계층이 불안정했다.**

### hardware_version = **13.00** → KEEPER 가설은 **약해졌다**

J-Link 하드웨어 **V13** = 현행 모델. 문서가 *"In **current** J-Link models,
a workaround is implemented"* 라 했으니 우회는 있을 가능성이 높다.
⇒ "장비를 바꿔야 한다" 는 결론으로 가지 않는다.

### ★★★ 치명적 정정 — `JTAG_AllowTAPReset` 을 **반대로** 썼다

SEGGER 공식 정의:
```
0 = Auto-detection is **enabled**
1 = Auto-detection is **disabled**
```
우리는 **`0` 을 쓰면서 주석에 "자동 검출 끔"** 이라고 달았다.

⇒ **지금까지의 모든 "수동 체인" 시험은 자동 검출을 켜 둔 채 돌았다.**
로그에 계속 `Id: 0x00000001` 이 나온 게 당연하다 — 우리가 선언한 TAP ID 를
자동 검출이 다시 덮었을 수 있다.

⇒ **"cJTAG 손잡이를 전부 돌렸다 / 소프트웨어로 더 할 게 없다" 는 판정을 철회한다.**

### ★ 훅도 틀렸다

manual chain 을 `InitTarget()` 에 넣었는데, 그 훅은 **전역 `CPU` 설정을 요구**한다.
그런데 **`CPU` 상수 목록에 RISC-V 가 없다** — 만족시킬 수 없는 조건이었다.
SEGGER 의 manual-chain 예제는 **`ConfigTargetSettings()`** 를 쓴다.
`JLINK_JTAG_SetDeviceId` 와 체인 전역 설정은 타깃 통신이 아니므로
그 훅의 금지 규칙과 모순되지 않는다.

**⇒ `InitTarget()` 제거. 전부 `ConfigTargetSettings()` 한 곳으로.**

### ★★★ 2026-08-11 — **체인 선언이 반영됐다.** TAP 계층 통과

```
form=JLINK_JTAG  script=3/3  connect=0/3  target=0/3
form=JTAG        script=3/3  connect=0/3  target=0/3
자동검출문자열=3/3   DTM오인=0/3   **로그 IDCODE = 0x5BA00477**
err: Could not find supported CPU.
```

**로그 IDCODE 가 `0x5BA00477` 이다 — 우리가 선언한 값이다.** 이전엔 `0x00000001`.
`AllowTAPReset=1` 정정이 먹었다. **DTM 오인도 0/3 으로 사라졌다.**

> `chain detection` 문자열이 로그에 남는 건 J-Link 이 **수동 선언된** 체인을
> 찍는 것이지 자동 검출이 도는 증거가 아니다 — IDCODE 가 우리 선언값인 게
> 그 판별이다. (도구 판정도 이렇게 정정했다)

**⇒ 이제 DAP 경로를 탄다.** 브링업 내내 못 넘던 TAP 계층을 넘었다.

### 남은 실패는 성격이 다르다

```
Could not find supported CPU.
```
DAP 는 탔는데 **그 뒤에서 RISC-V 코어를 못 찾는다.**
⇒ **이제서야** `SetIndexAPBAPToUse` / `SetCoreBaseAddr` / hart 가 의미를 갖는다.
그동안 이 변수들을 훑어도 소용없던 건 TAP 계층에서 막혀 있었기 때문이다.

### ❌ `--dmsweep` → `TARGET_NEVER_CONNECTED`

`CoreBase × AP` 를 훑어도 안 붙는다. 실패 문구는 여전히
**`Could not find supported CPU`** — DAP 는 탔는데 **그 뒤에서 코어를 못 찾는다.**

### ❌ `--cpusweep` — AHB 셀렉터도 아니다

```
sel=APB ap=0 dev=E76 에서 connect 가 한 번 올라온 것 외에는 전부
err = Could not find supported CPU.   target = 0/N
```
AP 셀렉터도 device 도 아니다. **조합 훑기는 여기서 멈춘다.**

### 지금 계층 상태 — TAP 은 넘었고 CPU 탐지에서 막힌다

| 계층 | |
|---|---|
| cJTAG / DP 통신 | ✅ (raw 경로로 확인) |
| DAP 전원 | ✅ 양쪽 ACK |
| AP 열거 / IDR | ✅ 6/6 T32 선언과 일치 |
| **TAP 인식** | ✅ **수동 선언으로 통과** (로그 IDCODE = 선언값, DTM 오인 소멸) |
| **CPU 탐지** | ❌ `Could not find supported CPU` |
| RISC-V DM | ⬜ 도달 못 함 |

### P0 — **J-Link 자신의 전체 로그를 읽는다** (한 번도 안 했다)

```bash
sudo python3 try_jlinkscript.py --dumplog
```

지금까지 로그에서 **패턴 몇 개만** 정규식으로 골라 봤다
(`Id:`, `JTAG-DTM`, `chain detection`). 그런데 실패가
`Could not find supported CPU` 로 바뀐 지금 필요한 건
**J-Link 이 어떤 AP 를 어떻게 두드렸고 무엇을 읽었는지**다.
그건 로그 본문에만 있고 **우리는 그걸 통째로 본 적이 없다.**

`SetLogVerbose=1` + `EnableRemarks=1` 로 받아 `jlink_connect.log` 에 전부 저장하고,
화면에는 **DAP/AP/CPU 탐지 구간만** 추려서 낸다(마지막 40줄).

조합은 인자로 바꾼다: `--log-sel APB|AHB --log-ap N --log-dev E76 --log-base 0x0`

**볼 것:** J-Link 이 **우리가 준 AP 맵을 실제로 쓰는지**, 아니면 무시하고
다른 걸 두드리는지. 그게 다음 수를 정한다.

> 이 로그 파일은 **SEGGER 지원에 그대로 첨부할 자료**이기도 하다.
> 어느 쪽으로 가든 헛일이 아니다.

### 교훈 — 세 번 반복된 것

**오라클과 설정 반영 여부를 먼저 검증하지 않으면 그 위의 측정은 전부 무효다.**
`require_power` → `script_ran` → `target_connected` → 그리고 이번
`AllowTAPReset` 값 반전. **네 번째다.**
매번 "다 해봤다" 는 결론이 나왔고 매번 틀렸다.

### P0.1 — 4선 JTAG 가 안 잡히는 것도 같이 물어볼 것

커넥터에 TDI/TDO 가 있는데 4선 JTAG 스캔이 **아예 없다.**
핀은 있으나 SoC 가 cJTAG 전용이거나, 모드 스트랩이 필요할 수 있다.
→ 하드웨어 설계팀에 물을 것 (벤더가 아니라 **내부**다).

### (참고) 이전 `CONNECT_ONLY` 판정 — 무효

```
connect 성공=24   DM 살아있음=0
connect 만 된 조합: ('Addr',0,'0x0') ('Addr',0,'0x81480000') ('Addr',0,'0x81481000')
                    ('Addr',1,'0x0') ('Addr',1,'0x81480000') ('Addr',1,'0x81481000') …
VERDICT: CONNECT_ONLY
```

**24 조합이 전부 connect 성공**했고 **`CoreBase` 가 `0x0` 이든 `0x81480000` 이든
결과가 똑같다.** 설정이 결과에 영향을 못 주고 있다는 뜻이다.

⇒ **스크립트가 실제로 로드·실행됐는지부터 증명해야 한다.**
그게 아니라면 24/24 는 스크립트와 무관한 결과이고, 조합 비교 자체가 무의미하다.
(또한 예전에 connect 는 불안정했는데 갑자기 24/24 인 것도 같은 의심을 키운다.)

### P0 — **스크립트가 실행됐는지 먼저 증명한다**

```bash
sudo python3 try_jlinkscript.py --brief
```

`ConfigTargetSettings()` 안에 마커를 넣었다:
```c
JLINK_SYS_Report("SFE76_SCRIPT_RAN");   // 호스트 출력 — 통신 금지 규칙에 안 걸린다
```
pylink 의 `JLink(log=, detailed_log=, error=, warn=)` 콜백으로 DLL 로그를 받아
**이 문자열이 실제로 나오는지** 본다.

| 출력 | 의미 | 다음 |
|---|---|---|
| `script실행=0/N` → `SCRIPT_NOT_LOADED` | ★ **설정이 반영된 적이 없다.** 지금까지의 조합 비교가 전부 무의미 | `ScriptFile` 지정 방식부터. `JLinkExe -jlinkscriptfile` 로 교차확인 |
| `script실행=N/N` + `CONNECT_ONLY` | 설정은 먹었는데 DM 이 안 산다 | hart / `RISCV_UseNexusLegacyMode` / device 변수 추가 |
| `DM_REACHED` | ★★ 끝 | 그 조합으로 굳힌다 |

> **교훈:** "설정을 바꿨는데 결과가 안 변한다" 는 **설정이 안 먹었다는 신호**로
> 먼저 읽어야 한다. 이 프로젝트에서 같은 종류의 실수를 반복했다.

### P0.1 — (이전) J-Link 네이티브 경로 설명

```bash
sudo python3 try_jlinkscript.py --brief
```

벤더는 T32 만 답한다. **J-Link 스크립트는 우리 몫이고, 그 길을 우리가
잘못된 이유로 닫아뒀다.**

★ **예전 JLinkScript 실패는 훅을 잘못 고른 탓이다.**
`InitTarget()` 은 JTAG 체인과 전역 `CPU` 를 **수동으로 다 지정해야** 하는데
안 해서 cJTAG 스캔이 깨졌다(`IRPrint=0x..0000`). 반면
**`ConfigTargetSettings()` 는 SEGGER 문서상 타깃 통신이 금지된 훅**이라
*"May not, under absolutely NO circumstances, call any API functions that
perform target communication"* — **스캔을 깨뜨릴 수가 없다.**
그리고 SEGGER 의 RISC-V-behind-DAP 예제가 쓰는 훅이 바로 이것이다.

raw MEM-AP 트랜잭션이 성립하지 않는 게 확인된 지금,
**DMI 프로토콜을 J-Link 에 맡기는 것이 맞다.** 우리는 위치만 알려준다.

| 훑는 변수 | 값 | 근거 |
|---|---|---|
| `AddAP` 문법 | `BaseAddr=` / `Addr=` | SEGGER 문서 **두 곳이 서로 다르다** |
| APB-AP 인덱스 | 0, 1, 4, 5 | APB 타입 AP 4개 |
| CoreBase | `0x81480000` / `0x0` / `0x81481000` | ROM 엔트리 지목 / SEGGER 예제 / Ncore |

오라클은 `halted()` — **DM 이 살아야만 되고 비침습**이다.
조합마다 **별도 프로세스**(핸들 재사용은 거짓 성공을 만든다).

`SF_E76_riscv.JLinkScript` 는 그 정본이다 — 값이 확정되면 이 파일 하나로 굳힌다.

| VERDICT | 다음 |
|---|---|
| `DM_REACHED` | ★★ **끝.** 그 조합으로 굳히고 트레이스 레지스터로 간다 |
| `CONNECT_ONLY` | connect 는 되는데 DM 이 안 산다 → hart/legacy 모드 변수 추가 |
| `NO_CONNECT` | 스크립트 경로 자체가 안 먹음 → JLinkExe 로 직접 확인 |

### P0.1 — `probe_rom_dm.py` : 전송이 **어느 단계에서** 깨지는지 확정

```bash
sudo python3 probe_rom_dm.py --brief
sudo python3 probe_rom_dm.py --json rom_dm.json     # 상세가 필요할 때
```

가장 부족한 정보는 "어디가 보이나" 가 아니라 **이것 하나**다:

> APBAP1 로 `0x81480000` 을 읽을 때 **MEM-AP 전송의 어느 단계에서
> 어떤 AP/DP 오류**가 나는가?

그래서 **접근은 최소로 좁히고**(APBAP1/2, ROM 후보 `0x0~0xC`+ID, DM 은 제한 접근)
대신 **각 전송의 전후 상태를 전부** 남긴다: `IDR/BASE/CFG`, CSW 원본·설정·되읽기,
`DeviceEn/SDeviceEn/Prot/Type`, TAR write·readback, DRW, **전송 전후 DP CTRL/STAT**,
`STICKYERR/WDATAERR/STICKYORUN`, **ABORT 로 오류가 해제되는지**.

★ **CSW 원본을 보존하고 세션 종료 전에 복구한다.** 지금까지 CSW 를 고쳐 쓰고
그대로 나왔다 — 다음 세션에 상태를 물려주는 원인이었다.

**판정은 여섯 갈래로 분리한다** (한 줄로 나온다):

| 판정 | 의미 |
|---|---|
| `ROM_CONFIRMED_DM_REACHABLE` | ★★ DM 까지 읽힌다 → CoreBase 설정으로 직행 |
| `ROM_CONFIRMED_DM_BLOCKED` | ★ ROM 은 읽히는데 **그것이 가리키는 DM 만** 막힘 → `ASK.md` §5-1 이 정확히 이 질문 |
| `ROM_ENTRY_LIKE_NOT_CONFIRMED` | ROM 처럼 보이나 확정 불가 → BASE/PIDR/CIDR·상대 오프셋 재확인 |
| `MEM_AP_TRANSFER_BROKEN` | 전송 자체가 성립 안 함 → 우리 AP 코드부터 |
| `ACCESS_ATTRIBUTE_OR_SECURITY_SUSPECTED` | 전송은 되는데 특정 영역만 거부 → Prot/Type/SDeviceEn 조합 |
| `INSUFFICIENT_VALID_SESSIONS` | 유효 세션 3회 미만 → **결론 금지** |

### ⚠ CIDR 부재를 "DM 없음" 의 근거로 쓰지 않는다 (feedback §2.4)

`T32 COREDEBUG.Base = CoreSight component base` 라고 가정하고 `+0xFF0` CIDR 을
읽었는데, **RISC-V DM 은 CoreSight 컴포넌트가 아닐 수 있다.**
`COREDEBUG.Base` 가 곧 **DMI aperture base** 라면 CIDR 검사는 애초에 의미가 없다.
→ 앞선 "CIDR 서명 없음" 은 **DM 부재의 증거가 아니다.** 참고 자료로만 남긴다.

### P0.2 — 물어봐야만 아는 것은 **둘뿐**이다

여섯 가지 미지수 중 넷은 **여기서 해결 가능**하다:

| | 항목 | 어떻게 |
|---|---|---|
| ① | 주소 aliasing | **P0 [A]** — 스스로 판정 |
| ② | `DOWN→wait→UP` | **P0 [B]** — 스스로 시험 |
| ③ | TE enable 설정 | **미리 몰라도 된다.** DM/SBA 뚫리면 `TECTRL` 을 읽어 확인 |
| ④ | 펌웨어 ELF | **벤더가 아니라 내부다.** 빌드 산출물 / T32 의 `Data.LOAD` 경로 |
| ⑤ | Nexus 디코더 | **Ozone 시험** — SEGGER 에 legacy SiFive 디코더가 있다. 허가 불필요 |
| ⑥ | 어느 APB-AP 인가 | ROM 엔트리로 **이미 답 나옴** (APBAP1) |

**물어봐야만 아는 것:**

> ⑦ 이 파트에 **퓨즈/패스워드가 걸렸는지** — 밖에서 신뢰성 있게 판정 불가
> ⑧ ①이 aliasing 이 아닐 때의 **DMI aperture**

**①이 성공하면 ⑧도 같이 사라진다.** 그래서 P0 를 먼저 돌린다.

### P0.1 — ROM 테이블을 끝까지 훑는다

```bash
sudo python3 probe_ap_raw.py --addrs rom --no-rom --sessions 3
```
엔트리가 하나뿐인지, `0xFD......`(TE/sink)를 가리키는 엔트리가 있는지 본다.
**있으면 트레이스 블록의 진짜 AP-공간 주소를 얻는다** — `SB:` 주소와 다를 수 있다.

### P0.2 — 그다음 J-Link 재시도 (확정된 값으로)

```
CORESIGHT_SetIndexAPBAPToUse = 0          ← 실측 확정 (APBAP1 이 메인 DM)
CORESIGHT_SetCoreBaseAddr    = 0x81480000 ← ROM 엔트리가 가리킨 값
RISCV_SetHartSel             = 0          ← hcore
```
이게 우리가 쓰던 값과 같다. **그런데도 실패했다** → 남은 변수는
`AddAP` 문법(`Addr=` vs `BaseAddr=`), DMI stride, hart 선택 시점.
→ `find_dm.py --sweep` 을 **이제야** 돌릴 가치가 생겼다(범위가 좁아졌다).

### P0.5 — 두 경로를 **병렬 후보**로 유지한다

| 경로 | 내용 | 상태 |
|---|---|---|
| **A. SEGGER 네이티브** | J-Link Plus + `RISCV_UseNexusLegacyMode=1` + `Set*BaseAddr`. **Ozone 으로 최소 실험** — SEGGER 의 legacy SiFive 디코더를 재사용할 수 있으면 공수가 훨씬 적다 | DM/SBA 정상화가 선행 |
| **B. raw MEM-AP 직접 제어** | 트레이스 레지스터를 AP 로 직접 read/write. J-Link 의 RISC-V CPU 연결을 우회 | ← 지금 P0 |

**둘 중 하나를 버리지 않는다.** A 는 디코더 공수를 크게 줄이고, B 는 블로커를 우회한다.

### P0' — 옛 P0 (완료)

```bash
sudo python3 probe_ap_raw.py --no-rom --sessions 3
```

`connect` 가 실패해도 진행된다(§2.5 의 `open_dap`). AP 마다 이 줄만 보면 된다:

```
CSW = 0x........  DeviceEn=?  SDeviceEn/SPIDEN=?  DbgSwEnable=?  TrInProg=?
```

| 결과 | 결론 | 다음 |
|---|---|---|
| **전 AP `DeviceEn=0`** | 버스 포트가 **하드웨어로** 꺼짐 — 소프트웨어로 못 연다 | **P2 로 직행.** 잠금 또는 버스 미전원 |
| `DeviceEn=1` | **잠금이 아니다.** 실패는 주소/코드 | P1 |
| AP 마다 다름 | `DeviceEn=1` 인 AP 로만 진행 | P1 |
| 전원 ACK 조차 없음 | 세션 무효 | 타깃 전원 사이클 후 1회만 재시도 |

### P1 — `DeviceEn=1` 일 때만: DM 위치 전수

```bash
sudo python3 find_dm.py --sweep
```
`AddAP` 문법(`Addr=` / `BaseAddr=`) × APB-AP 4개 × CoreBase 6개 = **48 조합**.
오라클은 `halted()`(DM 이 살아야만 동작, 비침습).
CoreBase 후보에 **`0x0` 이 맨 앞**에 있다 — SEGGER 예제가 `0x0` 이다.

### P2 — 질문서 발송 (`ASK.md`)

**`DeviceEn=0` 이면 P1 을 건너뛰고 바로 여기로 온다.** 그건 실패가 아니라 결론이다.

- **§4 SEGGER** — `SetCoreBaseAddr` 이 AP 주소공간 오프셋인가 / `Addr=` vs `BaseAddr=`
  / DMI 트랜잭션 로깅 방법 / cJTAG+DAP 지원 여부
- **§5 벤더** — DMI 오프셋·stride, DM↔AP 대응, **디버그 접근 제어(퓨즈/패스워드/PKI)
  설정 여부와 해제 절차**, 트레이스 블록이 SBA 전용인지, TE 인에이블 설정, **펌웨어 ELF**

> **P0 실행과 동시에 보내는 게 낫다.** 답을 기다리는 동안 결과가 나오는 구조.

### P3 — T32 스크립트 추가 확보 (`T32_SEARCH.md`)

우선순위: `ACCESSPORT` → `AP:0x` / `DAP:0x` → `Data.LOAD` → `Trace.METHOD`/`COVerage`
→ `TECTRL`. 1번 하나만 나와도 P1 스윕 범위가 확 줄어든다.

### P4 — 커버리지 파이프라인 (블로커 해소 후)

**★ 캡처마다 반드시 기록할 것** (없으면 커버리지 수치를 믿을 수 없다):
`wrap 여부` · `TE overflow/stall 비트` · `sink empty/flush 완료` ·
`실제 저장 바이트 수` · `source/hart 식별` · `capture 시작·종료 시점`

**★ wrap 의 의미:** wrap 된 dump 는 **최근 32KB 는 보존**하지만 그 전에 덮어쓴
실행 이력은 잃는다. 즉 커버리지가 **완전하지 않다.** 퍼저는 셋 중 하나가 필요하다:
**주기적 drain** / **짧은 test case** / **`coverage_incomplete` 플래그 처리.**
세 번째가 가장 현실적이다 — 기존 퍼저의 커버리지 집계에 이 플래그를 넣는다.

**raw capture 는 짧은 workload 부터.** 고정 NVMe 명령 1개 → 캡처 시간을 단계적으로
늘리며 **wrap/overflow 가 안 난 구간만** T32 와 비교한다. 버퍼 크기 충분 여부는
그 실측 뒤에 정한다.

**초기 구현은 `hcore`/TE0 하나로 제한한다.** T32 는 TE 4개를 funnel 에 물리지만
J-Link 은 한 번에 한 hart 가 기본이다. 4-source 의 SRC 구분과 공유 버퍼 압력은
나중에 따로 검증한다.

```
1. TE/ETB 포인터 로직        T32 legacy 오프셋(+0x1C/+0x20/+0x24) 그대로. 32비트 R/W 만
2. raw Nexus 바이트 덤프     .bin
3. 디코더                    Nexus 메시지 + 디스어셈블리 → PC 시퀀스
4. PC → BB/함수 매핑         ★ 기존 퍼저에 이미 있음 (Ghidra RISC-V export 만 새로)
5. 집계/시각화               ★ 이미 있음 (BB%, func%, firmware_map)
```

**설계 불확실성은 §1.2c 로 거의 사라졌다.** J-Link 명령이 T32 구성과 1:1 대응한다.

**디코더 공수 줄이는 법**
- SiFive 공개 디코더 확인 (GitHub `sifive/`)
- **T32 를 정답지로** — 같은 workload 의 raw `.bin` 과 T32 디코드 결과를 대조
- **단계적** — Sync/간접분기 메시지는 **실제 주소를 그대로 담는다.** 디스어셈블리
  없이 뽑아 **부분 커버리지로 퍼저를 먼저 띄우고**, 완전 디코더로 나중에 교체

### 커버리지 매핑에 필요한 것 (확인됨)

| 가진 것 | 얻는 것 |
|---|---|
| 바이너리만 | 실행된 주소/BB |
| + Ghidra | + 함수 경계 (이름은 `FUN_xxxx`) |
| **+ 심볼(ELF/map)** | **+ 진짜 함수 이름.** 디코드 정확도도 올라감(RVC 정렬) |
| + DWARF | + 소스 파일/라인 |

**소스만으로는 안 된다** — 칩에 올라간 **그 바이너리**가 필요하고, 빌드가 다르면 주소가 밀린다.
---

## 7. 게이트

| 주 트랙 (커버리지 = 목표) | | 보조 트랙 (halt PC 샘플링) | |
|---|---|---|---|
| C0a T32 동작 확인 | ✅ | **G0 cJTAG / DP / DAP 전원** | ✅ **통과** (양쪽 ACK) |
| C0b 재현 artifact 보존 | 🔶 덤프·설정 스크립트 확보 | G1 connect (CPU 인식) | ❌ `Could not find supported CPU` |
| **C1 메커니즘 식별** | ✅ **완료** (§1.3) | G2 halt | ❌ |
| **C1b 트레이스 토폴로지** | ✅ **완료** (§1.2c) — TE×4 / funnel / SRAM sink | G3~G6 | ⬜ |
| C2 데이터 경로·하드웨어 | ✅ 온칩 sink, 핀 트레이스 불필요 | | |
| **C2b AP 맵 실재 확인** | ✅ **완료** (§1.2d) — IDR 6/6 일치 | | |
| **C3 J-Link 명령 대응** | ✅ `RISCV_Set*BaseAddr` 이 1:1 대응 | | |
| **C3b 메모리 트랜잭션** | ❌ ← **여기서 막힘.** 전 AP·전 주소 실패 | | |
| **C3c `CSW.DeviceEn`** | ✅ =1 (트랜잭션 발행 가능. 잠금 반증은 아님) | | |
| **C3d 주소 읽기 판정** | ✅ 엄격 기준 도입 — AP 별로 갈림 | | |
| **C3e ROM 엔트리 → DM 위치** | ✅ `APBAP1→0x81480000`, `APBAP2→0x81481000` | | |
| **C3f DM 컴포넌트 읽기** | ❌ ← **여기서 막힘.** 그 주소가 MEM-AP 로 안 보인다 | | |
| **C3g 전송 실패 단계 확정** | ⬜ ← **다음 측정** (`probe_rom_dm.py`) | | |
| C4 raw 트레이스 1회 회수 | ⬜ | | |
| C5 T32 결과와 교차 검증 | ⬜ | | |
| C6 퍼저 반복·복구·성능 | ⬜ | | |

**보조 트랙은 목표가 아니다.** T32 도 halt 를 쓰지 않는다(`sys.cpuaccess DENIED`).
G1/G2 실패는 주 트랙의 블로커가 **아니다** — 다만 C3b 와 원인을 공유할 수 있다.

---

## 8. 한 줄 요약

**디버그 하드웨어는 정상이고, 메모리 읽기도 된다** — DP·DAP 전원·AP 6개
(IDR 6/6 일치)·`DeviceEn=1`·그리고 **AP 주소공간 `0x0` 에서 ROM 엔트리를 읽어
DM 위치(`APBAP1→0x81480000`)까지 확인했다.**

**막힌 곳은 하나다: 그 ROM 이 가리키는 주소가 MEM-AP 로는 안 읽힌다.**
트레이스 블록(`0xFD......`)도 마찬가지라 **DM 우회(경로 B)는 닫혔다.**

가장 그럴듯한 해석은 **ROM 엔트리의 주소가 AP 주소공간이 아니라 SoC 의 APB
버스 주소**라는 것이다. 이건 추측으로 좁힐 문제가 아니므로 **① `--map` 으로
AP 가 실제 디코드하는 구간을 관측하고, ② 동시에 `ASK.md` 를 보낸다.**
