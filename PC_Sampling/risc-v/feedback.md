# SF-E76 RISC-V 브링업 방향 검토 피드백

> 작성일: 2026-08-07  
> 대상: `PC_Sampling/risc-v/` 브링업 작업  
> 목적: 현재 접근 방향이 맞는지 검토하고, 다음 작업자가 바로 이어서 판단할 수 있도록
> 실측 사실과 권장 순서를 분리해 기록한다.

## 최신 피드백 — 2026-08-11: T32 CMM 조사 종료, J-Link DM 진단으로 전환

> 이 절이 아래의 과거 CMM 조사 계획보다 우선한다. 필요한 T32 구조는 충분히
> 확인됐다. 더 많은 CMM 호출 체인을 한 줄씩 해석하는 작업은 중단한다.

### 1. 결론

현재 목표는 T32 환경을 그대로 복제하는 것이 아니라, **J-Link Plus로 SF-E76의
legacy SiFive Nexus trace를 SRAM sink에서 회수해 코드 커버리지로 변환하는 것**이다.

T32 스크립트에서 목표 달성에 필요한 정보는 이미 거의 확보됐다.

```text
cJTAG
  → HCore에서 RISC-V DM 연결(SYStem.DOWN → WAIT 500ms → SYStem.UP)
  → DM의 SBA(SB:/ESB:)로 trace register 접근
  → TE0~TE3 → funnel → 32KB SRAM trace sink
  → TE/TF disable → SRAM drain → raw .bin 저장
```

현재 주 블로커는 halt가 아니고, **J-Link가 HCore DM `0x81480000`을 T32의
`SYStem.UP`과 같은 상태로 만들지 못하는 것**이다. 따라서 다음 작업은 CMM 추가
조사가 아니라 Python/J-Link로 DM 접근 실패 지점을 측정하는 것이다.

### 2. T32 attach에서 확인된 사실

#### 코어와 DM

| 코어 | DM base | hart/구성 |
|---|---:|---|
| HCore / CMCore / FCore / QCore | `APB:0x81480000` | hart 0/1/2/3, `CoreNumber 4` |
| NCore | `APB:0x81481000` | 별도 core/chip 그룹, `CoreNumber 2` |

#### DAP/AP 구성

```text
APBAP1.Base = DP:0x10000
APBAP2.Base = DP:0x20000
AXIAP1.Base = DP:0x30000
AHBAP1.Base = DP:0x40000
APBAP3.Base = DP:0x50000
APBAP4.Base = DP:0x60000
COREDEBUG.Base = APB:0x81480000 또는 APB:0x81481000
```

#### T32 접근 정책

```text
SYStem.CONFIG.DEBUGPORTTYPE CJTAG
CJTAGFLAGS NOKEEPER USEOAC
SYStem.MemAccess SB
SYStem.CPUAccess DENIED
SYStem.Option.ResetMode.NDMRST
```

HCore만 DAP master로 동작한다.

```text
HCore:
  Slave OFF
  DAPSYSPWRUPREQ OFF
  DAPDBGPWRUPREQ ON
  SYStem.Mode Prepare
  SYStem.DOWN → WAIT 500ms → SYStem.UP

CM/F/Q/NCore:
  Slave ON
  HCore가 초기화한 DAP/DM에 attach
```

코어별 `INTERCOM`/RCL/GDB 포트 번호, `TITLE`, GUI 창 구성, 반복되는
`SYStem.RESet`, `CORE.ASSIGN`은 TRACE32 멀티 인스턴스 운용 정보다. J-Link trace
구현에 그대로 복제할 필요가 없다.

또한 `SYStem.Mode Prepare`는 사용자 정의 `Prepare` 매크로가 아니라 TRACE32 명령이다.
별도 CMM 구현을 찾을 대상이 아니다. 반대로 `SYStem.UP`의 SF-E76 전용 내부 동작은
TRACE32 CPU 드라이버에 숨겨졌을 수 있으므로 CMM을 더 읽어도 나오지 않을 수 있다.

### 3. Nexus trace 경로에서 확인된 사실

`ViewNexusTracedump.cmm`:

```text
SYStem.CONFIG.NEXUS.Type SiFive
TE0 = SB:0xFD000000
TE1 = SB:0xFD001000
TE2 = SB:0xFD002000
TE3 = SB:0xFD003000
RVFUNNEL1 / RVSRAMTRACEsink1 = SB:0xFD180000
NEXUS.0~3 → funnel port 0~3
la.import.etb *
la.list
```

`NexusTracedatadump.cmm`:

```text
TE0 control       = ESB:0xFD000000, bit1 clear로 disable
TF control/base   = ESB:0xFD180000, bit1 clear로 disable
write pointer     = base + 0x1C, bit0=wrap
read pointer      = base + 0x20
data port         = base + 0x24, 읽을 때 자동 증가
buffer capacity   = 0x8000 bytes(32KB)
output            = raw binary
```

wrap이면 write pointer에서 bit0을 제거한 위치를 oldest record로 보고 read pointer에
기록한 뒤 최근 32KB를 drain한다. 따라서 wrap된 dump는 최신 구간은 보존하지만 그 전에
덮어쓴 실행 이력까지 포함한 전체 coverage를 보장하지 않는다. 퍼저에서는 주기적 drain,
짧은 test case 또는 `coverage_incomplete` 처리가 필요하다.

이 스크립트들이 `SB:/ESB:`를 사용한다는 사실이 중요하다. T32의 실제 경로는 raw
APB-AP direct read가 아니라 **RISC-V DM의 SBA**다. 따라서 raw MEM-AP에서
`0xFD......`가 안 읽힌 결과는 T32 성공과 모순되지 않는다.

### 4. CMM 조사에서 남은 미확정 사항과 종료 판단

FAE GUI의 Nexus 관련 GOSUB는 다음 두 파일을 `DO`로 직접 호출할 뿐이다.

```text
NexusTracedatadump.cmm
ViewNexusTracedump.cmm
```

확인한 CMM에서는 TE/funnel을 enable하는 명령이 발견되지 않았다. 가능한 주체는 다음이다.

1. 펌웨어가 부팅 과정에서 이미 활성화
2. TRACE32 `SYStem.UP`의 SF-E76 드라이버 내부 동작
3. 별도 수동 명령 또는 아직 확보하지 않은 외부 자동화

그러나 이것은 현재 DM 연결 블로커의 선행 정보가 아니다. DM/SBA 연결 뒤
`TECTRL`, `TFCTRL`, write pointer를 읽으면 활성 상태와 실제 기록 여부를 바로 판단할
수 있다. 따라서 enable 주체를 찾기 위한 CMM 전수 조사는 여기서 중단한다.

`T32_Start_RISCV.bat`의 INTERCOM/RCL/GDB 포트와 `t32rem`은 TRACE32 프로세스와 GUI를
기동·제어하기 위한 orchestration 정보다. J-Link coverage 로직에는 필요 없다.
`main.cmm`의 `PrepareDump+Attach`/`AttachOnly`, `FAE.cmm`, `AllCoreAnalysis.cmm`의 GUI
호출 관계도 trace enable을 찾지 못했다면 더 추적하지 않는다.

### 5. 현재 가장 부족한 정보

다른 CMM 파일이 아니라 다음 한 가지다.

> J-Link가 APBAP1을 통해 `0x81480000`을 읽을 때, MEM-AP 전송의 어느 단계에서
> 어떤 AP/DP 오류가 발생하는가?

최소 수집 항목:

```text
AP IDR / BASE / CFG
CSW 원본 및 설정 후 되읽기
CSW.DeviceEn / SDeviceEn / Prot / Type
TAR write 성공 여부와 readback
DRW 반환값
전송 전후 DP CTRL/STAT
STICKYERR / WDATAERR / STICKYORUN
ABORT 후 오류 해제 여부
```

주소 `0x0`에서 읽힌 `0x81480003`/`0x81481003`은 T32 DM base와 일치하는 매우 강한
정황이지만, 아직 실제 CoreSight ROM table이라고 확정하지 않는다. APBAP1/2의
`BASE`, 주소 `0xFE0~0xFFC` PIDR/CIDR, signed relative offset을 확인한 뒤
`ROM_CONFIRMED`와 `ROM_ENTRY_LIKE`를 구분한다.

`0x80000000`도 J-Link API error sentinel로 확정하지 않고 문맥상 의심값으로만 다룬다.

### 6. 다음 코드 작업

전체 4GB를 1MB 간격으로 읽는 `--map`은 다음 단계로 사용하지 않는다. 좁은 component를
놓치고, fixed default response를 live 영역으로 오판하며, read side effect가 있는 MMIO를
건드릴 수 있다.

새 표적 진단기 `probe_rom_dm.py`를 만드는 것이 우선이다.

```text
기본 3개 독립 세션
APBAP1/APBAP2만 우선 측정
ROM 후보 0x0~0xC 및 PIDR/CIDR만 제한 접근
DM 0x81480000/0x81481000 제한 접근
각 DRW 뒤 DP error 상태 기록
CSW 원본 보존 및 세션 종료 전 복구
JSON 상세 로그 + 한 줄 brief 판정
유효 세션 3회 미만이면 결론 금지
```

판정은 최소한 다음을 분리해야 한다.

```text
ROM_CONFIRMED_DM_REACHABLE
ROM_CONFIRMED_DM_BLOCKED
ROM_ENTRY_LIKE_NOT_CONFIRMED
MEM_AP_TRANSFER_BROKEN
ACCESS_ATTRIBUTE_OR_SECURITY_SUSPECTED
INSUFFICIENT_VALID_SESSIONS
```

### 7. 이후 실행 순서

```text
1. probe_rom_dm.py로 HCore DM 실패 단계 확정
2. J-Link native 연결 재시험
   - cJTAG
   - APBAP1
   - CoreBase 0x81480000
   - hart 0
   - RISCV_UseNexusLegacyMode=1
3. DM/SBA 연결 후 read-only로 확인
   - 0xFD000000    TE0 control
   - 0xFD180000    funnel control
   - 0xFD18001C    write pointer
   - 0xFD180020    read pointer
   - 0xFD180024    data port
4. write pointer가 실행 중 증가하는지 확인
5. 필요할 때만 TE0/funnel enable 절차 구현
6. 짧은 raw trace 1회를 회수해 기존 RISC-V coverage 변환 경로에 입력
7. hart0 성공 뒤에만 hart1~3 및 NCore로 확장
```

Halt/PC sampling은 보조 진단 트랙일 뿐 주 목표의 gate가 아니다. 첫 합격 기준은
`halt()`가 아니라 **HCore DM/SBA 접근과 raw Nexus trace 1회 회수**다.

## 결론

큰 아키텍처 판단은 맞다.

```text
cJTAG → ARM DAP → AP(APB/AHB) → RISC-V Debug Module(DMI) → hart
```

SEGGER는 **RISC-V behind CoreSight DAP** 구조를 공식 지원한다. 따라서 cJTAG와 ARM DAP를
거쳐 SF-E76에 접근하려는 방향 자체를 버릴 필요는 없다.

다만 현재 진행 순서는 수정해야 한다. 지금처럼 pylink로 DP/AP를 직접 읽고 그 위에서 RISC-V
halt와 `dpc` 접근까지 수동 구현하는 것을 주 경로로 삼으면 안 된다. 먼저 J-Link DLL에
**AP map, RISC-V가 연결된 AP, DMI register base**를 정확히 알려서 J-Link의 `connect()` 자체를
성공시켜야 한다.

현재 `SF_E76_addap.JLinkScript`는 AP 가설을 확인하는 진단 실험으로는 의미가 있지만,
그대로는 J-Link RISC-V 연결 설정이 완성되지 않는다.

---

## 1. 현재 실측이 의미하는 것

확인된 값:

```text
TIF        = 7 (cJTAG)
speed      = 10 MHz
DPIDR      = 0x6BA0009D
CTRL/STAT  = 0xF0000000
```

따라서 아래 계층은 이미 정상이다.

```text
J-Link USB
  → cJTAG 활성화
  → TAP 접근
  → ARM Debug Port 접근
  → system/debug power request 및 ACK
```

`connect("RISC-V")`가 실패한다는 사실을 **cJTAG 물리 연결 실패**로 해석하면 안 된다.
현재 실패 지점은 그 다음의 J-Link CPU setup 단계다.

J-Link가 아직 모르는 정보:

1. DAP 아래 AP들의 정확한 map
2. 어느 AP가 RISC-V DMI register로 연결되는지
3. 해당 AP 주소 공간에서 DMI register window가 어디인지
4. 멀티코어/멀티하트 선택 방법

RISC-V behind DAP에서는 J-Link가 이 정보를 자동 탐지할 수 없으므로 사용자가 수동으로
설정해야 한다.

---

## 2. 현재 AddAP 스크립트가 부족한 이유

대상 파일: `SF_E76_addap.JLinkScript`

### 2.1 설정 훅이 적절하지 않다

현재 AP 설정과 진단을 `InitTarget()`에서 수행한다. SEGGER의 RISC-V behind DAP 공식 예제는
AP topology와 RISC-V 연결 위치를 `ConfigTargetSettings()`에서 선언한다.

역할을 다음처럼 나누는 것이 맞다.

- `ConfigTargetSettings()`:
  - AP map 등록
  - RISC-V가 연결된 AP 선택
  - DMI/core base 설정
- `InitTarget()`:
  - 특수한 핀, 전원, unlock, cJTAG 전환 같은 저수준 초기화가 정말 필요할 때만 사용
- `SetupTarget()`:
  - 일반 connect 이후 추가 target 초기화

### 2.2 AP 등록만 하고 RISC-V 접근 경로를 선택하지 않는다

현재 스크립트에는 다음 설정이 없다.

```text
CORESIGHT_SetIndexAPBAPToUse
CORESIGHT_SetIndexAHBAPToUse
CORESIGHT_SetCoreBaseAddr
```

따라서 AP 1~6을 등록해도 J-Link는 다음을 모른다.

```text
어느 AP가 RISC-V DMI로 연결되는가?
그 AP 안에서 DMI register는 어느 주소에 있는가?
```

AP IDR 읽기가 성공해도 자동 `connect()`는 계속 실패할 수 있다.

### 2.3 deprecated AddAP API를 사용한다

현재 사용:

```c
JLINK_CORESIGHT_AddAP(Index, Type);
```

이 함수는 SEGGER 문서상 deprecated다. SoC-600/ADIv6 또는 nested AP를 표현할 수 없으므로
명령 문자열 방식이 권장된다.

```c
JLINK_ExecCommand(
    "CORESIGHT_AddAP = Index=1 Type=APB-AP BaseAddr=0x00010000"
);
```

T32의 `DP:0x10000`, `DP:0x20000`, ... 값이 단순 APSEL이 아니라 주소 기반 AP 위치라면
`BaseAddr`가 특히 중요하다.

### 2.4 `COREDEBUG.Base`의 의미가 아직 확정되지 않았다

현재 코드는 다음을 가정한다.

```text
T32 COREDEBUG.Base = CoreSight component base
```

그래서 `0x81480000 + 0xFF0`에서 CIDR0를 읽으려 한다. 하지만 RISC-V behind DAP에서
J-Link가 요구하는 `CORESIGHT_SetCoreBaseAddr`는 **AP 주소 공간에서 DMI register를 찾을 수 있는
위치**다.

실제 구조가 다음일 가능성도 있다.

```text
T32 COREDEBUG.Base = RISC-V DMI aperture base
```

그렇다면 `+0xFF0` CoreSight CIDR 검사는 의미가 없고, `0x81480000` 자체가 J-Link에 줄
DMI/core base일 수 있다. 이 부분은 T32 설정 또는 벤더 자료로 확정해야 하며 추측으로 고정하면
안 된다.

---

## 3. 권장 진행 순서

### 3.1 T32에서 연결 정의를 먼저 추출한다

J-Link AP scan을 더 늘리기 전에, 이미 연결에 성공하는 T32 설정에서 다음 값을 확보한다.

- APBAP/AHBAP/AXIAP의 index, type, base
- RISC-V가 실제로 연결된 AP
- RISC-V DMI register window base
- 코어별 hart 선택값 또는 인스턴스별 차이
- `SYStem.Up` 이전의 `Data.Set` 초기화/unlock 시퀀스
- `Init_FPGA_RISCV.cmm`이 현재 실리콘에서 실제 사용되는 경로인지

확인 대상 예:

```text
SYStem.CONFIG 전체 출력
APBAP*.Base
COREDEBUG.Base
DEBUGMODULE.Base 또는 DMI.Base와 유사한 설정
.bat → DO → CMM 실행 체인
코어별 T32 인스턴스에 전달되는 서로 다른 파라미터
```

RISC-V behind DAP에는 일반적인 ARM CoreSight ROM table 기반 RISC-V 자동 탐색이 없으므로,
AP scan만으로 DMI 위치까지 찾겠다는 접근은 한계가 있다.

### 3.2 공식 형태의 최소 JLinkScript를 만든다

아래는 **형태 예시**다. 숫자는 T32에서 확정한 뒤 넣어야 한다.

```c
void ConfigTargetSettings(void) {
  JLINK_ExecCommand(
    "CORESIGHT_AddAP = Index=1 Type=APB-AP BaseAddr=0x00010000"
  );

  JLINK_ExecCommand(
    "CORESIGHT_SetIndexAPBAPToUse = 1"
  );

  JLINK_ExecCommand(
    "CORESIGHT_SetCoreBaseAddr = 0x81480000"
  );

  return 0;
}
```

주의:

- `Index=1`, `BaseAddr=0x10000`, `CoreBaseAddr=0x81480000`은 현재 자료에 기반한 후보일 뿐이다.
- 먼저 RISC-V로 직접 연결되는 AP 하나만 등록해 connect를 확인하는 것이 좋다.
- 여러 AP 전체 등록과 trace/memory AP 설정은 connect 성공 후 확장한다.
- 대상이 APB-AP가 아니라 AHB-AP면 `CORESIGHT_SetIndexAHBAPToUse`를 사용한다.

### 3.3 성공 기준을 `connect()`로 올린다

DPIDR/AP IDR은 이제 중간 진단값일 뿐이다. v10 sampler 진입 조건은 다음 전체가 성공하는 것이다.

```text
generic RV32 target 선택
  → JLinkScript 로 AP/DMI topology 공급
  → J-Link connect 성공
  → halt 성공
  → dpc 읽기 성공
  → resume/go 성공
```

SF-E76은 RV32 계열이므로 generic RV32 설정을 출발점으로 쓰는 것이 합리적이다. 단, 실제 J-Link
버전에서 제공하는 정확한 generic device name은 설치된 J-Link Commander의 device 목록으로
확인한다.

### 3.4 connect 성공 후 pylink sampler로 이식한다

JLinkExe에서 공식 연결 경로가 성공한 다음 pylink로 옮긴다.

목표 형태:

```python
jl.connect(...)
jl.halt()
pc = jl.register_read(...dpc index...)
jl.restart()  # 또는 go/resume
```

J-Link DLL이 RISC-V DM, abstract command, hart 제어를 담당하게 해야 한다. pylink에서 DP/AP/DMI
프로토콜을 직접 다시 구현하는 것은 J-Link target setup이 불가능하다고 확정된 뒤의 최후 수단이다.

---

## 4. 현재 도구의 역할 재정의

### `probe_sfe76_pylink.py`

유효한 역할:

- cJTAG TIF/속도 확인
- ARM DPIDR 확인
- debug power ACK 확인
- J-Link/pylink API가 어느 단계까지 동작하는지 진단

주 경로로 삼지 말아야 할 역할:

- AP map을 추측으로 완성
- RISC-V DMI 프로토콜 직접 구현
- J-Link CPU connect를 우회한 production sampler 구현

### `SF_E76_addap.JLinkScript`

현재 역할:

- AddAP 등록 후 AP access가 실제 발행되는지 확인하는 보조 실험

아직 하지 못하는 것:

- J-Link RISC-V connect 설정 완성
- RISC-V AP 선택
- DMI base 지정
- hart 선택

따라서 이 스크립트가 AP IDR을 읽는 데 성공하더라도, 그것만으로 v10 sampler 경로가 해결된 것은
아니다.

---

## 5. 다음 실험의 판정표

| 결과 | 의미 | 다음 행동 |
|---|---|---|
| AddAP 후 AP IDR 성공 | AP 등록/주소 가설 일부 확인 | T32 값으로 공식 `ConfigTargetSettings()` 작성 |
| AddAP 후에도 AP IDR 0 | AP type/index/base 또는 초기화 시퀀스 오류 | T32 AP map과 `SYStem.Up` 전 시퀀스 확보 |
| 공식 script 적용 후 connect 성공 | J-Link target model 완성 | halt/dpc/resume 및 멀티하트 검증 |
| AP 접근 성공, connect 실패 | DMI base/hart/debug-spec 설정이 틀림 | T32 DMI 위치와 hart 설정 재확인 |
| T32 정보가 있어도 J-Link connect 실패 | J-Link DLL/device support 문제 가능 | SEGGER에 DPIDR, AP map, DMI base, 로그 제공 |

SEGGER 문의가 필요할 때 제공할 최소 자료:

```text
J-Link model / firmware / software version
VTref, interface=cJTAG, speed=10MHz
TIF=7
DPIDR=0x6BA0009D
CTRL/STAT=0xF0000000
T32에서 성공하는 AP map과 DMI base
적용한 ConfigTargetSettings() 전문
J-Link connect log 전문
```

---

## 6. v10.0 범위 판단

v10.0의 크리티컬 패스는 여전히 다음이다.

```text
J-Link connect → halt → dpc → resume → 기존 fuzzer sampler 교체
```

Nexus trace는 가치가 크지만 병행 트랙이다. SiFive는 Insight Advanced Trace에서 Nexus 기반
실행 trace를 제공하고, SEGGER도 RISC-V trace encoder/sink 관련 설정을 지원한다. 다만 trace
base와 sink 구성, 라이선스/IP 옵션이 확인되기 전에는 v10.0 연결 작업을 막으면 안 된다.

---

## 7. 최종 권고

1. 현재까지 확보한 DP 접근 성공은 유효한 진전이므로 폐기하지 않는다.
2. 현재 AddAP 스크립트는 **진단용**으로만 취급한다.
3. AP/DMI 위치를 추측으로 스캔하기보다 T32의 성공 설정에서 추출한다.
4. `ConfigTargetSettings()`에서 공식 RISC-V-behind-DAP 설정을 완성한다.
5. J-Link `connect()` 성공을 먼저 달성한 뒤 pylink sampler로 옮긴다.
6. 직접 DMI/hart 제어 구현은 공식 연결 경로가 불가능하다고 확인된 경우에만 검토한다.

즉, 현재 방향은 절반은 맞다. **토폴로지 판단은 맞지만, J-Link connect를 우회하려는 구현 순서는
바꿔야 한다.**

---

## 참고 자료

- SEGGER, RISC-V behind a CoreSight DAP 및 설정 예제:  
  <https://kb.segger.com/J-Link_RISC-V>
- SEGGER, J-Link Script 함수와 `ConfigTargetSettings()`/`InitTarget()` 역할:  
  <https://kb.segger.com/Using_J-Link_Script_Files>
- SEGGER, J-Link command strings (`CORESIGHT_AddAP`, AP 선택, core base):  
  <https://kb.segger.com/J-Link_command_strings>
- SEGGER, RISC-V 및 cJTAG/CoreSight DAP 지원 범위:  
  <https://www.segger.com/products/debug-probes/j-link/technology/cpus-and-devices/risc-v-support/>
- SiFive, Insight Standard Debug/Advanced Trace 개요:  
  <https://www.sifive.com/software/trace-and-debug>

---

## 8. 2026-08-07 후속 실험 — 첫 connect 실패, 두 번째 connect 성공

`connect_min.py`로 다음 세 실험을 수행했다.

```bash
# ① 단일 주소 1회 — 예열 없이 바로 연결
sudo python3 connect_min.py --order 0x81481000

# ② 같은 주소 두 번
sudo python3 connect_min.py --order 0x81480000,0x81480000

# ③ 주소 순서 뒤집기
sudo python3 connect_min.py --order 0x81481000,0x81480000
```

관측 결과:

```text
① 0x81481000
   1회차 실패

② 0x81480000 → 0x81480000
   1회차 실패 → 2회차 성공

③ 0x81481000 → 0x81480000
   1회차 실패 → 2회차 성공
```

### 8.1 현재 결과로 확정할 수 있는 것

- 첫 번째 `connect()`는 실패하고, 같은 J-Link handle 안의 두 번째 `connect()`는 성공한다.
- 첫 번째 주소가 무엇인지보다 **세션 내 시도 순서**가 성공 여부를 지배한다.
- `0x81480000`도 두 번째 시도에서 J-Link `connect()`를 통과하므로 유효한 연결 후보다.
- 따라서 이전 sweep의 실패를 곧바로 "해당 CoreBase가 틀렸다" 또는 "그 코어는 연결 불가"로
  해석하면 안 된다.

### 8.2 아직 확정할 수 없는 것

현재 `connect_min.py`의 각 회차는 실제로 다음 두 동작을 함께 반복한다.

```text
setup → connect
setup → connect
```

따라서 아직 다음 원인을 분리하지 못했다.

1. 실패한 첫 `connect()` 자체가 필요한 초기화를 수행한다.
2. `setup()` 명령을 두 번 적용해야 설정이 유효해진다.
3. 첫 시도가 실패하는 동안 시간이 지나 debug domain/DM이 준비된다.

또한 `connect()` 성공만으로 `0x81480000`이 hcore/CMCore/Fcore0/QCore 중 어느 코어에 연결됐는지
확정할 수 없다. 올바른 코어 귀속은 halt/PC/hart fingerprint 검증이 필요하다.

### 8.3 원인을 분리하는 최소 추가 실험

각 실험은 동일한 초기조건에서 수행하고, 가능하면 target 전원 사이클별로 반복한다.

#### 실험 A — connect만 두 번

```python
setup(0x81480000)
connect()       # 예상: 실패
connect()       # setup 재실행 없이 재시도
```

두 번째가 성공하면 **실패한 첫 connect 자체가 초기화 역할**을 한 것이다.

#### 실험 B — setup만 두 번

```python
setup(0x81480000)
setup(0x81480000)
connect()       # connect는 한 번만
```

첫 connect가 성공하면 첫 setup이 완전히 적용되지 않았거나, 설정을 두 번 적용해야 하는 문제다.

#### 실험 C — setup 후 대기

```python
setup(0x81480000)
sleep(1.0)      # 0.2 / 1 / 3초 비교
connect()
```

대기만으로 첫 connect가 성공하면 failed-connect warm-up이 아니라 **readiness 지연**이다.

### 8.4 가장 가능성 높은 구조적 원인

현재 Python 도구는 AP map과 CoreBase command string을 `connect()` 전에 pylink
`exec_command()`로 직접 전달한다. 반면 SEGGER 공식 RISC-V-behind-DAP 절차는 이 설정을
JLinkScript의 `ConfigTargetSettings()` 안에 둔다.

`ConfigTargetSettings()`는 J-Link의 정상 connect lifecycle에서 CPU 자동검출 및 target 초기화보다
앞서 호출되며, AP map/CoreBase 같은 DLL 전역 연결 설정을 지정하기 위한 훅이다.

가능한 현재 동작:

```text
첫 connect
  → generic RISC-V CPU module / DAP 경로를 부분 초기화
  → CPU setup 단계에서는 실패

두 번째 setup + connect
  → 이미 초기화된 DLL/target 상태에 AP/CoreBase 설정이 적용
  → connect 성공
```

따라서 최종 해결은 "항상 실패하는 connect를 한 번 먼저 호출"하는 것보다,
`ConfigTargetSettings()`를 사용한 정식 JLinkScript로 cold session의 첫 connect를 성공시키는 것이다.

형태 예시:

```c
int ConfigTargetSettings(void) {
  JLINK_ExecCommand(
    "CORESIGHT_AddAP = Index=0 Type=APB-AP Addr=0x10000"
  );
  /* 나머지 AP map 등록 */

  JLINK_ExecCommand(
    "CORESIGHT_SetIndexAPBAPToUse = 0"
  );
  JLINK_ExecCommand(
    "CORESIGHT_SetCoreBaseAddr = 0x81480000"
  );
  return 0;
}
```

주소와 AP 선택은 대상 코어별 실측값으로 바꾼다.

### 8.5 임시 sampler 연결 정책

JLinkScript로 첫 connect 문제를 해결하기 전까지는 동일 handle 내 bounded retry를 임시
workaround로 사용할 수 있다.

```text
새 J-Link handle
  → 모든 설정 command 성공 확인
  → connect 1회
  → 실패 시 짧은 대기
  → 동일 handle에서 동일 설정으로 connect 2회차
  → 성공 후 halt/PC/resume 검증
  → 모두 실패하면 세션 종료 및 복구
```

주의:

- 무한 재시도하지 않는다.
- 첫 실패를 숨기지 말고 로그와 카운터로 남긴다.
- 다른 AP/CoreBase 조합을 같은 handle에 섞지 않는다.
- 성공 또는 중간 실패 후 코어가 halt 상태로 남지 않도록 best-effort resume을 보장한다.

### 8.6 `0x81480000`의 현재 판정

정확한 표현:

> `0x81480000`은 동일 handle의 두 번째 시도에서 J-Link 연결을 성립시킬 수 있는 유효 후보다.
> 그러나 이 주소가 hcore/CMCore/Fcore0/QCore 중 어느 코어를 나타내며, 네 코어를 어떻게
> 선택하는지는 아직 미확정이다.

추가로 필요한 검증:

- J-Link register name으로 실제 PC/DPC index 확정
- halt → PC 읽기 → resume 성공
- `RISCV_SetHartSel`별 register/PC 비교
- 실제 NVMe workload와 PC 변화의 상관관계
- `0x81481000` 연결 결과와 PC fingerprint 비교

이번 후속 실험의 최종 해석:

> 동일 handle에서 첫 연결은 실패하고 두 번째 연결은 성공한다. 이는 주소 자체보다 연결 초기화
> 순서가 중요하다는 것을 입증한다. 다만 failed connect, setup 재적용, readiness delay 중 무엇이
> 필요한지는 추가 분리 실험이 필요하다. `0x81480000`은 유효 연결 후보지만 코어 귀속은
> halt/PC/hart 검증 전까지 미확정이다.

---

## 9. README / BRINGUP 현재 상황 리뷰

검토 대상:

- `README.md`
- `BRINGUP_riscv_v10.md`

검토 시점의 정확한 프로젝트 상태는 다음과 같다.

```text
물리 연결 / cJTAG / ARM DP                  검증 완료
AP map / CoreBase 수동 설정                 connect 단계에서 사용 가능
J-Link connect                              동일 handle의 두 번째 시도에서만 성공
0x81480000 / 0x81481000                     둘 다 connect 성공 후보
halt / PC 읽기 / resume                     미검증
실제 코어 및 hart 귀속                     미검증
반복 reconnect / POR / crash recovery       미검증
v10 sampler 통합                            시작 전
```

따라서 현재 위치는 **"transport와 J-Link CPU setup의 일부가 열린 상태"**이지,
아직 **"RISC-V PC sampler가 동작하는 상태"**는 아니다.

### 9.1 Critical issues

#### 1. README의 실행 안내가 현재 파일 상태와 충돌한다

README 상단 파일 표는 다음과 같이 현재 역할을 비교적 정확히 설명한다.

- `connect_sfe76.py`: 연결 동작
- `verify_halt_pc.py`: 현재 크리티컬 패스
- `probe_sfe76_pylink.py`: 초기 진단, 역할 종료

그런데 본문은 다시 `probe_sfe76_pylink.py ← 이걸 먼저 돌린다`고 안내하고,
이미 폐기된 APSEL 열거와 CoreSight `CIDR0` 판정을 주 절차로 제시한다.

BRINGUP 문서 자체는 뒤에서 다음 가정을 이미 폐기했다.

- `0x81480000 + 0xFF0`의 `CIDR0`로 DMI base를 판정한다.
- APSEL 번호를 순회해 AP를 찾는다.

새 작업자가 README만 읽으면 완료된 초기 진단을 다시 수행하고, 잘못된 판정 기준으로
정상 후보를 탈락시킬 수 있다. README 본문은 현재 절차인
`connect_sfe76.py → verify_halt_pc.py → diagnose_connect.py` 중심으로 교체해야 한다.

#### 2. BRINGUP의 "다음 단계"가 이미 완료된 과거 단계다

BRINGUP §5는 여전히 다음을 즉시 작업으로 지정한다.

1. 전원 사이클 후 4선 JTAG 스캔
2. J-Link cJTAG connect
3. 핀아웃 확인
4. DM base와 `SYStem.Up` 전 시퀀스 추출

하지만 같은 문서의 앞부분에서는 cJTAG, DP 접근, AP map/CoreBase 설정 및 J-Link connect까지
완료됐다고 선언한다. §3의 열린 질문 A/B/C와 §5는 역사 기록으로 이동하거나 완료 표시해야 한다.

현재의 실제 다음 단계는 **`verify_halt_pc.py`로 halt → PC 확인 → resume을 안전하게 검증하는 것**이다.

#### 3. `connect()` 성공의 의미를 과도하게 확대했다

BRINGUP에는 다음 표현이 있다.

- "두 DM 모두 접근 가능"
- "APB Index 0으로 둘 다 붙는다 → 다른 AP를 뒤질 이유 없음"
- 아키텍처 단계 `0a connect`: "완료"

현재 실험이 직접 입증한 것은 두 CoreBase 값에서 J-Link의 `connect('RISC-V')`가 두 번째 시도에
예외 없이 끝난다는 점이다. 아직 DM register, hart, PC 값, halt/resume이 검증되지 않았다.

따라서 현재는 다음처럼 표현해야 정확하다.

> 두 CoreBase 모두 **J-Link connect 후보로 통과**했다. 동일 AP 설정이 실제 DM과 올바른 코어에
> 도달하는지는 halt/register/PC fingerprint 검증 전까지 미확정이다.

특히 `0x81480000`을 네 코어가 공유하므로, CoreBase 외에 T32 인스턴스별 AP 경로, hart selection,
SoC 내부 선택 상태가 더 있을 수 있다. 지금 단계에서 다른 AP나 선택 메커니즘을 완전히 배제하면 안 된다.

#### 4. halt 실패 시 복구 조건이 크리티컬 패스에 명시돼야 한다

문서에 "halt 후 반드시 resume" 원칙은 있지만, `verify_halt_pc.py` 실행의 합격/실패 기준과
복구 불변조건이 없다. SSD 컨트롤러에서 halt 성공 후 PC read나 Python 예외가 발생하면 코어가
멈춘 채 남을 수 있다.

최소 요구사항:

```text
try:
    halt
    halted 상태 확인
    PC/DPC 읽기 및 유효성 검사
finally:
    best-effort resume
    running 상태 재확인
```

resume 확인이 실패하면 다음 실험을 계속하지 말고 해당 handle을 닫은 뒤 정해진 보드 복구 절차를
수행해야 한다.

### 9.2 Potential bugs / 과도한 확정

#### 1. "첫 connect는 구조적으로 실패"의 범위를 제한해야 한다

A/B/C 실험으로 확인된 것은 **현재 J-Link DLL/펌웨어, generic `RISC-V` device, 현재 명령 순서와
보드 상태에서 failed connect가 다음 connect 성공에 필요한 상태 변화를 만든다**는 것이다.

RISC-V나 해당 SoC에서 첫 connect가 원래 반드시 실패하는 것으로 일반화할 수는 없다.
문서 표현은 다음처럼 제한하는 것이 안전하다.

> 현재 연결 구현과 도구 버전에서는 cold handle의 첫 connect가 일관되게 실패한다.

J-Link 버전, 펌웨어, 전원 사이클 여부, device profile을 로그에 항상 기록해야 재현성이 생긴다.

#### 2. `dmactive`는 좋은 가설이지만 아직 원인으로 확정되지 않았다

A/B/C 결과는 "시간 경과나 setup 반복이 아니라 connect 내부 동작이 필요하다"는 점을 지지한다.
그러나 그 동작이 `dmcontrol.dmactive` write인지, ARM DP 전원 요청인지, J-Link 내부 캐시/CPU module
초기화인지는 직접 관측하지 않았다.

`dmactive` 설명은 **유력 가설**로 유지하고, 다음 중 하나가 있어야 확정할 수 있다.

- 첫 connect 전후 DMI/DM register의 실제 변화
- J-Link 상세 로그에서 해당 write 확인
- 명시적 `dmactive=1` 후 cold first connect 성공

#### 3. "JLinkScript에서 CoreSight API를 쓸 수 없다"는 결론이 너무 넓다

현재 관측은 특정 스크립트 훅과 현재 DLL에서 호출 결과가 `INT_MIN`이었다는 것이다.
훅 호출 시점, API 지원 범위, DLL 버전 또는 선행 초기화 조건 문제일 수 있다.

정확한 표현은 다음과 같다.

> 현재 사용한 JLinkScript 훅과 호출 순서에서는 `JLINK_CORESIGHT_*` 접근이 동작하지 않았다.

`ConfigTargetSettings()`의 command string 설정과 `InitTarget()`의 저수준 CoreSight API 실패도
서로 다른 경로이므로 한 결론으로 합치지 않는 편이 좋다.

#### 4. APB 메모리 접근과 RISC-V DMI register 접근을 동일시하면 안 된다

BRINGUP §6은 `dmcontrol 0x10`, `dmstatus 0x11` 등을 "APB 주소로 접근"한다고 단정한다.
이 값들은 RISC-V DMI register address이며 일반적인 APB byte offset이라는 뜻이 아니다.
`CORESIGHT_SetCoreBaseAddr`가 가리키는 vendor DMI aperture의 register layout과 J-Link의 변환 방식을
확인하지 않은 채 `base + 0x10`처럼 메모리 read/write하면 잘못된 장치를 건드릴 수 있다.

직접 접근은 SoC/T32 설정 또는 SEGGER 문서에서 DMI aperture layout을 확보한 뒤에만 진행해야 한다.

#### 5. 문서 날짜가 현재 실험 순서와 맞지 않는다

BRINGUP의 주요 완료 기록은 `2026-08-08`인데, 이번 검토 및 feedback 후속 실험은
`2026-08-07`로 기록돼 있다. 실제 실행일인지 예정일/문서 버전일인지 정리하지 않으면 로그와
결론의 선후관계를 추적하기 어렵다. 날짜를 실제 실험 시각과 commit 기준으로 통일하는 것이 좋다.

### 9.3 Reliability improvements

#### 1. README는 현재 runbook, BRINGUP은 조사 이력으로 역할을 분리한다

권장 구조:

```text
README.md
  - 현재 확정 상태
  - 지금 실행할 명령 1~3개
  - 성공/실패 판정
  - 안전 복구

BRINGUP_riscv_v10.md
  - 실험 이력과 근거
  - 폐기된 가정
  - 열린 가설
  - 다음 실험
```

README에서는 역할 종료 도구의 상세 실행법을 제거하고 BRINGUP의 역사 섹션으로 링크하는 편이 낫다.

#### 2. 연결 성공을 단계별 gate로 정의한다

```text
G0: cJTAG/DPIDR/전원 ACK
G1: bounded retry 안에 J-Link connect
G2: halt 성공 + halted 확인
G3: PC/DPC 읽기 성공 + 유효 범위/변화 확인
G4: resume 성공 + running 확인
G5: workload 중 반복 샘플링
G6: close/reopen, POR, crash recovery
```

현재는 **G1까지만 부분 통과**했다. v10 sampler 착수 조건은 최소 G4, 장시간 퍼징 투입 조건은
G5와 G6 통과로 두는 것이 안전하다.

#### 3. connect workaround를 명시적으로 계측한다

각 시도에 다음을 남긴다.

- monotonic timestamp와 시도 번호
- J-Link DLL/firmware/hardware version
- TIF, speed, AP map, CoreBase, hartsel
- 첫 실패의 정확한 error code/message
- connect 소요 시간
- halt/PC/resume 각 결과
- handle 재사용 여부와 target power-cycle ID

첫 실패를 정상으로 간주해 숨기면 실제 회귀와 warmup 실패를 구분할 수 없다.

#### 4. 코어 후보별 세션을 완전히 격리한다

`0x81480000`과 `0x81481000`, AP index, hartsel 조합마다 별도 handle과 별도 결과 레코드를 쓴다.
단, 한 후보 내에서는 warmup 상태를 보존하기 위해 동일 handle에서 bounded connect retry를 수행한다.

### 9.4 Suggested tests / 권장 실행 순서

#### P0 — 지금 바로 할 것

1. **Ncore 후보 `0x81481000` 하나만 선택한다.**
2. 동일 handle에서 같은 설정으로 connect를 최대 3회 수행한다.
3. 성공 직후 `verify_halt_pc.py`로 halt 상태를 확인한다.
4. PC/DPC를 여러 번 읽어 값이 정렬되고 실행 주소 범위에 있는지 본다.
5. `finally` 경로에서 resume하고 running 상태를 확인한다.
6. 실제 NVMe workload가 계속 진행되는지 확인한다.

이 단계가 실패하면 멀티코어 스윕이나 sampler 통합으로 넘어가지 않는다.

#### P1 — 첫 connect 원인과 지속 범위 분리

- 성공 후 handle close/reopen, target 전원은 유지하고 1회 connect
- target POR 후 새 handle에서 1회 connect
- `SF_E76_config.JLinkScript` 적용 cold session에서 첫 connect 결과 확인
- generic `RISC-V`와 정확한 device profile 후보 비교
- connect 전 `RISCV_SetHartSel` 적용 비교

이 결과로 warmup 상태가 DLL, probe, target DM 중 어디에 남는지 좁힌다.

#### P2 — `0x81480000` 네 코어 귀속

- 후보별로 PC fingerprint를 수집한다.
- 동일 workload에서 PC 변화 패턴을 비교한다.
- hartsel별 register/PC 차이를 비교한다.
- T32에서 알려진 각 코어 PC와 교차 검증한다.

PC가 읽힌다는 이유만으로 코어 이름을 붙이지 말고, 최소 두 개의 독립적인 fingerprint가 일치할 때
귀속을 확정한다.

#### P3 — sampler 투입 전 내구성

- halt/read/resume 1,000회 반복
- connect close/reopen 반복
- POR 후 자동 복구 반복
- 의도적인 PC read 예외에서 resume 보장 확인
- J-Link timeout과 USB 일시 오류 주입
- NVMe I/O와 동시 수행하여 timeout/hang/성능 영향 측정

### 9.5 최종 판단

현재 선택한 **pylink + J-Link + 수동 CoreSight AP/DMI 설정 방향은 맞다.** 실제 cJTAG와 ARM DP를
통과했고, 두 CoreBase 후보에서 반복 가능한 connect 성공 조건도 찾았다.

다만 프로젝트 상태를 "connect 완료"로 닫기에는 이르다. 현재 가장 큰 불확실성은 주소 탐색이 아니라
**성공한 연결이 실제 코어의 halt/PC/resume까지 안전하게 제어하는가**이다. 따라서 추가 AP sweep이나
트레이스 조사보다 `verify_halt_pc.py`의 안전한 단일-core 검증을 최우선으로 진행해야 한다.

---

## 10. 2026-08-07 전체 코드·문서 업데이트 리뷰

검토 대상:

- `README.md`
- `BRINGUP_riscv_v10.md`
- `sfe76_link.py`
- `verify_halt_pc.py`
- `diagnose_connect.py`
- `SF_E76_config.JLinkScript`
- `backup/` 구성과 현재 파일 간 역할 분리

정적 확인 결과 Python 세 파일은 `py_compile`을 통과했고 각 CLI의 `--help`도 정상 동작했다.
실제 J-Link/타깃 실행은 이 리뷰에서 수행하지 않았다.

전체 구조는 이전보다 좋아졌다. 특히 연결 지식을 `sfe76_link.py`로 모으고, README를 현재 runbook,
BRINGUP을 조사 이력으로 분리하려는 방향은 맞다. 다만 현재 `verify_halt_pc.py`를 보드에서 실행하기
전 수정해야 할 안전 및 판정 문제가 남아 있다.

### 10.1 Critical issues

#### 1. halt/resume 성공을 실제로 검증하지 않는다

`verify_halt_pc.py`의 단일 검증 및 반복 샘플링 경로는 다음 반환값을 무시한다.

- `jl.halt()`
- `jl.restart()`
- resume 이후 `jl.halted()` 상태

설치된 pylink 2.0.0 기준 `halt()`와 `restart()`는 실패 또는 no-op 상황에서 예외 대신 `False`를
반환할 수 있다. 현재 코드는 `halted=False`여도 `✅ halt 성공`을 출력할 수 있고, resume 후에도
코어가 계속 halt 상태인지 강제 검사하지 않는다.

영향:

- 실행 중인 코어에서 일반 레지스터를 PC라고 읽어 거짓 성공 가능
- resume 실패를 성공으로 기록 가능
- 코어가 halt 상태로 남은 채 다음 샘플 또는 NVMe 작업 진행 가능
- README의 G2/G4 판정과 실제 코드 동작 불일치

`sfe76_link.Link.resume()`도 `restart()`가 예외 없이 반환하기만 하면 반환값이 `False`여도 성공으로
판정한다. README에 적힌 "resume 실패 시 중단 및 POR" 정책이 코드에 구현되지 않았다.

필수 형태:

```python
if not jl.halt():
    raise RuntimeError("halt command failed")
if not wait_until(jl.halted, expected=True, timeout=...):
    raise RuntimeError("CPU did not enter halted state")

pc = jl.register_read(confirmed_pc_index)

if not jl.restart():
    raise RuntimeError("resume command failed")
if not wait_until(jl.halted, expected=False, timeout=...):
    raise RuntimeError("CPU remained halted")
```

resume 검증에 실패하면 다음 실험을 막고, 호출자에게 POR 필요 상태를 반환해야 한다.

#### 2. hart 열거가 "한 handle = 한 설정" 원칙을 위반한다

`verify_halt_pc.py --enum-harts`는 한 J-Link handle 안에서 hart 0~4 설정을 바꾸면서 반복해서
`connect()`한다. 이는 README와 BRINGUP에서 금지한 설정 혼합과 동일하다.

두 번째 hart부터는 다음을 구분할 수 없다.

- 새 `RISCV_SetHartSel`이 실제 반영된 성공
- 이전 연결 상태를 재사용한 거짓 성공
- 앞 hart의 failed connect가 뒤 hart를 예열한 순서 효과

이 결과로 hart 귀속을 판단하면 안 된다. hart별로 완전히 격리된 세션을 사용하되, 각 hart 후보
내부에서는 동일 handle로 동일 설정의 bounded retry만 허용해야 한다.

#### 3. `diagnose_connect.py`의 D/E/F 실험은 현재 구조로 원인을 분리하지 못한다

각 실험은 Python `JLink` 객체와 handle만 새로 만들고 같은 target과 probe를 계속 사용한다.

- D 성공만으로 상태가 target에 남았다고 결론 낼 수 없다. 동일 프로세스의 DLL 전역 상태나 probe
  firmware 상태가 유지될 수 있고, close 자체가 target 상태를 변경할 수도 있다.
- E는 앞 device 후보의 failed connect가 target을 예열해 뒤 device 후보를 성공시킬 수 있다.
- F도 앞 hart 시도가 뒤 hart 후보 결과에 영향을 줄 수 있다.
- 후보 순서가 고정돼 후보 효과와 실행 순서 효과가 교락된다.

따라서 현재 출력의 다음 판정은 증거보다 강하다.

- "상태가 타깃에 남는다"
- "장치명이 원인이었다"
- "특정 hart가 원인이었다"

후보별 별도 프로세스, 동일한 초기 target 상태, 필요 시 POR 또는 명시적 DM reset, 후보 순서
역전/무작위화가 필요하다.

#### 4. JLinkScript의 설정 상수가 실제 명령에 반영되지 않는다

`SF_E76_config.JLinkScript`는 `_CORE_BASE`만 수정하면 된다고 안내하지만 실제
`CORESIGHT_SetCoreBaseAddr` command string에는 `0x81480000`이 하드코딩돼 있다.

`_APB_INDEX`도 선언만 되고 실제 command string에서 사용되지 않는다. 따라서 상단 상수를
`0x81481000`으로 변경해도 실제 연결 대상은 바뀌지 않는다.

상수를 제거하고 실제 command string을 직접 설정하게 하거나, JLinkScript가 지원하는 방식으로
상수 값을 명령 생성에 확실히 반영해야 한다. 현재처럼 "여기만 바꾸면 된다"는 안내는 위험하다.

#### 5. 검증 실패가 프로세스 종료 코드에 반영되지 않는다

`verify_halt_pc.py`는 connect/halt/read/resume 예외를 출력만 하고 정상 종료한다.
`--enum-harts`도 일부 또는 전체 hart가 실패해도 성공 exit code로 끝난다.

자동화, CI, sampler bring-up 스크립트는 실패한 실험을 성공으로 인식할 수 있다. 최소한 다음을
서로 다른 non-zero exit code로 구분하는 것이 좋다.

- connect 실패
- halt 상태 진입 실패
- PC register 미확정/read 실패
- resume/running 복구 실패
- 결과 불충분

### 10.2 Potential bugs

#### 1. 연결 지식의 단일 출처가 아직 구현되지 않았다

README는 `sfe76_link.py`를 정식 연결 모듈이자 단일 출처로 선언하지만 `verify_halt_pc.py`와
`diagnose_connect.py`는 다음을 각각 복사해 갖고 있다.

- TIF/speed/CJTAG mode
- AP map/CoreBase
- setting 적용
- connect retry
- resume/close

그 결과 `verify_halt_pc.py`의 module docstring에는 이미 다음 오래된 설명이 남았다.

- backup으로 이동한 `connect_sfe76.py`가 현재 연결 코드라고 안내
- 첫 connect 실패를 범위 제한 없이 "구조적"이라고 표현
- halt/PC가 미검증인데 "두 DM 모두 접근 가능"이라고 표현

실험 스크립트도 `Link`를 사용하게 하고, 실험별 차이만 명시적으로 주입해야 한다.

#### 2. PC register를 못 찾으면 무조건 index 32로 진행한다

`find_pc_register()`가 PC/DPC 이름을 확정하지 못해도 코드가 index 32를 선택해 계속 샘플링한다.
index 32가 실제 PC가 아니면 일반 register 값을 PC로 기록하고 G3를 거짓 통과할 수 있다.

또한 `FW_LO=0`, `FW_HI=0xFFFFFFFF`는 실질적인 주소 검증이 아니며 현재 sampling 경로에서
사용되지 않는다.

PC register는 다음 중 하나가 충족될 때만 사용해야 한다.

- J-Link register name이 `PC`/`DPC`로 확인됨
- T32 또는 벤더 자료로 index를 교차 검증함
- 사용자가 명시한 `--pc-index`가 독립적인 PC fingerprint 실험을 통과함

E76은 32-bit core이므로 `& 0xFFFFFFFF` 자체는 현재 문제로 보지 않는다. 문제는 register의
정체와 주소 유효성 검증이다.

#### 3. cleanup 실패가 호출자에게 전달되지 않는다

`Link.close()`는 resume과 close 예외를 대부분 무시한다. 컨텍스트 종료 후 호출자는 코어가
정상 running 상태인지 알 수 없다.

`resume_failed`, `recovery_required` 같은 상태를 보존하거나, 정상 종료 중 cleanup 실패를 별도
예외로 전달해야 한다. 원래 예외가 있는 경우에는 cleanup 실패 정보를 잃지 않도록 함께 기록한다.

#### 4. J-Link probe를 명시적으로 선택하지 않는다

모든 스크립트가 인자 없이 `jl.open()`을 호출한다. 여러 probe가 연결된 환경에서는 다른 보드를
잡을 수 있다. `--serial` 옵션을 제공하고 실제 serial을 결과 레코드의 필수 필드로 남겨야 한다.

#### 5. connect retry마다 전체 AP map을 다시 등록한다

분리 실험 A는 setup 1회 후 connect 2회로 failed connect 자체의 효과를 확인했다. 그런데 정식
`Link.connect()`는 매 retry마다 AP map과 CoreBase를 다시 적용한다.

현재 실측상 동작할 수는 있지만, 동일 Index에 대한 `CORESIGHT_AddAP` 반복 등록이 DLL 버전에 따라
덮어쓰기, 중복 또는 오류로 바뀔 수 있다. `apply_settings()` 1회 후 동일 설정의 `connect()`만
bounded retry하는 형태가 분리 실험과도 정확히 일치한다.

#### 6. 문서에 남은 충돌

- README 제목은 "원칙 3개"지만 실제 항목은 4개다.
- BRINGUP은 다른 AP/선택 메커니즘을 배제하지 말라고 한 직후 "다른 AP를 뒤질 이유 없음"이라고 한다.
- BRINGUP에 backup으로 이동한 `connect_sfe76.py` 실행 안내가 남아 있다.
- README는 G1을 부분 통과로 표시하지만 BRINGUP 아키텍처 표는 connect를 완료 처리한다.
- Ncore가 단일 hart라는 것은 아직 추정인데 현재 실행 순서의 확정 근거처럼 표현한다.
- JLinkScript는 `InitTarget()` 전원 ACK가 실패했다는 BRINGUP 결과와 달리 전원 인가를 "진짜 병목"으로
  서술한다.
- `sfe76_link.py` module docstring은 `safe_resume()`을 호출하라고 하지만 실제 공개 메서드는
  `resume()`이다.
- `sfe76_link.py`의 안전 원칙 번호가 `1, 2, 4, 3` 순서다.

### 10.3 Reliability improvements

#### 1. checked state transition API를 공통 모듈에 둔다

권장 public API:

```text
Link.connect_checked()
Link.halt_checked(timeout_s)
Link.read_pc(confirmed_register)
Link.resume_checked(timeout_s)
Link.close(recovery_policy=...)
```

실험 스크립트는 `jl`의 raw halt/restart를 직접 호출하지 않고 이 API만 사용한다.

#### 2. 연결 및 결과 메타데이터를 구조화한다

각 실행에서 최소 다음을 JSON/JSONL로 남긴다.

- monotonic/wall-clock timestamp
- target power-cycle ID
- J-Link serial/product/firmware/DLL version
- device, TIF, speed, AP map, APB index, CoreBase, hart
- connect 시도별 error와 소요 시간
- halt/read/resume 반환값과 사후 상태
- PC register name/index/value
- NVMe 생존 확인 결과

#### 3. 결과 상태와 복구 상태를 분리한다

예를 들어 PC read 성공 후 resume 실패는 실험 데이터가 일부 존재해도 전체 실행은 실패다.

```text
measurement_status = pc_read_ok
target_recovery_status = failed
overall_status = failed_recovery_required
```

복구 실패가 다음 실험에 묻히지 않게 해야 한다.

#### 4. 문서의 확정 수준을 코드와 동일하게 유지한다

현재 정확한 표현:

> 두 CoreBase는 현 설정에서 J-Link connect 후보로 통과했다. 실제 DM/hart/core 귀속 및 안전한
> halt/PC/resume은 미검증이다.

G2~G4가 통과하기 전에는 "DM 접근 가능", "코어 연결 완료", "sampler 동작"으로 승격하지 않는다.

### 10.4 Suggested tests

#### P0 — 하드웨어 실행 전 mock 테스트

mock J-Link로 다음 경우를 강제한다.

1. `halt()`가 `False` 반환
2. halt 명령 후 `halted()`가 계속 `False`
3. `restart()`가 `False` 반환
4. restart 후 `halted()`가 계속 `True`
5. PC read 중 예외
6. resume 중 예외
7. connect 1회 실패 후 2회 성공
8. connect 3회 전부 실패

각 경우에 다음을 검사한다.

- 성공 메시지가 잘못 출력되지 않음
- 다음 샘플이 실행되지 않음
- cleanup이 항상 시도됨
- recovery 필요 상태가 보존됨
- 실패 exit code가 반환됨

#### P1 — 단일 Ncore 안전 검증

코드 수정 후에만 수행한다.

1. `0x81481000` 한 설정만 사용
2. 동일 handle, setup 1회, bounded connect retry
3. `halt()` 반환값과 `halted()==True` 확인
4. 이름 또는 외부 근거로 PC register 확정
5. PC read 및 정렬/코드 범위 검사
6. `restart()` 반환값과 `halted()==False` 확인
7. NVMe workload가 계속 진행되는지 확인

한 단계라도 실패하면 hart 열거와 sampler 통합으로 넘어가지 않는다.

#### P2 — D/E/F 재설계

- 후보별 별도 프로세스 사용
- target 초기상태를 동일하게 통제
- 필요 시 후보마다 POR 또는 명시적 debug-domain/DM reset
- 후보 순서 정방향/역방향 또는 무작위화
- 각 조건 최소 3회 반복
- J-Link serial/DLL/firmware와 power-cycle ID 기록

D에서 target/DLL/probe 상태를 분리하려면 다음 대조가 필요하다.

```text
같은 프로세스 + 새 handle
새 프로세스 + 같은 probe/target
probe USB reconnect + target 유지
target POR + probe 유지
```

#### P3 — 코어 귀속 및 내구성

P1 통과 후 순서:

1. 격리된 hart별 PC fingerprint
2. `0x81480000`과 `0x81481000` 비교
3. T32 PC와 교차 검증
4. workload 상관관계 확인
5. halt/read/resume 1,000회
6. close/reopen 반복
7. POR/crash recovery 반복
8. NVMe I/O 동시 수행 시 timeout/hang 영향 측정

### 10.5 최종 판단

현재 가장 먼저 수정할 세 항목:

1. **halt/resume 반환값과 사후 상태를 강제 검증한다.**
2. **hart/device 진단을 독립 세션과 통제된 target 상태로 격리한다.**
3. **JLinkScript의 `_CORE_BASE`/`_APB_INDEX` 하드코딩 불일치를 없앤다.**

이 세 가지가 해결되기 전 `verify_halt_pc.py`의 성공 출력은 G2~G4의 증거로 사용하면 안 된다.

---

## 11. 2026-08-07 추가 검토 — T32 커버리지는 확인됐고 halt 방식은 아님

### 11.1 새로 확인된 전제

사용자가 다음 사실을 확인했다.

- 기존 ARM 제품에서 사용하던 T32 커버리지 스크립트를 RISC-V 제품용으로 수정했다.
- 그 스크립트로 이 RISC-V 제품의 코드 커버리지가 실제로 측정되는 것을 확인했다.
- 해당 방식은 반복적인 `halt → PC read → resume` 방식이 아니다.
- 다만 현재 저장소에는 실제 T32 PRACTICE/CMM 스크립트가 없고, 정확한 수집 방식도 아직 식별되지 않았다.

이 사실은 feasibility 판단을 크게 바꾼다. 타깃이 코드 실행 정보를 외부로 제공할 수 있다는
점과, T32가 그 경로를 실제로 초기화할 수 있다는 점은 이미 입증됐다. 이제 핵심 질문은
"J-Link로 halt가 되는가"가 아니라 다음이다.

> T32가 어느 하드웨어/펌웨어 메커니즘으로 커버리지를 얻고 있으며, 그 메커니즘을 현재
> J-Link 하드웨어와 SEGGER 소프트웨어가 지원하는가?

### 11.2 현재 STATUS의 방향은 수정해야 한다

현재 `STATUS.md`는 아래 흐름을 크리티컬 패스로 둔다.

```text
connect → halt → PC read → resume → 반복 PC sampling
```

이 흐름은 기존 `JLinkHaltSampler`를 가장 적은 코드 변경으로 재사용하는 대안으로는 유효하다.
그러나 T32에서 확인된 실제 커버리지 방식이 halt가 아니라는 사실을 반영하면, 이것을 유일한
주 경로 또는 v10.0 착수 조건으로 두는 것은 맞지 않다.

특히 다음 표현은 현 상태와 맞지 않는다.

- `v10.0 샘플러 착수 조건 = G4(halt/PC/resume)`
- `find_haltable.py`가 지금 할 일
- Nexus trace는 크리티컬 패스가 아닌 병행 트랙
- `halt()` 실패가 곧 코드 커버리지 경로의 실패

`halt()` 실패는 **J-Link CPU run-control 연결이 완성되지 않았다는 증거**다. 그러나 T32
커버리지가 trace나 instrumentation 기반이라면, halt 기반 PC sampling의 실패와 전체
커버리지 feasibility는 동일한 문제가 아니다.

따라서 당분간 `find_haltable.py`의 CoreBase × hart × APB 전체 스윕은 보류한다. 정확한 T32
방식을 모른 채 halt 후보를 넓히는 것은 T32에서 성공한 경로를 재현하는 작업이 아니다.

### 11.3 먼저 구분해야 할 커버리지 방식

T32 스크립트와 실행 로그에서 아래 중 어느 방식인지 판별한다.

| T32 방식 | 확인할 흔적 | SEGGER 쪽 후보 | 현재 판단 |
|---|---|---|---|
| 펌웨어 instrumentation bitmap | 계측 빌드, RAM bitmap/counter, 메모리 dump/read | J-Link 메모리 주기 읽기 | **가능성 높음.** CPU halt가 불필요할 수 있음 |
| 온칩 Nexus/N-Trace SRAM buffer | Nexus/Trace Encoder, SRAM sink, trace buffer 설정 | `RISCV_SetTEBaseAddr`, `RISCV_SetSRAMBaseAddr`, trace source 설정 | **가능성 있음.** 정확한 TE/sink/AP 주소 필요 |
| ATB를 통한 온칩 trace sink | Nexus/N-Trace, ATB/funnel 설정 | `RISCV_UseNexusViaATB`, `RISCV_SetATBBaseAddr`, `RISCV_SetTFBaseAddr` | **가능성 있음.** SoC trace 토폴로지 필요 |
| 외부 핀 streaming trace | TRACE32 trace probe/포트, PIB, 연속 program flow | **J-Trace PRO RISC-V** + trace 핀 | 일반 J-Link만으로는 불가 |
| 디버거 내부의 다른 sampling/profiling | 주기적 샘플, snooper/profiler 명령 | 동일 기능 또는 별도 SDK 구현 | 스크립트 확인 전 판단 불가 |

SEGGER 문서는 streaming trace 기반 code coverage에 **J-Trace PRO가 필요하고 일반 J-Link
모델에서는 지원하지 않는다**고 명시한다. 따라서 "J-Link로 한다"가 일반 J-Link probe를
뜻하는지, J-Link 소프트웨어/DLL 생태계와 J-Trace 하드웨어까지 포함하는지 구분해야 한다.

공식 근거:

- SEGGER J-Link/J-Trace User Guide — streaming trace code coverage에는 J-Trace PRO 필요:
  https://kb.segger.com/UM08001_J-Link_/_J-Trace_User_Guide
- J-Trace PRO RISC-V — RISC-V live code coverage와 SiFive E-series trace 지원:
  https://www.segger.com/products/debug-probes/j-trace/models/j-trace-pro-risc-v/
- SEGGER command strings — RISC-V TE, SRAM/ATB/PIB/funnel sink 설정 명령:
  https://kb.segger.com/J-Link_command_strings
- Lauterbach — SiFive RISC-V Nexus program/data trace 지원:
  https://repo.lauterbach.com/news_514.html

`RISCV_SetTEBaseAddr` 명령이 존재한다는 사실만으로 현재 J-Link probe에서 코드 커버리지가
된다고 결론 내리면 안 된다. trace encoder뿐 아니라 sink 종류, trace 데이터 회수 경로,
probe 모델, 핀 배선, 디코더 지원이 모두 맞아야 한다.

### 11.4 새 크리티컬 패스

#### P0 — 실제 T32 스크립트와 측정 증거 확보

다음 파일과 정보를 `risc-v/` 아래에 보존한다.

1. 실제 실행한 `.cmm`/PRACTICE 스크립트 전체와 `DO`/include 체인
2. 실행한 T32 제품 및 trace probe 모델
3. 커버리지 시작·정지·저장에 사용한 명령 로그
4. T32 trace/coverage 설정 창의 설정값 또는 텍스트 export
5. coverage 결과 예시와 대상 ELF/심볼/빌드 정보
6. 타깃 펌웨어가 coverage instrumentation 빌드인지 일반 빌드인지
7. 디버그 커넥터 외 별도 trace 케이블/포트를 사용했는지
8. T32가 읽는 trace buffer 또는 bitmap의 주소

이 파일이 없으면 현재 문서의 AP/COREDEBUG/Data.Set 일부만으로 수집 방식을 복원할 수 없다.

#### P1 — T32 스크립트에서 두 계층을 분리

스크립트를 다음 두 덩어리로 나눠 분석한다.

```text
[A] debug/control 연결
    cJTAG activation, DP/AP, reset, unlock, DM/hart/core selection

[B] coverage data path
    instrumentation memory 또는 trace encoder → funnel/sink → probe/host
```

현재 작업은 [A]의 일부를 J-Link로 옮기면서 halt를 합격 기준으로 삼았다. 새 목표에서는
[B]를 먼저 식별해야 하며, [B]가 요구하는 만큼만 [A]를 구현한다. 예를 들어 RAM bitmap을
AP 메모리 접근으로 읽는 방식이면 CPU halt와 RISC-V register access가 필수 조건이 아닐 수 있다.

#### P2 — 메커니즘별 최소 증명

instrumentation 방식이면:

1. J-Link로 bitmap 주소를 read-only로 읽는다.
2. 서로 다른 두 workload에서 bitmap 변화가 달라지는지 확인한다.
3. T32 결과와 동일 빌드·동일 workload로 교차 검증한다.

온칩 trace buffer 방식이면:

1. T32에서 TE와 sink base, AP 경로, buffer 범위를 추출한다.
2. 최신 J-Link/J-Trace에서 해당 SiFive trace 규격 지원 여부를 확인한다.
3. 짧은 workload 한 번의 raw trace를 회수하고 T32 결과와 비교한다.

외부 streaming trace 방식이면:

1. 현재 probe가 일반 J-Link인지 J-Trace PRO RISC-V인지 확인한다.
2. 보드에 필요한 PIB/trace 핀이 실제로 노출·배선됐는지 확인한다.
3. 일반 J-Link라면 소프트웨어 작업을 계속하기 전에 하드웨어 요구사항부터 결정한다.

#### P3 — J-Link CPU connect/halt는 보조 트랙으로 축소

`sfe76_link.py`, `diagnose_connect.py`, `verify_halt_pc.py`, `find_haltable.py`는 버리지 않는다.
이 도구들은 다음 용도로 남긴다.

- J-Link run-control 지원 여부 진단
- trace 설정에 필요한 core/DM 연결 확인
- trace 실패 시 사용할 통계적 PC sampling 대안 검토
- SEGGER 문의용 재현 로그 생성

그러나 T32 커버리지 메커니즘이 확인되기 전에는 halt 성공을 v10.0의 단일 착수 조건으로
사용하지 않는다.

### 11.5 STATUS.md에 반영해야 할 새 게이트

권장 게이트는 다음과 같다.

| 게이트 | 조건 | 현재 상태 |
|---|---|---|
| C0 | T32에서 RISC-V coverage 측정 재현 | ✅ 사용자 확인 |
| C1 | T32 coverage 메커니즘 식별 | ❌ 스크립트/로그 미확보 |
| C2 | coverage 데이터 경로와 필요한 하드웨어 식별 | ❌ |
| C3 | 현재 J-Link 또는 필요한 J-Trace의 지원 가능성 확인 | ❌ |
| C4 | J-Link 계열로 raw coverage/trace/bitmap 1회 회수 | ❌ |
| C5 | T32 결과와 동일 workload 교차 검증 | ❌ |
| C6 | 퍼저 반복 수집·복구·성능 검증 | ❌ |

기존 G0~G6 run-control 게이트는 삭제할 필요는 없지만 `halt-PC sampling 대안 트랙`으로
이름을 바꾸는 것이 맞다.

### 11.6 최종 판단

T32에서 실제 코드 커버리지가 된다는 사실 때문에 **제품 자체의 coverage feasibility는 이미
상당 부분 입증됐다.** J-Link 계열로 옮길 가능성도 이전보다 높게 평가할 수 있다.

다만 현재는 T32가 무슨 방식으로 데이터를 얻는지 모르므로, 일반 J-Link만으로 가능한지까지는
판단할 수 없다.

- instrumentation 또는 온칩 SRAM trace sink라면 현재 J-Link로 구현할 가능성이 있다.
- 외부 streaming Nexus trace라면 일반 J-Link가 아니라 J-Trace PRO RISC-V가 필요할 가능성이 높다.
- 타깃 전용 trace 초기화나 multiple-DM 선택을 SEGGER가 지원하지 않으면 벤더/SEGGER의 device
  support 또는 전용 JLinkScript가 필요하다.

따라서 지금 가장 중요한 작업은 halt/APB/hart 스윕이 아니라 **성공한 T32 커버리지 스크립트를
확보하여 coverage 데이터 경로를 식별하는 것**이다. 그 결과가 나온 뒤 J-Link halt sampling,
J-Link 메모리 bitmap 읽기, J-Trace Nexus 중 하나를 주 경로로 선택한다.

---

## 12. 2026-08-07 수정된 STATUS.md 리뷰

### 12.1 Critical issues

#### 1. 새 주 트랙과 게이트 전환은 맞다

수정된 `STATUS.md`는 다음 핵심을 올바르게 반영했다.

- T32에서 RISC-V coverage가 된다는 사실을 C0로 분리했다.
- halt 실패와 제품의 coverage feasibility 실패를 분리했다.
- halt/APB/hart 확대 스윕을 보류했다.
- run-control G0~G6를 주 트랙이 아닌 보조 트랙으로 내렸다.
- 실제 T32 스크립트와 coverage 데이터 경로 식별을 C1/P0로 올렸다.

이 방향은 이전 STATUS보다 정확하다. 지금의 프로젝트 병목은 `halt()`가 아니라 **T32에서
성공한 coverage data path를 식별하지 못한 것**이다.

#### 2. “1·2는 둘 다 J-Link로 가능”은 아직 확정할 수 없다

`STATUS.md` 84행의 다음 문장은 과하다.

> instrumentation 메모리 읽기와 온칩 버퍼 드레인은 둘 다 J-Link로 가능하다.

다음처럼 낮춰 써야 한다.

> instrumentation 메모리 읽기와 온칩 버퍼 드레인은 **일반 J-Link로 검토할 수 있는
> 후보**다. 실제 가능 여부는 메모리 접근 경로, connect 시 halt 동작, trace sink 지원,
> raw trace 회수·디코딩 API를 확인해야 한다.

instrumentation bitmap도 자동으로 가능한 것이 아니다.

- bitmap이 어느 버스/AP에서 보이는지
- 실행 중 non-intrusive memory read가 가능한지
- J-Link `connect()`가 먼저 CPU halt를 요구하는지
- cache/coherency 때문에 외부 read 값이 최신인지
- bitmap 업데이트가 atomic한지

를 확인해야 한다.

온칩 SRAM trace buffer는 더 불확실하다. `RISCV_SetTEBaseAddr`와
`RISCV_SetSRAMBaseAddr` 명령의 존재는 구성 가능성을 보여줄 뿐, 현재 J-Link Plus가 이 SoC의
trace를 회수하고 program flow로 디코딩하여 coverage로 제공한다는 증거는 아니다.

#### 3. “connect 성공은 halt 없이는 의미 없다”는 새 주 트랙과 충돌한다

`STATUS.md` 158행의 금지 문구는 halt sampler 관점에서는 맞았지만, 새 coverage 주 트랙에서는
너무 좁다.

instrumentation bitmap 또는 trace buffer 방식이라면 CPU halt가 최종 조건이 아닐 수 있다.
따라서 다음처럼 바꾸는 편이 정확하다.

> `connect()` 무예외 종료만으로 run-control 또는 coverage data path 성공을 주장하지 않는다.
> 각 트랙의 실제 산출물(halted state, bitmap 변화, raw trace)을 확인한다.

즉 합격 기준은 모든 경로에서 halt가 아니라 **선택한 경로의 관측 가능한 산출물**이어야 한다.

#### 4. “모든 조합에서 POR 후 halt 실패”의 시험 범위를 명시해야 한다

보조 게이트 G2의 “전 조합 실패(POR 후에도)”는 아래 범위를 기록하지 않으면 나중에 APB
스윕까지 완료한 것으로 오해할 수 있다.

- 시험한 CoreBase 목록
- hart 목록과 `None` 포함 여부
- APB index
- 각 조합의 POR 여부와 power-cycle ID
- J-Link DLL/firmware/device profile

기존 시험이 APB index 0 고정이었다면 반드시 **“APB=0에서 시험한 CoreBase × hart 조합”**으로
한정해서 써야 한다.

### 12.2 Potential bugs

#### 1. C0의 증거 수준을 한 단계 더 구분할 필요가 있다

현재 C0는 “사용자 확인”으로 ✅ 처리했다. 프로젝트 방향을 정하기에는 충분하지만,
재현 가능한 기술 증거가 저장소에 없는 상태다. 다음 두 상태를 분리하면 좋다.

```text
C0a  T32 coverage 동작 확인                 ✅ 사용자 확인
C0b  동일 실행을 재현할 스크립트·로그 보존   ❌ P0
```

스크립트가 확보되기 전까지 “재현 완료”보다는 “동작 확인, artifact 미보존”이 정확하다.

#### 2. 10핀 커넥터만으로 T32의 trace 경로를 배제하면 안 된다

`STATUS.md`는 현재 10핀 디버그 커넥터에서 병렬 trace 핀이 나올 수 없다는 점을 잘 짚었다.
다만 이것은 **현재 확인한 커넥터**에 대한 결론이다. T32 측정 때 다음이 있었을 수 있다.

- 별도 MIPI/MICTOR/벤더 trace connector
- 보드 test point 또는 interposer
- ATB를 거친 온칩 sink
- 계측 펌웨어와 RAM bitmap

문서가 이미 “별도 트레이스 커넥터” 가능성을 남겼으므로, 실제 T32 장비 사진·케이블·probe
모델 확보 전에는 외부 trace를 낮은 가능성으로만 두고 폐기하지 않는 것이 맞다.

#### 3. J-Link 최신판이 문제를 “통째로 해결”할 가능성은 낮춰 표현해야 한다

SiFive E76 device profile이 존재해도 이 SSD SoC의 DAP/AP/DM/trace topology가 표준 E76
보드와 같다는 뜻은 아니다. 최신판 비교는 해야 하지만 목적은 다음으로 한정한다.

- RISC-V-behind-DAP와 N-Trace 관련 수정 확인
- 더 상세한 오류 로그 확보
- 현재 결과가 구버전 회귀인지 비교

새 버전 설치만으로 벤더 SoC의 AP/DM/trace 설정이 자동으로 생긴다고 기대하면 안 된다.

#### 4. README와 BRINGUP이 STATUS와 아직 충돌한다

`STATUS.md`는 방향 전환됐지만 다른 진입 문서에 옛 크리티컬 패스가 남아 있다.

- `README.md` 열린 질문에 `halt/PC/resume = v10.0 착수 조건`이 남아 있음
- `README.md`는 Nexus를 여전히 “크리티컬 패스에 두지 말 것”이라고 함
- `BRINGUP_riscv_v10.md`는 `verify_halt_pc.py`를 현재 단계로 표시함
- BRINGUP은 “0단계만 되면 퍼저가 돈다”며 halt sampler를 기본 결론으로 유지함

작업자가 STATUS가 아니라 README부터 읽으면 다시 halt 트랙으로 돌아갈 수 있다. STATUS의 새
결론을 README 첫 부분과 BRINGUP 최종 로드맵에 동기화해야 한다. 과거 조사 기록은 삭제하지
말고 “이전 가정/보조 트랙”으로 표시한다.

### 12.3 Reliability improvements

#### 1. T32 artifact 수집 시 원본을 먼저 보존한다

스크립트를 정리하거나 RISC-V 관련 줄만 복사하기 전에 다음을 원본 그대로 저장한다.

- 실행 entry `.cmm`
- 모든 `DO`, include, macro 파일
- 호출한 batch/launcher와 인자
- T32 버전, 라이선스, probe 모델과 serial
- 일반 debug cable 외 연결된 모든 cable
- target build ID, ELF hash, firmware image hash
- coverage 시작 전부터 export까지의 console log

T32 스크립트는 인자와 include에서 실제 주소·코어·trace 설정을 주입할 수 있으므로 한 파일만
보면 잘못된 결론을 낼 수 있다.

#### 2. C1 판별용 키워드를 정해 기계적으로 검색한다

원본 확보 후 최소한 다음 계열을 전체 include chain에서 검색한다.

```text
COVerage / Trace / NEXUS / N-Trace / Analyzer
SRAM / ATB / Funnel / PIB / Buffer
Data.Save / Data.dump / memory read / bitmap / counter
instrument / compiler option / coverage runtime
```

명령 이름만 보지 말고 커버리지 시작 전후의 메모리 쓰기와 export 파일 생성 경로까지 추적한다.

#### 3. “J-Link”의 범위를 장비명까지 고정한다

앞으로 결과에 최소한 다음을 명시한다.

```text
probe_model = J-Link Plus | J-Trace PRO RISC-V | TRACE32 probe model
host_software = J-Link Software Pack version | TRACE32 version
collection_mode = memory_bitmap | onchip_trace_buffer | streaming_trace | halt_pc
```

“J-Link 지원”이라는 표현은 J-Link Plus, J-Trace, J-Link SDK를 섞어 읽기 쉽다.

#### 4. 새 STATUS의 P3 병행 실험은 시간 상한을 둔다

P0 artifact를 기다리며 Commander와 최신 DLL을 확인하는 것은 좋다. 다만 halt 진단이 다시
주 작업이 되지 않도록 다음처럼 제한한다.

- Commander 원문 로그 1세트 확보
- 현재판/최신판 각 동일 조건 1세트 비교
- 그 뒤에는 T32 C1 분석 전 추가 CoreBase/hart/APB 확장 금지

### 12.4 Suggested tests

#### P0 — 코드 실행 없이 답할 수 있는 질문

T32를 실제로 사용한 사람에게 먼저 다음 다섯 가지만 확인한다.

1. coverage 측정 때 일반 debug cable 외에 다른 cable이 있었는가?
2. 사용한 Lauterbach probe의 정확한 모델은 무엇인가?
3. 대상 펌웨어가 일반 양산 이미지인가, coverage용 재빌드 이미지인가?
4. T32에서 coverage 시작할 때 누른 메뉴 또는 실행한 명령은 무엇인가?
5. 측정 종료 후 생성된 파일의 확장자와 이름은 무엇인가?

이 다섯 답만으로 instrumentation, on-chip buffer, external streaming 후보를 상당 부분
분리할 수 있다.

#### P1 — instrumentation 후보 최소 실험

1. T32로 workload 전/후 bitmap 후보 메모리를 저장한다.
2. 서로 다른 NVMe 명령 두 개가 서로 다른 bit/counter를 바꾸는지 확인한다.
3. T32 종료 후 J-Link의 AP memory read로 같은 주소를 읽는다.
4. CPU를 halt하지 않은 상태와 cache flush 조건을 나눠 비교한다.

#### P2 — trace 후보 최소 실험

1. T32 설정에서 TE, funnel, sink와 buffer base/size를 추출한다.
2. trace sink가 SRAM, ATB, PIB 중 무엇인지 확정한다.
3. raw trace 파일이 생성되는지와 포맷을 확인한다.
4. J-Link Plus가 아니라 J-Trace가 필요한 기능인지 SEGGER에 주소·sink 정보와 함께 문의한다.

#### P3 — 문서 일관성 검사

STATUS 반영 후 다음 문자열을 저장소 전체에서 검색한다.

```text
v10.0 착수 조건
지금 할 일
크리티컬 패스
Nexus.*병행
halt.*필수
```

모든 문장이 `coverage 주 트랙`과 `halt-PC sampling 보조 트랙`을 혼동하지 않는지 확인한다.

### 12.5 최종 판단

수정된 STATUS의 **방향 전환은 맞고, 현재 프로젝트의 대표 문서로 사용할 수 있는 수준에
가까워졌다.** 다만 다음 네 항목은 바로 고쳐야 한다.

1. “instrumentation/온칩 buffer는 J-Link로 가능”을 **가능 후보**로 낮춘다.
2. “connect 성공은 halt 없이는 의미 없다”를 **트랙별 실제 산출물 확인**으로 바꾼다.
3. G2의 “전 조합” 시험 범위를 APB index까지 명시한다.
4. README와 BRINGUP의 옛 halt 크리티컬 패스를 새 STATUS에 맞춘다.

그 뒤의 실제 P0는 변함없다. **성공한 T32 coverage의 원본 스크립트·include chain·probe와
cable 정보·측정 로그를 확보하는 것**이다.
