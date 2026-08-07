# SF-E76 RISC-V 브링업 방향 검토 피드백

> 작성일: 2026-08-07  
> 대상: `PC_Sampling/risc-v/` 브링업 작업  
> 목적: 현재 접근 방향이 맞는지 검토하고, 다음 작업자가 바로 이어서 판단할 수 있도록
> 실측 사실과 권장 순서를 분리해 기록한다.

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
