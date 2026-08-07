# SF-E76 브링업 — 현재 상태와 다음 할 일

> 2026-08-07 기준. **한 장짜리 요약.** 근거·이력은 `BRINGUP_riscv_v10.md`,
> 실행법은 `README.md`, 외부 검토는 `feedback.md`.

---

## ★ 방향 전환 (feedback §11)

**T32 로 이 제품의 코드 커버리지가 실제로 측정된다. 그리고 그 방식은
`halt → PC read → resume` 이 아니다.**

이 사실이 판을 바꾼다. 지금까지 나는 ARM 제품(PM9M1/P7/P9)에서 쓰던 halt
샘플러를 이식하는 것을 전제로 깔고 있었다. 그래서 `halt()` 실패를 크리티컬
블로커로 취급했는데, **halt 실패는 J-Link run-control 연결이 미완성이라는
증거일 뿐 커버리지 실현 가능성의 실패가 아니다.**

> **지금 가장 중요한 질문:**
> T32 는 **어떤 메커니즘**으로 커버리지를 얻고 있으며,
> 그 메커니즘을 **현재 J-Link 하드웨어와 SEGGER 소프트웨어가 지원하는가?**

**→ halt / APB / hart 스윕은 보류한다.** T32 방식을 모른 채 halt 후보를 넓히는 건
성공한 경로를 재현하는 작업이 아니다.

---

## 커버리지 게이트 (주 트랙)

| | 조건 | 상태 |
|---|---|---|
| **C0a** | T32 에서 RISC-V 커버리지 **동작 확인** | ✅ 사용자 확인 |
| **C0b** | 동일 실행을 **재현할 스크립트·로그 보존** | ❌ ← P0 |
| **C1** | T32 커버리지 **메커니즘 식별** | ❌ ← **지금 할 일** |
| **C2** | 데이터 경로와 필요한 하드웨어 식별 | ❌ |
| **C3** | 현재 J-Link(또는 필요한 J-Trace)의 지원 가능성 | ❌ |
| **C4** | J-Link 계열로 raw coverage/trace/bitmap **1회 회수** | ❌ |
| **C5** | 동일 workload 로 T32 결과와 교차 검증 | ❌ |
| **C6** | 퍼저 반복 수집·복구·성능 검증 | ❌ |

**C0a 가 ✅ 라는 게 중요하다.** 타깃이 코드 실행 정보를 외부로 낼 수 있다는 것과
T32 가 그 경로를 초기화할 수 있다는 것이 **이미 입증됐다.**

## run-control 게이트 (보조 트랙 — halt PC sampling 대안)

| | 조건 | 상태 |
|---|---|---|
| G0 | cJTAG / DP / 디버그 전원 ACK | ✅ |
| G1 | J-Link `connect()` | ⚠️ 2회차에만, 의미 불확실 |
| G2 | halt + `halted` 확인 | ❌ 실패 — **범위 아래 참조** |
| G3~G6 | PC / resume / 반복 / 복구 | ⬜ |

> **G2 실패의 시험 범위 (오해 방지):**
> **`APB index = 0` 고정**에서 시험한 `CoreBase × hart` 조합에 한한다.
> APB index 1/4/5 는 **한 번도 시험하지 않았다**(도구에는 추가돼 있으나 보류 중).
> POR 1회 후 재시도 포함. 각 조합의 power-cycle ID·DLL/firmware/device profile 은
> 아직 체계적으로 기록하지 않았다.

이 트랙은 **버리지 않는다.** 용도가 바뀔 뿐이다 — J-Link run-control 지원 여부
진단, trace 설정에 필요한 core/DM 연결 확인, trace 실패 시 대안, SEGGER 문의용
재현 로그. **다만 halt 성공을 v10.0 단일 착수 조건으로 쓰지 않는다.**

---

## T32 가 쓰는 방식 — 후보와 판정

| 방식 | 스크립트에서 찾을 흔적 | J-Link 쪽 대응 | 현재 판단 |
|---|---|---|---|
| **펌웨어 instrumentation bitmap** | 계측 빌드, RAM bitmap/counter, 주기적 메모리 read | J-Link 메모리 읽기 | **가능성 높음.** CPU halt 불필요할 수 있음 |
| **온칩 Nexus/트레이스 SRAM 버퍼** | Trace Encoder, SRAM sink, buffer 설정 | `RISCV_SetTEBaseAddr`, `RISCV_SetSRAMBaseAddr` | **가능성 있음.** TE/sink/AP 주소 필요 |
| **ATB 경유 온칩 sink** | ATB/funnel 설정 | `RISCV_UseNexusViaATB`, `RISCV_SetATBBaseAddr` | 가능성 있음. SoC trace 토폴로지 필요 |
| **외부 핀 streaming trace** | trace probe/포트, PIB, 연속 program flow | **J-Trace PRO RISC-V 필요** | ⚠️ 아래 참조 |
| 디버거 내부 profiling | snooper/profiler 명령 | 별도 구현 필요 | 스크립트 확인 전 판단 불가 |

### ⚠️ 하드웨어 리스크

SEGGER 문서는 **streaming trace 기반 code coverage 에 J-Trace PRO 가 필요하고
일반 J-Link 에서는 지원하지 않는다**고 명시한다. 만약 T32 가 외부 streaming
trace 를 쓰고 있었다면 **지금 장비(J-Link Plus)로는 원리적으로 불가**이고,
소프트웨어 작업을 더 하기 전에 **장비 조달 판단**이 먼저다.

### ★ 다만 우리가 아는 것으로 좁혀지는 부분

현재 디버그 커넥터는 **10핀**이고 cJTAG(2선) + TDI/TDO 정도다.
**10핀에 병렬 트레이스 핀이 나올 자리가 없다.** 즉 *이 커넥터로는* 외부
streaming trace 가 불가능하다. 따라서 T32 가 커버리지를 얻었다면 남는 건:

1. **instrumentation 메모리 읽기**, 또는
2. **온칩 버퍼를 디버그 포트로 드레인**, 또는
3. **우리가 모르는 별도 트레이스 커넥터를 썼다**

**1·2 는 일반 J-Link 로 "검토할 수 있는 후보"** 다. **가능이 확정된 게 아니다** —
아래를 확인해야 한다:

| instrumentation 이면 | 온칩 버퍼면 |
|---|---|
| bitmap 이 **어느 버스/AP** 에서 보이나 | TE·sink base 와 AP 경로 |
| 실행 중 **non-intrusive read** 가 되나 | 현재 probe 가 그 SoC trace 를 회수하나 |
| J-Link `connect()` 가 **halt 를 먼저 요구**하나 | raw trace **디코딩 API** 가 있나 |
| **cache/coherency** — 외부 read 가 최신인가 | program flow 로 재구성되나 |
| bitmap 갱신이 **atomic** 한가 | |

`RISCV_SetTEBaseAddr` / `RISCV_SetSRAMBaseAddr` 명령의 **존재는 구성 가능성일 뿐**,
J-Link Plus 가 이 SoC 의 trace 를 회수·디코딩해 커버리지로 준다는 증거가 아니다.

3 이면 장비 문제가 된다.
→ **"T32 는 어느 커넥터를 썼나"가 저비용 고수확 질문이다.**

> ⚠ 10핀 결론은 **현재 확인한 커넥터**에 대한 것이다. T32 측정 때 별도
> MIPI/MICTOR/벤더 trace 커넥터, 보드 test point, interposer 가 있었을 수 있다.
> **실제 장비 사진·케이블·probe 모델을 확보하기 전에는 외부 trace 를 낮은
> 가능성으로 두되 폐기하지 않는다.**

### 그리고 1번이면 오히려 좋은 소식이다

instrumentation bitmap 이면 halt 샘플링보다 **훨씬 나은 커버리지**를 얻는다.
ARM 제품에서 프로젝트 최대 약점이던 **부분맹(halt under-sampling)이 사라지고**,
AFL 식 bitmap 을 그대로 쓸 수 있다. 대신 "양산 이미지 그대로" 라는 기존 전제는
바뀐다(계측 빌드 필요).

---

## 다음 할 일

### P0-a — ★ 코드 없이 답할 수 있는 다섯 질문 (제일 먼저)

T32 를 실제로 쓴 사람에게 이것만 물으면 **후보가 대부분 갈린다:**

> 1. 커버리지 측정 때 **일반 debug cable 외에 다른 cable** 이 있었는가?
> 2. 사용한 **Lauterbach probe 의 정확한 모델**은?
> 3. 대상 펌웨어가 **양산 이미지인가, 커버리지용 재빌드 이미지인가?**
> 4. T32 에서 커버리지 시작 시 **누른 메뉴 / 실행한 명령**은?
> 5. 측정 종료 후 생성된 **파일의 확장자와 이름**은?

**3번이 instrumentation 여부를, 1·2번이 외부 trace 여부를 가른다.**

### P0-b — 실제 T32 스크립트와 측정 증거 확보

**원본을 먼저 보존한다.** 정리하거나 RISC-V 관련 줄만 뽑기 전에 —
T32 스크립트는 인자와 include 로 실제 주소·코어·trace 설정을 주입하므로
한 파일만 보면 잘못된 결론이 난다.

`risc-v/t32/` 아래에 보존한다:

1. 실제 실행한 **`.cmm`/PRACTICE 스크립트 전체**와 `DO`/include 체인
2. 실행한 **T32 제품 및 trace probe 모델**
3. 커버리지 **시작·정지·저장 명령 로그**
4. T32 trace/coverage **설정값** 또는 텍스트 export
5. **커버리지 결과 예시**와 대상 ELF/심볼/빌드 정보
6. 타깃 펌웨어가 **계측 빌드인지 일반 빌드인지**
7. **디버그 커넥터 외 별도 trace 케이블/포트**를 썼는지 ← ★
8. T32 가 읽는 **trace buffer 또는 bitmap 주소**

**이게 없으면 지금 가진 AP/COREDEBUG/Data.Set 조각만으로는 방식을 복원할 수 없다.**

#### 확보 후 기계적으로 검색할 키워드

```
COVerage / Trace / NEXUS / N-Trace / Analyzer
SRAM / ATB / Funnel / PIB / Buffer
Data.Save / Data.dump / memory read / bitmap / counter
instrument / compiler option / coverage runtime
```
명령 이름만 보지 말고 **커버리지 시작 전후의 메모리 쓰기**와
**export 파일 생성 경로**까지 추적한다.

### P1 — 스크립트를 두 계층으로 분리

```
[A] debug/control 연결   cJTAG, DP/AP, reset, unlock, DM/hart 선택
[B] coverage 데이터 경로  instrumentation 메모리 또는 TE → funnel/sink → probe
```

지금까지 한 작업은 **[A] 의 일부**를 J-Link 로 옮기면서 halt 를 합격 기준으로 삼은 것이다.
새 목표에서는 **[B] 를 먼저 식별하고, [B] 가 요구하는 만큼만 [A] 를 구현**한다.
RAM bitmap 을 AP 메모리 접근으로 읽는 방식이라면 **CPU halt 와 레지스터 접근이
필수 조건이 아닐 수 있다.**

### P2 — 메커니즘별 최소 증명

**instrumentation 이면**
1. J-Link 로 bitmap 주소를 read-only 로 읽는다
2. 서로 다른 두 workload 에서 bitmap 변화가 다른지 확인
3. T32 결과와 동일 빌드·동일 workload 로 교차 검증

**온칩 trace buffer 면**
1. T32 에서 TE·sink base, AP 경로, buffer 범위 추출
2. 최신 J-Link/J-Trace 의 해당 SiFive trace 규격 지원 여부 확인
3. 짧은 workload 의 raw trace 1회 회수 후 T32 결과와 비교

**외부 streaming trace 면**
1. 현재 probe 가 일반 J-Link 인지 J-Trace PRO RISC-V 인지 확정
2. 보드에 PIB/trace 핀이 실제로 노출·배선됐는지 확인
3. 일반 J-Link 라면 **소프트웨어 작업을 계속하기 전에 하드웨어 요구사항부터 결정**

### P3 — 저비용 병행 (P0 기다리는 동안) — **상한을 둔다**

> halt 진단이 다시 주 작업이 되지 않도록 제한한다:
> **Commander 원문 로그 1세트** + **현재판/최신판 동일 조건 1세트 비교**까지.
> 그 뒤에는 **T32 C1 분석 전까지 CoreBase/hart/APB 확장 금지.**

- **`JLinkExe` 로 직접 halt** — pylink 의 `False` 보다 SEGGER 원문 에러가 자세하다
- **J-Link 소프트웨어 팩 최신판 비교** — 현재 `JLink_V912`.
  ⚠ **"설치만 하면 해결" 을 기대하지 말 것.** SiFive E76 프로파일이 있어도 이 SSD SoC 의
  DAP/AP/DM/trace 토폴로지가 표준 E76 보드와 같다는 뜻이 아니다. 목적은 셋으로 한정:
  (a) RISC-V-behind-DAP / N-Trace 관련 수정 확인 (b) 더 상세한 오류 로그 확보
  (c) 현재 결과가 구버전 회귀인지 비교. **업그레이드 전에 현재 상태 기록**(변수 하나씩)
- **벤더 질문** — 이제 커버리지 방식까지 포함해서:
  > 1. 이 제품의 **코드 커버리지 수집 방식**은? (계측 빌드 / 온칩 트레이스 / 기타)
  > 2. 계측이면 **bitmap 주소와 포맷**, 트레이스면 **TE·sink 주소와 AP 경로**
  > 3. RISC-V **DM 의 DMI aperture 주소**와 **hart 번호** (run-control 트랙용)
  > 4. J-Link 또는 OpenOCD 설정 파일이 있습니까?
  > 5. NVMe 명령 처리 펌웨어가 도는 코어는?

### 하지 말 것

- **halt/APB/hart 스윕 확대** — T32 방식을 모른 채 후보를 넓히는 건 재현이 아니다
- **`connect()` 무예외 종료만으로 성공을 주장하기** — run-control 이든 coverage 든,
  각 트랙의 **실제 산출물**(halted 상태 / bitmap 변화 / raw trace)을 확인한다.
  합격 기준은 halt 가 아니라 **선택한 경로의 관측 가능한 산출물**이다
- 한 프로세스에 여러 조합 섞기 — 두 번 데였다

---

## 결과에 항상 명시할 것 (용어 혼동 방지)

"J-Link 지원" 은 J-Link Plus / J-Trace / J-Link SDK 를 섞어 읽기 쉽다. 그래서:

```
probe_model      = J-Link Plus | J-Trace PRO RISC-V | (T32 probe 모델)
host_software    = J-Link Software Pack 버전 | TRACE32 버전
collection_mode  = memory_bitmap | onchip_trace_buffer | streaming_trace | halt_pc
```

**현재 우리 장비:** `probe_model = J-Link Plus` (FW V13), `host_software = JLink_V912`

---

## 확정된 사실 (변함 없음)

| | |
|---|---|
| 물리 | VTref 1.793V, **10핀** 커넥터에 TDI/TDO 배선 |
| 인터페이스 | **cJTAG (TIF=7), 10MHz.** 1000kHz 로 낮추면 활성화 실패 |
| DP | `reg0 = 0x6BA0009D` — PARTNO `0xBA00`(ARM DAP), DESIGNER 는 ARM 아님 |
| 디버그 전원 | `CTRL/STAT ← 0x50000000` → `0xF0000000` |
| 토폴로지 | cJTAG → ARM DP → APB-AP → RISC-V DM(DMI) |
| 자동 검출 | 불가 — SEGGER KB 명시 |
| OpenOCD | cJTAG 미지원 |
| JLinkScript | 현재 훅·호출 순서에서 `JLINK_CORESIGHT_*` 동작 안 함 |

## 폐기된 결론 (같은 실수 반복 금지)

| 한때 결론 | 실제 |
|---|---|
| "`0x81480000` 은 연결 실패" | 틀림. 항상 첫 자리였을 뿐 — 순서 문제 |
| "T32 재시도 루프 = 연결 불안정" | 틀림. 첫 connect 가 구조적으로 실패 |
| "두 DM 모두 접근 가능" | 과함. connect 후보 통과일 뿐 |
| "resume 실패 → 보드 복구 필요" | 거짓 경보. halt 가 안 돼 멈춘 적이 없었다 |
| **"halt/PC/resume 이 v10.0 착수 조건"** | **틀림. T32 커버리지는 halt 방식이 아니다** |
