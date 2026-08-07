# RISC-V 신제품 (SF-E76) — v10.0 브링업

신제품(SiFive E76 기반 RISC-V SSD 컨트롤러)에 퍼저를 올리기 위한 조사·도구 모음.

| 파일 | 내용 |
|---|---|
| `BRINGUP_riscv_v10.md` | **조사 노트(살아있는 문서)** — 확정 사실 / 추론 / 열린 질문 |
| `feedback.md` | 외부 검토 피드백 (방향 검증) |
| **`connect_sfe76.py`** | **연결 — 동작함.** AP map + DMI base 수동 설정 |
| **`verify_halt_pc.py`** | **halt / PC / resume 검증** ← v10.0 크리티컬 패스 |
| **`diagnose_connect.py`** | **첫 connect 실패 근본원인** (D 세션지속성 / E 장치명 / F 하트) |
| `connect_min.py` | 최소 재현 — 순서 지정(`--order`)으로 위치 vs 주소 분리 |
| `isolate_warmup.py` | warmup 메커니즘 분리 (A/B/C) — **완료: A만 성공** |
| `SF_E76_config.JLinkScript` | `ConfigTargetSettings()` 정식 설정 (InitTarget 전원인가는 실패) |
| `probe_sfe76_pylink.py` | 초기 진단 — DP/전원 확인용 (역할 종료) |
| `SF_E76_cJTAG_probe.JLinkScript` | 초기 진단 (역할 종료) — JLinkScript 는 CoreSight API 사용 불가 |
| `SF_E76_addap.JLinkScript` | 위와 같음 (역할 종료) |

---

## 지금 상황

| 계층 | 상태 |
|---|---|
| 물리 (VTref 1.793V, 배선) | ✅ |
| cJTAG 활성화 @10MHz (TIF=7) | ✅ |
| ARM DP 통신 | ✅ `DP reg0 = 0x6BA0009D` |
| 디버그 도메인 전원 | ✅ `CTRL/STAT = 0xF0000000` |
| AP map / DMI base 설정 | ✅ `CORESIGHT_AddAP` + `SetIndexAPBAPToUse` + `SetCoreBaseAddr` |
| **J-Link connect** | ⚠️ **되지만 2회차에만** — 근본원인 미규명 |
| **halt / PC / resume** | ⬜ **미검증** ← v10.0 크리티컬 패스 |
| 코어 귀속 (어느 코어인가) | ⬜ 미확정 |

### 확정된 연결 설정

```
SetcJTAGInitMode = 0
set_tif(7)  # cJTAG      set_speed(10000)   ← 1000kHz 로 낮추면 활성화 실패
CORESIGHT_AddAP = Index=0 Type=APB-AP Addr=0x10000     (…Index=5 까지)
CORESIGHT_SetIndexAPBAPToUse = 0
CORESIGHT_SetCoreBaseAddr    = 0x81480000   # 또는 0x81481000 (Ncore)
connect('RISC-V')                            # ★ 1회차 실패, 2회차 성공
```

**근거:** SEGGER KB 가 "RISC-V 는 ROM table scan 이 없어 hybrid DAP 구성을
자동 검출할 수 없다" 고 명시한다. 수동 선언이 필수다.

### ⚠ 지켜야 할 원칙

| | |
|---|---|
| **한 handle = 한 설정** | 조합을 섞으면 거짓 성공 또는 전체 실패 (실측 2회) |
| **첫 connect 는 실패한다** | 재시도 필요. 원인 규명 중 (`diagnose_connect.py`) |
| **halt 후 반드시 resume** | ★ 코어가 멈춘 채 남으면 SSD 가 hang 한다 |

---

## `probe_sfe76_pylink.py` ← **이걸 먼저 돌린다**

JLinkScript 판은 **에러 메시지가 없어서** 왜 실패했는지 알 수 없었다(모든 반환이
`0x80000000` = INT_MIN = API 에러). pylink 는 예외/메시지가 나와 원인이 보인다.
게다가 **퍼저가 결국 쓰는 API** 라 여기서 확정한 절차를 그대로 샘플러로 옮길 수 있다.

```bash
# pylink 가 venv 가 아니라 시스템 python3 에 있을 수 있다 — 둘 다 시도
sudo python3 probe_sfe76_pylink.py
sudo /home/ssd/gdbfuzz/.venv/bin/python3 probe_sfe76_pylink.py

sudo python3 probe_sfe76_pylink.py --tif 7        # cJTAG TIF 값 직접 지정
```

### 단계와 판정

| 단계 | 확인 | 실패 시 |
|---|---|---|
| **[1]** 지원 TIF 목록 | **cJTAG 를 pylink 로 고를 수 있나** | JLinkScript 경로로 복귀 |
| [2] set_tif / set_speed | 인터페이스 선택 | — |
| **[3]** `coresight_configure()` | CoreSight 초기화 | **예외 메시지가 핵심** (JLinkScript 가 여기서 죽었을 것) |
| **[4]** DPIDR + 전원 인가 | ARM DAP 확정 + 디버그 전원 ACK | DPIDR 무효 → SEGGER / ACK 없음 → 벤더 |
| [5] AP 열거 | APSEL 0~7 중 실재하는 것 | 전원 또는 AP 매핑 |
| [6] `0x81480000` | CoreSight ID | `CIDR0` 하위 `0x0D` 면 주소 정확 |

**[1] 이 관문이다.** pylink 가 cJTAG TIF 값을 모르면 이름 없는 TIF 후보를 찍어주니,
`--tif` 로 바꿔가며 재실행하면 된다.

---

## `SF_E76_cJTAG_probe.JLinkScript` (보조)

J-Link 의 자동 식별을 거치지 않고, **T32 가 `SYStem.Up` 한 줄로 자동 수행하는
ARM ADI 표준 절차를 명시적으로** 실행한다. 1차 목표는 연결이 아니라 **진단**이다.

### 실행

```bash
JLinkExe -if cJTAG -speed 10000 -device <아무 이름> \
         -JLinkScriptFile SF_E76_cJTAG_probe.JLinkScript
```

- `-device` 는 식별에 실패해도 무방하다. `InitTarget()` 이 **그보다 먼저** 실행된다.
- **속도는 10000(10MHz) 고정.** 실측상 1000kHz 로 낮추면 cJTAG 활성화 자체가 실패한다
  (T32 설정도 "USB 연결 시 10MHz").
- 다른 디버거(T32 등)가 J-Link 을 점유 중이면 실패한다.

### 무엇을 확인하나

| 단계 | 확인 | 실패 시 의미 |
|---|---|---|
| **[2]** DPIDR | 유효한 DP ID 가 읽히나 | cJTAG **스캔 포맷 불일치** → SEGGER 문의 |
| **[3]** CTRL/STAT | 디버그 전원 ACK 가 서나 | **전원/인증 게이팅** → 벤더 문의 |
| **[4]** AP 열거 | APSEL 0~7 중 실재하는 AP | AP 매핑 추론 검증 |
| **[5]** `0x81480000` | CoreSight ID 가 읽히나 | 코어 디버그 주소 검증 |

`CIDR0 = 0x0D` 가 나오면 CoreSight 컴포넌트 확정이고 주소가 맞다는 뜻이다.

### 전부 통과하면

스크립트 마지막의 `return 0;` 을 **`return 1;`** 로 바꾼다.
J-Link 의 (틀린) 자동 식별을 건너뛰고 스크립트 설정을 그대로 쓰게 된다.

### 값이 안 맞을 때 만질 곳

파일 상단 설정 블록:

| 상수 | 기본 | 언제 바꾸나 |
|---|---|---|
| `_COREDEBUG_BASE_A/B` | `0x81480000` / `0x81481000` | T32 `COREDEBUG.Base` 가 다르면 |
| `_CSW_32BIT` | `0x80000002` | AP 읽기가 전부 0 이면 `0x23000052`, `0x00000002` 시도 |
| `IRLenDevice=4` | 4 | 체인에 TAP 이 여럿이면 `IRPre/IRPost/DRPre/DRPost` 도 채울 것 |

---

## 결과 보고

출력 전문을 그대로 남겨두면 된다. **성공보다 실패 지점이 정보가 많다** —
어느 단계에서 끊기느냐에 따라 다음 행동(SEGGER 문의 / 벤더 문의 / 주소 수정)이 갈린다.

미해결로 남은 질문은 `BRINGUP_riscv_v10.md` §3 에 정리돼 있다.
