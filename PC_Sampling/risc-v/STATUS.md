# SF-E76 브링업 — 현재 상태와 다음 할 일

> 2026-08-07 기준. **한 장짜리 요약.** 근거·이력은 `BRINGUP_riscv_v10.md`,
> 실행법은 `README.md`, 외부 검토는 `feedback.md`.

---

## 한 줄

**transport 는 뚫렸고 코어 제어는 안 된다.** `connect()` 는 되는데
`halt()` 가 DLL 레벨에서 거부되며, 시도한 **모든 (CoreBase × hart) 조합에서
POR 후에도 동일**하다.

---

## 게이트 현황

| | 조건 | 상태 |
|---|---|---|
| **G0** | cJTAG / DP / 디버그 전원 ACK | ✅ |
| **G1** | J-Link `connect()` | ⚠️ 조건부 — 2회차에만, **의미 불확실** |
| **G2** | halt + `halted` 확인 | ❌ **실패** |
| G3 | PC 읽기 | ⬜ 미도달 |
| G4 | resume + running 확인 | ⬜ 미도달 |
| G5 | workload 중 반복 샘플링 | ⬜ |
| G6 | reconnect / POR / crash 복구 | ⬜ |

**v10.0 샘플러 착수 조건 = G4.** 현재 G2 에서 막혀 있다.

---

## 확정된 사실

| | |
|---|---|
| 물리 | VTref 1.793V, 10핀에 TDI/TDO 배선 있음 |
| 인터페이스 | **cJTAG (TIF=7), 10MHz.** 1000kHz 로 낮추면 활성화 자체가 실패 |
| DP | `reg0 = 0x6BA0009D` — PARTNO `0xBA00`(ARM DAP)이나 **DESIGNER 는 ARM 아님**(벤더 DAP) |
| 디버그 전원 | `CTRL/STAT ← 0x50000000` → `0xF0000000` (ACK 2개) |
| 토폴로지 | cJTAG → ARM DP → APB-AP → RISC-V DM(DMI). SEGGER 가 공식 지원하는 hybrid 구성 |
| 자동 검출 | **불가.** SEGGER KB 가 "RISC-V 는 ROM table scan 이 없어 AP/DMI 위치를 자동 검출할 수 없다" 고 명시 |
| J-Link cJTAG | 지원함 (`si cJTAG` 수락, FW V13) |
| OpenOCD | **cJTAG 미지원** (jlink 드라이버에 명령 없음) |
| JLinkScript | 현재 훅·호출 순서에서 `JLINK_CORESIGHT_*` 동작 안 함 |

## 폐기된 결론 (같은 실수 반복 금지)

| 한때 결론 | 실제 |
|---|---|
| "`0x81480000` 은 연결 실패" | **틀림.** 항상 첫 자리에 있었을 뿐 — 순서 문제였다 |
| "T32 재시도 루프 = 연결 불안정" | **틀림.** 첫 connect 가 구조적으로 실패하는 것 |
| "두 DM 모두 접근 가능" | **과함.** connect 후보 통과일 뿐, halt 는 안 된다 |
| "AP 스윕 불필요" | **틀림.** APB index 를 0 으로 고정한 채였다 (이번에 추가) |
| "resume 실패 → 보드 복구 필요" | **거짓 경보.** halt 가 애초에 안 돼 멈춘 적이 없었다 |

---

## 무엇이 문제인가

`connect()` 성공이 **제어 가능한 하트 도달을 뜻하지 않는다.** J-Link 의 connect
자체도 1회차에 `Error while halting CPU` 로 실패하므로, 2회차 "성공" 이
**halt 실패를 눈감고 통과한 것**일 가능성이 높다.

halt 가 전 조합에서 실패한다는 것은 아래 중 하나가 틀렸다는 뜻이다:

1. **DMI aperture 주소** (`CORESIGHT_SetCoreBaseAddr`) — T32 `COREDEBUG.Base` 로
   추정했으나 그 해석이 맞는지 미확인
2. **AP 선택** — APB index 를 계속 0 으로 고정했다
3. **hart 번호** — 0~4 는 순전한 추측
4. **누락된 초기화** — DM 활성화(`dmactive`)나 벤더 언락 등

**1·3 은 실험으로 알아낼 수 없다.** 벤더 정보다.

---

## 다음 할 일

### P0 — 지금, 병렬로 (전부 저비용)

**① J-Link Commander 로 직접 halt** — pylink 의 `False` 보다 **에러 메시지가 자세하다**
```
JLinkExe -if cJTAG -speed 10000 -device RISC-V
J-Link> connect
J-Link> halt
```
SEGGER 의 원문 에러가 곧 단서다.

**② J-Link 소프트웨어 팩 버전 확인**
현재 `/opt/SEGGER/JLink_V912/`. **RISC-V 지원은 빠르게 바뀌는 영역**이라
최신 팩에 이 SoC 가 장치 DB 로 들어가 있으면 지금 문제가 통째로 사라질 수 있다.
단, **업그레이드 전에 현재 상태를 기록**해 둘 것(변수를 한 번에 하나만).

**③ T32 설정 재조사 — RISC-V 전용 항목**
지금까지 `APBAP*.Base` 와 `COREDEBUG.Base` 만 봤다. RISC-V 전용 설정을 놓쳤을 수 있다.
```
DEBUGMODULE / DMI / HART / SMP / CORENUMBER / RISCV
SYStem.CONFIG.CORE / SYStem.CPU 주변 전체
코어별 T32 인스턴스에 전달되는 서로 다른 파라미터
```

**④ 벤더 질문 — 질문이 아주 짧아졌다**
> 1. RISC-V **Debug Module 의 DMI aperture 주소**와, 그것이 **어느 AP** 뒤에 있는지?
> 2. **하트 개수와 hartsel 값**은? (코어 5개: hcore/CMCore/Fcore0/QCore/Ncore)
> 3. 디버그 활성화/언락 절차가 있습니까?
> 4. J-Link 또는 OpenOCD 설정 파일이 있습니까?
> 5. NVMe 명령 처리 펌웨어가 도는 코어는 어느 것입니까?

증거를 붙일 것: cJTAG 10MHz 활성화 OK / `DPIDR=0x6BA0009D` /
`CTRL/STAT=0xF0000000` / connect 는 2회차에 성공 / **halt 는 전 조합 실패**.

### P1 — 남은 기술적 공백

**⑤ APB index 스윕** (이번에 도구에 추가)
```bash
sudo python3 find_haltable.py --apbs 0,1,4,5
```
CoreBase × hart 만 훑고 **APB index 는 0 고정**이었다. 4개 APB-AP 중 다른 것일 수 있다.

**⑥ SEGGER 문의** — ①③⑤ 가 다 실패하면. 증거 패키지는 이미 갖춰져 있다.

### 하지 말 것

- 주소·hart 를 더 무작위로 넓혀 스윕하기 — 조합만 늘고 정보는 안 는다
- `connect()` 성공을 진전으로 기록하기 — halt 없이는 의미 없다
- 한 handle/프로세스에 여러 조합 섞기 — 두 번 데였다

---

## 병행 트랙 (크리티컬 패스 아님)

- **Nexus 트레이스** — 성공하면 부분맹 커버리지와 halt 유발 문제를 한 번에 없앤다.
  SiFive Insight 는 Nexus 기반이고 `RISCV_SetTEBaseAddr` 명령이 J-Link 에 존재한다.
  다만 **연결이 먼저다.**
- **halt 가 PCIe 를 멈추는지** — ARM 제품(P7/P9)에서 호스트 프리즈로 몇 달을 태웠다.
  halt 가 되기 시작하면 **본격 개발 전에** `halt_loop_stress.py` 를 포팅해 확인.
- **오버레이** — ARM 제품에서 미해결로 남은 문제. `.text` 범위와 함께 벤더에 확인.
