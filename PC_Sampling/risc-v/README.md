# RISC-V 신제품 (SF-E76) — v10.0 브링업

SiFive **E76** 기반 RISC-V SSD 컨트롤러에 퍼저를 올리기 위한 작업.

> ## ★ 먼저 읽을 것: [`STATUS.md`](STATUS.md)
>
> **T32 로 이 제품의 커버리지가 실제로 측정되며, 그 방식은 halt 가 아니다.**
> 따라서 현재 주 트랙은 **"T32 커버리지 메커니즘 식별"(C0~C6)** 이고,
> 아래의 halt/PC/resume(G0~G6)는 **보조 트랙**이다.
> 이 문서의 실행 안내도 대부분 보조 트랙용이다.

**v10.0 범위:** 커버리지 수집 방식이 확정되기 전까지는 **미정**이다.
halt PC 샘플링이면 샘플러 층 교체만으로 끝나지만(기존 `pc_sampling_fuzzer_v9.7.py`
대비 `_read_all_pcs()` 수준), instrumentation bitmap 이면 수집 계층 자체가 달라진다.
NVMe 전송·코퍼스·변이·LLM·replay·POR 는 어느 쪽이든 그대로 간다.

---

## 진행 상황

| 계층 | 상태 |
|---|---|
| 물리 (VTref 1.793V, 배선) | ✅ |
| cJTAG 활성화 (TIF=7, 10MHz) | ✅ |
| ARM DP 통신 | ✅ `DP reg0 = 0x6BA0009D` |
| 디버그 도메인 전원 | ✅ `CTRL/STAT = 0xF0000000` |
| AP map / DMI base 선언 | ✅ |
| **J-Link connect** | ⚠️ **되지만 2회차에만** — 근본원인 규명 중 |
| **halt** | ❌ **실패** — `JLINKARM_Halt()` 가 DLL 레벨에서 거부 |
| PC / resume | ⬜ halt 가 안 돼 도달 못 함 |
| 코어 귀속 (어느 코어인가) | ⬜ 미확정 |
| 반복 reconnect / POR / crash 복구 | ⬜ 미검증 |
| Nexus 트레이스 | ⬜ 병행 트랙 (크리티컬 패스 아님) |

### 게이트 — 지금 어디까지 왔나

| | 조건 | 상태 |
|---|---|---|
| **G0** | cJTAG / DPIDR / 전원 ACK | ✅ |
| **G1** | bounded retry 안에 J-Link `connect()` | ⚠️ 부분 (2회차에만) |
| **G2** | halt 성공 + `halted` 확인 | ❌ **실패** |
| **G3** | PC/DPC 읽기 + 유효 범위·변화 확인 | ⬜ |
| **G4** | resume 성공 + running 확인 | ⬜ |
| **G5** | workload 중 반복 샘플링 | ⬜ |
| **G6** | close/reopen · POR · crash 복구 | ⬜ |

**이 게이트는 halt PC 샘플링 대안 트랙의 것이다.** 주 트랙은 `STATUS.md` 의 C0~C6.
halt 경로를 택하게 될 경우의 착수 조건이 G4, 장시간 투입 조건이 G5+G6 이다.

> ⚠️ **`connect()` 성공은 코어 도달을 뜻하지 않는다 — 실측으로 확인됐다.**
> `connect()` 는 2회차에 성공하는데 **`halt()` 는 DLL 레벨에서 거부된다.**
> J-Link 의 connect 도 1회차에 "Error while halting CPU" 로 실패하므로,
> 2회차 "성공" 이 **halt 실패를 눈감고 통과한 것**일 가능성이 있다. 지금 입증된 것은
> "두 CoreBase 값에서 `connect('RISC-V')` 가 2회차에 예외 없이 끝난다" 뿐이다.
> DM register·hart·PC·halt/resume 은 아직 검증 전이므로 **"두 DM 모두 접근 가능"
> 같은 표현은 과하다.** 정확히는 **"J-Link connect 후보로 통과했다"** 이다.

---

## 파일

| 파일 | 역할 |
|---|---|
| **`STATUS.md`** | **한 장짜리 현황 + 다음 할 일** ← 여기부터 |
| **`sfe76_link.py`** | **연결 계층 — 정식 모듈.** 연결 지식의 단일 출처. 샘플러도 여기를 쓴다 |
| `find_haltable.py` | halt 되는 (CoreBase, hart, APB) 조합 찾기 — **보조 트랙** |
| **`verify_halt_pc.py`** | halt / PC / resume 검증 (halt 되는 조합을 찾은 뒤) |
| **`diagnose_connect.py`** | 첫 connect 실패 **근본원인** (D 세션지속성 / E 장치명 / F 하트) |
| `SF_E76_config.JLinkScript` | `ConfigTargetSettings()` 정식 설정 (미해결 항목 있음) |
| `BRINGUP_riscv_v10.md` | 조사 노트 (사실 / 추론 / 열린 질문) |
| `feedback.md` | 외부 검토 피드백 |
| `backup/` | 역할이 끝난 도구 + **무엇을 밝혀냈는지** 기록 |

---

## 확정된 연결 설정

```
SetcJTAGInitMode = 0
set_tif(7)                # cJTAG — pylink enum 에 없어 정수로 지정
set_speed(10000)          # ★ 1000kHz 로 낮추면 cJTAG 활성화 자체가 실패

CORESIGHT_AddAP = Index=0 Type=APB-AP Addr=0x10000    # APBAP1
CORESIGHT_AddAP = Index=1 Type=APB-AP Addr=0x20000    # APBAP2
CORESIGHT_AddAP = Index=2 Type=AXI-AP Addr=0x30000    # AXIAP1
CORESIGHT_AddAP = Index=3 Type=AHB-AP Addr=0x40000    # AHBAP1
CORESIGHT_AddAP = Index=4 Type=APB-AP Addr=0x50000    # APBAP3
CORESIGHT_AddAP = Index=5 Type=APB-AP Addr=0x60000    # APBAP4

CORESIGHT_SetIndexAPBAPToUse = 0
CORESIGHT_SetCoreBaseAddr    = 0x81480000   # 또는 0x81481000 (Ncore)

connect('RISC-V')          # ★ 1회차 실패, 2회차 성공
```

**근거:** [SEGGER KB — J-Link RISC-V](https://kb.segger.com/J-Link_RISC-V) 가
`JTAG → SWJ-DP → APB-AP → DMI` 를 공식 지원 토폴로지로 문서화하면서,
**"RISC-V 는 ROM table scan 이 없어 AP 위치와 DMI 위치를 자동 검출할 수 없다"** 고
명시한다. 수동 선언이 필수다 — 자동 검출 시도가 전부 실패한 이유가 이것이다.

**용어 주의:** `CORESIGHT_AddAP` 의 `Index` 는 **J-Link 내부 AP 맵 번호**이지
하드웨어 APSEL 이 아니다. 실제 위치는 `Addr` 이고, 그게 T32 의 `DP:0xN0000` 이다.

---

## ⚠ 지켜야 할 원칙 4개

**1. 한 handle = 한 설정**
조합을 섞으면 (a) 한 번 붙은 뒤 이후가 전부 **거짓 성공**(24개 중 23개)하거나
(b) 조합마다 close 로 격리하면 **전부 실패**한다. 실측으로 둘 다 겪었다.

**2. 첫 `connect()` 는 실패한다 — 임시 workaround 중**
통제 실험 결과 setup 이중 적용도, 대기도 아니고 **connect 시도 자체**가 필요하다.
bounded retry(3회)로 우회하되 **정상이 아니다.** 퍼저는 POR 복구·크래시 후
수백 번 재연결하므로 원인을 찾아야 한다 → `diagnose_connect.py`

> 범위 제한: **현재 J-Link DLL/펌웨어, generic `RISC-V` device profile, 현재 명령
> 순서, 현재 보드 상태**에서 일관되게 관측된 현상이다. RISC-V 나 이 SoC 일반의
> 성질로 일반화하지 말 것. 재현성을 위해 **DLL/펌웨어 버전·device·전원 사이클 여부**를
> 항상 로그에 남긴다.

**3. halt 후 반드시 resume — 실패 시 중단**
코어를 멈춘 채 두면 **SSD 컨트롤러가 멈춰 NVMe 가 hang 한다.**

```
try:    halt → halted 확인 → PC 읽기·유효성 검사
finally: best-effort resume → running 재확인
```

**resume 확인이 실패하면 다음 실험을 계속하지 말고** handle 을 닫은 뒤
보드 복구 절차(전원 사이클)를 수행한다. `sfe76_link.Link` 가 컨텍스트 매니저
종료 시 자동 resume 하지만, **성공 여부를 확인하는 것은 호출자 책임**이다.

**4. APB 메모리 접근 ≠ RISC-V DMI 레지스터 접근**
`dmcontrol 0x10`, `dmstatus 0x11` 등은 **DMI register address** 이지 APB byte
offset 이 아니다. `CORESIGHT_SetCoreBaseAddr` 가 가리키는 벤더 DMI aperture 의
레이아웃과 J-Link 의 변환 방식을 확인하기 전에 `base + 0x10` 식으로 메모리를
읽고 쓰면 **엉뚱한 장치를 건드릴 수 있다.** 직접 접근은 벤더/T32 자료로
aperture 레이아웃을 확보한 뒤에만.

---

## 실행

```bash
# 연결만 확인
sudo python3 sfe76_link.py
sudo python3 sfe76_link.py --core-base 0x81481000     # Ncore

# ⚠ halt 트랙은 보류 중이다 (STATUS.md 참조).
#   T32 커버리지가 halt 방식이 아님이 확인돼, 먼저 T32 메커니즘을 식별한다.
#   아래는 보조 트랙(run-control 진단)용.
sudo python3 find_haltable.py

# halt / PC / resume
#   ★ 먼저 Ncore(0x81481000) 로 검증한다. 단일 하트라 변수가 적다.
#     0x81480000 은 4코어 공유라 hart 선택까지 얽혀 원인 분리가 어렵다.
#   1단계 — PC 레지스터 후보 조사 (샘플링 안 함)
sudo python3 verify_halt_pc.py --scan-registers
#   2단계 — 확정된 인덱스로만 (추측 금지)
sudo python3 verify_halt_pc.py --pc-index <번호> --samples 100
#   다른 코어는 프로세스를 새로 (한 실행 = 한 설정)
sudo python3 verify_halt_pc.py --core-base 0x81480000 --hart 0 --scan-registers

# 첫 connect 실패 원인
sudo python3 diagnose_connect.py
```

> pylink 가 venv 가 아니라 **시스템 `python3`** 에 설치된 경우가 있다. 둘 다 시도할 것.
> J-Link 이 여러 대면 `--serial` 로 지정할 것 (안 하면 엉뚱한 보드를 잡는다).

**종료 코드** — 자동화가 실패를 성공으로 읽지 않게 구분한다:
`0` 정상 / `2` connect / `3` halt / `4` PC / **`5` resume 실패(보드 복구 필요)** / `6` 불충분

---

## 열린 질문

| # | 질문 | 확인 방법 |
|---|---|---|
| 0 | **★ T32 는 어떤 메커니즘으로 커버리지를 얻나** | `STATUS.md` P0. **주 트랙** |
| 1 | 첫 connect 가 왜 실패하나 | `diagnose_connect.py`. 유력 가설 = RISC-V DM 의 `dmactive` (쓴 뒤 되읽어 1 될 때까지 기다려야 하는데 J-Link 이 안 기다리는 것으로 의심) |
| 2 | halt / PC / resume 이 되나 | `verify_halt_pc.py` — **보조 트랙**. 현재 halt 실패(APB=0 범위) |
| 3 | PC 레지스터 인덱스 | `verify_halt_pc.py --scan-registers`. **추측 금지** — 이름/T32 교차검증/fingerprint 중 하나로 확정해야 샘플링한다 |
| 4 | `0x81480000` 이 **어느 코어**인가 | halt 후 PC/hart 비교. connect 성공만으론 알 수 없다 |
| 5 | **NVMe 를 처리하는 코어**는? | 벤더 문의 — `hcore` 추정이나 미확인 |
| 6 | 펌웨어 `.text` 범위 / 오버레이 | 벤더 문의. 커버리지 필터에 필요 |
| 7 | JLinkScript 판의 첫 connect 는 성공했나 | 전원 ACK 만 확인됐고 connect 결과 미확인 |

---

## 벤더 질문지

> 1. **NVMe 명령 처리 펌웨어가 도는 코어**는 `hcore`/`CMCore`/`Fcore0`/`QCore`/`Ncore` 중 무엇입니까?
> 2. 각 코어의 **Debug Module 주소와 hart 번호**는?
> 3. 펌웨어 **`.text` 범위**와 **오버레이/코드 뱅킹 사용 여부**는?
> 4. J-Link 또는 OpenOCD **설정 파일**이 있습니까?
> 5. Nexus 트레이스의 **Class 등급**과 **싱크(온칩 버퍼 여부)** 는?

---

## 알아둘 것

- **오버레이 문제**(ARM 제품에서 미해결로 남은 것)가 이 제품에도 있을 수 있다.
  코드가 주소를 공유하면 커버리지가 서로 덮어써 **탐색 자체가 망가진다.**
  `.text` 범위와 함께 반드시 확인할 것.
- **halt 가 PCIe 를 멈추는지** 조기에 봐야 한다. ARM 제품(P7/P9)에서 호스트
  프리즈로 몇 달을 태웠다. `halt_loop_stress.py` 를 포팅해 **본격 개발 전에** 확인.
- **Nexus 트레이스**는 이제 **병행 트랙이 아니라 주 트랙 후보 중 하나**다.
  T32 가 트레이스로 커버리지를 얻고 있었다면 그게 재현해야 할 경로다.
  ⚠ 다만 **외부 streaming trace 라면 J-Trace PRO 가 필요**하고 현재 J-Link Plus 로는
  불가하다(SEGGER 문서 명시). 온칩 버퍼면 J-Link 로 검토 가능.
